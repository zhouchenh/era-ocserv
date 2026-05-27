package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/zhouchenh/era-ocserv/internal/cstp"
	"github.com/zhouchenh/era-ocserv/internal/dtlsuds"
	"github.com/zhouchenh/era-ocserv/internal/tun"
)

// transport is the per-client abstraction the bridge uses to dispatch
// outbound (TUN → client) IP packets. Both *cstp.Tunnel and *dtlsuds.Session
// implement it.
//
// The two implementations have different lifecycles: the CSTP tunnel is
// a long-lived goroutine pair (reader + heartbeat) while the DTLS session
// is purely state — receive-driven by the dtlsuds listener with no
// goroutine of its own here in the bridge.
type transport interface {
	// WritePacket sends an IP packet toward the client. Returns
	// io.ErrClosedPipe (or equivalent) once the transport is gone; the
	// bridge logs at Debug and continues with the next packet.
	WritePacket(p []byte) (int, error)
	// label returns a short identifier for log lines ("cstp" / "dtls").
	label() string
}

type cstpTransport struct{ t *cstp.Tunnel }

func (c cstpTransport) WritePacket(p []byte) (int, error) { return c.t.WritePacket(p) }
func (cstpTransport) label() string                       { return "cstp" }

type dtlsTransport struct{ s *dtlsuds.Session }

func (d dtlsTransport) WritePacket(p []byte) (int, error) { return d.s.WritePacket(p) }
func (dtlsTransport) label() string                       { return "dtls" }

// activeClient holds the per-/128 transport set. The DTLS session, when
// present, is preferred for egress; the CSTP tunnel is the fallback. This
// matches OpenConnect's data-path convention: DTLS is the high-throughput
// channel, CSTP is the control channel that doubles as a data fallback.
//
// Either pointer may be nil; the bridge only deregisters the /128 entry
// when both go away. WritePacket selects the active transport at call
// time so a DTLS arrival mid-flow takes over without bouncing the
// activeClient struct itself.
type activeClient struct {
	mu   sync.Mutex
	cstp *cstp.Tunnel
	dtls *dtlsuds.Session
}

// chooseTransport returns the preferred outbound transport for this /128
// or nil if both are gone.
func (a *activeClient) chooseTransport() transport {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dtls != nil {
		return dtlsTransport{s: a.dtls}
	}
	if a.cstp != nil {
		return cstpTransport{t: a.cstp}
	}
	return nil
}

type bridge struct {
	dev       *tun.Device
	srv       *cstp.Server
	clients   sync.Map // netip.Addr -> *activeClient
	rrCounter atomic.Uint64
}

func newBridge(dev *tun.Device, srv *cstp.Server) *bridge {
	return &bridge{dev: dev, srv: srv}
}

func (b *bridge) run(ctx context.Context) {
	for _, q := range b.dev.Queues() {
		go b.pumpTunQueue(ctx, q)
	}
	for {
		t, err := b.srv.Accept(ctx)
		if err != nil {
			if !errors.Is(err, cstp.ErrServerClosed) && !errors.Is(err, context.Canceled) {
				slog.Error("cstp accept", "err", err)
			}
			return
		}
		go b.pumpTunnel(ctx, t)
	}
}

// loadOrCreateClient returns the activeClient stored under inner, or stores
// and returns a new one.
func (b *bridge) loadOrCreateClient(inner netip.Addr) *activeClient {
	if v, ok := b.clients.Load(inner); ok {
		return v.(*activeClient)
	}
	ac := &activeClient{}
	if actual, loaded := b.clients.LoadOrStore(inner, ac); loaded {
		return actual.(*activeClient)
	}
	return ac
}

func (b *bridge) pumpTunQueue(ctx context.Context, q *tun.Queue) {
	buf := make([]byte, 65535)
	for {
		n, err := q.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				slog.Debug("tun queue read", "err", err)
			}
			return
		}
		if n < 40 || buf[0]>>4 != 6 {
			continue
		}
		dst, ok := netip.AddrFromSlice(buf[24:40])
		if !ok {
			continue
		}
		v, ok := b.clients.Load(dst)
		if !ok {
			continue
		}
		ac := v.(*activeClient)
		tr := ac.chooseTransport()
		if tr == nil {
			continue
		}
		if _, err := tr.WritePacket(buf[:n]); err != nil {
			slog.Debug("transport write", "transport", tr.label(), "inner", dst, "err", err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// pumpTunnel registers a freshly-accepted CSTP tunnel under its /128 and
// pumps inbound IP packets into the tun device for the lifetime of the
// tunnel. On exit it deregisters the CSTP transport; the DTLS session, if
// any, is left in place (the /128 is shared).
func (b *bridge) pumpTunnel(ctx context.Context, t *cstp.Tunnel) {
	id := t.Identity()
	inner := id.IPv6.Addr()
	ac := b.loadOrCreateClient(inner)

	ac.mu.Lock()
	prev := ac.cstp
	ac.cstp = t
	ac.mu.Unlock()
	if prev != nil {
		slog.Warn("displacing prior CSTP tunnel on same /128", "device", id.DeviceID, "inner", inner)
		prev.Close()
	}
	slog.Info("cstp client connected", "device", id.DeviceID, "inner", inner, "session", t.SessionID())

	defer func() {
		ac.mu.Lock()
		if ac.cstp == t {
			ac.cstp = nil
		}
		empty := ac.cstp == nil && ac.dtls == nil
		ac.mu.Unlock()
		if empty {
			b.clients.CompareAndDelete(inner, ac)
		}
		t.Close()
		slog.Info("cstp client disconnected", "device", id.DeviceID, "inner", inner)
	}()

	queues := b.dev.Queues()
	if len(queues) == 0 {
		return
	}
	buf := make([]byte, 65535)
	for {
		n, err := t.ReadPacket(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				slog.Debug("tunnel read", "device", id.DeviceID, "err", err)
			}
			return
		}
		qIdx := int(b.rrCounter.Add(1) % uint64(len(queues)))
		if _, err := queues[qIdx].Write(buf[:n]); err != nil {
			slog.Debug("tun write", "queue", qIdx, "err", err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// OnAdmit is the dtlsuds.SessionLifecycle hook called when a new DTLS
// session enters the listener's table. The bridge registers the session
// against the device's inner /128 so subsequent TUN egress packets pick
// the DTLS transport.
func (b *bridge) OnAdmit(s *dtlsuds.Session) {
	inner := s.InnerIPv6()
	ac := b.loadOrCreateClient(inner)
	ac.mu.Lock()
	prev := ac.dtls
	ac.dtls = s
	ac.mu.Unlock()
	if prev != nil && prev != s {
		slog.Warn("displacing prior DTLS session on same /128",
			"device", s.DeviceID(), "inner", inner,
		)
	}
	slog.Info("dtls client connected",
		"device", s.DeviceID(), "inner", inner, "trace_id", s.TraceID(),
	)
}

// OnEvict is the dtlsuds.SessionLifecycle hook called when a DTLS session
// leaves the listener's table (idle timeout or listener Close). The bridge
// clears the DTLS transport and removes the /128 entry if no CSTP tunnel
// is still active.
func (b *bridge) OnEvict(s *dtlsuds.Session) {
	inner := s.InnerIPv6()
	v, ok := b.clients.Load(inner)
	if !ok {
		return
	}
	ac := v.(*activeClient)
	ac.mu.Lock()
	if ac.dtls == s {
		ac.dtls = nil
	}
	empty := ac.cstp == nil && ac.dtls == nil
	ac.mu.Unlock()
	if empty {
		b.clients.CompareAndDelete(inner, ac)
	}
	slog.Info("dtls client disconnected",
		"device", s.DeviceID(), "inner", inner, "trace_id", s.TraceID(),
	)
}

// SinkAdapter exposes the tun device to the DTLS listener as a PacketSink.
// We pick a queue round-robin per write so DTLS traffic spreads across the
// host's tun queues the same way CSTP traffic does.
type tunSink struct {
	dev       *tun.Device
	rrCounter atomic.Uint64
}

func newTunSink(dev *tun.Device) *tunSink { return &tunSink{dev: dev} }

func (s *tunSink) WritePacket(p []byte) (int, error) {
	queues := s.dev.Queues()
	if len(queues) == 0 {
		return 0, io.ErrClosedPipe
	}
	qIdx := int(s.rrCounter.Add(1) % uint64(len(queues)))
	return queues[qIdx].Write(p)
}
