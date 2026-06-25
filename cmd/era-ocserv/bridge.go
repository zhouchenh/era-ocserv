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

	"github.com/zhouchenh/era-ocserv/internal/clatxlat"
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
// Either pointer may be nil; the bridge only deregisters the /128 entries
// when both go away. WritePacket selects the active transport at call
// time so a DTLS arrival mid-flow takes over without bouncing the
// activeClient struct itself.
//
// CLAT: when the device has a CLAT-source /128, xlat is set and clatV6 holds
// that /128. The SAME *activeClient pointer is registered in the bridge's
// clients map under BOTH the native /128 and the CLAT /128 so 64:ff9b::
// replies (whose inner destination is the CLAT /128) resolve to this client.
// xlat is set once (idempotently) the first time a transport learns the
// CLAT /128; both CSTP and DTLS for the same device carry the same one.
type activeClient struct {
	mu     sync.Mutex
	cstp   *cstp.Tunnel
	dtls   *dtlsuds.Session
	xlat   *clatxlat.Translator
	clatV6 netip.Addr
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

// translator returns the per-session CLAT translator, or nil when CLAT is
// disabled for this client.
func (a *activeClient) translator() *clatxlat.Translator {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.xlat
}

// placeholderClatV4 is the universal AnyConnect inner source IPv4. The SIIT
// engine maps it to/from the device's CLAT-source /128. It is the SAME value
// advertised on the wire as X-CSTP-Address (cstp.ClatPlaceholderV4) so the
// client's inner v4 source and the translator's expected source can never
// drift. NOTE: it is intentionally NOT 192.0.0.1 — that collides with the iOS
// system CLAT address on 464XLAT carriers and makes the client reassert; see
// cstp.ClatPlaceholderV4 / emitCSTPHeaders.
var placeholderClatV4 = cstp.ClatPlaceholderV4

type bridge struct {
	dev       *tun.Device
	srv       *cstp.Server
	clients   sync.Map // netip.Addr -> *activeClient (keyed under native AND CLAT /128)
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

// installCLAT sets up the per-session translator and CLAT-/128 registry key
// for ac, idempotently. clatV6 is the device's CLAT-source /128 (or the zero
// Addr when CLAT is disabled, in which case this is a no-op). The native
// argument is the native /128 the ac is already registered under; the CLAT
// /128 is registered as a SECOND key pointing at the SAME *activeClient so
// 64:ff9b:: replies route back. Returns true when a CLAT key was installed
// (so the matching deregister deletes it).
func (b *bridge) installCLAT(ac *activeClient, native, clatV6 netip.Addr) bool {
	if !clatV6.IsValid() || clatV6 == native {
		return false
	}
	ac.mu.Lock()
	if ac.xlat == nil {
		// placeholderV4 is the universal AnyConnect CLAT inner source.
		if tr, ok := clatxlat.New(placeholderClatV4, clatV6); ok {
			ac.xlat = tr
			ac.clatV6 = clatV6
		}
	}
	ac.mu.Unlock()
	// Point the CLAT /128 at the same *activeClient. LoadOrStore avoids
	// clobbering a concurrent winner; if a different ac already holds the
	// key we leave it (the displaced-transport warning paths handle that).
	b.clients.LoadOrStore(clatV6, ac)
	return true
}

// deregisterKeys removes ac from both the native and (when present) CLAT
// /128 keys, but only when ac currently has no live transport. Called from
// the teardown paths. CompareAndDelete ensures we never delete a key a newer
// activeClient has taken over.
func (b *bridge) deregisterKeys(ac *activeClient, native netip.Addr) {
	b.clients.CompareAndDelete(native, ac)
	ac.mu.Lock()
	clatV6 := ac.clatV6
	ac.mu.Unlock()
	if clatV6.IsValid() && clatV6 != native {
		b.clients.CompareAndDelete(clatV6, ac)
	}
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
		// tun->client: when the inner destination is this session's CLAT
		// /128, SIIT64 the v6 packet back to the client's inner IPv4
		// (src=realV4, dst=192.0.0.1). When it is the native /128, pass the
		// v6 through unchanged (the pre-CLAT path).
		out := buf[:n]
		ac.mu.Lock()
		isCLAT := ac.clatV6.IsValid() && dst == ac.clatV6
		xlat := ac.xlat
		ac.mu.Unlock()
		// Server-side ICMPv6 PTB origination (DEC-l3-mtu-model): the inner link
		// MTU is 1400 (native /128) or 1420 (CLAT /128, pre-SIIT64; the −20 on
		// v6->v4 translation yields the 1400 inner v4). An oversize packet is
		// DROPPED and a PTB is sent to its v6 source so PMTUD shrinks the sender —
		// never a silent drop, and we never shrink the static 1400/1420.
		if isCLAT {
			if n > ptbCapCLAT {
				b.originatePTB(q, dst, ptbCapCLAT, buf[:n])
				continue
			}
		} else if n > ptbCapNative {
			b.originatePTB(q, dst, ptbCapNative, buf[:n])
			continue
		}
		if isCLAT {
			if xlat == nil {
				continue
			}
			translated, okx := xlat.TunToClient(buf[:n])
			if !okx {
				continue
			}
			out = translated
		}
		if _, err := tr.WritePacket(out); err != nil {
			slog.Debug("transport write", "transport", tr.label(), "inner", dst, "err", err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// writeClientToTun applies the client->tun CLAT translation (inner v4 →
// device CLAT /128 SIIT source) when xlat is set, then writes the resulting
// packet to a tun queue. A v4 packet xlat declines is dropped (fail closed);
// a v6 packet passes through unchanged. Shared by the CSTP and DTLS ingress
// paths so both transports translate identically.
func (b *bridge) writeClientToTun(xlat *clatxlat.Translator, pkt []byte) {
	queues := b.dev.Queues()
	if len(queues) == 0 {
		return
	}
	out := pkt
	if xlat != nil {
		translated, ok := xlat.ClientToTun(pkt)
		if !ok {
			// Untranslatable/dropped inner v4 — fail closed, do not leak.
			return
		}
		out = translated
	}
	qIdx := int(b.rrCounter.Add(1) % uint64(len(queues)))
	if _, err := queues[qIdx].Write(out); err != nil {
		slog.Debug("tun write", "queue", qIdx, "err", err)
	}
}

// pumpTunnel registers a freshly-accepted CSTP tunnel under its /128 (and the
// device's CLAT /128 when present) and pumps inbound IP packets into the tun
// device for the lifetime of the tunnel, translating the client's inner v4
// via SIIT on the way. On exit it deregisters the CSTP transport; the DTLS
// session, if any, is left in place (the /128 keys are shared).
func (b *bridge) pumpTunnel(ctx context.Context, t *cstp.Tunnel) {
	id := t.Identity()
	inner := id.IPv6.Addr()
	ac := b.loadOrCreateClient(inner)

	ac.mu.Lock()
	prev := ac.cstp
	ac.cstp = t
	// A fresh CSTP CONNECT supersedes any DTLS session bound to this /128:
	// AnyConnect only establishes DTLS *after* a CONNECT (the PSK comes from
	// the CONNECT response), so any DTLS present at connect time belongs to a
	// PRIOR client session and is stale. Leaving it would make chooseTransport
	// (DTLS-preferred) ship this client's downloads into the dead session —
	// e.g. an iPhone that had DTLS then reconnects CSTP-only (WiFi->5G where
	// UDP :443 is blocked), or a stale openconnect session on the same device
	// /128. Clear it so egress falls to this CSTP tunnel; the client re-admits
	// its own DTLS via OnAdmit if/when its UDP leg comes up.
	prevDTLS := ac.dtls
	ac.dtls = nil
	ac.mu.Unlock()
	if prev != nil {
		slog.Warn("displacing prior CSTP tunnel on same /128", "device", id.DeviceID, "inner", inner)
		prev.Close()
	}
	if prevDTLS != nil {
		// Detach from egress only; the dtlsuds listener's eviction walker
		// reclaims the orphaned session (it will fail DPD / idle out). It can
		// no longer steal this client's downloads the moment we clear it here.
		slog.Warn("detaching stale DTLS session on fresh CSTP connect", "device", id.DeviceID, "inner", inner)
	}
	// Build the per-session translator + CLAT /128 key (no-op without a
	// CLAT /128 → today's v6-only behavior).
	var clatV6 netip.Addr
	if id.IPv6CLAT.IsValid() {
		clatV6 = id.IPv6CLAT.Addr()
	}
	b.installCLAT(ac, inner, clatV6)
	xlat := ac.translator()
	slog.Info("cstp client connected", "device", id.DeviceID, "inner", inner, "clat", clatV6, "session", t.SessionID())

	defer func() {
		ac.mu.Lock()
		if ac.cstp == t {
			ac.cstp = nil
		}
		empty := ac.cstp == nil && ac.dtls == nil
		ac.mu.Unlock()
		if empty {
			b.deregisterKeys(ac, inner)
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
		b.writeClientToTun(xlat, buf[:n])
		if ctx.Err() != nil {
			return
		}
	}
}

// OnAdmit is the dtlsuds.SessionLifecycle hook called when a new DTLS
// session enters the listener's table. The bridge registers the session
// against the device's inner /128 (and the CLAT /128 when present) so
// subsequent TUN egress packets pick the DTLS transport.
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
	b.installCLAT(ac, inner, s.ClatV6())
	slog.Info("dtls client connected",
		"device", s.DeviceID(), "inner", inner, "clat", s.ClatV6(), "trace_id", s.TraceID(),
	)
}

// OnEvict is the dtlsuds.SessionLifecycle hook called when a DTLS session
// leaves the listener's table (idle timeout or listener Close). The bridge
// clears the DTLS transport and removes the /128 entries (native + CLAT) if
// no CSTP tunnel is still active.
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
		b.deregisterKeys(ac, inner)
	}
	slog.Info("dtls client disconnected",
		"device", s.DeviceID(), "inner", inner, "trace_id", s.TraceID(),
	)
}

// tunSink exposes the tun device to the DTLS listener as a PacketSink and a
// SessionPacketSink. We pick a queue round-robin per write so DTLS traffic
// spreads across the host's tun queues the same way CSTP traffic does. The
// session-aware variant applies the per-session CLAT client->tun translation
// via the bridge's client registry.
type tunSink struct {
	b         *bridge
	dev       *tun.Device
	rrCounter atomic.Uint64
}

func newTunSink(b *bridge, dev *tun.Device) *tunSink { return &tunSink{b: b, dev: dev} }

func (s *tunSink) WritePacket(p []byte) (int, error) {
	queues := s.dev.Queues()
	if len(queues) == 0 {
		return 0, io.ErrClosedPipe
	}
	qIdx := int(s.rrCounter.Add(1) % uint64(len(queues)))
	return queues[qIdx].Write(p)
}

// WritePacketFromSession applies the session's CLAT client->tun translation
// (inner v4 → device CLAT /128 SIIT source) before injection. A v4 packet the
// translator declines is dropped (fail closed) and reported as written so the
// listener does not treat the drop as a transport error; a v6 packet passes
// through. Sessions without a CLAT /128 translate nothing (native path).
func (s *tunSink) WritePacketFromSession(sess *dtlsuds.Session, p []byte) (int, error) {
	var xlat *clatxlat.Translator
	if v, ok := s.b.clients.Load(sess.InnerIPv6()); ok {
		xlat = v.(*activeClient).translator()
	}
	if xlat == nil {
		return s.WritePacket(p)
	}
	out, ok := xlat.ClientToTun(p)
	if !ok {
		// Fail closed: untranslatable inner v4. Report the original length
		// as written so the listener does not surface a spurious error.
		return len(p), nil
	}
	if _, err := s.WritePacket(out); err != nil {
		return 0, err
	}
	return len(p), nil
}
