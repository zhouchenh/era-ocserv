// Package bridge wires the CSTP control-plane Server to a Linux tun
// device. It pumps inner IPv6 packets in both directions: tunnel ->
// tun (egress from the client) and tun -> tunnel (ingress destined
// for the client's per-device /128).
//
// The bridge depends on two narrow interfaces (QueueIO, Device) rather
// than the concrete Linux-only *tun.Device. This lets cross-platform
// tests substitute an in-memory fake while production code in
// cmd/era-ocserv passes a thin adapter around the real device.
package bridge

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
)

// QueueIO is the per-queue subset of *tun.Queue the bridge needs.
// One IP packet per Read; one IP packet per Write (the tun device is
// message-oriented, not a byte stream).
type QueueIO interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
}

// Device is the subset of *tun.Device the bridge needs. Only Queues
// is consumed at runtime; the caller (cmd/era-ocserv) owns Open and
// Close.
type Device interface {
	Queues() []QueueIO
}

// Bridge couples a *cstp.Server to a tun Device. Constructed with New
// and started with Run.
type Bridge struct {
	dev       Device
	srv       *cstp.Server
	clients   sync.Map
	rrCounter atomic.Uint64
}

type activeClient struct {
	tunnel *cstp.Tunnel
	inner  netip.Addr
	// spoofedDrops counts packets dropped because their inner source
	// IP didn't match the client's assigned /128 (or 192.0.0.1 for
	// IPv4). Read by tests; not currently surfaced via metrics.
	spoofedDrops atomic.Uint64
}

// New builds a Bridge for the given tun device and CSTP server. The
// returned value is not started; call Run on a goroutine.
func New(dev Device, srv *cstp.Server) *Bridge {
	return &Bridge{dev: dev, srv: srv}
}

// Run drives the bridge until ctx is canceled or the CSTP server is
// closed. It launches one goroutine per tun queue plus one goroutine
// per accepted tunnel. Returns when Accept returns ErrServerClosed
// or context.Canceled.
func (b *Bridge) Run(ctx context.Context) {
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

// pumpTunQueue reads IP packets from one tun queue and forwards each
// one to the matching connected client tunnel based on the IPv6
// destination address. Non-IPv6, too-short, or unmatched packets are
// silently dropped.
func (b *Bridge) pumpTunQueue(ctx context.Context, q QueueIO) {
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
		if _, err := ac.tunnel.WritePacket(buf[:n]); err != nil {
			slog.Debug("tunnel write", "device", ac.tunnel.Identity().DeviceID, "err", err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// pumpTunnel reads inner IP packets from one client tunnel and
// round-robins them across the available tun queues for egress.
//
// Inner-source anti-spoof (protocol spec §6.1, ADR 0057 §5): every
// IPv6 packet must source from the client's assigned /128, and every
// IPv4 packet (CLAT) must source from 192.0.0.1. Anything else is
// silently dropped — same discipline kernel WireGuard's AllowedIPs
// provides. Without this filter, an authenticated client could write
// packets sourced from any inner address and trivially spoof other
// devices' /128s inside the fabric.
func (b *Bridge) pumpTunnel(ctx context.Context, t *cstp.Tunnel) {
	id := t.Identity()
	inner := id.IPv6.Addr()
	ac := &activeClient{tunnel: t, inner: inner}

	if prev, loaded := b.clients.LoadOrStore(inner, ac); loaded {
		old := prev.(*activeClient)
		slog.Warn("displacing prior client on same /128", "device", id.DeviceID, "inner", inner)
		old.tunnel.Close()
		b.clients.Store(inner, ac)
	}
	slog.Info("client connected", "device", id.DeviceID, "inner", inner, "session", t.SessionID())

	defer func() {
		b.clients.CompareAndDelete(inner, ac)
		t.Close()
		slog.Info("client disconnected", "device", id.DeviceID, "inner", inner)
	}()

	queues := b.dev.Queues()
	if len(queues) == 0 {
		return
	}
	buf := make([]byte, 65535)
	var spoofedCount uint64
	for {
		n, err := t.ReadPacket(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				slog.Debug("tunnel read", "device", id.DeviceID, "err", err)
			}
			return
		}
		if !innerSourceAllowed(buf[:n], inner) {
			spoofedCount++
			// Log at debug to avoid flooding on a buggy client; the
			// counter on the activeClient is the canonical signal.
			if spoofedCount&0xFF == 1 {
				slog.Debug("dropped spoofed inner packet",
					"device", id.DeviceID,
					"client_inner", inner,
					"count", spoofedCount)
			}
			ac.spoofedDrops.Add(1)
			if ctx.Err() != nil {
				return
			}
			continue
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

// innerSourceAllowed returns true if pkt's inner source IP is the
// expected one for a tunnel whose client is assigned the given /128
// (or the CLAT placeholder 192.0.0.1 for IPv4 packets). pkt is the
// raw IP frame as it appears on the tunnel; the IP version is taken
// from byte 0's high nibble.
//
// Short / malformed packets are dropped. We do not attempt to parse
// extension headers; the source IP lives at a fixed offset in both
// IPv4 (bytes 12..16) and IPv6 (bytes 8..24).
func innerSourceAllowed(pkt []byte, clientInner netip.Addr) bool {
	if len(pkt) < 1 {
		return false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return false
		}
		src, ok := netip.AddrFromSlice(pkt[12:16])
		if !ok {
			return false
		}
		return src == clatPlaceholderV4
	case 6:
		if len(pkt) < 40 {
			return false
		}
		src, ok := netip.AddrFromSlice(pkt[8:24])
		if !ok {
			return false
		}
		// Compare against the client's /128. We do not (yet) accept
		// link-local self-traffic; if a real client surfaces that
		// later, the rule moves to a prefix-match.
		return src == clientInner
	default:
		return false
	}
}

// clatPlaceholderV4 is the per-spec CLAT placeholder all clients
// source IPv4 packets from (ADR 0035 §3). The bridge accepts it as
// the only legal IPv4 inner source for any connected client.
var clatPlaceholderV4 = netip.MustParseAddr("192.0.0.1")
