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
