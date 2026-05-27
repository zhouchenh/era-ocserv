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
	"github.com/zhouchenh/era-ocserv/internal/tun"
)

type bridge struct {
	dev       *tun.Device
	srv       *cstp.Server
	clients   sync.Map
	rrCounter atomic.Uint64
}

type activeClient struct {
	tunnel *cstp.Tunnel
	inner  netip.Addr
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
		if _, err := ac.tunnel.WritePacket(buf[:n]); err != nil {
			slog.Debug("tunnel write", "device", ac.tunnel.Identity().DeviceID, "err", err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func (b *bridge) pumpTunnel(ctx context.Context, t *cstp.Tunnel) {
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
