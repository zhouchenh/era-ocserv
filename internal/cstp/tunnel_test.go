package cstp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock advances on demand. It is goroutine-safe.
type fakeClock struct {
	now atomic.Int64
}

func newFakeClock(start time.Time) *fakeClock {
	fc := &fakeClock{}
	fc.now.Store(start.UnixNano())
	return fc
}

func (fc *fakeClock) Now() time.Time {
	return time.Unix(0, fc.now.Load())
}

func (fc *fakeClock) Advance(d time.Duration) {
	fc.now.Add(int64(d))
}

// pipeTunnel builds a Tunnel running over a net.Pipe pair, with a
// fake clock so the heartbeat loop can be exercised deterministically.
// The returned client conn is the peer that would normally be the
// AnyConnect client.
func pipeTunnel(t *testing.T, fc *fakeClock, cfg Config) (*Tunnel, net.Conn) {
	t.Helper()
	cfg.Now = fc.Now
	cfg.Verifier = &stubVerifier{user: "u", pass: "p", deviceID: "d"}
	cfg.Resolver = &stubResolver{want: Identity{DeviceID: "d", IPv6: netip.MustParsePrefix("2001:db8::1/128"), MTU: 1406}}
	s := NewServer(cfg)
	t.Cleanup(func() { _ = s.Close() })

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	br := bufio.NewReader(serverConn)
	bw := bufio.NewWriter(serverConn)
	rw := bufio.NewReadWriter(br, bw)
	id := Identity{DeviceID: "d", IPv6: netip.MustParsePrefix("2001:db8::1/128"), MTU: 1406}
	tun := s.newTunnel(serverConn, rw, id, "session-token-xyz")
	return tun, clientConn
}

func TestTunnelDataRoundTrip(t *testing.T) {
	fc := newFakeClock(time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC))
	tun, client := pipeTunnel(t, fc, Config{
		DPDInterval:       1 << 20, // effectively disabled for this test
		KeepaliveInterval: 1 << 20,
		IdleTimeout:       1 << 20,
	})
	defer tun.Close()

	// Client -> server.
	payload := []byte("client-to-server")
	frame := make([]byte, frameHeaderLen+len(payload))
	if _, err := encodeFrame(frame, pktData, payload); err != nil {
		t.Fatalf("encodeFrame: %v", err)
	}
	go func() {
		_, _ = client.Write(frame)
	}()

	buf := make([]byte, 4096)
	n, err := tun.ReadPacket(buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload mismatch: got %q want %q", buf[:n], payload)
	}

	// Server -> client. WritePacket is synchronous over net.Pipe so
	// we start the client-side read first, then write from the
	// server side; otherwise pipe.Write would block on no reader.
	type readResult struct {
		typ byte
		n   int
		buf []byte
		err error
	}
	resCh := make(chan readResult, 1)
	go func() {
		hdr := make([]byte, frameHeaderLen)
		rcv := make([]byte, 4096)
		typ, m, err := readFrame(client, hdr, rcv)
		resCh <- readResult{typ, m, rcv[:m], err}
	}()
	if _, err := tun.WritePacket([]byte("server-to-client")); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	res := <-resCh
	if res.err != nil {
		t.Fatalf("client readFrame: %v", res.err)
	}
	if res.typ != pktData {
		t.Fatalf("typ=%d", res.typ)
	}
	if string(res.buf) != "server-to-client" {
		t.Fatalf("got %q", res.buf)
	}
}

func TestTunnelDPDEcho(t *testing.T) {
	fc := newFakeClock(time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC))
	tun, client := pipeTunnel(t, fc, Config{
		DPDInterval:       1 << 20,
		KeepaliveInterval: 1 << 20,
		IdleTimeout:       1 << 20,
	})
	defer tun.Close()

	// Client sends a DPD-out; server should echo as DPD-resp with
	// the same payload.
	payload := []byte("ping-magic")
	frame := make([]byte, frameHeaderLen+len(payload))
	if _, err := encodeFrame(frame, pktDPDOut, payload); err != nil {
		t.Fatalf("encodeFrame: %v", err)
	}
	go func() { _, _ = client.Write(frame) }()

	hdr := make([]byte, frameHeaderLen)
	buf := make([]byte, 4096)
	typ, n, err := readFrame(client, hdr, buf)
	if err != nil {
		t.Fatalf("client readFrame: %v", err)
	}
	if typ != pktDPDResp {
		t.Fatalf("typ=%d want pktDPDResp(%d)", typ, pktDPDResp)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf[:n], payload)
	}
}

func TestTunnelDisconnectClosesReader(t *testing.T) {
	fc := newFakeClock(time.Now())
	tun, client := pipeTunnel(t, fc, Config{
		DPDInterval:       1 << 20,
		KeepaliveInterval: 1 << 20,
		IdleTimeout:       1 << 20,
	})
	defer tun.Close()

	frame := make([]byte, frameHeaderLen+1)
	if _, err := encodeFrame(frame, pktDisconnect, []byte{0}); err != nil {
		t.Fatalf("encodeFrame: %v", err)
	}
	go func() { _, _ = client.Write(frame) }()

	buf := make([]byte, 256)
	_, err := tun.ReadPacket(buf)
	if err == nil {
		t.Fatalf("expected error after disconnect")
	}
	if !errors.Is(err, errClientDisconnect) && !errors.Is(err, io.EOF) {
		t.Logf("got close cause: %v", err)
	}
}

// TestTunnelHeartbeatDPD makes the heartbeat goroutine fire by
// advancing the fake clock past the DPD interval while the inbound
// channel stays silent. We then read on the client side and expect a
// DPD-out frame.
func TestTunnelHeartbeatDPD(t *testing.T) {
	fc := newFakeClock(time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC))
	tun, client := pipeTunnel(t, fc, Config{
		DPDInterval:       1,    // 1s for fast test
		KeepaliveInterval: 1000, // suppress
		IdleTimeout:       1000,
	})
	defer tun.Close()

	// Drain whatever the heartbeat emits on the client side. After
	// advancing 2s, the heartbeat should have fired at least one
	// DPD-out frame.
	gotDPD := make(chan struct{}, 1)
	go func() {
		hdr := make([]byte, frameHeaderLen)
		buf := make([]byte, 4096)
		for {
			typ, _, err := readFrame(client, hdr, buf)
			if err != nil {
				return
			}
			if typ == pktDPDOut {
				select {
				case gotDPD <- struct{}{}:
				default:
				}
				return
			}
		}
	}()

	// Advance the clock and let the ticker fire. The heartbeat's
	// ticker is a real time.Ticker so we wait wall-clock for it; the
	// fake clock is only used inside the heartbeat to decide whether
	// to emit a DPD vs keepalive.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-gotDPD:
			return
		case <-deadline:
			t.Fatalf("heartbeat did not emit DPD within 3s wall time")
		default:
			fc.Advance(500 * time.Millisecond)
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// TestTunnelKeepaliveEmittedWhenOutboundIdle confirms the heartbeat
// path can emit pktKeepalive when there has been no outbound traffic
// for the keepalive interval, even when DPD is disabled.
func TestTunnelKeepaliveEmittedWhenOutboundIdle(t *testing.T) {
	fc := newFakeClock(time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC))
	tun, client := pipeTunnel(t, fc, Config{
		DPDInterval:       1 << 20, // suppress DPD by making it huge
		KeepaliveInterval: 1,
		IdleTimeout:       1 << 20,
	})
	defer tun.Close()

	// Pretend the inbound channel has had activity so DPD does not
	// fire. We do this by writing some other-purpose frame in: a
	// keepalive frame which the server treats as "saw something".
	go func() {
		frame := make([]byte, frameHeaderLen)
		_, _ = encodeFrame(frame, pktKeepalive, nil)
		_, _ = client.Write(frame)
	}()

	gotKA := make(chan struct{}, 1)
	go func() {
		hdr := make([]byte, frameHeaderLen)
		buf := make([]byte, 4096)
		for {
			typ, _, err := readFrame(client, hdr, buf)
			if err != nil {
				return
			}
			if typ == pktKeepalive {
				select {
				case gotKA <- struct{}{}:
				default:
				}
				return
			}
		}
	}()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-gotKA:
			return
		case <-deadline:
			t.Fatalf("heartbeat did not emit keepalive within 3s wall time")
		default:
			fc.Advance(500 * time.Millisecond)
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func TestTunnelAcceptContextCancellation(t *testing.T) {
	s, _, _ := freshServer(t)
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.Accept(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Accept returned %v, want context.Canceled", err)
	}
}
