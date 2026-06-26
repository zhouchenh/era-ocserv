package udshandoff

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
)

// memoryDgramConn is an in-memory net.PacketConn that lets a test inject
// "received from facade" datagrams and observe replies. Avoids filesystem
// for the cross-platform test.
type memoryDgramConn struct {
	rxQ    chan dgramItem
	tx     []dgramItem
	mu     sync.Mutex
	closed atomic.Bool
}

type dgramItem struct {
	data []byte
	peer net.Addr
}

func newMemoryDgramConn() *memoryDgramConn {
	return &memoryDgramConn{
		rxQ: make(chan dgramItem, 16),
	}
}

func (m *memoryDgramConn) ReadFrom(b []byte) (int, net.Addr, error) {
	item, ok := <-m.rxQ
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(b, item.data)
	return n, item.peer, nil
}

func (m *memoryDgramConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed.Load() {
		return 0, net.ErrClosed
	}
	dup := append([]byte(nil), p...)
	m.tx = append(m.tx, dgramItem{data: dup, peer: addr})
	return len(p), nil
}

func (m *memoryDgramConn) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	close(m.rxQ)
	return nil
}

func (m *memoryDgramConn) LocalAddr() net.Addr { return memoryAddr("memory") }

func (m *memoryDgramConn) SetDeadline(time.Time) error      { return nil }
func (m *memoryDgramConn) SetReadDeadline(time.Time) error  { return nil }
func (m *memoryDgramConn) SetWriteDeadline(time.Time) error { return nil }

func (m *memoryDgramConn) deliver(data []byte) {
	if m.closed.Load() {
		return
	}
	m.rxQ <- dgramItem{data: data, peer: memoryAddr("facade")}
}

type memoryAddr string

func (memoryAddr) Network() string { return "memory" }
func (a memoryAddr) String() string { return string(a) }

func makeHysteria2Frame(t *testing.T, payload []byte) []byte {
	t.Helper()
	src := netip.MustParseAddrPort("[2001:db8::7]:51000")
	dst := netip.MustParseAddrPort("[2001:db8::1]:443")
	inner := &proxyproto.HeaderV2{
		Family: 0x22, Src: src, Dst: dst,
	}
	era := []proxyproto.TLV{
		{Type: proxyproto.EraTLVSpecVersion, Value: []byte{proxyproto.SpecVersionStage1}},
		{Type: proxyproto.EraTLVTraceID, Value: []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")},
		{Type: proxyproto.EraTLVToken, Value: make([]byte, 12)},
		{Type: proxyproto.EraTLVDeviceID, Value: []byte("123e4567-e89b-12d3-a456-426614174000")},
		{Type: proxyproto.EraTLVUserID, Value: []byte("u1")},
		{Type: proxyproto.EraTLVALPNDetail, Value: []byte("h3")},
		{Type: proxyproto.EraTLVQUICConnID, Value: make([]byte, 16)},
		{Type: proxyproto.EraTLVSourceHintV6, Value: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}},
	}
	return buildDgram(t, proxyproto.SpecVersionStage1, DirFacadeToBackend, inner, era, payload)
}

func TestDatagramListener_HappyPath(t *testing.T) {
	pc := newMemoryDgramConn()
	defer pc.Close()
	metrics := NewMetrics()
	spec := LookupProtocol(ProtoHysteria2)
	gotPayload := make(chan []byte, 1)
	handler := func(_ context.Context, acc *AcceptedDatagram) error {
		dup := append([]byte(nil), acc.Frame.Payload...)
		gotPayload <- dup
		// Send a reply.
		return acc.Reply([]byte("PONG"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dl, err := ListenDatagram(ctx, ListenerOptions{
		Logger:             newTestLogger(),
		Metrics:            metrics,
		Spec:               spec,
		PreboundPacketConn: pc,
	}, handler)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer dl.Close()

	pc.deliver(makeHysteria2Frame(t, []byte("PING")))
	select {
	case got := <-gotPayload:
		if string(got) != "PING" {
			t.Fatalf("payload = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handler")
	}
	// Verify reply landed.
	time.Sleep(100 * time.Millisecond)
	pc.mu.Lock()
	if len(pc.tx) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(pc.tx))
	}
	pc.mu.Unlock()
	snap := metrics.Snapshot()
	if snap.HandoffAccept[ProtoHysteria2] != 1 {
		t.Errorf("HandoffAccept[hy2] = %d", snap.HandoffAccept[ProtoHysteria2])
	}
}

func TestDatagramListener_RejectsBadVersion(t *testing.T) {
	pc := newMemoryDgramConn()
	defer pc.Close()
	metrics := NewMetrics()
	spec := LookupProtocol(ProtoHysteria2)
	handler := func(_ context.Context, _ *AcceptedDatagram) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dl, err := ListenDatagram(ctx, ListenerOptions{
		Logger:             newTestLogger(),
		Metrics:            metrics,
		Spec:               spec,
		PreboundPacketConn: pc,
	}, handler)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer dl.Close()

	frame := makeHysteria2Frame(t, []byte("X"))
	frame[0] = 0x42 // wrong version
	pc.deliver(frame)
	time.Sleep(100 * time.Millisecond)
	snap := metrics.Snapshot()
	if snap.FrameRejected[ProtoHysteria2] != 1 {
		t.Errorf("FrameRejected[hy2] = %d", snap.FrameRejected[ProtoHysteria2])
	}
}

func TestDatagramListener_RejectsWrongDirection(t *testing.T) {
	pc := newMemoryDgramConn()
	defer pc.Close()
	metrics := NewMetrics()
	spec := LookupProtocol(ProtoHysteria2)
	handler := func(_ context.Context, _ *AcceptedDatagram) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dl, err := ListenDatagram(ctx, ListenerOptions{
		Logger:             newTestLogger(),
		Metrics:            metrics,
		Spec:               spec,
		PreboundPacketConn: pc,
	}, handler)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer dl.Close()

	// Build a backend→facade frame; backend should not receive these.
	src := netip.MustParseAddrPort("[2001:db8::7]:51000")
	dst := netip.MustParseAddrPort("[2001:db8::1]:443")
	inner := &proxyproto.HeaderV2{Family: 0x22, Src: src, Dst: dst}
	frame := buildDgram(t, proxyproto.SpecVersionStage1, DirBackendToFacade, inner, nil, []byte("X"))
	pc.deliver(frame)
	time.Sleep(100 * time.Millisecond)
	snap := metrics.Snapshot()
	if snap.FrameRejected[ProtoHysteria2] != 1 {
		t.Errorf("FrameRejected[hy2] = %d", snap.FrameRejected[ProtoHysteria2])
	}
}

func TestDatagramListener_BindRealUDS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("real UDS bind tested only on linux; current GOOS=%s", runtime.GOOS)
	}
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "hy2.sock")
	metrics := NewMetrics()
	spec := LookupProtocol(ProtoHysteria2)
	gotPayload := make(chan string, 1)
	handler := func(_ context.Context, acc *AcceptedDatagram) error {
		gotPayload <- string(acc.Frame.Payload)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dl, err := ListenDatagram(ctx, ListenerOptions{
		Logger:     newTestLogger(),
		Metrics:    metrics,
		Spec:       spec,
		SocketPath: sockPath,
	}, handler)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer dl.Close()

	// Bind a temp client socket; SOCK_DGRAM UDS requires the client to
	// have a path of its own (Linux requirement).
	cliPath := filepath.Join(dir, "client.sock")
	cli, err := net.ListenPacket("unixgram", cliPath)
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer cli.Close()

	frame := makeHysteria2Frame(t, []byte("REAL-DGRAM"))
	addr, _ := net.ResolveUnixAddr("unixgram", sockPath)
	if _, err := cli.WriteTo(frame, addr); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case got := <-gotPayload:
		if got != "REAL-DGRAM" {
			t.Fatalf("payload = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}
