package udshandoff

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
)

// newTestLogger returns a slog.Logger that discards output; tests assert
// metric state, not log lines.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// makeAnytlsHeader returns the wire bytes of a PROXY-v2 header satisfying
// the anytls protocol matrix row.
func makeAnytlsHeader(t *testing.T) []byte {
	t.Helper()
	src := netip.MustParseAddrPort("203.0.113.7:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	tlvs := []proxyproto.TLV{
		{Type: proxyproto.EraTLVSpecVersion, Value: []byte{proxyproto.SpecVersionStage1}},
		{Type: proxyproto.EraTLVToken, Value: make([]byte, 12)},
		{Type: proxyproto.EraTLVDeviceID, Value: []byte("123e4567-e89b-12d3-a456-426614174000")},
		{Type: proxyproto.EraTLVUserID, Value: []byte("user-1")},
		{Type: proxyproto.EraTLVSourceHintV6, Value: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}},
		{Type: proxyproto.EraTLVTraceID, Value: []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")},
	}
	hdr := &proxyproto.HeaderV2{
		Family: 0x11, // TCP4
		Src:    src,
		Dst:    dst,
		TLVs:   tlvs,
	}
	b, err := hdr.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

// pipeListener is an in-memory net.Listener that hands out pre-paired conns.
// It avoids filesystem bind+chmod, which Windows + non-Linux platforms
// handle differently. The framework's listener accepts ANY net.Listener via
// PreboundListener, so this exercises the same code path.
type pipeListener struct {
	conns chan net.Conn
	addr  net.Addr
	mu    sync.Mutex
	closed bool
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		conns: make(chan net.Conn, 8),
		addr:  pipeAddr{},
	}
}

func (p *pipeListener) Accept() (net.Conn, error) {
	c, ok := <-p.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (p *pipeListener) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.conns)
	}
	return nil
}

func (p *pipeListener) Addr() net.Addr { return p.addr }

func (p *pipeListener) deliver(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		c.Close()
		return
	}
	p.conns <- c
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func TestStreamListener_HappyPath(t *testing.T) {
	pl := newPipeListener()
	metrics := NewMetrics()
	spec := LookupProtocol(ProtoAnyTLS)
	var (
		gotBytes []byte
		got      string
		gotTrace string
		hCalls   int
		mu       sync.Mutex
	)
	handler := func(_ context.Context, acc *AcceptedStream) error {
		mu.Lock()
		hCalls++
		gotTrace = acc.TraceID()
		mu.Unlock()
		// Read payload.
		gotBytes = make([]byte, 16)
		n, _ := acc.Read(gotBytes)
		gotBytes = gotBytes[:n]
		got = string(gotBytes)
		// Echo back.
		_, _ = acc.Write([]byte("OK"))
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sl, err := ListenStream(ctx, ListenerOptions{
		Logger:           newTestLogger(),
		Metrics:          metrics,
		Spec:             spec,
		SocketPath:       "test://anytls",
		PreboundListener: pl,
	}, handler)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sl.Close()

	c1, c2 := net.Pipe()
	pl.deliver(c1)
	// Writer side simulates the facade.
	hdrBytes := makeAnytlsHeader(t)
	go func() {
		_, _ = c2.Write(hdrBytes)
		_, _ = c2.Write([]byte("PAYLOAD"))
	}()
	// Read the response.
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c2, resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(resp) != "OK" {
		t.Fatalf("resp = %q", resp)
	}
	_ = c2.Close()
	// Allow the handler to return.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := hCalls > 0
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if hCalls == 0 {
		t.Fatalf("handler not called")
	}
	if got != "PAYLOAD" {
		t.Fatalf("payload = %q", got)
	}
	if gotTrace != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("trace_id = %q", gotTrace)
	}
	snap := metrics.Snapshot()
	if snap.HandoffAccept[ProtoAnyTLS] != 1 {
		t.Errorf("HandoffAccept[anytls] = %d, want 1", snap.HandoffAccept[ProtoAnyTLS])
	}
	if snap.HandoffInvalid[ProtoAnyTLS] != 0 {
		t.Errorf("HandoffInvalid[anytls] = %d, want 0", snap.HandoffInvalid[ProtoAnyTLS])
	}
}

func TestStreamListener_RejectsBadSignature(t *testing.T) {
	pl := newPipeListener()
	metrics := NewMetrics()
	spec := LookupProtocol(ProtoAnyTLS)
	var hCalls int
	var mu sync.Mutex
	handler := func(_ context.Context, _ *AcceptedStream) error {
		mu.Lock()
		hCalls++
		mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sl, err := ListenStream(ctx, ListenerOptions{
		Logger:           newTestLogger(),
		Metrics:          metrics,
		Spec:             spec,
		PreboundListener: pl,
	}, handler)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sl.Close()

	c1, c2 := net.Pipe()
	pl.deliver(c1)
	// Send 16 bytes of garbage — signature_invalid path.
	go func() {
		buf := make([]byte, 16)
		for i := range buf {
			buf[i] = 0xFF
		}
		_, _ = c2.Write(buf)
		_ = c2.Close()
	}()
	// Wait briefly for the listener to process.
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if hCalls != 0 {
		t.Fatalf("handler was called on bad signature")
	}
	snap := metrics.Snapshot()
	if snap.ProxyV2InvalidSignature != 1 {
		t.Errorf("ProxyV2InvalidSignature = %d", snap.ProxyV2InvalidSignature)
	}
	if snap.HandoffInvalid[ProtoAnyTLS] != 1 {
		t.Errorf("HandoffInvalid[anytls] = %d", snap.HandoffInvalid[ProtoAnyTLS])
	}
}

func TestStreamListener_RejectsMissingMandatory(t *testing.T) {
	pl := newPipeListener()
	metrics := NewMetrics()
	spec := LookupProtocol(ProtoAnyTLS)
	hCalls := 0
	var mu sync.Mutex
	handler := func(_ context.Context, _ *AcceptedStream) error {
		mu.Lock()
		hCalls++
		mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sl, err := ListenStream(ctx, ListenerOptions{
		Logger:           newTestLogger(),
		Metrics:          metrics,
		Spec:             spec,
		PreboundListener: pl,
	}, handler)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sl.Close()

	c1, c2 := net.Pipe()
	pl.deliver(c1)
	// Build header WITHOUT EraTLVToken (mandatory for anytls).
	src := netip.MustParseAddrPort("203.0.113.7:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	hdr := &proxyproto.HeaderV2{
		Family: 0x11,
		Src:    src,
		Dst:    dst,
		TLVs: []proxyproto.TLV{
			{Type: proxyproto.EraTLVSpecVersion, Value: []byte{proxyproto.SpecVersionStage1}},
			{Type: proxyproto.EraTLVDeviceID, Value: []byte("123e4567-e89b-12d3-a456-426614174000")},
			{Type: proxyproto.EraTLVUserID, Value: []byte("u")},
			{Type: proxyproto.EraTLVSourceHintV6, Value: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}},
			{Type: proxyproto.EraTLVTraceID, Value: []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")},
		},
	}
	b, err := hdr.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	go func() {
		_, _ = c2.Write(b)
		_ = c2.Close()
	}()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if hCalls != 0 {
		t.Fatalf("handler was called on missing mandatory")
	}
	snap := metrics.Snapshot()
	if snap.HandoffInvalid[ProtoAnyTLS] != 1 {
		t.Errorf("HandoffInvalid[anytls] = %d", snap.HandoffInvalid[ProtoAnyTLS])
	}
}

func TestStreamListener_RejectsForbidden(t *testing.T) {
	pl := newPipeListener()
	metrics := NewMetrics()
	spec := LookupProtocol(ProtoAnyTLS)
	handler := func(_ context.Context, _ *AcceptedStream) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sl, err := ListenStream(ctx, ListenerOptions{
		Logger:           newTestLogger(),
		Metrics:          metrics,
		Spec:             spec,
		PreboundListener: pl,
	}, handler)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sl.Close()

	c1, c2 := net.Pipe()
	pl.deliver(c1)
	// Take the canonical anytls header and add VLESS_TARGET (forbidden).
	src := netip.MustParseAddrPort("203.0.113.7:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	hdr := &proxyproto.HeaderV2{
		Family: 0x11,
		Src:    src,
		Dst:    dst,
		TLVs: []proxyproto.TLV{
			{Type: proxyproto.EraTLVSpecVersion, Value: []byte{proxyproto.SpecVersionStage1}},
			{Type: proxyproto.EraTLVToken, Value: make([]byte, 12)},
			{Type: proxyproto.EraTLVDeviceID, Value: []byte("123e4567-e89b-12d3-a456-426614174000")},
			{Type: proxyproto.EraTLVUserID, Value: []byte("u")},
			{Type: proxyproto.EraTLVVLESSTarget, Value: []byte("upstream:443")},
			{Type: proxyproto.EraTLVSourceHintV6, Value: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}},
			{Type: proxyproto.EraTLVTraceID, Value: []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")},
		},
	}
	b, _ := hdr.Encode()
	go func() {
		_, _ = c2.Write(b)
		_ = c2.Close()
	}()
	time.Sleep(100 * time.Millisecond)
	snap := metrics.Snapshot()
	if snap.HandoffInvalid[ProtoAnyTLS] != 1 {
		t.Errorf("HandoffInvalid[anytls] = %d", snap.HandoffInvalid[ProtoAnyTLS])
	}
}

func TestStreamListener_RejectsReservedRangeTLV(t *testing.T) {
	pl := newPipeListener()
	metrics := NewMetrics()
	spec := LookupProtocol(ProtoAnyTLS)
	handler := func(_ context.Context, _ *AcceptedStream) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sl, err := ListenStream(ctx, ListenerOptions{
		Logger:           newTestLogger(),
		Metrics:          metrics,
		Spec:             spec,
		PreboundListener: pl,
	}, handler)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sl.Close()

	c1, c2 := net.Pipe()
	pl.deliver(c1)
	// Header with a 0x90 (reserved-range) TLV — DecodeTLVs rejects pre-validate.
	src := netip.MustParseAddrPort("203.0.113.7:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	hdr := &proxyproto.HeaderV2{
		Family: 0x11, Src: src, Dst: dst,
		TLVs: []proxyproto.TLV{
			{Type: proxyproto.EraTLVSpecVersion, Value: []byte{proxyproto.SpecVersionStage1}},
			{Type: proxyproto.TLVType(0x90), Value: []byte("evil")},
		},
	}
	b, _ := hdr.Encode()
	go func() {
		_, _ = c2.Write(b)
		_ = c2.Close()
	}()
	time.Sleep(100 * time.Millisecond)
	snap := metrics.Snapshot()
	if snap.HandoffInvalid[ProtoAnyTLS] != 1 {
		t.Errorf("HandoffInvalid[anytls] = %d", snap.HandoffInvalid[ProtoAnyTLS])
	}
}

func TestStreamListener_RejectsIncompleteHeader(t *testing.T) {
	pl := newPipeListener()
	metrics := NewMetrics()
	spec := LookupProtocol(ProtoAnyTLS)
	handler := func(_ context.Context, _ *AcceptedStream) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sl, err := ListenStream(ctx, ListenerOptions{
		Logger:           newTestLogger(),
		Metrics:          metrics,
		Spec:             spec,
		PreboundListener: pl,
	}, handler)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sl.Close()

	c1, c2 := net.Pipe()
	pl.deliver(c1)
	// Send only 8 bytes — short of the fixed 16-byte prefix.
	go func() {
		_, _ = c2.Write(make([]byte, 8))
		_ = c2.Close()
	}()
	time.Sleep(150 * time.Millisecond)
	snap := metrics.Snapshot()
	if snap.IncompleteHeader != 1 {
		t.Errorf("IncompleteHeader = %d", snap.IncompleteHeader)
	}
	if snap.HandoffInvalid[ProtoAnyTLS] != 1 {
		t.Errorf("HandoffInvalid[anytls] = %d", snap.HandoffInvalid[ProtoAnyTLS])
	}
}

func TestStreamListener_UnknownERATLV_SkipWithCounter(t *testing.T) {
	// We can't actually inject an unknown ERA TLV because spec §4.2 declares
	// all 16 slots in the ERA range. The "unknown ERA TLV" path is only
	// reachable if a TLV is present that's NOT in the protocol's
	// M/O/F set AND not in universalMandatory/Optional AND it's in the ERA
	// range. We exercise this by using EraTLVMTLSSubjectDN (0xED) on the
	// anytls row — anytls's matrix marks it F, so this would fail the
	// forbidden check. To reach UnknownERA, we'd need a hypothetical
	// future TLV. Instead, assert via a hand-crafted spec that the
	// validator emits UnknownERA on a type not in any row of its matrix.
	custom := &Spec{
		Name: "test-proto", L4: "tcp",
		Mandatory: nil, Optional: nil, Forbidden: nil,
	}
	res := custom.Validate([]proxyproto.TLV{
		{Type: proxyproto.EraTLVSpecVersion, Value: []byte{proxyproto.SpecVersionStage1}},
		{Type: proxyproto.EraTLVTraceID, Value: []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")},
		// 0xED is an ERA TLV not in the test-proto matrix → UnknownERA.
		{Type: proxyproto.EraTLVMTLSSubjectDN, Value: []byte("CN=device")},
	})
	if !res.OK {
		t.Fatalf("baseline mandatories satisfied but res.OK=false: %+v", res)
	}
	if len(res.UnknownERA) != 1 || res.UnknownERA[0] != proxyproto.EraTLVMTLSSubjectDN {
		t.Fatalf("UnknownERA = %v", res.UnknownERA)
	}
}

func TestStreamListener_BindAndUseRealUDS(t *testing.T) {
	// On Windows the unix-socket type was added in Go 1.21, but path
	// semantics differ. Skip on non-Linux to keep the suite clean (the spec
	// is Linux-targeted; era-proxy runs on Linux). The PreboundListener
	// tests above exercise the same accept loop on every platform.
	if runtime.GOOS != "linux" {
		t.Skipf("real UDS bind tested only on linux; current GOOS=%s", runtime.GOOS)
	}
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "anytls.sock")
	metrics := NewMetrics()
	spec := LookupProtocol(ProtoAnyTLS)
	gotPayload := make(chan string, 1)
	handler := func(_ context.Context, acc *AcceptedStream) error {
		b := make([]byte, 16)
		n, _ := acc.Read(b)
		gotPayload <- string(b[:n])
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sl, err := ListenStream(ctx, ListenerOptions{
		Logger:     newTestLogger(),
		Metrics:    metrics,
		Spec:       spec,
		SocketPath: sockPath,
	}, handler)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sl.Close()

	cli, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()
	hdr := makeAnytlsHeader(t)
	if _, err := cli.Write(hdr); err != nil {
		t.Fatalf("write hdr: %v", err)
	}
	if _, err := cli.Write([]byte("REAL-UDS")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	select {
	case got := <-gotPayload:
		if got != "REAL-UDS" {
			t.Fatalf("payload = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handler")
	}
}

func TestStreamListener_RequiresSpec(t *testing.T) {
	_, err := ListenStream(context.Background(), ListenerOptions{
		Logger: newTestLogger(),
	}, func(context.Context, *AcceptedStream) error { return nil })
	if err == nil {
		t.Fatal("expected error for missing Spec")
	}
}
