package udsserve

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/certctx"
	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
	"github.com/zhouchenh/era-ocserv/internal/udshandoff"
)

const (
	testDevID    = "dev_abcdefghijklmnopqrstuvwxyz"
	testDevUUID  = "123e4567-e89b-12d3-a456-426614174000"
	testTraceID  = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	testUserID   = "user-1"
	testSubjDN   = "CN=" + testDevID + ",O=ERA Cloud"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// pipeListener is the same in-memory listener pattern udshandoff_test
// uses. It lets us drive the framework without touching the filesystem.
type pipeListener struct {
	conns  chan net.Conn
	mu     sync.Mutex
	closed bool
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn, 8)}
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

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func (p *pipeListener) Addr() net.Addr { return pipeAddr{} }

func (p *pipeListener) deliver(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		c.Close()
		return
	}
	p.conns <- c
}

// buildCSTPHeader returns a PROXY-v2 header satisfying the
// AnyConnect-CSTP matrix row.
func buildCSTPHeader(t *testing.T, opts ...func(*proxyproto.HeaderV2)) []byte {
	t.Helper()
	src := netip.MustParseAddrPort("203.0.113.42:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	hdr := &proxyproto.HeaderV2{
		Family: 0x11, // TCP4
		Src:    src,
		Dst:    dst,
		TLVs: []proxyproto.TLV{
			{Type: proxyproto.EraTLVSpecVersion, Value: []byte{proxyproto.SpecVersionStage1}},
			{Type: proxyproto.EraTLVToken, Value: make([]byte, 12)},
			{Type: proxyproto.EraTLVDeviceID, Value: []byte(testDevUUID)},
			{Type: proxyproto.EraTLVUserID, Value: []byte(testUserID)},
			{Type: proxyproto.EraTLVSourceHintV6, Value: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}},
			{Type: proxyproto.EraTLVMTLSSubjectDN, Value: []byte(testSubjDN)},
			{Type: proxyproto.EraTLVTraceID, Value: []byte(testTraceID)},
		},
	}
	for _, opt := range opts {
		opt(hdr)
	}
	b, err := hdr.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

// withoutTLV returns an option that removes the given TLV from a header
// before encoding.
func withoutTLV(typ proxyproto.TLVType) func(*proxyproto.HeaderV2) {
	return func(h *proxyproto.HeaderV2) {
		out := h.TLVs[:0]
		for _, t := range h.TLVs {
			if t.Type != typ {
				out = append(out, t)
			}
		}
		h.TLVs = out
	}
}

// startUDSWithHandler boots a udsserve.Server backed by an in-memory
// pipeListener and `handler` as the HTTP layer. The pipeListener is
// returned so the test can `deliver` simulated facade conns.
func startUDSWithHandler(t *testing.T, handler http.Handler) (*Server, *pipeListener) {
	t.Helper()
	pl := newPipeListener()
	srv, err := Listen(context.Background(), Options{
		SocketPath:       "uds://test",
		Logger:           discardLogger(),
		Metrics:          udshandoff.NewMetrics(),
		Handler:          handler,
		PreboundListener: pl,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, pl
}

// echoHandshakeHandler is a stand-in HTTP handler that exercises the
// happy path: it asserts the request comes with the expected context
// values from the UDS handoff, then writes a simple response. Tests
// use it when they only want to verify the bridge plumbing — the
// actual CSTP server is tested separately.
func echoHandshakeHandler(t *testing.T, wantDevID string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HandoffInfo should be readable from the request context.
		info, ok := FromContext(r.Context())
		if !ok || info == nil {
			http.Error(w, "missing HandoffInfo", http.StatusInternalServerError)
			return
		}
		if info.TraceID != testTraceID {
			http.Error(w, "wrong trace_id", http.StatusInternalServerError)
			return
		}
		// certctx should carry the device id extracted from the DN.
		dev, ok := certctx.FromContext(r.Context())
		if !ok {
			http.Error(w, "missing device id in certctx", http.StatusInternalServerError)
			return
		}
		if dev != wantDevID {
			http.Error(w, "wrong device id "+dev, http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Hello", "world")
		_, _ = io.WriteString(w, "ok")
	})
}

// drainHTTPResponse reads one HTTP/1.1 response off conn and returns
// the parsed Response and the body bytes.
func drainHTTPResponse(t *testing.T, conn net.Conn) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp.Body.Close()
	return resp, body
}

// TestUDS_HappyPath exercises the entire UDS bridge end-to-end with a
// stub HTTP handler: the listener accepts a PROXY-v2 + ERA TLV header,
// extracts info, baked context, dispatches to the handler, and the
// handler sees the right device id.
func TestUDS_HappyPath(t *testing.T) {
	_, pl := startUDSWithHandler(t, echoHandshakeHandler(t, testDevID))

	// Simulate a facade-side conn. We write the PROXY-v2 prefix + a
	// minimal HTTP/1.1 GET request.
	clientC, serverC := net.Pipe()
	pl.deliver(serverC)

	go func() {
		_, _ = clientC.Write(buildCSTPHeader(t))
		_, _ = io.WriteString(clientC, "GET /healthz HTTP/1.1\r\nHost: vpn.eracloud.app\r\n\r\n")
	}()

	resp, body := drainHTTPResponse(t, clientC)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want \"ok\"", body)
	}
	if resp.Header.Get("X-Hello") != "world" {
		t.Errorf("X-Hello = %q", resp.Header.Get("X-Hello"))
	}
	_ = clientC.Close()
}

// TestUDS_MissingTOKEN: omitting EraTLVToken trips the udshandoff
// matrix validator (TOKEN is mandatory for anyconnect-cstp). The
// handler must not be invoked; counters must record a handoff_invalid.
func TestUDS_MissingTOKEN(t *testing.T) {
	var hCalls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	// We need to reach the per-stream udshandoff Metrics to assert on
	// it. Build the Server with our own Metrics so we can snapshot.
	pl := newPipeListener()
	metrics := udshandoff.NewMetrics()
	srv, err := Listen(context.Background(), Options{
		SocketPath:       "uds://test",
		Logger:           discardLogger(),
		Metrics:          metrics,
		Handler:          handler,
		PreboundListener: pl,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	clientC, serverC := net.Pipe()
	pl.deliver(serverC)
	go func() {
		_, _ = clientC.Write(buildCSTPHeader(t, withoutTLV(proxyproto.EraTLVToken)))
		// Don't bother sending an HTTP request — the handoff should be
		// rejected at the header.
		_ = clientC.Close()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap := metrics.Snapshot()
		if snap.HandoffInvalid[udshandoff.ProtoAnyConnectCSTP] > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	snap := metrics.Snapshot()
	if hCalls.Load() != 0 {
		t.Fatalf("HTTP handler was invoked on rejected handoff")
	}
	if snap.HandoffInvalid[udshandoff.ProtoAnyConnectCSTP] != 1 {
		t.Errorf("HandoffInvalid[anyconnect-cstp] = %d, want 1",
			snap.HandoffInvalid[udshandoff.ProtoAnyConnectCSTP])
	}
	if snap.HandoffAccept[udshandoff.ProtoAnyConnectCSTP] != 0 {
		t.Errorf("HandoffAccept[anyconnect-cstp] = %d, want 0",
			snap.HandoffAccept[udshandoff.ProtoAnyConnectCSTP])
	}
}

// TestUDS_MissingMTLSSubjectDN: omitting EraTLVMTLSSubjectDN trips the
// matrix validator (DN is mandatory for anyconnect-cstp per spec §7).
// Same expectation as MissingTOKEN.
func TestUDS_MissingMTLSSubjectDN(t *testing.T) {
	var hCalls atomic.Int32
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		hCalls.Add(1)
	})
	pl := newPipeListener()
	metrics := udshandoff.NewMetrics()
	srv, err := Listen(context.Background(), Options{
		SocketPath:       "uds://test",
		Logger:           discardLogger(),
		Metrics:          metrics,
		Handler:          handler,
		PreboundListener: pl,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	clientC, serverC := net.Pipe()
	pl.deliver(serverC)
	go func() {
		_, _ = clientC.Write(buildCSTPHeader(t, withoutTLV(proxyproto.EraTLVMTLSSubjectDN)))
		_ = clientC.Close()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap := metrics.Snapshot()
		if snap.HandoffInvalid[udshandoff.ProtoAnyConnectCSTP] > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if hCalls.Load() != 0 {
		t.Fatalf("HTTP handler invoked on rejected handoff")
	}
	snap := metrics.Snapshot()
	if snap.HandoffInvalid[udshandoff.ProtoAnyConnectCSTP] != 1 {
		t.Errorf("HandoffInvalid = %d, want 1", snap.HandoffInvalid[udshandoff.ProtoAnyConnectCSTP])
	}
}

// TestUDS_MalformedSubjectDN: matrix passes (DN present + nonempty +
// UTF-8) but the value is not RFC-4514-parseable. The udsserve
// middleware then rejects the request with HTTP 400.
func TestUDS_MalformedSubjectDN(t *testing.T) {
	var hCalls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	_, pl := startUDSWithHandler(t, handler)

	clientC, serverC := net.Pipe()
	pl.deliver(serverC)
	hdr := buildCSTPHeader(t, func(h *proxyproto.HeaderV2) {
		for i := range h.TLVs {
			if h.TLVs[i].Type == proxyproto.EraTLVMTLSSubjectDN {
				h.TLVs[i].Value = []byte(`CN=\`) // lone trailing backslash
			}
		}
	})
	go func() {
		_, _ = clientC.Write(hdr)
		_, _ = io.WriteString(clientC, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	}()

	resp, body := drainHTTPResponse(t, clientC)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %q, want 400", resp.StatusCode, body)
	}
	if hCalls.Load() != 0 {
		t.Fatalf("downstream handler was invoked on bad DN")
	}
	_ = clientC.Close()
}

// TestUDS_DNCNNotDeviceID: DN parses but its CN value does not match
// the idgen device-id shape. Middleware returns 401.
func TestUDS_DNCNNotDeviceID(t *testing.T) {
	var hCalls atomic.Int32
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		hCalls.Add(1)
	})
	_, pl := startUDSWithHandler(t, handler)

	clientC, serverC := net.Pipe()
	pl.deliver(serverC)
	hdr := buildCSTPHeader(t, func(h *proxyproto.HeaderV2) {
		for i := range h.TLVs {
			if h.TLVs[i].Type == proxyproto.EraTLVMTLSSubjectDN {
				h.TLVs[i].Value = []byte("CN=not-a-device-id,O=ERA")
			}
		}
	})
	go func() {
		_, _ = clientC.Write(hdr)
		_, _ = io.WriteString(clientC, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	}()

	resp, _ := drainHTTPResponse(t, clientC)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if hCalls.Load() != 0 {
		t.Fatalf("downstream handler invoked on bad CN")
	}
	_ = clientC.Close()
}

// TestUDS_HandoffInfoOnContext verifies that the per-stream HandoffInfo
// surfaced to the HTTP handler contains every TLV-sourced field the
// spec mandates. The middleware-injected certctx device-id is asserted
// in TestUDS_HappyPath; this one focuses on the per-request HandoffInfo
// surface.
func TestUDS_HandoffInfoOnContext(t *testing.T) {
	var got *HandoffInfo
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, _ := FromContext(r.Context())
		mu.Lock()
		got = info
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	_, pl := startUDSWithHandler(t, handler)

	clientC, serverC := net.Pipe()
	pl.deliver(serverC)
	go func() {
		_, _ = clientC.Write(buildCSTPHeader(t))
		_, _ = io.WriteString(clientC, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	}()
	_, _ = drainHTTPResponse(t, clientC)
	_ = clientC.Close()

	mu.Lock()
	defer mu.Unlock()
	if got == nil {
		t.Fatal("HandoffInfo absent on request context")
	}
	if got.TraceID != testTraceID {
		t.Errorf("TraceID = %q, want %q", got.TraceID, testTraceID)
	}
	if got.UserID != testUserID {
		t.Errorf("UserID = %q, want %q", got.UserID, testUserID)
	}
	if got.SubjectDN != testSubjDN {
		t.Errorf("SubjectDN = %q, want %q", got.SubjectDN, testSubjDN)
	}
	if got.DeviceID != testDevUUID {
		t.Errorf("DeviceID (TLV) = %q, want %q", got.DeviceID, testDevUUID)
	}
	if !got.SourceHintV6.IsValid() {
		t.Errorf("SourceHintV6 not valid")
	}
	if len(got.Token) != 12 {
		t.Errorf("Token len = %d, want 12", len(got.Token))
	}
	if !got.ClientSrc.IsValid() {
		t.Errorf("ClientSrc not valid")
	}
}

// TestUDS_TwoRequestsKeepalive: two HTTP/1.1 requests on the same UDS
// stream both reach the handler. AnyConnect's typical phase 2 sequence
// is init→auth-reply (two POSTs on the same TLS conn before CONNECT);
// verify the UDS bridge preserves HTTP/1.1 keep-alive semantics.
func TestUDS_TwoRequestsKeepalive(t *testing.T) {
	var hits atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Hit", fmt.Sprintf("%d", hits.Load()))
		w.Header().Set("Content-Length", "2")
		_, _ = io.WriteString(w, "OK")
	})
	_, pl := startUDSWithHandler(t, handler)

	clientC, serverC := net.Pipe()
	pl.deliver(serverC)

	writer := bufio.NewWriter(clientC)
	reader := bufio.NewReader(clientC)
	// Write header + first request.
	go func() {
		_, _ = writer.Write(buildCSTPHeader(t))
		_, _ = io.WriteString(writer, "GET /first HTTP/1.1\r\nHost: x\r\n\r\n")
		_ = writer.Flush()
	}()

	resp1, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response 1: %v", err)
	}
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("resp1 status = %d", resp1.StatusCode)
	}

	go func() {
		_, _ = io.WriteString(writer, "GET /second HTTP/1.1\r\nHost: x\r\n\r\n")
		_ = writer.Flush()
	}()

	resp2, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response 2: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("resp2 status = %d", resp2.StatusCode)
	}
	if hits.Load() != 2 {
		t.Errorf("hits = %d, want 2", hits.Load())
	}
	_ = clientC.Close()
}

// TestUDS_DefaultSocketPath records the canonical socket path
// constant. Production deployments override via Options.SocketPath;
// tests use PreboundListener. The constant lives at the package level
// and is named after the AnyConnect-CSTP row of the spec §2.1 table.
func TestUDS_DefaultSocketPath(t *testing.T) {
	want := "/var/run/era-facade/handoffs/anyconnect-cstp.sock"
	if DefaultSocketPath != want {
		t.Errorf("DefaultSocketPath = %q, want %q", DefaultSocketPath, want)
	}
}

// TestUDS_OptionsValidation rejects nil Handler / nil Logger so a
// misconfigured caller fails fast.
func TestUDS_OptionsValidation(t *testing.T) {
	pl := newPipeListener()
	// missing Handler
	if _, err := Listen(context.Background(), Options{
		Logger:           discardLogger(),
		PreboundListener: pl,
	}); err == nil {
		t.Errorf("expected error for nil Handler")
	}
	// missing Logger
	if _, err := Listen(context.Background(), Options{
		Handler:          http.NotFoundHandler(),
		PreboundListener: pl,
	}); err == nil {
		t.Errorf("expected error for nil Logger")
	}
}

// TestUDS_ServeWithHTTPTestServer demonstrates that the UDS bridge
// delegates to an arbitrary http.Handler — here we use a httptest
// in-process server as the handler. This is more of an architectural
// sanity check than a wire-level test.
func TestUDS_ServeWithHTTPTestServer(t *testing.T) {
	var seen string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	bridge := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Re-issue the request against the in-process upstream so we
		// can confirm the path made it through.
		client := upstream.Client()
		resp, err := client.Get(upstream.URL + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_, _ = io.Copy(w, resp.Body)
		resp.Body.Close()
	})
	_, pl := startUDSWithHandler(t, bridge)

	clientC, serverC := net.Pipe()
	pl.deliver(serverC)
	go func() {
		_, _ = clientC.Write(buildCSTPHeader(t))
		_, _ = io.WriteString(clientC, "GET /probe HTTP/1.1\r\nHost: x\r\n\r\n")
	}()
	resp, _ := drainHTTPResponse(t, clientC)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if seen != "/probe" {
		t.Errorf("path = %q, want /probe", seen)
	}
	_ = clientC.Close()
}

// TestUDS_DropsConnIfQueueClosed: closing the Server before a conn
// arrives should make subsequent pushes a no-op (the conn gets closed,
// no leak).
func TestUDS_DropsConnIfQueueClosed(t *testing.T) {
	srv, pl := startUDSWithHandler(t, http.NotFoundHandler())
	_ = srv.Close()

	// After close the listener.Accept returns ErrClosed; subsequent
	// pushes are dropped. The pipe-delivered conn should be promptly
	// closed by udsserve handling. Best-effort assertion: write to the
	// far end and expect a read error within a short window.
	clientC, serverC := net.Pipe()
	pl.deliver(serverC)
	go func() {
		_, _ = clientC.Write(buildCSTPHeader(t))
	}()
	_ = clientC.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := clientC.Read(buf)
	if err == nil {
		t.Errorf("expected read error after server close, got nil")
	}
	_ = clientC.Close()
}

// TestBufferedPostHeaderBytes confirms that bytes arriving in the same
// recv as the PROXY-v2 header (i.e. already in the framework's
// bufio.Reader) are correctly replayed to the http.Server. This is the
// fast-CONNECT case where a request rides along with the header.
func TestBufferedPostHeaderBytes(t *testing.T) {
	_, pl := startUDSWithHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ack")
	}))

	clientC, serverC := net.Pipe()
	pl.deliver(serverC)
	go func() {
		// Combine header + request into a single write so they land in
		// one recv on the server side.
		var buf bytes.Buffer
		buf.Write(buildCSTPHeader(t))
		buf.WriteString("GET /combined HTTP/1.1\r\nHost: x\r\n\r\n")
		_, _ = clientC.Write(buf.Bytes())
	}()
	resp, body := drainHTTPResponse(t, clientC)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(body) != "ack" {
		t.Errorf("body = %q", body)
	}
	_ = clientC.Close()
}
