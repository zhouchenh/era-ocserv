package cstp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubVerifier returns success for one canned username/password.
type stubVerifier struct {
	user, pass string
	deviceID   string
	called     int
}

func (s *stubVerifier) Verify(_ context.Context, u, p string) (string, error) {
	s.called++
	if u == s.user && p == s.pass {
		return s.deviceID, nil
	}
	return "", errors.New("bad creds")
}

// stubResolver returns a canned Identity for one device.
type stubResolver struct {
	want Identity
	err  error
}

func (s *stubResolver) Resolve(_ context.Context, deviceID string) (Identity, error) {
	if s.err != nil {
		return Identity{}, s.err
	}
	if deviceID != s.want.DeviceID {
		return Identity{}, fmt.Errorf("unknown device %q", deviceID)
	}
	return s.want, nil
}

// freshServer builds a Server with deterministic randomness so tests
// can match cookies byte-for-byte if they want to. The verifier and
// resolver are returned so tests can inspect them.
func freshServer(t *testing.T) (*Server, *stubVerifier, *stubResolver) {
	t.Helper()
	ip := netip.MustParsePrefix("2001:470:f9d1:9001:dead:beef::1/128")
	v := &stubVerifier{user: "alice", pass: "hunter2", deviceID: "dev-001"}
	r := &stubResolver{
		want: Identity{
			DeviceID: "dev-001",
			IPv6:     ip,
			MTU:      1406,
		},
	}
	// Deterministic-ish randomness; the source is large enough that
	// successive 32-byte tokens don't collide trivially.
	rnd := &fixedRand{src: []byte("01234567890abcdefABCDEFxyzwQRSTuvi.PQR_")}
	s := NewServer(Config{
		Verifier:          v,
		Resolver:          r,
		ServerName:        "vpn.eracloud.app",
		DNS:               []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")},
		DPDInterval:       30,
		KeepaliveInterval: 20,
		IdleTimeout:       1800,
		DefaultMTU:        1406,
		RandRead:          rnd.Read,
	})
	return s, v, r
}

func newInitBody() string {
	return `<?xml version="1.0"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
  <version who="vpn">5.1.10.233</version>
  <device-id unique-id="DEADBEEF">linux-64</device-id>
</config-auth>`
}

func newAuthReplyBody(opaqueID, user, pass string) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
  <opaque is-for="sg"><session-id>%s</session-id></opaque>
  <auth>
    <username>%s</username>
    <password>%s</password>
  </auth>
</config-auth>`, opaqueID, user, pass)
}

// extractOpaqueID pulls the <session-id> value out of an auth-request
// response body. The XML form is well-defined here so we don't need a
// full XML parse.
func extractOpaqueID(body string) string {
	const open = "<session-id>"
	const closeTag = "</session-id>"
	i := strings.Index(body, open)
	if i < 0 {
		return ""
	}
	rest := body[i+len(open):]
	j := strings.Index(rest, closeTag)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func extractSessionToken(body string) string {
	const open = "<session-token>"
	const closeTag = "</session-token>"
	i := strings.Index(body, open)
	if i < 0 {
		return ""
	}
	rest := body[i+len(open):]
	j := strings.Index(rest, closeTag)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func TestPhase2HappyPath(t *testing.T) {
	s, _, _ := freshServer(t)
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Phase 2a: init POST.
	resp, err := http.Post(ts.URL+"/", "application/xml", strings.NewReader(newInitBody()))
	if err != nil {
		t.Fatalf("init POST: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("init status=%d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `type="auth-request"`) {
		t.Fatalf("expected auth-request, got: %s", body)
	}
	opaqueID := extractOpaqueID(string(body))
	if opaqueID == "" {
		t.Fatalf("missing opaque id in: %s", body)
	}

	// Phase 2b: auth-reply with correct creds.
	resp, err = http.Post(ts.URL+"/auth", "application/xml",
		strings.NewReader(newAuthReplyBody(opaqueID, "alice", "hunter2")))
	if err != nil {
		t.Fatalf("auth POST: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("auth status=%d", resp.StatusCode)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `type="complete"`) {
		t.Fatalf("expected complete, got: %s", body)
	}
	token := extractSessionToken(string(body))
	if token == "" {
		t.Fatalf("missing session token in: %s", body)
	}
}

func TestPhase2AuthFailure(t *testing.T) {
	s, v, _ := freshServer(t)
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Phase 2a.
	resp, err := http.Post(ts.URL+"/", "application/xml", strings.NewReader(newInitBody()))
	if err != nil {
		t.Fatalf("init POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	opaqueID := extractOpaqueID(string(body))
	if opaqueID == "" {
		t.Fatalf("missing opaque id")
	}

	// Phase 2b: wrong password.
	resp, err = http.Post(ts.URL+"/auth", "application/xml",
		strings.NewReader(newAuthReplyBody(opaqueID, "alice", "wrong")))
	if err != nil {
		t.Fatalf("auth POST: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("auth status=%d, want 200 with auth-request retry", resp.StatusCode)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `type="auth-request"`) {
		t.Fatalf("expected auth-request retry, got: %s", body)
	}
	if !strings.Contains(string(body), "failed") && !strings.Contains(string(body), "Sign-in") {
		t.Fatalf("expected failure message, got: %s", body)
	}
	if v.called != 1 {
		t.Fatalf("verifier called %d times, want 1", v.called)
	}
}

func TestPhase2AuthEmptyOpaque(t *testing.T) {
	s, _, _ := freshServer(t)
	ts := httptest.NewServer(s)
	defer ts.Close()

	// No prior phase 2a; supplies an opaque the server never minted.
	resp, err := http.Post(ts.URL+"/auth", "application/xml",
		strings.NewReader(newAuthReplyBody("BOGUS", "alice", "hunter2")))
	if err != nil {
		t.Fatalf("auth POST: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("auth status=%d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `type="auth-request"`) {
		t.Fatalf("expected auth-request, got: %s", body)
	}
	if !strings.Contains(string(body), "expired") && !strings.Contains(string(body), "sign in") {
		t.Fatalf("expected resync message, got: %s", body)
	}
}

func TestAndroidCiscoSCRejected(t *testing.T) {
	s, _, _ := freshServer(t)
	ts := httptest.NewServer(s)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/", strings.NewReader(newInitBody()))
	req.Header.Set("User-Agent", "AnyConnect Android 5.1.5.65")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestOpenConnectAndroidAccepted(t *testing.T) {
	s, _, _ := freshServer(t)
	ts := httptest.NewServer(s)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/", strings.NewReader(newInitBody()))
	req.Header.Set("User-Agent", "Open AnyConnect VPN Agent v9.12 OpenConnect-Android")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPhase3MissingCookieIs401(t *testing.T) {
	s, _, _ := freshServer(t)
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Use a raw TCP+HTTP dial because http.Client refuses to send a
	// CONNECT through a regular httptest.Server transport cleanly.
	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n" +
		"Host: vpn.eracloud.app\r\n" +
		"User-Agent: AnyConnect Windows 5.1.10.233\r\n" +
		"X-CSTP-Version: 1\r\n" +
		"X-CSTP-Base-MTU: 1500\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(statusLine, " 401 ") {
		t.Fatalf("expected 401, got: %q", statusLine)
	}
}

func TestPhase3BadCookieIs401(t *testing.T) {
	s, _, _ := freshServer(t)
	ts := httptest.NewServer(s)
	defer ts.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n" +
		"Host: vpn.eracloud.app\r\n" +
		"Cookie: webvpn=not-a-real-cookie\r\n" +
		"X-CSTP-Version: 1\r\n" +
		"X-CSTP-Base-MTU: 1500\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, _ := br.ReadString('\n')
	if !strings.Contains(statusLine, " 401 ") {
		t.Fatalf("expected 401, got: %q", statusLine)
	}
}

// TestEndToEndPhase23AndTunnel drives the full pipeline: phase 2a,
// 2b, phase 3, then sends a data frame from the client side and
// reads it through Tunnel.ReadPacket on the server side.
func TestEndToEndPhase23AndTunnel(t *testing.T) {
	s, _, _ := freshServer(t)
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Phase 2a.
	body := postAndRead(t, ts.URL+"/", newInitBody())
	opaqueID := extractOpaqueID(body)
	if opaqueID == "" {
		t.Fatalf("missing opaque id: %s", body)
	}

	// Phase 2b.
	body = postAndRead(t, ts.URL+"/auth", newAuthReplyBody(opaqueID, "alice", "hunter2"))
	token := extractSessionToken(body)
	if token == "" {
		t.Fatalf("missing session token: %s", body)
	}

	// Phase 3 + binary tunnel: raw TCP dial.
	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n" +
		"Host: vpn.eracloud.app\r\n" +
		"User-Agent: AnyConnect Windows 5.1.10.233\r\n" +
		"Cookie: webvpn=" + token + "\r\n" +
		"X-CSTP-Version: 1\r\n" +
		"X-CSTP-Base-MTU: 1500\r\n" +
		"X-CSTP-MTU: 1400\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// Read status line + headers up to blank line.
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(statusLine, "200") || !strings.Contains(statusLine, "CONNECTED") {
		t.Fatalf("expected 200 CONNECTED, got: %q", statusLine)
	}

	// Walk through headers; capture key ones.
	gotHeaders := map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("header read: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			gotHeaders[k] = v
		}
	}
	if gotHeaders["X-CSTP-Address-IP6"] == "" {
		t.Fatalf("missing X-CSTP-Address-IP6: %v", gotHeaders)
	}
	if gotHeaders["X-CSTP-Hostname"] != "vpn.eracloud.app" {
		t.Fatalf("unexpected X-CSTP-Hostname: %q", gotHeaders["X-CSTP-Hostname"])
	}

	// Server should have published a tunnel to Accept by now.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tun, err := s.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer tun.Close()

	if tun.SessionID() != token {
		t.Fatalf("tunnel session id=%q want %q", tun.SessionID(), token)
	}
	if !tun.Identity().IPv6.IsValid() {
		t.Fatalf("tunnel identity missing IPv6")
	}

	// Send a data frame from the client.
	payload := []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x3a, 0x40} // IPv6 header-ish
	frame := make([]byte, frameHeaderLen+len(payload))
	if _, err := encodeFrame(frame, pktData, payload); err != nil {
		t.Fatalf("encodeFrame: %v", err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write data frame: %v", err)
	}

	// Read on the server side.
	rbuf := make([]byte, 4096)
	n, err := tun.ReadPacket(rbuf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if !bytes.Equal(rbuf[:n], payload) {
		t.Fatalf("payload mismatch: got %x want %x", rbuf[:n], payload)
	}

	// Round trip: server writes a packet, client reads it.
	srvPayload := []byte("server-to-client")
	if _, err := tun.WritePacket(srvPayload); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	hdr := make([]byte, frameHeaderLen)
	rcvBuf := make([]byte, 4096)
	typ, gotN, err := readFrame(br, hdr, rcvBuf)
	if err != nil {
		t.Fatalf("client readFrame: %v", err)
	}
	if typ != pktData {
		t.Fatalf("server emitted typ=%d", typ)
	}
	if !bytes.Equal(rcvBuf[:gotN], srvPayload) {
		t.Fatalf("server payload mismatch: got %q want %q", rcvBuf[:gotN], srvPayload)
	}
}

func postAndRead(t *testing.T, url, body string) string {
	t.Helper()
	resp, err := http.Post(url, "application/xml", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("POST %s status=%d body=%s", url, resp.StatusCode, b)
	}
	return string(b)
}

// TestServerCloseUnblocksAccept ensures Accept returns ErrServerClosed
// when the server is closed without a pending tunnel.
func TestServerCloseUnblocksAccept(t *testing.T) {
	s, _, _ := freshServer(t)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := s.Accept(context.Background())
		if !errors.Is(err, ErrServerClosed) {
			t.Errorf("Accept returned %v, want ErrServerClosed", err)
		}
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	_ = s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("Accept did not return after Close")
	}
	wg.Wait()
}
