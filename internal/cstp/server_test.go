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

// newAuthReplyUsername / newAuthReplyPassword are the two rounds of the 2-step
// simple auth flow: the client submits the username (step 1), then the password
// (step 2), each echoing the round-tripped opaque session id.
func newAuthReplyUsername(opaqueID, user string) string {
	return fmt.Sprintf(`<config-auth client="vpn" type="auth-reply"><opaque is-for="sg"><session-id>%s</session-id></opaque><auth><username>%s</username></auth></config-auth>`, opaqueID, user)
}

func newAuthReplyPassword(opaqueID, pass string) string {
	return fmt.Sprintf(`<config-auth client="vpn" type="auth-reply"><opaque is-for="sg"><session-id>%s</session-id></opaque><auth><password>%s</password></auth></config-auth>`, opaqueID, pass)
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
	// Stock ocserv's simple auth path serves the auth-request as bare text/xml
	// with NO X-Aggregate-Auth — the path the iOS Cisco Secure Client drives
	// end-to-end. (A combined form + X-Aggregate-Auth put iOS on the aggregate
	// path, which authenticated but then never sent the CONNECT.)
	if ct := resp.Header.Get("Content-Type"); ct != "text/xml" {
		t.Fatalf("auth-request Content-Type=%q, want exactly text/xml", ct)
	}
	if av := resp.Header.Get("X-Aggregate-Auth"); av != "" {
		t.Fatalf("auth-request X-Aggregate-Auth=%q, want absent (simple path)", av)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `type="auth-request"`) {
		t.Fatalf("expected auth-request, got: %s", body)
	}
	// Step-1 form is username-only (2-step simple path).
	if !strings.Contains(string(body), `name="username"`) || strings.Contains(string(body), `name="password"`) {
		t.Fatalf("step-1 form must be username-only: %s", body)
	}
	if strings.Contains(string(body), "aggregate-auth-version") {
		t.Fatalf("server auth-request must NOT carry aggregate-auth-version (client-only attr): %s", body)
	}
	opaqueID := extractOpaqueID(string(body))
	if opaqueID == "" {
		t.Fatalf("missing opaque id in: %s", body)
	}

	// Phase 2b step 1: submit username -> server returns the password form.
	resp, err = http.Post(ts.URL+"/auth", "application/xml",
		strings.NewReader(newAuthReplyUsername(opaqueID, "alice")))
	if err != nil {
		t.Fatalf("username POST: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("username step status=%d", resp.StatusCode)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `type="auth-request"`) || !strings.Contains(string(body), `name="password"`) {
		t.Fatalf("expected password form after username step, got: %s", body)
	}
	opaqueID = extractOpaqueID(string(body))
	if opaqueID == "" {
		t.Fatalf("missing opaque id in password form: %s", body)
	}

	// Phase 2b step 2: submit password -> complete.
	resp, err = http.Post(ts.URL+"/auth", "application/xml",
		strings.NewReader(newAuthReplyPassword(opaqueID, "hunter2")))
	if err != nil {
		t.Fatalf("password POST: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("auth status=%d", resp.StatusCode)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `type="complete"`) {
		t.Fatalf("expected complete, got: %s", body)
	}
	// The session credential is delivered via the Set-Cookie: webvpn header
	// (the Cisco Secure Client path), not an XML element.
	var token string
	for _, c := range resp.Cookies() {
		if c.Name == "webvpn" && c.Value != "" {
			token = c.Value
			break
		}
	}
	if token == "" {
		t.Fatalf("missing webvpn auth cookie carrying the session token: %s", body)
	}
	// The post-auth directive cookie must be stock ocserv's minimal shape:
	// bu/p/iu/sh only. fu:/fh: (profile fetch) and lu: (translation-table fetch)
	// drove the iOS Cisco Secure Client into a pre-tunnel fetch it never
	// completed, so it went silent after the complete and never sent the CONNECT.
	// They must stay absent.
	var directive string
	for _, c := range resp.Cookies() {
		if c.Name == "webvpnc" && c.Value != "" {
			directive = c.Value
		}
	}
	if directive == "" {
		t.Fatalf("missing webvpnc post-auth directive cookie")
	}
	if !strings.Contains(directive, "p:t") || !strings.Contains(directive, "sh:") {
		t.Fatalf("webvpnc directive missing p:t/sh: %q", directive)
	}
	if strings.Contains(directive, "fu:") || strings.Contains(directive, "fh:") || strings.Contains(directive, "lu:") {
		t.Fatalf("webvpnc directive must NOT carry fu:/fh:/lu: (regression): %q", directive)
	}
}

// TestPhase2SimpleFormPath exercises Cisco Secure Client's SIMPLE auth path:
// the auth-reply arrives application/x-www-form-urlencoded ("username=...",
// then "password=...") with NO body <opaque>, and the pre-auth session is
// carried in the webvpncontext cookie set on the auth-request responses.
func TestPhase2SimpleFormPath(t *testing.T) {
	s, _, _ := freshServer(t)
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Phase 2a: init -> username form; grab the webvpncontext session cookie.
	resp, err := http.Post(ts.URL+"/", "application/xml", strings.NewReader(newInitBody()))
	if err != nil {
		t.Fatalf("init POST: %v", err)
	}
	var ctx string
	for _, c := range resp.Cookies() {
		if c.Name == "webvpncontext" && c.Value != "" {
			ctx = c.Value
		}
	}
	resp.Body.Close()
	if ctx == "" {
		t.Fatalf("init did not set webvpncontext cookie")
	}

	formPost := func(bodyStr string) *http.Response {
		req, _ := http.NewRequest("POST", ts.URL+"/auth", strings.NewReader(bodyStr))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Cookie", "webvpncontext="+ctx)
		r, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatalf("form POST %q: %v", bodyStr, e)
		}
		return r
	}

	// Step 1: form-urlencoded username -> password form.
	resp = formPost("username=alice")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `type="auth-request"`) || !strings.Contains(string(body), `name="password"`) {
		t.Fatalf("expected password form after form username, got: %s", body)
	}

	// Step 2: form-urlencoded password -> complete with webvpn session cookie.
	resp = formPost("password=hunter2")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `type="complete"`) {
		t.Fatalf("expected complete via form path, got: %s", body)
	}
	hasWebVPN := false
	for _, c := range resp.Cookies() {
		if c.Name == "webvpn" && c.Value != "" {
			hasWebVPN = true
		}
	}
	if !hasWebVPN {
		t.Fatalf("form path: missing webvpn session cookie: %s", body)
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

	// Phase 2b step 1: submit username -> password form.
	resp, err = http.Post(ts.URL+"/auth", "application/xml",
		strings.NewReader(newAuthReplyUsername(opaqueID, "alice")))
	if err != nil {
		t.Fatalf("username POST: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	opaqueID = extractOpaqueID(string(body))
	if opaqueID == "" {
		t.Fatalf("missing opaque id in password form: %s", body)
	}

	// Phase 2b step 2: wrong password -> auth-request retry with error message.
	resp, err = http.Post(ts.URL+"/auth", "application/xml",
		strings.NewReader(newAuthReplyPassword(opaqueID, "wrong")))
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

	// No prior phase 2a; supplies an opaque the server never minted. Because the
	// reply carries a username, the handler (matching stock ocserv's stateless
	// init, where the session is created on the username step) recovers
	// gracefully: it mints a fresh session, stashes the username, and prompts for
	// the password rather than erroring.
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
	if !strings.Contains(string(body), `type="auth-request"`) || !strings.Contains(string(body), `name="password"`) {
		t.Fatalf("expected graceful restart at the password form, got: %s", body)
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

	// Phase 2b: 2-step simple auth (username then password). The session token
	// is delivered via the Set-Cookie: webvpn header (stock-ocserv / Cisco Secure
	// Client shape), not an XML element.
	uResp, err := http.Post(ts.URL+"/auth", "text/xml", strings.NewReader(newAuthReplyUsername(opaqueID, "alice")))
	if err != nil {
		t.Fatalf("username POST: %v", err)
	}
	uBody, _ := io.ReadAll(uResp.Body)
	uResp.Body.Close()
	opaqueID = extractOpaqueID(string(uBody))
	if opaqueID == "" {
		t.Fatalf("missing opaque in password form: %s", uBody)
	}
	authResp, err := http.Post(ts.URL+"/auth", "text/xml", strings.NewReader(newAuthReplyPassword(opaqueID, "hunter2")))
	if err != nil {
		t.Fatalf("auth POST: %v", err)
	}
	authResp.Body.Close()
	var token string
	for _, c := range authResp.Cookies() {
		if c.Name == "webvpn" && c.Value != "" {
			token = c.Value
			break
		}
	}
	if token == "" {
		t.Fatalf("missing webvpn session cookie")
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

func TestDTLSAddressForRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodConnect, "https://eracloud.app/CSCOSSLC/tunnel", nil)
	r.Host = "eracloud.app:443"
	if got := dtlsAddressForRequest(r, Config{ServerName: "vpn.eracloud.app"}); got != "eracloud.app" {
		t.Fatalf("dtlsAddressForRequest host = %q, want eracloud.app", got)
	}
	if got := dtlsAddressForRequest(nil, Config{ServerName: "vpn.eracloud.app"}); got != "vpn.eracloud.app" {
		t.Fatalf("dtlsAddressForRequest fallback = %q, want vpn.eracloud.app", got)
	}
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
