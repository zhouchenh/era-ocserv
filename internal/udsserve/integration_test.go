package udsserve

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/certctx"
	"github.com/zhouchenh/era-ocserv/internal/cstp"
)

// stubCstpVerifier returns success for a canned user/password pair and
// derives the device id from the certctx. This mirrors the
// `certBoundVerifier` shape in cmd/era-ocserv so the UDS bridge gets
// integration-tested with the same wiring production uses.
type stubCstpVerifier struct {
	user, pass string
	deviceID   string
}

func (v *stubCstpVerifier) Verify(ctx context.Context, u, p string) (string, error) {
	certID, ok := certctx.FromContext(ctx)
	if !ok {
		return "", errors.New("no cert deviceID in context")
	}
	if u != v.user || p != v.pass {
		return "", errors.New("bad creds")
	}
	if certID != v.deviceID {
		return "", errors.New("cert/password device mismatch")
	}
	return certID, nil
}

type stubCstpResolver struct{ id cstp.Identity }

func (r *stubCstpResolver) Resolve(_ context.Context, dev string) (cstp.Identity, error) {
	if dev != r.id.DeviceID {
		return cstp.Identity{}, fmt.Errorf("unknown device %q", dev)
	}
	return r.id, nil
}

// fixedRand replays a byte sequence cyclically. Lifted from the cstp
// package's test fixtures to give the cookie / opaque-id generator a
// stable input.
type fixedRand struct {
	src []byte
	off int
	mu  sync.Mutex
}

func (f *fixedRand) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range p {
		p[i] = f.src[f.off%len(f.src)]
		f.off++
	}
	return len(p), nil
}

// newCSTPServerForUDS wires a *cstp.Server with the same verifier
// shape main.go uses (Verifier wants cert id from context).
func newCSTPServerForUDS(t *testing.T) *cstp.Server {
	t.Helper()
	ip := netip.MustParsePrefix("2001:470:f9d1:9001:dead:beef::1/128")
	verifier := &stubCstpVerifier{user: "alice", pass: "hunter2", deviceID: testDevID}
	resolver := &stubCstpResolver{id: cstp.Identity{
		DeviceID: testDevID,
		IPv6:     ip,
		MTU:      1406,
	}}
	rnd := &fixedRand{src: []byte("01234567890abcdefABCDEFxyzwQRSTuvi.PQR_")}
	return cstp.NewServer(cstp.Config{
		Verifier:          verifier,
		Resolver:          resolver,
		ServerName:        "vpn.eracloud.app",
		DNS:               []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")},
		DPDInterval:       30,
		KeepaliveInterval: 20,
		IdleTimeout:       1800,
		DefaultMTU:        1406,
		RandRead:          rnd.Read,
	})
}

func cstpInitBody() string {
	return `<?xml version="1.0"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
  <version who="vpn">5.1.10.233</version>
  <device-id unique-id="DEADBEEF">linux-64</device-id>
</config-auth>`
}

func cstpAuthReplyBody(opaqueID, user, pass string) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
  <opaque is-for="sg"><session-id>%s</session-id></opaque>
  <auth>
    <username>%s</username>
    <password>%s</password>
  </auth>
</config-auth>`, opaqueID, user, pass)
}

func cstpAuthReplyUsername(opaqueID, user string) string {
	return fmt.Sprintf(`<config-auth client="vpn" type="auth-reply"><opaque is-for="sg"><session-id>%s</session-id></opaque><auth><username>%s</username></auth></config-auth>`, opaqueID, user)
}

func cstpAuthReplyPassword(opaqueID, pass string) string {
	return fmt.Sprintf(`<config-auth client="vpn" type="auth-reply"><opaque is-for="sg"><session-id>%s</session-id></opaque><auth><password>%s</password></auth></config-auth>`, opaqueID, pass)
}

// cstpDoAuth runs the 2-step simple auth flow (username then password) over the
// hijacked CSTP stream and returns the final /auth response — a complete on
// success, or an auth-request retry on bad creds.
func cstpDoAuth(t *testing.T, w *bufio.Writer, r *bufio.Reader, opaqueID, user, pass string) *http.Response {
	t.Helper()
	resp := writeHTTPPost(t, w, r, "/auth", cstpAuthReplyUsername(opaqueID, user))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("username step status=%d body=%s", resp.StatusCode, body)
	}
	op := extractTag(string(body), "session-id")
	if op == "" {
		t.Fatalf("missing opaque in password form: %s", body)
	}
	return writeHTTPPost(t, w, r, "/auth", cstpAuthReplyPassword(op, pass))
}

func extractTag(body, tag string) string {
	open := "<" + tag + ">"
	closeT := "</" + tag + ">"
	i := strings.Index(body, open)
	if i < 0 {
		return ""
	}
	rest := body[i+len(open):]
	j := strings.Index(rest, closeT)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// writeHTTPPost is a tiny client helper that sends a POST request and
// reads one response off the conn. It does NOT close the conn so the
// caller can pipeline.
func writeHTTPPost(t *testing.T, w *bufio.Writer, r *bufio.Reader, path, body string) *http.Response {
	t.Helper()
	req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: vpn.eracloud.app\r\nUser-Agent: AnyConnect-1.0\r\nContent-Type: application/xml\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
		path, len(body), body)
	if _, err := io.WriteString(w, req); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush %s: %v", path, err)
	}
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("read response %s: %v", path, err)
	}
	return resp
}

// TestUDS_CSTPInitAuthSequence walks the AnyConnect phase-2 control
// exchange (init → auth-reply → complete) through the UDS bridge. This
// is the most important end-to-end test: it exercises the entire
// listener stack (PROXY-v2 + TLV parse → middleware → http.Server →
// cstp.Server) on a single in-memory pipe.
func TestUDS_CSTPInitAuthSequence(t *testing.T) {
	cstpSrv := newCSTPServerForUDS(t)
	defer cstpSrv.Close()
	_, pl := startUDSWithHandler(t, cstpSrv)

	clientC, serverC := net.Pipe()
	pl.deliver(serverC)

	w := bufio.NewWriter(clientC)
	r := bufio.NewReader(clientC)
	// Header arrives once at the front of the stream.
	if _, err := w.Write(buildCSTPHeader(t)); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush header: %v", err)
	}

	// Phase 2a: init.
	resp := writeHTTPPost(t, w, r, "/", cstpInitBody())
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("init status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `type="auth-request"`) {
		t.Fatalf("expected auth-request, got: %s", body)
	}
	opaqueID := extractTag(string(body), "session-id")
	if opaqueID == "" {
		t.Fatalf("missing opaque id: %s", body)
	}

	// Phase 2b: auth-reply with correct creds.
	resp = cstpDoAuth(t, w, r, opaqueID, "alice", "hunter2")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("auth status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `type="complete"`) {
		t.Fatalf("expected complete, got: %s", body)
	}
	// The session token is delivered via Set-Cookie: webvpn (stock-ocserv /
	// Cisco Secure Client shape), not a <session-token> element.
	hasWebVPN := false
	for _, c := range resp.Cookies() {
		if c.Name == "webvpn" && c.Value != "" {
			hasWebVPN = true
			break
		}
	}
	if !hasWebVPN {
		t.Fatalf("missing webvpn session cookie: %s", body)
	}
	_ = clientC.Close()
}

// TestUDS_CSTPBadCreds walks the same flow with a wrong password. The
// server replies with another auth-request (per ocserv semantics), not
// an HTTP error.
func TestUDS_CSTPBadCreds(t *testing.T) {
	cstpSrv := newCSTPServerForUDS(t)
	defer cstpSrv.Close()
	_, pl := startUDSWithHandler(t, cstpSrv)

	clientC, serverC := net.Pipe()
	pl.deliver(serverC)
	w := bufio.NewWriter(clientC)
	r := bufio.NewReader(clientC)
	_, _ = w.Write(buildCSTPHeader(t))
	_ = w.Flush()

	resp := writeHTTPPost(t, w, r, "/", cstpInitBody())
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	opaqueID := extractTag(string(body), "session-id")
	if opaqueID == "" {
		t.Fatalf("init missing opaque id")
	}

	resp = cstpDoAuth(t, w, r, opaqueID, "alice", "wrong")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("auth status = %d", resp.StatusCode)
	}
	// On bad password we expect another auth-request (error path), not
	// the complete envelope.
	if strings.Contains(string(body), `type="complete"`) {
		t.Fatalf("got complete on bad creds: %s", body)
	}
	if !strings.Contains(string(body), `type="auth-request"`) {
		t.Fatalf("expected auth-request on retry, got: %s", body)
	}
	_ = clientC.Close()
}

// TestUDS_CSTPTunnelHandshake walks all three phases including the
// CONNECT /CSCOSSLC/tunnel hijack. After the hijack, the underlying
// conn carries binary CSTP frames; the test verifies the 200 CONNECTED
// status line arrives on the wire and that the cstp.Server publishes a
// *cstp.Tunnel on Accept.
func TestUDS_CSTPTunnelHandshake(t *testing.T) {
	cstpSrv := newCSTPServerForUDS(t)
	defer cstpSrv.Close()
	_, pl := startUDSWithHandler(t, cstpSrv)

	clientC, serverC := net.Pipe()
	pl.deliver(serverC)
	w := bufio.NewWriter(clientC)
	r := bufio.NewReader(clientC)
	_, _ = w.Write(buildCSTPHeader(t))
	_ = w.Flush()

	// Phase 2a + 2b.
	resp := writeHTTPPost(t, w, r, "/", cstpInitBody())
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	opaqueID := extractTag(string(body), "session-id")

	resp = cstpDoAuth(t, w, r, opaqueID, "alice", "hunter2")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `type="complete"`) {
		t.Fatalf("phase 2 didn't complete: %s", body)
	}
	token := ""
	for _, c := range resp.Cookies() {
		if c.Name == "webvpn" && c.Value != "" {
			token = c.Value
			break
		}
	}
	if token == "" {
		t.Fatalf("no webvpn session cookie")
	}

	// Phase 3: CONNECT /CSCOSSLC/tunnel with the cookie.
	connReq := "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n" +
		"Host: vpn.eracloud.app\r\n" +
		"User-Agent: AnyConnect-1.0\r\n" +
		"Cookie: webvpn=" + token + "\r\n" +
		"X-CSTP-Version: 1\r\n" +
		"X-CSTP-Base-MTU: 1500\r\n" +
		"X-CSTP-MTU: 1406\r\n" +
		"X-CSTP-Address-Type: IPv6\r\n" +
		"\r\n"
	if _, err := io.WriteString(w, connReq); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush CONNECT: %v", err)
	}

	// On the success path the server hijacks the conn and writes
	// "HTTP/1.1 200 CONNECTED\r\n..." directly. Read the status line.
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read connect status: %v", err)
	}
	if !strings.HasPrefix(line, "HTTP/1.1 200 CONNECTED") {
		t.Fatalf("status = %q", line)
	}
	// Drain headers up to a blank line.
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if l == "\r\n" {
			break
		}
	}

	// The Server publishes a *Tunnel; pull it off Accept to confirm.
	tunCtx, tunCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer tunCancel()
	tun, err := cstpSrv.Accept(tunCtx)
	if err != nil {
		t.Fatalf("cstp Accept: %v", err)
	}
	if tun == nil {
		t.Fatal("nil tunnel")
	}
	_ = tun.Close()
	_ = clientC.Close()
}
