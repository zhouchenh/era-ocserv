package e2e_test

import (
	"bytes"
	"crypto/tls"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestStage1HappyPath drives the full sequence in one test:
//
//	mTLS handshake -> POST / (init) -> POST /auth -> CONNECT
//	-> binary frame round-trip (client -> server and server -> client).
//
// Asserts the gateway emits X-CSTP-Address-IP6, X-CSTP-MTU, and
// X-DTLS-Master-Secret on the CONNECT response, and that data
// flows both directions.
func TestStage1HappyPath(t *testing.T) {
	h := newHarness(t)

	clientCert := h.pk.issueClientLeaf(t, canonicalDeviceID)
	client := &fakeClient{addr: h.Address(), tlsConfig: h.pk.clientTLSConfig(clientCert)}
	if err := client.dial(); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.close()

	token, _, _, err := client.initAndAuth("vpn.eracloud.app", "alice", "hunter2")
	if err != nil {
		t.Fatalf("initAndAuth: %v", err)
	}
	if token == "" {
		t.Fatalf("empty session token")
	}

	hdr, err := client.connect("vpn.eracloud.app", token)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Required CONNECT-response headers per protocol §1.6.
	if got := hdr.Get("X-CSTP-Address-IP6"); !strings.HasPrefix(got, "2001:470:f9d1:9001:2a::ff") {
		t.Errorf("X-CSTP-Address-IP6 = %q, want 2001:470:f9d1:9001:2a::ff/128", got)
	}
	if got := hdr.Get("X-CSTP-MTU"); got == "" {
		t.Errorf("X-CSTP-MTU missing")
	}
	if got := hdr.Get("X-CSTP-Hostname"); got != "vpn.eracloud.app" {
		t.Errorf("X-CSTP-Hostname = %q, want vpn.eracloud.app", got)
	}
	// Stage 1 default ships no DTLS server, so the gateway MUST NOT
	// advertise X-DTLS-* headers. The Stage 2 work item (separate
	// branch feat/internal-dtls) flips DTLSAdvertise=true and the
	// dedicated TestStage1DTLSAdvertisedWhenEnabled test exercises
	// the positive path.
	if got := hdr.Get("X-DTLS-Master-Secret"); got != "" {
		t.Errorf("X-DTLS-Master-Secret should be omitted in Stage 1 default (no DTLS server), got %q", got)
	}
	if got := hdr.Get("X-DTLS-CipherSuite"); got != "" {
		t.Errorf("X-DTLS-CipherSuite should be omitted in Stage 1 default, got %q", got)
	}

	// --- client -> server (tunnel ingress -> tun queue) -------------
	// The bridge writes the inner packet to one of the fake tun queues.
	// We construct a real IPv6 packet so the bridge does not silently
	// drop it.
	clientSrc := netip.MustParseAddr("2001:470:f9d1:9001:2a::ff")
	upstream := netip.MustParseAddr("2606:4700:4700::1111")
	payload := []byte("hello-from-client")
	pkt := makeIPv6Packet(clientSrc, upstream, payload)
	if err := client.writeFrame(cstpPktData, pkt); err != nil {
		t.Fatalf("client writeFrame: %v", err)
	}

	// Drain the fake tun's out channel. Bridge writes there from the
	// tunnel-read goroutine.
	q := h.tun.QueuesTyped()[0]
	select {
	case got := <-q.out:
		if !bytes.Equal(got, pkt) {
			t.Errorf("tun received %x bytes\n want %x", got, pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for bridge to forward client packet to fake tun")
	}

	// --- server -> client (tun queue -> tunnel egress) --------------
	// Inject a packet destined for the canonical /128 into the fake
	// tun. The bridge's pumpTunQueue should match on dst and forward
	// it through the tunnel.
	revPayload := []byte("hello-from-tun")
	revPkt := makeIPv6Packet(upstream, clientSrc, revPayload)
	if !q.Inject(revPkt) {
		t.Fatalf("Inject failed (queue closed?)")
	}

	typ, body, err := client.readFrameWithDeadline(3 * time.Second)
	if err != nil {
		t.Fatalf("client readFrame: %v", err)
	}
	if typ != cstpPktData {
		t.Fatalf("expected pktData (%d), got %d", cstpPktData, typ)
	}
	if !bytes.Equal(body, revPkt) {
		t.Errorf("client received %x\n want %x", body, revPkt)
	}
}

// TestStage1WrongPasswordReprompts asserts that a wrong password
// returns an auth-request with an error message (status 200 with a
// reprompt body — matching ocserv semantics) rather than tearing the
// conn down.
func TestStage1WrongPasswordReprompts(t *testing.T) {
	h := newHarness(t)
	clientCert := h.pk.issueClientLeaf(t, canonicalDeviceID)
	client := &fakeClient{addr: h.Address(), tlsConfig: h.pk.clientTLSConfig(clientCert)}
	if err := client.dial(); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.close()

	// initAndAuth should NOT fail at the transport layer but the
	// returned token will be empty (the body carries a fresh
	// auth-request, not a complete).
	token, _, authResp, err := client.initAndAuth("vpn.eracloud.app", "alice", "wrong-password")
	if err != nil {
		t.Fatalf("initAndAuth (wrong pw): %v", err)
	}
	if token != "" {
		t.Fatalf("expected empty token on wrong password, got %q", token)
	}
	if authResp == nil || authResp.StatusCode != 200 {
		t.Fatalf("expected 200 reprompt, got %+v", authResp)
	}
	body := string(authResp.Body)
	if !strings.Contains(body, `type="auth-request"`) {
		t.Fatalf("expected auth-request reprompt, got body: %s", body)
	}
	if !strings.Contains(body, "failed") && !strings.Contains(body, "Sign-in") {
		t.Fatalf("expected failure message, got: %s", body)
	}

	// Verifier was called exactly once.
	if calls := h.verifier.Calls(); len(calls) != 1 {
		t.Errorf("verifier called %d times, want 1", len(calls))
	}
}

// TestStage1MissingClientCertFailsTLS asserts that a connection
// without a client cert is rejected because the server enforces
// RequireAndVerifyClientCert.
//
// Under TLS 1.3, Go's client-side handshake can return nil even when
// the server is about to send a "certificate required" alert — the
// alert is delivered on the client's next Read. To surface the
// failure deterministically, the test attempts a small Write+Read
// after the dial and asserts that fails. This matches what the real
// AnyConnect client would observe: it'd send its first HTTP byte and
// only then see the TLS alert.
func TestStage1MissingClientCertFailsTLS(t *testing.T) {
	h := newHarness(t)
	cfg := h.pk.clientTLSConfig(tls.Certificate{})
	conn, err := tls.Dial("tcp", h.Address(), cfg)
	if err != nil {
		// TLS 1.2 path or any future config where the handshake
		// errors synchronously. That's the expected shape.
		return
	}
	defer conn.Close()

	// TLS 1.3 path: drive a read to force the server's alert.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("POST / HTTP/1.1\r\nHost: vpn.eracloud.app\r\n\r\n"))
	buf := make([]byte, 256)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatalf("expected read to fail (no client cert), got nil error")
	}
	// We don't tightly match the error string because it varies by
	// TLS version. The important thing is the conn never carried
	// real data.
}

// TestStage1BadCookieAtConnectIs401 issues a CONNECT with a session
// token the server never minted. The server replies 401 and closes
// the conn.
func TestStage1BadCookieAtConnectIs401(t *testing.T) {
	h := newHarness(t)
	clientCert := h.pk.issueClientLeaf(t, canonicalDeviceID)
	client := &fakeClient{addr: h.Address(), tlsConfig: h.pk.clientTLSConfig(clientCert)}
	if err := client.dial(); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.close()

	// Don't go through phase 2 at all; just CONNECT with a bogus cookie.
	_, err := client.connect("vpn.eracloud.app", "not-a-real-cookie")
	if err == nil {
		t.Fatalf("expected CONNECT failure, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 in error, got: %v", err)
	}
}

// TestStage1DPDFiresWithinInterval connects a client, then waits and
// asserts the gateway emits a DPD-out frame on the binary channel
// when the inbound channel has been silent for at least DPDInterval.
//
// To keep the test fast we override DPDInterval to 1 second (the
// heartbeat goroutine wakes at half that). We tolerate either DPD or
// keepalive — both are documented under "heartbeat" in the protocol.
func TestStage1DPDFiresWithinInterval(t *testing.T) {
	h := newHarness(t, withDPDInterval(1), withKeepaliveInterval(1))
	clientCert := h.pk.issueClientLeaf(t, canonicalDeviceID)
	client := &fakeClient{addr: h.Address(), tlsConfig: h.pk.clientTLSConfig(clientCert)}
	if err := client.dial(); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.close()

	token, _, _, err := client.initAndAuth("vpn.eracloud.app", "alice", "hunter2")
	if err != nil {
		t.Fatalf("initAndAuth: %v", err)
	}
	if _, err := client.connect("vpn.eracloud.app", token); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Wait for the first heartbeat frame to land. With DPD=1s the
	// heartbeat ticker wakes every 500ms; we allow 3s for the first
	// frame to be emitted on slow CI.
	deadline := time.Now().Add(3 * time.Second)
	var sawHeartbeat bool
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		typ, _, err := client.readFrameWithDeadline(remaining)
		if err != nil {
			break
		}
		if typ == cstpPktDPDOut || typ == cstpPktKeepalive {
			sawHeartbeat = true
			break
		}
		// Some other frame type arrived; keep waiting.
	}
	if !sawHeartbeat {
		t.Fatalf("expected DPD or keepalive frame within 3s, got none")
	}
}

// TestStage1GracefulShutdownClosesTunnel sets up a full session,
// then cancels the harness's context. Asserts:
//
//   - The client's binary read returns an error (conn closed).
//   - Harness goroutines drain back to baseline.
func TestStage1GracefulShutdownClosesTunnel(t *testing.T) {
	h := newHarness(t)
	clientCert := h.pk.issueClientLeaf(t, canonicalDeviceID)
	client := &fakeClient{addr: h.Address(), tlsConfig: h.pk.clientTLSConfig(clientCert)}
	if err := client.dial(); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.close()

	token, _, _, err := client.initAndAuth("vpn.eracloud.app", "alice", "hunter2")
	if err != nil {
		t.Fatalf("initAndAuth: %v", err)
	}
	if _, err := client.connect("vpn.eracloud.app", token); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Drive the shutdown.
	h.Close()

	// Subsequent client reads must fail. We give it 2s to notice.
	if err := client.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1024)
	_, err = client.conn.Read(buf)
	if err == nil {
		t.Fatalf("expected client read to fail after shutdown")
	}
	// We tolerate any non-nil error: io.EOF, net.ErrClosed, "use of
	// closed network connection", and "connection reset" are all
	// plausible depending on platform + timing.

	// Allow a short settle for stragglers, then check goroutine delta.
	// We don't assert exact == 0 because the runtime can still be
	// reaping a finalizer; we just want no obvious leak (<5 extra).
	settle := time.Now().Add(2 * time.Second)
	for time.Now().Before(settle) {
		if h.goroutineDelta() <= 5 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if delta := h.goroutineDelta(); delta > 5 {
		t.Errorf("goroutine leak after shutdown: delta=%d (current=%d, baseline=%d)",
			delta, runtime.NumGoroutine(), h.goroutineBaseline)
	}
}

// TestStage1CertCNMismatchRejected asserts that a client cert with a
// CN whose deviceID doesn't match the MockVerifier's recorded
// deviceID for the supplied credentials is rejected during phase 2b.
//
// This exercises the certBoundAdapter wiring (cert deviceID vs
// password deviceID mismatch).
func TestStage1CertCNMismatchRejected(t *testing.T) {
	h := newHarness(t)
	// Issue a leaf whose CN encodes a DIFFERENT device id from the
	// one alice's password resolves to.
	otherID := "dev_bbbbbbbbbbbbbbbbbbbbbbbbbb"
	clientCert := h.pk.issueClientLeaf(t, otherID)
	client := &fakeClient{addr: h.Address(), tlsConfig: h.pk.clientTLSConfig(clientCert)}
	if err := client.dial(); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.close()

	token, _, authResp, err := client.initAndAuth("vpn.eracloud.app", "alice", "hunter2")
	if err != nil {
		t.Fatalf("initAndAuth: %v", err)
	}
	if token != "" {
		t.Fatalf("expected empty token on cert/password mismatch, got %q", token)
	}
	if authResp == nil || authResp.StatusCode != 200 {
		t.Fatalf("expected 200 reprompt, got %+v", authResp)
	}
	if !strings.Contains(string(authResp.Body), `type="auth-request"`) {
		t.Fatalf("expected auth-request reprompt, got: %s", authResp.Body)
	}
}
