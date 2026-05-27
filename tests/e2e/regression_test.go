package e2e_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/iam"
)

// TestStage1Phase3CertReBindRejectsMismatch covers P0 #1 from the
// wave-1 review (docs/review/wave-1-stage-1.md): the phase-3 CONNECT
// handler must re-extract the device id from the inbound mTLS cert
// and reject the CONNECT (401) when it does not match the deviceID
// captured at phase-2 promote time. Without this re-bind, a leaked
// session token plus any validly-signed ERA device cert could take
// over another device's /128 (spec §1.8, ADR 0057 §4).
//
// Setup: drive the full phase 2 flow on conn-A with cert-A and obtain
// a session token. Open conn-B with cert-B (signed by the same client
// CA, valid by every other measure, but a DIFFERENT deviceID). On
// conn-B, present the conn-A session token at CONNECT. The server
// must respond 401 and close.
func TestStage1Phase3CertReBindRejectsMismatch(t *testing.T) {
	h := newHarness(t)

	// We need cert-B's deviceID to also be plausibly known to the
	// system (so the only thing failing is the CONNECT rebind, not
	// some unrelated downstream check). Seed it; we never actually
	// drive phase 2 as bob.
	otherID := "dev_bbbbbbbbbbbbbbbbbbbbbbbbbb"
	h.verifier.Set("bob", "swordfish", otherID)
	h.resolver.Set(otherID, iam.Identity{
		IPv6: netip.MustParsePrefix("2001:470:f9d1:9001:2b::ff/128"),
		MTU:  1500,
	})

	certA := h.pk.issueClientLeaf(t, canonicalDeviceID)
	certB := h.pk.issueClientLeaf(t, otherID)

	// --- conn-A: drive phase 2, harvest session token ---------------
	clientA := &fakeClient{addr: h.Address(), tlsConfig: h.pk.clientTLSConfig(certA)}
	if err := clientA.dial(); err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer clientA.close()

	token, _, _, err := clientA.initAndAuth("vpn.eracloud.app", "alice", "hunter2")
	if err != nil {
		t.Fatalf("initAndAuth A: %v", err)
	}
	if token == "" {
		t.Fatalf("empty session token on conn-A")
	}

	// --- conn-B: replay token with a different cert -----------------
	clientB := &fakeClient{addr: h.Address(), tlsConfig: h.pk.clientTLSConfig(certB)}
	if err := clientB.dial(); err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer clientB.close()

	if _, err := clientB.connect("vpn.eracloud.app", token); err == nil {
		t.Fatalf("CONNECT with mismatched cert succeeded; expected 401")
	} else if !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401, got: %v", err)
	}

	// --- defense in depth: the session is now consumed -------------
	// A second attempt with the original cert must also fail (the
	// server drops the token on rebind failure to collapse the attack
	// window to a single CONNECT).
	clientA2 := &fakeClient{addr: h.Address(), tlsConfig: h.pk.clientTLSConfig(certA)}
	if err := clientA2.dial(); err != nil {
		t.Fatalf("dial A2: %v", err)
	}
	defer clientA2.close()
	if _, err := clientA2.connect("vpn.eracloud.app", token); err == nil {
		t.Fatalf("token was reused after rebind failure; expected 401")
	}
}

// TestStage1InnerSourceSpoofDropped covers P0 #2: when a connected
// client sends an inner IPv6 packet whose src is outside its /128,
// the bridge must drop it before writing to the tun device. Without
// this filter, an authenticated client can source-spoof any inner
// address — escaping the per-device identity model (ADR 0035/0036 →
// 0057 §5) and trivially spoofing other devices' /128s.
//
// We send one spoofed packet followed by one legitimate packet on the
// same tunnel and observe the tun queue: only the legit one must
// arrive. The "send two packets, observe order" pattern catches the
// case where spoof-checking happens but only by chance (e.g. the tun
// is closed mid-test); the legit packet flowing confirms the bridge
// is otherwise healthy.
func TestStage1InnerSourceSpoofDropped(t *testing.T) {
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

	q := h.tun.QueuesTyped()[0]

	clientAssigned := netip.MustParseAddr("2001:470:f9d1:9001:2a::ff")
	spoofedSrc := netip.MustParseAddr("2001:470:f9d1:9001:dead:beef::1") // somebody else's /128
	upstream := netip.MustParseAddr("2606:4700:4700::1111")
	spoofed := makeIPv6Packet(spoofedSrc, upstream, []byte("spoofed-payload"))
	if err := client.writeFrame(cstpPktData, spoofed); err != nil {
		t.Fatalf("client writeFrame spoofed: %v", err)
	}
	legit := makeIPv6Packet(clientAssigned, upstream, []byte("legit-payload"))
	if err := client.writeFrame(cstpPktData, legit); err != nil {
		t.Fatalf("client writeFrame legit: %v", err)
	}

	select {
	case got := <-q.out:
		// Whatever we got first MUST be the legit packet. If we ever
		// see the spoofed one, the bridge let it through.
		if eqBytes(got, spoofed) {
			t.Fatalf("bridge forwarded spoofed packet to tun (src=%s, client=%s)",
				spoofedSrc, clientAssigned)
		}
		if !eqBytes(got, legit) {
			t.Fatalf("tun received unknown payload (len=%d), expected legit packet", len(got))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for legit packet to be forwarded (anti-spoof may have dropped it too)")
	}

	// Drain a short window to confirm the spoofed packet never
	// arrives out of order.
	select {
	case got := <-q.out:
		if eqBytes(got, spoofed) {
			t.Fatalf("bridge forwarded spoofed packet (delayed)")
		}
	case <-time.After(200 * time.Millisecond):
		// Nothing else arrived — expected.
	}
}

// TestStage1DTLSAdvertisedWhenEnabled covers P1 #1 + P1 #5: when
// Config.DTLSAdvertise is true AND the client offered the locked
// AES128-GCM-SHA256 cipher, the gateway emits X-DTLS-* headers with
// the locked cipher echoed back. The reverse cases (gate disabled,
// or client offered a different cipher) are covered by
// TestStage1DTLSOmittedWhenGateDisabled and
// TestStage1DTLSOmittedWhenClientOffersUnsupportedCipher below.
func TestStage1DTLSAdvertisedWhenEnabled(t *testing.T) {
	h := newHarness(t, withDTLSAdvertise())
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
	hdr, err := client.connect("vpn.eracloud.app", token)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got := hdr.Get("X-DTLS-Master-Secret"); got == "" {
		t.Errorf("X-DTLS-Master-Secret missing when DTLSAdvertise=true")
	}
	if got := hdr.Get("X-DTLS-CipherSuite"); got != "AES128-GCM-SHA256" {
		t.Errorf("X-DTLS-CipherSuite = %q, want AES128-GCM-SHA256", got)
	}
}

// TestStage1DTLSOmittedWhenClientOffersUnsupportedCipher covers
// P1 #5: if the client's X-DTLS-CipherSuite list does not contain
// AES128-GCM-SHA256 (the cipher ADR 0057 §6 locks the DTLS profile
// to), the server must omit the X-DTLS-* header set entirely, even
// when DTLSAdvertise is on.
func TestStage1DTLSOmittedWhenClientOffersUnsupportedCipher(t *testing.T) {
	h := newHarness(t, withDTLSAdvertise())
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
	hdr, err := client.connectWithCipher("vpn.eracloud.app", token, "AES256-GCM-SHA384")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got := hdr.Get("X-DTLS-Master-Secret"); got != "" {
		t.Errorf("X-DTLS-Master-Secret should be omitted (client offered unsupported cipher), got %q", got)
	}
	if got := hdr.Get("X-DTLS-CipherSuite"); got != "" {
		t.Errorf("X-DTLS-CipherSuite should be omitted, got %q", got)
	}
}

// eqBytes is a tiny equality helper that avoids importing bytes for
// one call.
func eqBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
