package e2e_test

import (
	"net/netip"
	"strings"
	"testing"

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
