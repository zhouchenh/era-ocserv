package cstp

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseInitEnvelope(t *testing.T) {
	in := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
  <version who="vpn">5.1.10.233</version>
  <device-id device-type="linux-x86_64" unique-id="DEADBEEF">linux-64</device-id>
</config-auth>`)
	pa, err := parseAuthRequest(bytes.NewReader(in))
	if err != nil {
		t.Fatalf("parseAuthRequest init: %v", err)
	}
	if pa.Type != authTypeInit {
		t.Fatalf("Type=%q want %q", pa.Type, authTypeInit)
	}
	if pa.DeviceUUID != "DEADBEEF" {
		t.Fatalf("DeviceUUID=%q want DEADBEEF", pa.DeviceUUID)
	}
}

func TestParseAuthReply(t *testing.T) {
	in := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
  <opaque is-for="sg"><session-id>ABCD1234</session-id></opaque>
  <auth>
    <username>alice</username>
    <password>hunter2</password>
  </auth>
</config-auth>`)
	pa, err := parseAuthRequest(bytes.NewReader(in))
	if err != nil {
		t.Fatalf("parseAuthRequest auth-reply: %v", err)
	}
	if pa.Type != authTypeAuthReply {
		t.Fatalf("Type=%q want %q", pa.Type, authTypeAuthReply)
	}
	if pa.OpaqueID != "ABCD1234" {
		t.Fatalf("OpaqueID=%q want ABCD1234", pa.OpaqueID)
	}
	if pa.Username != "alice" || pa.Password != "hunter2" {
		t.Fatalf("creds wrong: u=%q p=%q", pa.Username, pa.Password)
	}
}

func TestParseRejectsNonRoot(t *testing.T) {
	bad := []byte(`<not-config-auth/>`)
	if _, err := parseAuthRequest(bytes.NewReader(bad)); err == nil {
		t.Fatalf("expected error for non-root xml")
	}
}

func TestBuildAuthRequestRoundTrip(t *testing.T) {
	body, err := buildUsernameRequest("OPAQUE-ID-XYZ", "Please enter your username.")
	if err != nil {
		t.Fatalf("buildUsernameRequest: %v", err)
	}
	s := string(body)
	// Stock ocserv prefixes config-auth with the XML declaration (OC_LOGIN_START
	// / oc_success_msg_head), and iOS Cisco Secure Client connects against it.
	if !strings.HasPrefix(s, "<?xml ") {
		t.Fatalf("expected xml declaration prefix (stock ocserv sends it), got: %q", s[:20])
	}
	if !strings.Contains(s, `type="auth-request"`) {
		t.Fatalf("missing type=auth-request: %s", s)
	}
	if !strings.Contains(s, "OPAQUE-ID-XYZ") {
		t.Fatalf("missing opaque id: %s", s)
	}
	// Step-1 form is username-ONLY (2-step simple path); the password lives in a
	// separate step-2 form. A combined form would trip iOS onto aggregate-auth.
	if !strings.Contains(s, `name="username"`) {
		t.Fatalf("missing username input: %s", s)
	}
	if strings.Contains(s, `name="password"`) {
		t.Fatalf("step-1 form must NOT carry a password input (2-step): %s", s)
	}
	pw, err := buildPasswordRequest("OPAQUE-ID-XYZ", "Please enter your password.")
	if err != nil {
		t.Fatalf("buildPasswordRequest: %v", err)
	}
	if ps := string(pw); !strings.Contains(ps, `name="password"`) || strings.Contains(ps, `name="username"`) {
		t.Fatalf("step-2 form must be password-only: %s", ps)
	}
}

func TestBuildAuthCompleteRoundTrip(t *testing.T) {
	body, err := buildAuthComplete()
	if err != nil {
		t.Fatalf("buildAuthComplete: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, `type="complete"`) {
		t.Fatalf("missing type=complete: %s", s)
	}
	if !strings.Contains(s, `<auth id="success">`) {
		t.Fatalf("missing auth success block: %s", s)
	}
	if !strings.Contains(s, "<title>SSL VPN Service</title>") {
		t.Fatalf("missing success title: %s", s)
	}
	// The complete is the minimal stock-ocserv shape: NO <config> and NO
	// <vpn-profile-manifest>. A side-by-side capture proved stock (with no client
	// profile) sends just version + auth success + title and the iOS Cisco Secure
	// Client connects instantly; advertising a profile manifest instead sent the
	// iOS Network Extension into a pre-tunnel fetch it never completed. The
	// post-auth instruction the client needs is the webvpnc directive cookie (set
	// in handleAuth), not an XML <config>.
	if strings.Contains(s, `<config client=`) || strings.Contains(s, "vpn-profile-manifest") {
		t.Fatalf("complete must NOT carry a <config>/manifest (stock omits it): %s", s)
	}
	// The session credential rides the Set-Cookie: webvpn header, NOT a
	// <session-token> element, and there is no <session-id>/<message>.
	if strings.Contains(s, "session-token") || strings.Contains(s, "<session-id>") {
		t.Fatalf("complete must not carry session-token/session-id elements: %s", s)
	}
}

func TestBuildAuthErrorIncludesPromptAndForm(t *testing.T) {
	// On a verification failure we re-prompt the password step with the error
	// message (the username is already stashed for the 2-step flow).
	body, err := buildPasswordRequest("X", "Sign-in failed.")
	if err != nil {
		t.Fatalf("buildPasswordRequest: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "Sign-in failed.") {
		t.Fatalf("missing error message: %s", s)
	}
	if !strings.Contains(s, `name="password"`) {
		t.Fatalf("missing form input on retry: %s", s)
	}
}

// TestBuildParseRoundTripAuthRequest exercises the wire shape end-to-end:
// the server-side build is parsed back through the client-side decoder.
func TestBuildParseRoundTripAuthRequest(t *testing.T) {
	body, err := buildUsernameRequest("OPAQUE-1", "Please enter your username.")
	if err != nil {
		t.Fatalf("buildUsernameRequest: %v", err)
	}
	pa, err := parseAuthRequest(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("parseAuthRequest after build: %v", err)
	}
	if pa.Type != authTypeAuthRequest {
		t.Fatalf("Type=%q want %q", pa.Type, authTypeAuthRequest)
	}
	if pa.OpaqueID != "OPAQUE-1" {
		t.Fatalf("OpaqueID=%q want OPAQUE-1", pa.OpaqueID)
	}
}
