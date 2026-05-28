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
	body, err := buildAuthRequest("OPAQUE-ID-XYZ", "Sign in to ERA")
	if err != nil {
		t.Fatalf("buildAuthRequest: %v", err)
	}
	s := string(body)
	if !strings.HasPrefix(s, "<?xml ") {
		t.Fatalf("expected xml header, got: %q", s[:20])
	}
	if !strings.Contains(s, `type="auth-request"`) {
		t.Fatalf("missing type=auth-request: %s", s)
	}
	if !strings.Contains(s, "OPAQUE-ID-XYZ") {
		t.Fatalf("missing opaque id: %s", s)
	}
	if !strings.Contains(s, `name="username"`) || !strings.Contains(s, `name="password"`) {
		t.Fatalf("missing form inputs: %s", s)
	}
}

func TestBuildAuthCompleteRoundTrip(t *testing.T) {
	body, err := buildAuthComplete("session-token-blob", "OPAQUE-ID-XYZ", "")
	if err != nil {
		t.Fatalf("buildAuthComplete: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, `type="complete"`) {
		t.Fatalf("missing type=complete: %s", s)
	}
	if !strings.Contains(s, "<session-token>session-token-blob</session-token>") {
		t.Fatalf("missing session token: %s", s)
	}
	if !strings.Contains(s, "<title>SSL VPN Service</title>") {
		t.Fatalf("missing success title: %s", s)
	}
}

func TestBuildAuthErrorIncludesPromptAndForm(t *testing.T) {
	body, err := buildAuthError("X", "Sign-in failed.")
	if err != nil {
		t.Fatalf("buildAuthError: %v", err)
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
	body, err := buildAuthRequest("OPAQUE-1", "Sign in")
	if err != nil {
		t.Fatalf("buildAuthRequest: %v", err)
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
