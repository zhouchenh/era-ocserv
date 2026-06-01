package cstp

import (
	"strings"
	"testing"
)

// TestBuildWebVPNC checks that buildWebVPNC produces stock ocserv's minimal
// directive shape and pins the supplied SHA-1 in the sh: field.
func TestBuildWebVPNC(t *testing.T) {
	const certSHA1 = "AABBCCDDEEFF00112233445566778899AABBCCDD"
	got := buildWebVPNC("/", certSHA1)
	want := "bu:/&p:t&iu:1/&sh:" + certSHA1
	if got != want {
		t.Fatalf("buildWebVPNC = %q, want %q", got, want)
	}
	// The fetch fields that stalled the iOS Cisco Secure Client must stay absent.
	if strings.Contains(got, "fu:") || strings.Contains(got, "fh:") || strings.Contains(got, "lu:") {
		t.Fatalf("buildWebVPNC must NOT carry fu:/fh:/lu: (regression): %q", got)
	}
}

// TestServerWebVPNCOverride checks that a non-empty ServerCertSHA1 overrides the
// built-in default pin and that an empty (or whitespace-only) override falls
// back to the serverCertSHA1 constant, so the proven legacy path is unchanged.
func TestServerWebVPNCOverride(t *testing.T) {
	const override = "0123456789ABCDEF0123456789ABCDEF01234567"

	got := NewServer(Config{ServerCertSHA1: override}).webvpnc
	if want := buildWebVPNC("/", override); got != want {
		t.Fatalf("override webvpnc = %q, want %q", got, want)
	}

	wantDefault := buildWebVPNC("/", serverCertSHA1)
	for _, empty := range []string{"", "   "} {
		got := NewServer(Config{ServerCertSHA1: empty}).webvpnc
		if got != wantDefault {
			t.Fatalf("empty override %q: webvpnc = %q, want default %q", empty, got, wantDefault)
		}
	}
}
