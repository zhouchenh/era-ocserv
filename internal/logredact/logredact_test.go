package logredact

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGroupURLTokens(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/drive/access/synthetic-token", "/drive/access/[redacted]"},
		{"/drive/access/synthetic-token/", "/drive/access/[redacted]/"},
		{"/drive/access/synthetic-token/auth", "/drive/access/[redacted]/auth"},
		{"/drive/access/a/drive/access/b/x", "/drive/access/[redacted]/drive/access/[redacted]/x"},
		{"/drive/access//x", "/drive/access//x"},
		{"/CSCOSSLC/tunnel", "/CSCOSSLC/tunnel"},
		{"/", "/"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := GroupURLTokens(tc.in); got != tc.want {
			t.Errorf("GroupURLTokens(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFingerprint(t *testing.T) {
	const secret = "synthetic-session-token-0123456789abcdef"
	fp := Fingerprint(secret)
	if len(fp) != 16 {
		t.Fatalf("Fingerprint length = %d (%q), want 16 hex chars", len(fp), fp)
	}
	if strings.Contains(secret, fp) || strings.Contains(fp, secret) {
		t.Fatalf("Fingerprint %q overlaps the raw value", fp)
	}
	if again := Fingerprint(secret); again != fp {
		t.Fatalf("Fingerprint not stable: %q then %q", fp, again)
	}
	if other := Fingerprint(secret + "x"); other == fp {
		t.Fatalf("distinct values share fingerprint %q", fp)
	}
	// Domain separation: not a prefix of the undomained sha256(value), which
	// is what the DTLS binding token sha256(cookie)[:12] starts with.
	plain := sha256.Sum256([]byte(secret))
	if strings.HasPrefix(hex.EncodeToString(plain[:]), fp) || strings.HasPrefix(fp, hex.EncodeToString(plain[:4])) {
		t.Fatalf("Fingerprint %q shares a prefix with plain sha256(value)", fp)
	}
	// KAT: sha256("era-ocserv/session-log/v1\x00abc")[:8].
	if got := Fingerprint("abc"); got != "99270592ffdcf8fa" {
		t.Fatalf("Fingerprint(abc) = %q, want 99270592ffdcf8fa", got)
	}
	if got := Fingerprint(""); got != "" {
		t.Fatalf("Fingerprint(\"\") = %q, want empty", got)
	}
}
