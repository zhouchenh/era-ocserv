// Package logredact removes bearer-like path segments from values that are
// written to diagnostic logs. It never changes routing or response values.
package logredact

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// GroupURLTokens replaces the token segment after every /drive/access/ in
// path with "[redacted]", preserving the surrounding route (including nested
// group URLs on unrouted input).
func GroupURLTokens(path string) string {
	parts := strings.Split(path, "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "drive" && parts[i+1] == "access" && parts[i+2] != "" {
			parts[i+2] = "[redacted]"
		}
	}
	return strings.Join(parts, "/")
}

// sessionLogDomain domain-separates log fingerprints from every other
// SHA-256 derivation of the same value (notably the DTLS binding token,
// sha256(cookie)[:12]), so a logged fingerprint is never a prefix of it.
const sessionLogDomain = "era-ocserv/session-log/v1\x00"

// Fingerprint returns a short, non-reversible correlation handle for a
// secret-bearing value such as a CSTP session token: the first 8 bytes
// (16 hex chars, matching dtlsuds psk_fp) of
// SHA-256("era-ocserv/session-log/v1\x00" || value). The raw value is never
// returned. An empty value yields "".
func Fingerprint(value string) string {
	if value == "" {
		return ""
	}
	h := sha256.Sum256([]byte(sessionLogDomain + value))
	return hex.EncodeToString(h[:8])
}
