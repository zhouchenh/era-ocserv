package auth

import (
	"errors"
	"strings"
)

// ErrInvalidSubjectDN indicates the RFC 4514 Subject DN string did not
// parse into recognisable RDN components, or its CN component was empty.
//
// Wave II adds this sentinel for UDS-mode CSTP: the facade hands us the
// already-validated client-cert Subject DN via
// `ERA_TLV_MTLS_SUBJECT_DN` (0xED) and we extract the device UUID from
// the CN field without ever seeing the cert itself.
var ErrInvalidSubjectDN = errors.New("auth: invalid RFC 4514 subject DN")

// DeviceIDFromSubjectDN parses an RFC 4514 Subject DN string and returns
// the device UUID extracted from its CN component. The legacy loopback
// path uses CertValidator + x509.Certificate.Subject.CommonName; the UDS
// path uses this function instead. The two callers agree on shape:
//
//   - the CN value must be a valid ERA device-id (idgen-shaped:
//     "dev_" + 26 base32 chars; see deviceid.go); and
//   - the DN itself must be parseable by the subset of RFC 4514 the
//     facade actually emits (Go's crypto/x509 marshals Subject as RFC
//     4514, comma-separated, with backslash-escaped specials).
//
// The function does NOT validate the chain — that is the facade's job —
// it only extracts and shape-checks the CN.
//
// Returns ErrInvalidSubjectDN when the DN string itself is malformed
// (lone trailing backslash, unknown escape, etc.). Returns ErrNoDeviceID
// when the DN parses but its CN component is missing, empty, or not
// idgen-shaped.
func DeviceIDFromSubjectDN(dn string) (string, error) {
	cn, kind := extractCN(dn)
	switch kind {
	case extractOK:
		// fall through
	case extractMalformed:
		return "", ErrInvalidSubjectDN
	default: // extractMissing
		return "", ErrNoDeviceID
	}
	if !validDeviceID(cn) {
		return "", ErrNoDeviceID
	}
	return cn, nil
}

// extractResult is the three-way outcome of extractCN. The caller maps
// these to the two public sentinels (ErrInvalidSubjectDN vs ErrNoDeviceID).
type extractResult int

const (
	extractMissing   extractResult = iota // DN parsed but no usable CN
	extractMalformed                      // DN itself malformed
	extractOK                             // CN extracted into a string value
)

// extractCN walks an RFC 4514 DN string and returns the value of the
// first CN= component (case-insensitive). It tolerates the subset Go's
// pkix.Name.String() emits: comma-separated, optional whitespace after
// commas, attribute values backslash-escaped for the RFC 4514
// special characters (`,`, `+`, `"`, `\`, `<`, `>`, `;`, leading `#`,
// leading/trailing space). Hex-pair escapes (`\xx`) are decoded as
// literal bytes. Unknown attribute types are skipped.
//
// Result classification:
//   - extractOK + non-empty value — CN found
//   - extractMissing — DN parsed (or was empty) and has no usable CN
//     component (no CN= attribute, or CN= had an empty value)
//   - extractMalformed — DN had a structural error (lone trailing
//     backslash, bad escape) that prevents parsing
func extractCN(dn string) (string, extractResult) {
	if dn == "" {
		return "", extractMissing
	}
	rdns, ok := splitRDNs(dn)
	if !ok {
		return "", extractMalformed
	}
	for _, rdn := range rdns {
		// Multi-AVA RDNs (joined by `+`) are uncommon but legal; the CN
		// can be inside one. Split on unescaped `+` too.
		avas, ok := splitAVAs(rdn)
		if !ok {
			return "", extractMalformed
		}
		for _, ava := range avas {
			eq := strings.IndexByte(ava, '=')
			if eq < 1 {
				continue
			}
			attr := strings.TrimSpace(ava[:eq])
			if !strings.EqualFold(attr, "CN") {
				continue
			}
			val, ok := unescapeRFC4514(strings.TrimSpace(ava[eq+1:]))
			if !ok {
				return "", extractMalformed
			}
			if val == "" {
				return "", extractMissing
			}
			return val, extractOK
		}
	}
	return "", extractMissing
}

// splitRDNs splits a DN string at unescaped commas. RFC 4514 allows
// `,` inside an AVA value only if escaped (`\,` or `\2C`); the splitter
// honours that.
func splitRDNs(dn string) ([]string, bool) {
	return splitUnescaped(dn, ',')
}

// splitAVAs splits an RDN at unescaped `+`. RFC 4514 allows multi-AVA
// RDNs joined by `+`.
func splitAVAs(rdn string) ([]string, bool) {
	return splitUnescaped(rdn, '+')
}

// splitUnescaped walks s and splits on unescaped occurrences of sep.
// A `\` skips the next byte (so `\,` is part of the value). Returns
// ok=false on a trailing lone `\` (malformed).
func splitUnescaped(s string, sep byte) ([]string, bool) {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) {
				return nil, false
			}
			i++ // skip the escaped byte
		case sep:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out, true
}

// unescapeRFC4514 reverses Go's pkix.Name.String() escaping. Per RFC 4514:
//
//   - `\` followed by any of `,`, `+`, `"`, `\`, `<`, `>`, `;`, ` `, `#`,
//     or `=` is a literal of that character.
//   - `\xx` (two hex digits) is the byte with that hex value.
//
// Returns ok=false on malformed escapes.
func unescapeRFC4514(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		// Escape sequence; need at least one more byte.
		if i+1 >= len(s) {
			return "", false
		}
		next := s[i+1]
		if isHexDigit(next) {
			// Hex-pair escape; need two hex digits.
			if i+2 >= len(s) || !isHexDigit(s[i+2]) {
				return "", false
			}
			b.WriteByte(hexPair(next, s[i+2]))
			i += 2
			continue
		}
		// Single-char escape; accept the RFC 4514 specials.
		switch next {
		case ',', '+', '"', '\\', '<', '>', ';', ' ', '#', '=':
			b.WriteByte(next)
			i++
		default:
			return "", false
		}
	}
	return b.String(), true
}

func isHexDigit(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'f':
		return true
	case c >= 'A' && c <= 'F':
		return true
	default:
		return false
	}
}

func hexPair(hi, lo byte) byte { return (hexNibble(hi) << 4) | hexNibble(lo) }

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}
