// PROXY protocol v2 TLV parsing (the type-length-value section that follows
// the address block inside the header's length-counted region).
//
// The TLV registry — both the standard PROXY-v2 codes (0x01 PP2_TYPE_ALPN,
// 0x02 PP2_TYPE_AUTHORITY, 0x20 PP2_TYPE_SSL with its nested subtypes) and the
// ERA-custom range (0xE0-0xEF) — lives in this file. The wire format and
// validation rules implemented here are normative per
// `era-facade/docs/architecture/uds-handoff-protocol.md` §3.2 + §4.
//
// This is the READER side: it parses TLVs the facade emitted; it does NOT
// write them (the writer lives in era-facade, stream F-W). The reader is
// strict on validation — the facade is the trust anchor (§9.1 of the spec) so
// any TLV that fails validation indicates either a misconfigured facade or a
// corrupted stream, both of which the backend MUST reject by closing the UDS
// connection (§8.1).

package proxyproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

// TLVType is the 1-byte PROXY-v2 TLV type tag. Constants below cover both the
// standard PROXY-v2 codes used by ERA Cloud and the entire ERA-custom range.
type TLVType byte

// Standard PROXY-v2 TLV type codes (re-used by ERA — see spec §4.1).
const (
	// PP2TypeALPN is the negotiated outer ALPN string (e.g. "h2", "h3").
	PP2TypeALPN TLVType = 0x01
	// PP2TypeAuthority is the SNI / :authority string.
	PP2TypeAuthority TLVType = 0x02
	// PP2TypeSSL carries the standard PROXY-v2 SSL information (nested
	// subtypes 0x21-0x25). Stage 1 era-proxy treats the whole TLV's value as
	// opaque bytes; the optional sub-TLV decode is implemented in DecodeSSL.
	PP2TypeSSL TLVType = 0x20
	// PP2SubtypeSSLVersion / PP2SubtypeSSLCN / PP2SubtypeSSLCipher /
	// PP2SubtypeSSLSigAlg / PP2SubtypeSSLKeyAlg are the nested codes inside a
	// PP2TypeSSL TLV value (see HAProxy PROXY-v2 spec).
	PP2SubtypeSSLVersion TLVType = 0x21
	PP2SubtypeSSLCN      TLVType = 0x22
	PP2SubtypeSSLCipher  TLVType = 0x23
	PP2SubtypeSSLSigAlg  TLVType = 0x24
	PP2SubtypeSSLKeyAlg  TLVType = 0x25
)

// ERA custom TLV type codes (spec §4.2). 0xE0 is the pre-existing route-tag
// from ADR-F3; ERA Stage 1 TLVs occupy 0xE1-0xEF inclusive.
const (
	// EraTLVRouteTag is the pre-existing facade route-tag (ADR-F3).
	EraTLVRouteTag TLVType = 0xE0
	// EraTLVOrigSNI is the original SNI from the client ClientHello, lowercase
	// ASCII or IDN A-label.
	EraTLVOrigSNI TLVType = 0xE1
	// EraTLVALPNDetail is facade's resolved ALPN intent (e.g. "vless-ws/h2",
	// "h3-29"). Finer-grained than PP2TypeALPN.
	EraTLVALPNDetail TLVType = 0xE2
	// EraTLVToken is the HMAC-derived 96-bit (12 B) path token.
	EraTLVToken TLVType = 0xE3
	// EraTLVDeviceID is the device UUID (RFC 4122 canonical lowercase form,
	// 36 bytes with hyphens).
	EraTLVDeviceID TLVType = 0xE4
	// EraTLVUserID is the ERA Cloud account identifier (1-64 B printable ASCII,
	// no whitespace).
	EraTLVUserID TLVType = 0xE5
	// EraTLVVLESSTarget is the VLESS upstream target in host:port form.
	EraTLVVLESSTarget TLVType = 0xE6
	// EraTLVVLESSUUID is the VLESS user UUID (RFC 4122 canonical form).
	EraTLVVLESSUUID TLVType = 0xE7
	// EraTLVVLESSFlow is the VLESS flow string ("xtls-rprx-vision-seed" or
	// empty for none).
	EraTLVVLESSFlow TLVType = 0xE8
	// EraTLVQUICConnID is the QUIC destination Connection ID (RFC 9000 §17.2,
	// 8-20 bytes).
	EraTLVQUICConnID TLVType = 0xE9
	// EraTLVQUICStreamID is a QUIC varint (1, 2, 4, or 8 bytes encoded).
	EraTLVQUICStreamID TLVType = 0xEA
	// EraTLVDTLSPSK is the 32-byte DTLS pre-shared key.
	EraTLVDTLSPSK TLVType = 0xEB
	// EraTLVSourceHintV6 is the per-device egress source IPv6 in network byte
	// order (16 bytes).
	EraTLVSourceHintV6 TLVType = 0xEC
	// EraTLVMTLSSubjectDN is the client-cert Subject DN (RFC 4514 string).
	EraTLVMTLSSubjectDN TLVType = 0xED
	// EraTLVTraceID is the facade-assigned trace correlation ID (26-char ULID).
	EraTLVTraceID TLVType = 0xEE
	// EraTLVSpecVersion is the 1-byte spec version (Stage 1 = 0x01). MANDATORY
	// on every header.
	EraTLVSpecVersion TLVType = 0xEF
)

// SpecVersionStage1 is the wire-version byte ERA Stage 1 ships with.
const SpecVersionStage1 byte = 0x01

// TLV is one parsed type-length-value record.
type TLV struct {
	Type  TLVType
	Value []byte
}

// IsERACustom reports whether t is in the ERA-custom range 0xE0-0xEF.
func (t TLVType) IsERACustom() bool { return t >= 0xE0 && t <= 0xEF }

// IsStandardPP2 reports whether t is in a standard PROXY-v2 range as
// classified by §4.4: 0x00-0x1F and 0x20-0x7F. (The split is historical; both
// are "standard / known to PROXY-v2 readers" — the spec's unknown-TLV rule
// treats them the same way: skip silently.)
func (t TLVType) IsStandardPP2() bool { return t <= 0x7F }

// IsReserved reports whether t is in a reserved-by-PROXY-v2 range (0x80-0xDF
// or 0xF0-0xFF) where the spec mandates rejection of any unknown TLV.
func (t TLVType) IsReserved() bool {
	switch {
	case t >= 0x80 && t <= 0xDF:
		return true
	case t >= 0xF0:
		return true
	default:
		return false
	}
}

// Errors that DecodeTLVs may return. They are exported so the listener layer
// (which has access to per-flow context for diagnostics) can distinguish
// hard-reject cases (close UDS) from soft cases (skip+log).
var (
	// ErrTLVTruncated indicates a TLV declared a length that runs past the
	// containing block.
	ErrTLVTruncated = errors.New("proxyproto: TLV truncated")
	// ErrTLVDuplicate indicates the same type byte appeared twice in one
	// header. Per spec §4.4, this is a hard reject.
	ErrTLVDuplicate = errors.New("proxyproto: duplicate TLV type")
	// ErrTLVReservedRange indicates an unknown TLV in the 0x80-0xDF or
	// 0xF0-0xFF reserved range. Per spec §4.4, this is a hard reject.
	ErrTLVReservedRange = errors.New("proxyproto: unknown TLV in reserved range")
	// ErrTLVTrailingGarbage indicates bytes past the last complete TLV record
	// remain inside the address-block length.
	ErrTLVTrailingGarbage = errors.New("proxyproto: trailing garbage after TLV block")
)

// DecodeTLVs walks a byte slice containing concatenated TLV records (the
// address-block region after the family-specific address fields, OR a
// SOCK_DGRAM TLV block per §5.1). It returns all records in source order, the
// number of bytes consumed, and any structural error.
//
// Structural errors (truncation, duplicate types, reserved-range unknowns,
// trailing garbage) are returned immediately. Per-TLV value validation is the
// caller's responsibility (ValidateTLV). The unknown-but-allowed handling
// (skip-silent for standard PP2, skip-with-log for ERA range) lives one layer
// up in the listener — DecodeTLVs returns everything it parses; the listener
// decides what to do with each.
//
// Duplicate-detection is by type byte: if the same byte appears twice anywhere
// in the block, the function returns ErrTLVDuplicate. The unique-types set
// uses the type byte directly (no value hashing), matching the spec's "each
// TLV type MAY appear at most once" rule (§3.2).
func DecodeTLVs(block []byte) ([]TLV, int, error) {
	out := make([]TLV, 0, 8)
	seen := make(map[TLVType]struct{}, 8)
	off := 0
	for off < len(block) {
		if len(block)-off < 3 {
			return nil, off, fmt.Errorf("%w: %d bytes left, need >=3 for header", ErrTLVTruncated, len(block)-off)
		}
		t := TLVType(block[off])
		l := int(binary.BigEndian.Uint16(block[off+1 : off+3]))
		if off+3+l > len(block) {
			return nil, off, fmt.Errorf("%w: type=0x%02x declared_len=%d remaining=%d", ErrTLVTruncated, t, l, len(block)-off-3)
		}
		if _, dup := seen[t]; dup {
			return nil, off, fmt.Errorf("%w: type=0x%02x", ErrTLVDuplicate, t)
		}
		seen[t] = struct{}{}
		// Reserved-range unknowns are a hard reject per spec §4.4. We
		// short-circuit here because reserved means "no implementation knows
		// what this TLV is" — we cannot even attempt to validate it.
		if t.IsReserved() {
			return nil, off, fmt.Errorf("%w: type=0x%02x", ErrTLVReservedRange, t)
		}
		val := make([]byte, l)
		copy(val, block[off+3:off+3+l])
		out = append(out, TLV{Type: t, Value: val})
		off += 3 + l
	}
	if off != len(block) {
		// off>len(block) is unreachable (the loop guards it). off<len(block)
		// is unreachable too because the loop only advances and always
		// consumes ≥3 bytes when entering. Defend anyway with a clean error
		// rather than panic.
		return nil, off, ErrTLVTrailingGarbage
	}
	return out, off, nil
}

// ValidateTLV checks one parsed TLV's value against the per-type rules
// in spec §4.2. It returns nil on success or a descriptive error.
//
// This is value-level validation only (length bounds, UTF-8 well-formedness,
// format constraints like "lowercase IDN A-label"). It is type-agnostic for
// unknown ERA codes (they are not validated here; the listener decides
// skip-with-log per §4.4) and for standard PP2 codes (returned as-is to the
// caller; the caller decides whether to validate against the PROXY-v2 spec —
// Stage 1 only needs the value bytes).
func ValidateTLV(t TLV) error {
	switch t.Type {
	case PP2TypeALPN:
		if len(t.Value) == 0 || len(t.Value) > 255 {
			return fmt.Errorf("PP2TypeALPN: length %d out of bounds 1-255", len(t.Value))
		}
		return nil
	case PP2TypeAuthority:
		if len(t.Value) == 0 || len(t.Value) > 255 {
			return fmt.Errorf("PP2TypeAuthority: length %d out of bounds 1-255", len(t.Value))
		}
		if !utf8.Valid(t.Value) {
			return errors.New("PP2TypeAuthority: invalid UTF-8")
		}
		return nil
	case PP2TypeSSL:
		// Stage 1 treats the whole SSL TLV value as opaque. The nested subtypes
		// (0x21-0x25) are not parsed here; if a backend cares it should use
		// EraTLVMTLSSubjectDN (0xED) instead — the spec calls out the dual
		// surface (§4.1 last paragraph).
		if len(t.Value) < 5 {
			return fmt.Errorf("PP2TypeSSL: value too short (%d)", len(t.Value))
		}
		return nil
	case EraTLVRouteTag:
		if len(t.Value) < 1 || len(t.Value) > 255 {
			return fmt.Errorf("EraTLVRouteTag: length %d out of bounds 1-255", len(t.Value))
		}
		if !utf8.Valid(t.Value) {
			return errors.New("EraTLVRouteTag: invalid UTF-8")
		}
		return nil
	case EraTLVOrigSNI:
		if len(t.Value) < 1 || len(t.Value) > 253 {
			return fmt.Errorf("EraTLVOrigSNI: length %d out of bounds 1-253", len(t.Value))
		}
		if !utf8.Valid(t.Value) {
			return errors.New("EraTLVOrigSNI: invalid UTF-8")
		}
		// Must be lowercase ASCII or IDN A-label. A-labels begin with the
		// ACE prefix "xn--"; we accept any all-lowercase-ASCII string here
		// (DNS labels) and rely on the facade to A-label-encode non-ASCII.
		s := string(t.Value)
		for _, r := range s {
			if r > unicode.MaxASCII {
				return fmt.Errorf("EraTLVOrigSNI: non-ASCII rune %U (facade must A-label-encode)", r)
			}
			if r >= 'A' && r <= 'Z' {
				return errors.New("EraTLVOrigSNI: must be lowercase")
			}
		}
		return nil
	case EraTLVALPNDetail:
		if len(t.Value) < 1 || len(t.Value) > 32 {
			return fmt.Errorf("EraTLVALPNDetail: length %d out of bounds 1-32", len(t.Value))
		}
		if !utf8.Valid(t.Value) {
			return errors.New("EraTLVALPNDetail: invalid UTF-8")
		}
		return nil
	case EraTLVToken:
		if len(t.Value) != 12 {
			return fmt.Errorf("EraTLVToken: length %d != 12", len(t.Value))
		}
		return nil
	case EraTLVDeviceID:
		if !isCanonicalUUID(t.Value) && !isLegacyDeviceID(t.Value) {
			return fmt.Errorf("EraTLVDeviceID: invalid stable device identifier")
		}
		return nil
	case EraTLVVLESSUUID:
		// 36 bytes, canonical RFC 4122 form: lowercase hex with hyphens at
		// positions 8, 13, 18, 23.
		if len(t.Value) != 36 {
			return fmt.Errorf("UUID-TLV(0x%02x): length %d != 36", byte(t.Type), len(t.Value))
		}
		if !isCanonicalUUID(t.Value) {
			return fmt.Errorf("UUID-TLV(0x%02x): not canonical lowercase RFC 4122", byte(t.Type))
		}
		return nil
	case EraTLVUserID:
		if len(t.Value) < 1 || len(t.Value) > 64 {
			return fmt.Errorf("EraTLVUserID: length %d out of bounds 1-64", len(t.Value))
		}
		for _, b := range t.Value {
			if b <= 0x20 || b >= 0x7F {
				return fmt.Errorf("EraTLVUserID: byte 0x%02x not printable ASCII (or is whitespace)", b)
			}
		}
		return nil
	case EraTLVVLESSTarget:
		if len(t.Value) < 3 || len(t.Value) > 260 {
			return fmt.Errorf("EraTLVVLESSTarget: length %d out of bounds 3-260", len(t.Value))
		}
		if !utf8.Valid(t.Value) {
			return errors.New("EraTLVVLESSTarget: invalid UTF-8")
		}
		if err := validateHostPort(string(t.Value)); err != nil {
			return fmt.Errorf("EraTLVVLESSTarget: %w", err)
		}
		return nil
	case EraTLVVLESSFlow:
		if len(t.Value) > 32 {
			return fmt.Errorf("EraTLVVLESSFlow: length %d > 32", len(t.Value))
		}
		if !utf8.Valid(t.Value) {
			return errors.New("EraTLVVLESSFlow: invalid UTF-8")
		}
		// Stage 1: only the empty string or "xtls-rprx-vision-seed" are valid.
		s := string(t.Value)
		switch s {
		case "", "xtls-rprx-vision-seed":
			return nil
		default:
			return fmt.Errorf("EraTLVVLESSFlow: unknown flow %q", s)
		}
	case EraTLVQUICConnID:
		if len(t.Value) < 8 || len(t.Value) > 20 {
			return fmt.Errorf("EraTLVQUICConnID: length %d out of bounds 8-20", len(t.Value))
		}
		return nil
	case EraTLVQUICStreamID:
		// QUIC varint per RFC 9000 §16: 1, 2, 4, or 8 bytes.
		switch len(t.Value) {
		case 1, 2, 4, 8:
			return nil
		default:
			return fmt.Errorf("EraTLVQUICStreamID: length %d not a QUIC varint", len(t.Value))
		}
	case EraTLVDTLSPSK:
		if len(t.Value) != 32 {
			return fmt.Errorf("EraTLVDTLSPSK: length %d != 32", len(t.Value))
		}
		return nil
	case EraTLVSourceHintV6:
		if len(t.Value) != 16 {
			return fmt.Errorf("EraTLVSourceHintV6: length %d != 16", len(t.Value))
		}
		// Must be a 2000::/3 global-unicast or fc00::/7 ULA. Reject
		// linklocal/loopback/multicast/unspecified.
		var arr [16]byte
		copy(arr[:], t.Value)
		ip := netip.AddrFrom16(arr)
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("EraTLVSourceHintV6: %s is loopback/linklocal/multicast/unspecified", ip)
		}
		// 2000::/3 has first byte high-3-bits = 001 (0x20-0x3F). fc00::/7 has
		// first 7 bits = 1111110 (0xFC-0xFD).
		b := t.Value[0]
		if !((b >= 0x20 && b <= 0x3F) || b == 0xFC || b == 0xFD) {
			return fmt.Errorf("EraTLVSourceHintV6: %s is neither 2000::/3 nor fc00::/7", ip)
		}
		return nil
	case EraTLVMTLSSubjectDN:
		if len(t.Value) < 1 || len(t.Value) > 1024 {
			return fmt.Errorf("EraTLVMTLSSubjectDN: length %d out of bounds 1-1024", len(t.Value))
		}
		if !utf8.Valid(t.Value) {
			return errors.New("EraTLVMTLSSubjectDN: invalid UTF-8")
		}
		return nil
	case EraTLVTraceID:
		if len(t.Value) != 26 {
			return fmt.Errorf("EraTLVTraceID: length %d != 26", len(t.Value))
		}
		// Crockford Base32 alphabet for ULID — letters I, L, O, U are
		// excluded. Accept uppercase only.
		for _, b := range t.Value {
			if !isCrockfordBase32(b) {
				return fmt.Errorf("EraTLVTraceID: byte 0x%02x not Crockford base32", b)
			}
		}
		return nil
	case EraTLVSpecVersion:
		if len(t.Value) != 1 {
			return fmt.Errorf("EraTLVSpecVersion: length %d != 1", len(t.Value))
		}
		return nil
	default:
		// Unknown type. Returning nil here means "no value-level rule to
		// apply"; the listener decides skip-silent (standard PP2) vs
		// skip-with-log (ERA range) per spec §4.4.
		return nil
	}
}

// isCanonicalUUID checks that v is the lowercase-hex-with-hyphens UUID
// representation: 8-4-4-4-12 with hyphens at fixed positions.
func isCanonicalUUID(v []byte) bool {
	if len(v) != 36 {
		return false
	}
	for i, b := range v {
		switch i {
		case 8, 13, 18, 23:
			if b != '-' {
				return false
			}
		default:
			if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
				return false
			}
		}
	}
	return true
}

func isLegacyDeviceID(v []byte) bool {
	if len(v) < 5 || len(v) > 64 {
		return false
	}
	if !strings.HasPrefix(string(v), "dev-") && !strings.HasPrefix(string(v), "dev_") {
		return false
	}
	for i := 4; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// validateHostPort accepts "host:port" where host is IPv4, "[IPv6]", or a DNS
// name ≤253 B and port is 1-65535.
func validateHostPort(s string) error {
	// Try parsing as "[ipv6]:port" first; netip.ParseAddrPort handles both
	// IPv4 + bracketed IPv6.
	if _, err := netip.ParseAddrPort(s); err == nil {
		return nil
	}
	// Otherwise must be "dnsname:port".
	idx := strings.LastIndex(s, ":")
	if idx < 1 || idx == len(s)-1 {
		return fmt.Errorf("not host:port: %q", s)
	}
	host, portStr := s[:idx], s[idx+1:]
	if len(host) == 0 || len(host) > 253 {
		return fmt.Errorf("host length %d out of bounds 1-253", len(host))
	}
	// DNS label sanity: not strictly RFC 1035-validated (operator-trust per
	// spec §9.1), just no whitespace / control.
	for _, r := range host {
		if r <= 0x20 || r == 0x7F {
			return fmt.Errorf("host contains control/whitespace at %U", r)
		}
	}
	// Port must be 1-65535 (uint16, nonzero).
	var port int
	for _, b := range portStr {
		if b < '0' || b > '9' {
			return fmt.Errorf("port %q not numeric", portStr)
		}
		port = port*10 + int(b-'0')
		if port > 65535 {
			return fmt.Errorf("port %s > 65535", portStr)
		}
	}
	if port < 1 {
		return fmt.Errorf("port %s < 1", portStr)
	}
	return nil
}

// isCrockfordBase32 reports whether b is one of the 32 characters in the
// Crockford Base32 alphabet used by ULID: 0-9 and A-Z minus I, L, O, U.
func isCrockfordBase32(b byte) bool {
	switch {
	case b >= '0' && b <= '9':
		return true
	case b == 'I' || b == 'L' || b == 'O' || b == 'U':
		return false
	case b >= 'A' && b <= 'Z':
		return true
	default:
		return false
	}
}
