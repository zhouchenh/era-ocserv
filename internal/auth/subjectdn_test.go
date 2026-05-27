package auth

import (
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
)

// validDevID is a fixed ERA-shaped device id used across cases.
const validDevID = "dev_abcdefghijklmnopqrstuvwxyz"

// TestDeviceIDFromSubjectDN_HappyPath covers the canonical DN shape Go's
// crypto/x509 emits for a cert whose Subject.CommonName is an idgen
// device id.
func TestDeviceIDFromSubjectDN_HappyPath(t *testing.T) {
	cases := []struct {
		name string
		dn   string
	}{
		{"plain CN", "CN=" + validDevID},
		{"CN + O", "CN=" + validDevID + ",O=ERA Cloud"},
		{"O + CN", "O=ERA Cloud,CN=" + validDevID},
		{"CN + OU + O", "CN=" + validDevID + ",OU=devices,O=ERA Cloud"},
		{"lowercase attr", "cn=" + validDevID + ",o=era"},
		{"whitespace after comma", "O=ERA Cloud, CN=" + validDevID},
		{"mixed-case attr", "Cn=" + validDevID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeviceIDFromSubjectDN(tc.dn)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != validDevID {
				t.Errorf("got %q, want %q", got, validDevID)
			}
		})
	}
}

// TestDeviceIDFromSubjectDN_PKIXRoundtrip verifies that the DN strings
// crypto/x509 actually produces from pkix.Name.String() parse back to
// the same CN. The DN format era-facade emits via
// peer.Subject.String() must be readable by this package.
func TestDeviceIDFromSubjectDN_PKIXRoundtrip(t *testing.T) {
	names := []pkix.Name{
		{CommonName: validDevID},
		{CommonName: validDevID, Organization: []string{"ERA Cloud"}},
		{CommonName: validDevID, Organization: []string{"ERA Cloud, Inc."}}, // comma in O forces escape
		{CommonName: validDevID, OrganizationalUnit: []string{"devices"}, Organization: []string{"ERA"}},
	}
	for _, n := range names {
		dn := n.String()
		got, err := DeviceIDFromSubjectDN(dn)
		if err != nil {
			t.Errorf("dn=%q: err=%v", dn, err)
			continue
		}
		if got != validDevID {
			t.Errorf("dn=%q: got %q, want %q", dn, got, validDevID)
		}
	}
}

// TestDeviceIDFromSubjectDN_EscapedCN covers the RFC 4514 escape syntax
// the facade is required to emit: backslash-prefix for `,+\"<>;#=`, hex
// pairs for arbitrary bytes, leading/trailing space escape.
func TestDeviceIDFromSubjectDN_EscapedCN(t *testing.T) {
	// CN values containing RFC 4514 specials cannot be a valid device
	// id (the device-id alphabet is a-z2-7), so we verify the unescape
	// pipeline on a non-device-id value via the lower-level helper and
	// confirm a properly-shaped CN still works when neighbour RDNs use
	// escapes.
	cases := []struct {
		name string
		dn   string
	}{
		{"escaped comma in O", `O=ERA\, Cloud,CN=` + validDevID},
		{"escaped equals in OU", `OU=key\=value,CN=` + validDevID},
		{"hex-escaped char in O", `O=ERA\20Cloud,CN=` + validDevID}, // 0x20 = space
		{"multi-AVA RDN", `CN=` + validDevID + `+UID=foo`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeviceIDFromSubjectDN(tc.dn)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != validDevID {
				t.Errorf("got %q, want %q", got, validDevID)
			}
		})
	}
}

func TestDeviceIDFromSubjectDN_Rejections(t *testing.T) {
	cases := []struct {
		name string
		dn   string
		want error
	}{
		{"empty", "", ErrNoDeviceID},
		{"no CN", "O=ERA Cloud", ErrNoDeviceID},
		{"empty CN", "CN=,O=ERA", ErrNoDeviceID},
		{"non-device-id CN", "CN=bogus", ErrNoDeviceID},
		// Note: a single space after `=` (CN= dev_...) is trimmed by
		// pkix.Name.String() convention, so it round-trips fine. The
		// way to actually inject a leading space is `\ ` (escaped).
		{"escaped-leading-space breaks shape", `CN=\ ` + validDevID, ErrNoDeviceID},
		{"trailing backslash", `CN=\`, ErrInvalidSubjectDN},
		{"bad single escape", `CN=foo\Z`, ErrInvalidSubjectDN},
		{"bad hex escape (short)", `CN=foo\2`, ErrInvalidSubjectDN},
		{"bad hex escape (non-hex)", `CN=foo\2Z`, ErrInvalidSubjectDN},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DeviceIDFromSubjectDN(tc.dn)
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestExtractCN_UnknownAttributesIgnored covers DNs whose first RDN is
// some attribute we don't care about — we must skip past it to find CN.
func TestExtractCN_UnknownAttributesIgnored(t *testing.T) {
	dn := "1.2.3.4=opaque,OID.2.5.4.7=hk,CN=" + validDevID
	got, err := DeviceIDFromSubjectDN(dn)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != validDevID {
		t.Errorf("got %q, want %q", got, validDevID)
	}
}

// TestExtractCN_FirstWins documents the behaviour for a (pathological)
// DN with two CN= components: the first encountered wins. This matches
// pkix.Name.String() which emits CN at most once but the facade is the
// trust anchor — defence-in-depth is documented, not enforced.
func TestExtractCN_FirstWins(t *testing.T) {
	dn := "CN=" + validDevID + ",CN=dev_other000000000000000000"
	got, err := DeviceIDFromSubjectDN(dn)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != validDevID {
		t.Errorf("got %q, want %q", got, validDevID)
	}
}

// TestUnescapeRFC4514 directly exercises the unescape routine on the
// strings pkix.Name marshal would emit.
func TestUnescapeRFC4514(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`abc`, `abc`},
		{`a\,b`, `a,b`},
		{`a\\b`, `a\b`},
		{`a\20b`, "a b"},
		{`leading\ space`, "leading space"},
		{`\#hash`, "#hash"},
		{`\=eq`, "=eq"},
	}
	for _, tc := range cases {
		got, ok := unescapeRFC4514(tc.in)
		if !ok {
			t.Errorf("in=%q: ok=false", tc.in)
			continue
		}
		if got != tc.want {
			t.Errorf("in=%q: got %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnescapeRFC4514_Rejections(t *testing.T) {
	cases := []string{
		`a\`,    // trailing lone backslash
		`a\Z`,   // unknown single escape
		`a\2`,   // half hex pair
		`a\2Z`,  // bad hex pair
		`a\X4F`, // bad hex pair (first nibble)
	}
	for _, in := range cases {
		if _, ok := unescapeRFC4514(in); ok {
			t.Errorf("in=%q: ok=true, want false", in)
		}
	}
}

func TestExtractCN_LongDN(t *testing.T) {
	// Pathological worst case: a DN whose escape pattern stresses the
	// unescape loop. Make sure it doesn't degrade catastrophically.
	parts := []string{"CN=" + validDevID}
	for i := 0; i < 8; i++ {
		parts = append(parts, `OU=field\,with\,commas\20and\20spaces`)
	}
	dn := strings.Join(parts, ",")
	got, err := DeviceIDFromSubjectDN(dn)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != validDevID {
		t.Errorf("got %q want %q", got, validDevID)
	}
}
