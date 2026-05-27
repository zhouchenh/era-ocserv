package auth

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"
)

// CertValidator validates an mTLS client certificate against ERA's PKI
// and extracts the device UUID claim from the subject DN.
//
// The validator is safe for concurrent use. It does not retain
// references to TLS state across calls.
type CertValidator struct {
	roots        *x509.CertPool
	subjectField subjectField
	now          func() time.Time
}

// CertValidatorConfig configures a CertValidator. Construct with
// NewCertValidator.
type CertValidatorConfig struct {
	// ClientCAs is the pool of CAs that issue ERA device certs. Required.
	ClientCAs *x509.CertPool

	// SubjectField names which DN field carries the device UUID. The
	// allowed values are "CN" (peer.Subject.CommonName) and "OU"
	// (peer.Subject.OrganizationalUnit[0]). An empty value defaults to
	// "CN". Comparison is case-insensitive.
	SubjectField string

	// Now is injectable for tests; defaults to time.Now. Used both for
	// the explicit not-before / not-after check and for the chain
	// verification's CurrentTime.
	Now func() time.Time
}

type subjectField uint8

const (
	subjectCN subjectField = iota
	subjectOU
)

// NewCertValidator returns a new validator configured against cfg.
// A nil ClientCAs pool is allowed (Validate will fail every cert with
// ErrCertUntrusted); callers normally pass a populated pool.
func NewCertValidator(cfg CertValidatorConfig) *CertValidator {
	field := subjectCN
	switch strings.ToUpper(strings.TrimSpace(cfg.SubjectField)) {
	case "", "CN":
		field = subjectCN
	case "OU":
		field = subjectOU
	default:
		// Unknown values fall back to CN. The validator stays usable;
		// configuration is verified at app startup, not here.
		field = subjectCN
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &CertValidator{
		roots:        cfg.ClientCAs,
		subjectField: field,
		now:          now,
	}
}

// Validate inspects a TLS connection state, re-verifies the peer chain
// against the configured ClientCAs with ExtKeyUsageClientAuth, checks
// the leaf's validity window, and returns the device UUID extracted
// from the configured subject DN field.
//
// Returns ErrNoCert when no peer cert is present, ErrCertExpired when
// the leaf is outside its validity window, ErrCertUntrusted when the
// chain does not verify, and ErrNoDeviceID when the subject DN does
// not contain a value matching ERA's device-id shape.
func (v *CertValidator) Validate(state tls.ConnectionState) (string, error) {
	if len(state.PeerCertificates) == 0 {
		return "", ErrNoCert
	}
	leaf := state.PeerCertificates[0]
	now := v.now()

	// Explicit validity-window check first so an expired cert reports
	// ErrCertExpired rather than ErrCertUntrusted (Verify would lump
	// both into the same x509.CertificateInvalidError).
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return "", ErrCertExpired
	}

	// Build an intermediates pool from the rest of the chain the peer
	// sent; the leaf itself does not go into intermediates.
	var intermediates *x509.CertPool
	if len(state.PeerCertificates) > 1 {
		intermediates = x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return "", ErrCertUntrusted
	}

	deviceID, ok := extractDeviceID(leaf, v.subjectField)
	if !ok {
		return "", ErrNoDeviceID
	}
	return deviceID, nil
}

// extractDeviceID pulls the device UUID candidate from the configured
// DN field and validates it against ERA's idgen shape.
func extractDeviceID(leaf *x509.Certificate, field subjectField) (string, bool) {
	var candidate string
	switch field {
	case subjectOU:
		if ou := leaf.Subject.OrganizationalUnit; len(ou) > 0 {
			candidate = strings.TrimSpace(ou[0])
		}
	default:
		candidate = strings.TrimSpace(leaf.Subject.CommonName)
	}
	if !validDeviceID(candidate) {
		return "", false
	}
	return candidate, true
}
