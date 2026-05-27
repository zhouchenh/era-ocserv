package auth

import "errors"

// Sentinel errors returned by CertValidator and PasswordVerifier
// implementations. Callers should use errors.Is to match.
var (
	// ErrNoCert indicates the TLS state contains no peer certificate.
	// The client either did not present one or the handshake completed
	// without mTLS.
	ErrNoCert = errors.New("auth: no client certificate presented")

	// ErrCertExpired indicates the leaf certificate's not-before/
	// not-after window does not include Now().
	ErrCertExpired = errors.New("auth: client certificate expired")

	// ErrCertUntrusted indicates the certificate chain did not verify
	// against ClientCAs with ExtKeyUsageClientAuth.
	ErrCertUntrusted = errors.New("auth: client certificate untrusted")

	// ErrNoDeviceID indicates the subject DN did not contain a value
	// matching ERA's device-id shape (dev_<26 base32>).
	ErrNoDeviceID = errors.New("auth: device id not found in subject DN")

	// ErrBadCredentials indicates the upstream verifier rejected the
	// username/password pair (HTTP 401 from era-portal).
	ErrBadCredentials = errors.New("auth: invalid username or password")

	// ErrAccountLocked indicates the upstream verifier reported the
	// account is locked (HTTP 423 from era-portal). Distinct from
	// ErrBadCredentials so callers can show different UI.
	ErrAccountLocked = errors.New("auth: account locked")

	// ErrUpstream indicates the upstream verifier failed in a way that
	// is not the caller's fault: 5xx, network timeout, malformed
	// response, etc.
	ErrUpstream = errors.New("auth: upstream verifier error")
)
