// Package auth implements the two-factor authentication surface used by
// era-ocserv: validating an mTLS client certificate against ERA's PKI and
// verifying the AnyConnect password-form challenge against era-portal.
//
// Both factors are owned here. The CSTP layer (internal/cstp) calls into
// this package to verify credentials; TLS setup itself (configuring
// ClientCAs and tls.RequestClientCert) happens in main wiring. Mapping a
// device UUID to its assigned /128 is internal/iam's responsibility.
//
// Surface:
//
//   - CertValidator: validate a *tls.ConnectionState and extract a device
//     UUID from the subject DN.
//   - PasswordVerifier: interface, implemented by HTTPVerifier (calls
//     era-portal) and MockVerifier (tests).
//
// Behavior contract:
//
//   - Cert chain validation is re-run against an explicit ClientCAs pool
//     and ExtKeyUsageClientAuth; we do not trust crypto/tls's own
//     verification result.
//   - Device UUIDs must look like dev_<26 lowercase base32 chars> per
//     ERA's idgen scheme. Malformed UUIDs fail with ErrNoDeviceID.
//   - HTTPVerifier maps HTTP statuses to error sentinels: 401 ->
//     ErrBadCredentials, 423 -> ErrAccountLocked, 5xx -> ErrUpstream.
//
// The package is pure Go and has no platform-specific code.
package auth
