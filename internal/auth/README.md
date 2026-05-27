# internal/auth

## Purpose

Implements era-ocserv's two-factor authentication surface: validating an mTLS
client certificate against ERA's PKI and verifying the AnyConnect
password-form challenge against era-portal. Both factors are owned here. The
CSTP layer calls in to verify credentials; TLS setup itself (`ClientCAs`,
`tls.RequestClientCert`) is wired in `cmd/era-ocserv` and is NOT this
package's concern. Mapping the resulting device UUID to its assigned /128
belongs to `internal/iam`.

## Contract

- **`CertValidator`** — validates a `tls.ConnectionState`, re-verifies the
  peer chain against an explicit `ClientCAs` pool with
  `ExtKeyUsageClientAuth`, checks the leaf validity window, and returns the
  device UUID extracted from the configured DN field (`CN` or `OU[0]`).
  Constructed via `NewCertValidator`.
- **`PasswordVerifier`** — interface consumed by `internal/cstp` during
  phase 2b. Two implementations ship here: `HTTPVerifier` (calls
  era-portal's auth-verify endpoint) and `MockVerifier` (in-memory, exported
  for downstream tests).
- **Sentinel errors** — `ErrNoCert`, `ErrCertExpired`, `ErrCertUntrusted`,
  `ErrNoDeviceID`, `ErrBadCredentials`, `ErrAccountLocked`, `ErrUpstream`.
  Wrapped with `%w` when context is added; callers match with `errors.Is`.
- **Device-id shape** — `dev_<26 lowercase base32>` per ERA's idgen scheme.
  Validated centrally by `validDeviceID`; malformed values fail with
  `ErrNoDeviceID` (cert path) or `ErrUpstream` (password path).

## Dependencies

Standard library only: `crypto/tls`, `crypto/x509`, `encoding/json`,
`net/http`, `net/url`, `regexp`, plus the usual `context` / `sync` /
`time` / `io`. No third-party imports.

## Invariants

Callers MUST:

- Re-verify the chain themselves through `CertValidator.Validate` even if
  the TLS server has already accepted the peer. We do not trust
  `crypto/tls`'s own result: the chain is rebuilt against an explicit
  `ClientCAs` pool with `ExtKeyUsageClientAuth` so an inadvertent
  server-auth-only cert cannot impersonate a device.
- Configure `HTTPVerifier` with a non-nil `BaseURL` and non-empty
  `ServiceToken` before the first `Verify`. Missing values surface as
  `ErrUpstream` on the call rather than a panic; this leaves wiring
  validation to the caller.
- Never log a `MockCall`. The captured password is plaintext for test
  convenience; production code MUST NOT use `MockVerifier`.

The HTTP-status map is fixed: `401 -> ErrBadCredentials`,
`423 -> ErrAccountLocked`, `5xx / non-2xx -> ErrUpstream`. era-portal
implementations must conform.

## Threading model

- `CertValidator.Validate`, `HTTPVerifier.Verify`, and `MockVerifier.Verify`
  are safe for concurrent use; no state is mutated on the hot path beyond
  `MockVerifier`'s internal mutex.
- `MockVerifier.Set` / `Reset` / `Calls` are safe to call concurrently with
  `Verify`; the call log is a snapshot under the same lock.

## Testing model

- `cert_test.go` mints a small in-memory PKI (`testpki_test.go`) and drives
  every error path — expired leaf, untrusted root, wrong ExtKeyUsage,
  intermediate chain, missing / malformed device-id, `CN` vs `OU`.
- `verifier_test.go` exercises `HTTPVerifier` against `httptest.Server` to
  cover the status-code map, body-size cap, timeout path, base-path
  preservation, and request-shape stability.
- Downstream packages mock the password factor by injecting
  `MockVerifier` (or its `VerifyFunc` hook for error-path drills); see
  `internal/cstp` tests for the seam.

## Cross-refs

- Protocol doc — [§3 mTLS + auth challenge](../../docs/architecture/era-ocserv-protocol.md#3-authentication)
  (cert shape, password-form XML, ErrAccountLocked semantics).
- ADR 0057 §4 — two-factor decision (mTLS gates the TLS handshake;
  password-form gates the CSTP session).
