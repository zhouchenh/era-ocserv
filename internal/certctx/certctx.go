// Package certctx carries the per-request facade-validated device id
// across the CSTP handler chain. It exists so both the legacy loopback
// TCP+TLS path (which extracts the device id from
// `r.TLS.PeerCertificates`) and the UDS plaintext path (which extracts
// it from `ERA_TLV_MTLS_SUBJECT_DN`) can hand the result to
// `certBoundVerifier` in cmd/era-ocserv via a single shared context
// key.
//
// The legacy and UDS modes differ in HOW they obtain the device id from
// the client cert; they agree on WHAT the cross-check downstream does
// with it (compare against the password-verify response). This package
// is the thin glue between the two.
package certctx

import "context"

// contextKey is the unexported key type that gates access to the
// device id stored on a request context. External callers can only
// read/write via the WithDeviceID / FromContext helpers below.
type contextKey int

const (
	deviceIDKey contextKey = iota
)

// WithDeviceID returns a context that carries deviceID. Pass it to
// http.Request.WithContext or inject via http.Server.ConnContext.
//
// A zero deviceID is allowed (the downstream cross-check will then
// reject the flow): callers do not need to pre-validate the value.
func WithDeviceID(ctx context.Context, deviceID string) context.Context {
	return context.WithValue(ctx, deviceIDKey, deviceID)
}

// FromContext returns the device id stored on ctx and ok=true; or "",
// false when no device id has been recorded. The downstream
// password-verify cross-check uses this to assert that the cert-side
// and password-side device IDs agree.
func FromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(deviceIDKey).(string)
	return v, ok && v != ""
}
