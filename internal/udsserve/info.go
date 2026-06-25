package udsserve

import (
	"context"
	"net/netip"
)

// HandoffInfo is the per-stream metadata the UDS handoff carries. It is
// extracted from the PROXY-v2 + ERA TLV header by Serve and stored on the
// request context for the downstream HTTP handler to consume.
//
// The fields mirror the AnyConnect-CSTP row of the Stage 1 spec §7 plus
// the universally-mandatory TraceID and SpecVersion.
type HandoffInfo struct {
	// DeviceID is the device UUID extracted from the MTLS Subject DN's CN
	// field (RFC 4514 form). The facade has already validated the
	// client-cert chain; this is the trust-anchor identifier era-ocserv
	// uses for cross-check against the password-verify response.
	DeviceID string

	// SubjectDN is the raw RFC 4514 Subject DN from
	// `ERA_TLV_MTLS_SUBJECT_DN` (0xED). Carried as-is for diagnostics and
	// audit logging.
	SubjectDN string

	// UserID is the ERA Cloud account identifier from
	// `ERA_TLV_USER_ID` (0xE5). For audit logging.
	UserID string

	// Token is the 12-byte HMAC-derived path-access token from
	// `ERA_TLV_TOKEN` (0xE3). Already HMAC-validated by the facade.
	Token []byte

	// SourceHintV6 is the per-device egress source IPv6 from
	// `ERA_TLV_SOURCE_HINT_V6` (0xEC). era-ocserv does not bind egress
	// (the tun device handles egress), but the field is captured so
	// future routing changes can consume it without spec changes.
	SourceHintV6 netip.Addr

	// TraceID is the facade-assigned 26-char ULID from
	// `ERA_TLV_TRACE_ID` (0xEE). Logged on every flow lifecycle event.
	TraceID string

	// OrigSNI is the original SNI from `ERA_TLV_ORIG_SNI` (0xE1) if
	// emitted. Optional per the matrix; empty if absent.
	OrigSNI string

	// ALPNDetail is the resolved ALPN from `ERA_TLV_ALPN_DETAIL` (0xE2)
	// if emitted. Optional.
	ALPNDetail string

	// ClientSrc is the announced original client address from the
	// PROXY-v2 src field. Logged for forensics.
	ClientSrc netip.AddrPort

	// OriginalDst is the announced original public destination at the
	// facade from the PROXY-v2 dst field.
	OriginalDst netip.AddrPort
}

// contextKey is the unexported type for this package's context keys.
type contextKey int

const (
	handoffInfoKey contextKey = iota
)

// contextWithInfo returns a new context carrying info.
func contextWithInfo(ctx context.Context, info *HandoffInfo) context.Context {
	return context.WithValue(ctx, handoffInfoKey, info)
}

// FromContext returns the HandoffInfo a UDS-served HTTP request was
// dispatched with. Returns ok=false on requests that did not come through
// the UDS hop (e.g. legacy loopback TCP+TLS mode).
func FromContext(ctx context.Context) (*HandoffInfo, bool) {
	v, ok := ctx.Value(handoffInfoKey).(*HandoffInfo)
	if !ok || v == nil {
		return nil, false
	}
	return v, true
}
