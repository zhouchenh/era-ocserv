// Package udsserve bridges the UDS+PROXY-v2+TLV handoff framework
// (internal/udshandoff) to the era-ocserv CSTP HTTP gateway
// (internal/cstp).
//
// ADR-F7 Stage 2 (Wave II stream O-I) moves the AnyConnect CSTP gateway
// from terminating its own TLS on `127.0.0.1:8444` to consuming UDS
// plaintext on `/var/run/era-facade/handoffs/anyconnect-cstp.sock`. The
// facade keeps doing TLS+mTLS termination upstream and surfaces the
// already-validated client-cert Subject DN through
// `ERA_TLV_MTLS_SUBJECT_DN` (0xED) per the Stage 1 handoff spec §7. This
// package is the glue: it accepts UDS streams, extracts the per-handoff
// metadata, and serves the existing CSTP HTTP handler over each
// plaintext stream.
//
// Wire shape on the UDS hop is the AnyConnect-CSTP row of
// `era-facade/docs/architecture/uds-handoff-protocol.md` §7:
//
//   - Mandatory TLVs: TOKEN, DEVICE_ID, USER_ID, SOURCE_HINT_V6,
//     MTLS_SUBJECT_DN, SPEC_VERSION, TRACE_ID.
//   - Optional TLVs: ORIG_SNI, ALPN_DETAIL.
//   - Forbidden TLVs: anything else.
//
// The framework validates the matrix; this package is invoked only on
// already-validated handoffs.
package udsserve
