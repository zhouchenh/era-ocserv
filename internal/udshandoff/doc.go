// Package udshandoff implements the backend reader side of the
// facade↔backend UDS+PROXY-v2+TLV handoff protocol.
//
// This is a copy of `era-proxy/internal/udshandoff` (Wave I, stream P-X).
// We carry it in-tree as `internal/udshandoff` for minimum-friction Wave II
// integration (era-ocserv stream O-I). Stage 7 may consolidate into a
// shared module `github.com/zhouchenh/era-shared/udshandoff` once a second
// backend has shipped a production cutover; until then, drift between the
// two copies is small and tracked by code-review.
//
// The wire spec is `era-facade/docs/architecture/uds-handoff-protocol.md`
// (Stage 1, ADR-F7). This package consumes:
//
//   - SOCK_STREAM UDS sockets where each connection carries a PROXY-v2
//     header (with ERA TLVs) followed by the plaintext payload stream. (§3 of
//     the spec.)
//   - SOCK_DGRAM UDS sockets where each datagram carries a fixed 6-byte
//     header + TLV block (PROXY-v2 inner + ERA TLVs) + payload. (§5.)
//
// What this package gives consumers (per-protocol inbounds, wired up in
// Wave II):
//
//   - StreamListener — accept loop that reads + validates the PROXY-v2 + TLV
//     prefix, hands a *AcceptedStream off to a per-flow handler.
//   - DatagramListener — receive loop that parses + validates each SOCK_DGRAM
//     frame and hands a *AcceptedDatagram off to a per-packet handler.
//   - ProtocolMatrix — the §7 per-protocol mandatory/optional/forbidden TLV
//     matrix, encoded as code so a backend can validate it owns the right
//     pieces of data BEFORE doing any application-layer work.
//   - Counters — the metrics names the spec mandates in §8 (and §2.5):
//     uds_incomplete_header_total, uds_proxy_v2_invalid_signature_total,
//     uds_handoff_unknown_era_tlv_total{type,protocol}, plus per-protocol
//     handoff counters.
//   - LogFields — the structured-log payload spec §8.3 requires on every
//     lifecycle event.
//
// This package is the FRAMEWORK. Wiring it into a specific inbound (anytls,
// vless-ws, …) is the Wave II per-protocol stream's job. The framework's
// per-protocol shape is intentionally minimal: a ProtocolName, a Spec
// instance from the matrix, and a Handler that gets called with an Accepted*
// after the framework has done all PROXY-v2 + TLV work. The handler then
// does whatever the inbound does (e.g. for anytls: speak AnyTLS framing over
// the conn).
package udshandoff
