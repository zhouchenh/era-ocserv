// Package dtlsuds implements the era-ocserv side of the AnyConnect-DTLS
// SOCK_DGRAM UDS handoff (Wave IV stream O-S of the ADR-F7 Stage 2-7 plan).
//
// In the Shape A architecture (ADR-F7), era-facade owns DTLS termination at
// the apex `eracloud.app:443/udp`. Once a DTLS record is decrypted, the
// facade hands the inner plaintext L3 packet to era-ocserv over the UDS
// socket `/var/run/era-facade/handoffs/anyconnect-dtls.sock` (spec §2.1, §7
// of `era-facade/docs/architecture/uds-handoff-protocol.md`).
//
// The handoff wire shape is the SOCK_DGRAM framing of §5.1 + §5.4: a fixed
// 6-byte header (v + fl + tlvlen + pldlen), then a TLV block whose leading
// bytes form a PROXY-v2 inner envelope (carrying the real source / facade-
// destination 4-tuple) followed by ERA TLVs, then the decrypted L3 packet
// as the payload.
//
// What this package does:
//
//   - Binds the UDS DGRAM socket and receives datagrams via the shared
//     `udshandoff.DatagramListener` framework.
//   - Maintains a per-DTLS-session table keyed by the source 4-tuple (spec
//     §5.3: DTLS 1.2 has no Connection ID).
//   - On the FIRST datagram per 4-tuple, parses + caches `ERA_TLV_DTLS_PSK`
//     (32 B) and resolves the device → inner /128 → identity. On follow-up
//     datagrams the PSK TLV MAY be omitted (spec §5.3 + §7 table note).
//     era-facade owns the DTLS handshake and PSK derivation; era-ocserv
//     trusts the cached PSK only as an audit fingerprint — it is NOT used
//     to re-derive keys here.
//   - Plumbs the post-DTLS L3 plaintext payload to the era-ocserv TUN
//     bridge so packets arrive on the same multi-queue tun device that
//     handles the CSTP transport.
//   - Idle-evicts sessions after 300 s of inactivity (spec §5.3).
//   - For the reply path, accepts an L3 packet from the bridge, wraps it
//     in the §5.1 datagram framing with `fl` bit-0 set to backend→facade,
//     and writes it back to the same UDS peer.
//
// What this package does NOT do:
//
//   - DTLS handshake or record-layer crypto — era-facade owns both.
//   - PSK derivation — era-facade derives it during CSTP auth and binds
//     to the source IP; we receive it on first datagram and cache by
//     4-tuple per spec §5.3.
//   - CSTP control protocol — that is internal/cstp, the Wave II stream
//     O-I work. DTLS and CSTP share a /128 (the device's inner IPv6) but
//     are distinct transports; this package only handles DTLS.
//
// The session table is keyed on the inner 4-tuple announced in the
// PROXY-v2 inner envelope (spec §5.3), NOT on the UDS-peer address. The
// UDS peer address is the facade's transient sender address (constant
// in practice but the spec treats it as opaque).
package dtlsuds
