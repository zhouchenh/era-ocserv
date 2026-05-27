// Package dtls is the era-ocserv DTLS 1.2 data channel.
//
// It is the Stage-2 module of the era-ocserv data plane: an unmodified
// AnyConnect-compatible client completes the CSTP control handshake
// (TLS on TCP/443) in internal/cstp, receives an X-DTLS-Master-Secret
// (the 32-byte RFC 5705 keying material derived from the outer TLS
// session with label `EXPORTER-openconnect-psk`) plus the matching
// session token in the `webvpn` cookie, and is then expected to bring
// up a parallel DTLS 1.2 PSK-NEGOTIATE channel on UDP. That UDP
// channel becomes the preferred data path for the session; the TLS
// control channel keeps running for DPD/keepalive/disconnect.
//
// This package implements the server side of that UDP channel:
//
//   - A UDP listener bound to the same loopback address as the CSTP
//     server (default 127.0.0.1:8444). era-facade demuxes public
//     UDP/443 by first-byte sniff and forwards 0x16 (DTLS ClientHello)
//     datagrams to this socket.
//
//   - A pion/dtls/v3 server with a narrow profile: DTLS 1.2 only
//     (the only version pion v3 implements as of v3.1.2), PSK-only
//     (the certificate path is disabled by leaving Certificates nil),
//     and a single cipher suite TLS_PSK_WITH_AES_128_GCM_SHA256.
//     This is the policy laid down in ADR 0057 §6 and
//     docs/architecture/era-ocserv-protocol.md §2.
//
//   - A PSK callback that maps the DTLS client's PSK identity (the
//     same string as the CSTP session token) back to the per-session
//     PSK and active *cstp.Tunnel through a SessionRegistry interface
//     supplied at construction time. internal/cstp.*Server satisfies
//     that interface via its LookupSession method.
//
//   - Per-connection hand-off: once the handshake completes, the
//     DTLS conn is attached to the Tunnel through Tunnel.AttachDTLS,
//     so subsequent WritePacket calls go out as 1-byte-typed DTLS
//     datagrams instead of 8-byte CSTP frames. Inbound DTLS data
//     frames are routed back to the same Tunnel via InjectInbound,
//     and inbound DTLS control frames (DPD/keepalive/disconnect) are
//     handled locally per the protocol (echo DPD, count keepalive,
//     tear DTLS down on disconnect).
//
//   - Rekey / size budget: pion v3 does not expose an in-place
//     renegotiation API, and the AnyConnect protocol's
//     `X-DTLS-Rekey-Method: ssl` is implemented by clients as a
//     fresh DTLS handshake on the same UDP socket. We honour the
//     budget by tearing the DTLS conn down at 8 hours OR after
//     8 GiB of data, whichever fires first, and falling back to
//     CSTP-over-TLS until the client opens a new DTLS conn. This is
//     defense-in-depth against future AES-GCM nonce issues; the
//     known CVE-2026-26014 was already fixed upstream in v3.1.1
//     (this package pins v3.1.2).
//
// The Tunnel survives DTLS teardown: a clean close, an idle timeout,
// or a rekey budget hit only calls Tunnel.DetachDTLS, not Tunnel.Close.
// The client may re-establish DTLS on a network change (Wi-Fi ->
// cellular handoff) without the CSTP control channel ever blinking.
package dtls
