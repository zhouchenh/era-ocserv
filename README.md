# era-ocserv

Go port of OpenConnect's `ocserv` for ERA. A real L3 VPN gateway speaking the
Cisco AnyConnect / OpenConnect SSL VPN protocol so unmodified Cisco Secure
Client and OpenConnect clients can connect.

Sibling to `era-wg` (kernel WireGuard). Single shared multi-queue Linux tun.
mTLS plus AnyConnect password-form challenge against era-portal.

## Listener modes

- **UDS plaintext** (ADR-F7 Stage 2 default). era-facade owns `:443`,
  terminates TLS+mTLS, and hands era-ocserv a plaintext UDS stream with the
  validated client-cert Subject DN in `ERA_TLV_MTLS_SUBJECT_DN`. Socket:
  `/var/run/era-facade/handoffs/anyconnect-cstp.sock`. See `internal/cstp/README.md`
  and `internal/udsserve/`.
- **Legacy loopback TCP+TLS** (pre-cutover compat). era-ocserv terminates
  TLS+mTLS itself on `127.0.0.1:8444` and validates the client cert via
  `internal/auth.CertValidator`. Selected by `-mode=legacy`.

The default `-mode=auto` chooses UDS if the facade's handoff directory
(parent of `-uds-socket`) exists, otherwise falls back to legacy.

## Status

Stage 1 + ADR-F7 Wave II (CSTP UDS bridge). DTLS lifted to facade in Stage 5.

## Reference

- Protocol spec &mdash; <https://github.com/zhouchenh/tpm/blob/main/docs/architecture/era-ocserv-protocol.md>
- Architecture ADR 0057 &mdash; <https://github.com/zhouchenh/tpm/blob/main/docs/decisions/0057-era-ocserv-architecture.md>
