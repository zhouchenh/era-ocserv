# era-ocserv

Go port of OpenConnect's `ocserv` for ERA. A real L3 VPN gateway speaking the
Cisco AnyConnect / OpenConnect SSL VPN protocol so unmodified Cisco Secure
Client and OpenConnect clients can connect.

Sibling to `era-wg` (kernel WireGuard). Listens on loopback behind
`era-facade`'s SNI / UDP demux at `:443`. Single shared multi-queue Linux tun.
mTLS plus AnyConnect password-form challenge against era-portal.

## Status

Stage 1 scaffold. No protocol code yet.

## Reference

- Protocol spec &mdash; <https://github.com/zhouchenh/tpm/blob/main/docs/architecture/era-ocserv-protocol.md>
- Architecture ADR 0057 &mdash; <https://github.com/zhouchenh/tpm/blob/main/docs/decisions/0057-era-ocserv-architecture.md>
