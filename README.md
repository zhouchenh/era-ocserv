# era-ocserv

Go port of OpenConnect's `ocserv` for ERA. A real L3 VPN gateway speaking the
Cisco AnyConnect / OpenConnect SSL VPN protocol so unmodified Cisco Secure
Client and OpenConnect clients can connect.

Sibling to `era-wg` (kernel WireGuard). Single shared multi-queue Linux tun.
The shipping auth path is now:

- facade validates the per-device token-prefix URL at the apex
- era-ocserv runs the Cisco/OpenConnect auth-form challenge
- era-portal verifies `username=dev_...` plus the per-device AnyConnect secret

This keeps the client UX close to WireGuard-once-imported: import the VPN
profile, save the device secret once, then reconnect without retyping.

## Listener modes

- **UDS plaintext** (ADR-F7 Stage 2 default). era-facade owns `:443`,
  terminates TLS, validates the token-prefix path, and hands era-ocserv a
  plaintext UDS stream. Socket:
  `/var/run/era-facade/handoffs/anyconnect-cstp.sock`. See `internal/cstp/README.md`
  and `internal/udsserve/`.
- **Legacy loopback TCP+TLS** (pre-cutover compat). era-ocserv terminates
  TLS itself on `127.0.0.1:8444`. Selected by `-mode=legacy`.

The default `-mode=auto` chooses UDS if the facade's handoff directory
(parent of `-uds-socket`) exists, otherwise falls back to legacy.

## Status

Stage 1 + ADR-F7 Wave II (CSTP UDS bridge). DTLS lifted to facade in Stage 5.

## Reference

- Protocol spec &mdash; <https://github.com/zhouchenh/tpm/blob/main/docs/architecture/era-ocserv-protocol.md>
- Architecture ADR 0057 &mdash; <https://github.com/zhouchenh/tpm/blob/main/docs/decisions/0057-era-ocserv-architecture.md>
