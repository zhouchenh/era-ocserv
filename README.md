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

## Architecture

era-ocserv is a standalone Go daemon that speaks the Cisco AnyConnect /
OpenConnect SSL VPN protocol on behalf of ERA. It runs parallel to
`era-wg` (kernel WireGuard) — both terminate user traffic on the same node
and share the same per-device native IPv6 /128 pool, but they are
independent processes with no shared in-process state. era-facade terminates
TLS and DTLS at the public `:443` apex, then forwards CSTP / DTLS bytes to
era-ocserv over loopback. The data plane is one shared multi-queue Linux tun
that the daemon opens at startup; per-client routing happens inside the
daemon, not in the kernel FIB.

```
                     +-----------------------------+
   public :443  -->  | era-facade                  |
   (TCP+UDP)         |   - TLS / DTLS termination  |
                     |   - SNI + UDP demux         |
                     +--------------+--------------+
                                    | loopback (TCP / UDP)
                                    v
                     +-----------------------------+
                     | era-ocserv (this daemon)    |
                     |  cmd/era-ocserv main wiring |
                     |  +-----------------------+  |
                     |  | internal/cstp         |  |  HTTP-shaped handshake,
                     |  |  Server + Tunnel      |  |  8-byte binary frames,
                     |  +----+--------------+---+  |  heartbeat + DPD
                     |       |              |      |
                     |       v              v      |
                     |  internal/auth   internal/iam   <-> era-portal + tpm
                     |  (mTLS + pw)     (UUID -> /128)
                     |       |              |      |
                     |       +------+-------+      |
                     |              v              |
                     |       internal/tun          |  one /dev/net/tun,
                     |        N queues             |  multi-queue, IFF_NO_PI
                     +--------------+--------------+
                                    | IPv6 packets
                                    v
                              ERA NAT64 / WAN
```

The daemon is a separate process from `era-wg` to keep blast radius small
and let each protocol evolve independently: WireGuard's kernel module is
stable but rigid, AnyConnect's protocol matrix needs a userspace state
machine. They share only the IPv6 /128 pool through TPM (see
`internal/iam`) so a device's source address is identical regardless of
which transport it picks.

era-ocserv listens on loopback only. era-facade is the single TLS / DTLS
terminator at `eracloud.app:443` and dispatches by SNI for TCP and by UDP
demux for DTLS; era-ocserv itself never sees the public socket. This lets
the facade swap front-side TLS stacks (covert TLS, QUIC sniffing, decoy
HTTP) without touching the VPN daemon.

Stage 1 is IPv6-only inside the tunnel: each client gets a CLAT-style
placeholder `192.0.0.1/32` for IPv4 source and a real native /128 for IPv6,
matching the existing era-wg + TAYGA NAT64 setup (ADR 0035 / 0036). Stage 2
adds DTLS via `pion/dtls/v3` for the UDP data path; the CSTP TCP control
plane stays primary and DTLS is advertised through the existing
`X-DTLS-Master-Secret` PSK exporter so the implementation can be staged
without flag days.

## Packages

- [`internal/cstp`](internal/cstp/README.md) — AnyConnect control protocol
  and the post-CONNECT binary frame stream.
- [`internal/tun`](internal/tun/README.md) — Linux multi-queue TUN wrapper.
- [`internal/auth`](internal/auth/README.md) — mTLS cert validator and
  password-form verifier.
- [`internal/iam`](internal/iam/README.md) — TPM-backed device-UUID -> /128
  resolver.
