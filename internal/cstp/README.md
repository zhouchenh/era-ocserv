# internal/cstp — AnyConnect CSTP control + tunnel

This package implements the AnyConnect Secure Transport Protocol (CSTP) control
plane and the post-CONNECT binary frame tunnel that carries inner IP packets
between an AnyConnect-compatible client (Cisco Secure Client, OpenConnect) and
the era-ocserv gateway.

Reference: `docs/architecture/era-ocserv-protocol.md` §1 and IETF draft
`draft-mavrogiannopoulos-openconnect-04`.

## What this package owns

- HTTP-shaped phase-2 negotiation (`POST /` init, `POST /auth` auth-reply,
  `CONNECT /CSCOSSLC/tunnel` upgrade).
- Cookie-based session state for the brief init→auth→tunnel window.
- Per-tunnel 8-byte-framed binary CSTP packets (data, DPD, keepalive,
  disconnect).
- Per-tunnel DPD + keepalive heartbeat goroutine.

## What this package does NOT own

These are dependencies the caller injects through `Config` (`Verifier`,
`Resolver`) or wires up at the integration layer (the listener, TLS or UDS).

- TLS termination (legacy mode: `cmd/era-ocserv` owns it; UDS mode: the facade
  owns it on the shared `eracloud.app:443` edge).
- Device-credential verification (`internal/auth.HTTPVerifier` → era-portal).
- IPv6 prefix / MTU resolution (`internal/iam.TPMResolver` → tpm).
- The host tun device (`internal/tun` + `cmd/era-ocserv/bridge`).

## Two listener modes

### Legacy: loopback TCP + TLS (pre-cutover compatibility)

era-ocserv listens on `127.0.0.1:8444` (the historical default) and terminates
TLS itself. The listener requires and verifies a client certificate signed by
the configured `-client-ca`; the certificate's CN supplies the device ID.
The password verifier response must return the same device ID, so a valid
portal credential cannot be used with a different device certificate.

This path is kept operational so a Wave II deploy can fall back without
rebuilding. It is selected by `-mode=legacy` or `-mode=auto` on a host whose
facade UDS directory is absent.

```
client ──TLS+mTLS── era-ocserv:8444 ──┐
                                       └─► cstp.Server.ServeHTTP
                                              ├─ init / auth (POSTs)
                                              └─ CONNECT (binary tunnel)
```

### UDS: facade-terminated TLS + plaintext handoff (shipping shared-apex path)

era-facade owns `eracloud.app:443`, terminates TLS, validates the token-prefixed
URL at `/drive/access/<token>/*`, and hands era-ocserv a plaintext UDS stream.
era-ocserv then runs the normal CSTP HTTP handler chain and asks era-portal to
verify `username=dev_...` plus the per-device AnyConnect setup secret.

```
client ──TLS── facade ──UDS+PROXY-v2+TLVs── era-ocserv ──┐
                                                          └─► cstp.Server.ServeHTTP
                                                                ├─ init / auth
                                                                └─ CONNECT (binary tunnel)
```

Wire spec for the UDS hop:
`era-facade/docs/architecture/uds-handoff-protocol.md` (Stage 1).

UDS mode is selected by `-mode=uds`, or by `-mode=auto` when the parent
directory of `-uds-socket` (default
`/var/run/era-facade/handoffs/anyconnect-cstp.sock`) exists. Plumbing lives in
`internal/udsserve`.

## DTLS

The DTLS UDS-DGRAM consumer exists in-tree and is started by `cmd/era-ocserv`
when `-dtls-uds-socket` is set, but the facade-owned shared-apex DTLS binding
path is still incomplete. As a result, the `X-DTLS-*` advertisement remains
honest only where era-ocserv still has access to the outer TLS session. Shared-
apex deployments should currently treat CSTP-over-TLS as the ready path and
DTLS as follow-up integration work.
