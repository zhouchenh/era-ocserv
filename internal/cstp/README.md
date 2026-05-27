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
  owns it).
- mTLS client-certificate validation (legacy: `internal/auth.CertValidator`;
  UDS: `auth.DeviceIDFromSubjectDN` against the TLV value).
- Password verification (`internal/auth.HTTPVerifier` → era-portal).
- IPv6 prefix / MTU resolution (`internal/iam.TPMResolver` → tpm).
- The host tun device (`internal/tun` + `cmd/era-ocserv/bridge`).

## Two listener modes

### Legacy: loopback TCP + TLS (pre-cutover)

era-ocserv listens on `127.0.0.1:8444` (the historical default), terminates TLS
itself, and validates the client cert via `internal/auth.CertValidator`. The
extracted device id is stored on `certctx` for the downstream password verifier
to cross-check.

This path is kept operational so a Wave II deploy can fall back without
rebuilding. It is selected by `-mode=legacy` or `-mode=auto` on a host whose
facade UDS directory is absent.

```
client ──TLS+mTLS── era-ocserv:8444 ──┐
                                       └─► cstp.Server.ServeHTTP
                                              ├─ init / auth (POSTs)
                                              └─ CONNECT (binary tunnel)
```

### UDS: facade-terminated TLS + plaintext handoff (ADR-F7 Stage 2)

era-facade owns `:443`, terminates TLS+mTLS, validates the device cert, and
hands era-ocserv a plaintext UDS stream with the device cert's Subject DN
carried in `ERA_TLV_MTLS_SUBJECT_DN` (0xED). era-ocserv extracts the device id
from the DN's CN, runs the same CSTP HTTP handler chain, and emits a CONNECT
response onto the plaintext stream. The facade re-encrypts the response and
relays to the client.

```
client ──TLS+mTLS── facade ──UDS+PROXY-v2+TLVs── era-ocserv ──┐
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

Out of scope for Wave II. ADR-F7 Stage 5 lifts DTLS termination into the
facade; era-ocserv stays a plaintext consumer. The `X-DTLS-*` advertisement
emitted by `handleConnect` still runs in legacy mode (it derives the PSK via
the TLS exporter) and silently downgrades to TCP-only when no `r.TLS` is
present — which is the case under UDS mode in Wave II. Stage 5 will replace
that downgrade with a DTLS UDS-DGRAM consumer; see
`docs/decisions/0057-era-ocserv-architecture.md` (TODO: amendment landing in
the Stage 5 PR).
