# internal/cstp

## Purpose

Implements the AnyConnect CSTP control protocol. CSTP is the HTTP-shaped
handshake that runs over TLS on TCP/443 before the connection is upgraded
to a binary frame stream carrying inner IP packets. This package owns the
negotiation (init / auth / CONNECT), the 8-byte binary frame format on
the post-CONNECT stream, the heartbeat (DPD + keepalive) loop, the
in-memory session table, and DTLS PSK advertisement in the `X-DTLS-*`
headers. It does NOT own TLS termination, mTLS chain validation, password
verification, the identity store, or the host tun device — those are
injected via interfaces.

## Contract

- **`Server`** — `http.Handler` that routes the three CSTP control-plane
  endpoints. After phase 3 completes the resulting `*Tunnel` is
  published on an internal channel and drained by `Accept`.
- **`Config`** — construction-time deps and tuning knobs. Required:
  `Verifier`, `Resolver`, `ServerName`. Numeric knobs default to the
  protocol doc §1.6 values.
- **`Verifier`** / **`Resolver`** — interface stubs the package consumes.
  The implementations live in `internal/auth` and `internal/iam`; cstp
  re-declares the interface shape locally so it does not import either.
- **`Identity`** — per-device data threaded from Resolver into the
  CONNECT response and into `*Tunnel`. Distinct from `iam.Identity` to
  keep the dependency arrow one-way.
- **`Tunnel`** — post-CONNECT binary frame stream. `ReadPacket` returns
  one inbound data-frame payload; `WritePacket` sends one. Heartbeat
  runs in a dedicated goroutine that ends with `Close`.
- **`ErrServerClosed`** — sentinel returned by `Accept` after `Close`.

The wire frame format and full `X-CSTP-*` / `X-DTLS-*` header list are
authoritative in protocol doc §1.5 / §1.6.

## Dependencies

Standard library only: `crypto/sha256`, `crypto/subtle`, `encoding/hex`,
`encoding/base64`, `encoding/xml`, `encoding/binary`, `net/http`,
`net/netip`, plus the usual `sync` / `time` / `io`.

## Invariants

Callers MUST:

- Serve `Server` behind a TLS listener that exposes `*tls.Conn` on
  `r.TLS`. DTLS PSK derivation reads `ExportKeyingMaterial`; a nil
  `r.TLS` silently downgrades to TCP-only CSTP (allowed but usually a
  wiring bug).
- Populate `Verifier`, `Resolver`, `ServerName` in `Config` before the
  first request lands. `NewServer` does not panic on missing fields —
  the failure surfaces as a nil-deref on auth/CONNECT.
- Drain `Accept` and `Close` every `*Tunnel` returned. The Server does
  not track tunnels after handing them out; the heartbeat goroutine
  only ends when the caller calls `Close`.

Callers MUST NOT read or write the underlying `net.Conn` after a
`*Tunnel` is returned — the Tunnel owns the conn from that point.

## Threading model

- `Server.ServeHTTP` is safe under `http.Server`'s concurrent-request
  model. The session table is one mutex over both indexes.
- `Server.Accept` and `Server.Close` are safe from any goroutine;
  `Close` is idempotent.
- `*Tunnel` runs two internal goroutines (read, heartbeat). `ReadPacket`
  and `WritePacket` are safe concurrently with each other and with
  `Close`. `WritePacket` is serialised internally because
  `crypto/tls.(*Conn).Write` is not safe for concurrent use.

## Testing model

- The package's own tests use `net.Pipe()` plus a fake clock (`pipeTunnel`
  in `tunnel_test.go`) to drive the heartbeat deterministically.
- Downstream callers test against `cstp.Server` by injecting
  `auth.MockVerifier` + `iam.MockResolver` (both packages ship Example
  tests showing the seam), serving via `httptest.NewTLSServer`, and
  connecting with a stock client that speaks the AnyConnect XML shapes.
  For unit tests that only care about wire behaviour, call `ServeHTTP`
  directly with `httptest.NewRecorder` and a hand-rolled `http.Request`.

## Cross-refs

- Protocol doc — [§1 CSTP wire protocol](../../docs/architecture/era-ocserv-protocol.md#1-cstp-wire-protocol-authoritative)
  (frame format, header set, MTU negotiation, reconnect).
- ADR 0057 §2 (era-facade demux), §4 (auth: mTLS + password challenge),
  §6 (DTLS PSK-NEGOTIATE).
