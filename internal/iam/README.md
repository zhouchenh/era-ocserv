# internal/iam

## Purpose

Resolves a device UUID to the per-device identity era-ocserv needs to set up
a CSTP session: the assigned native IPv6 /128 from ERA's
`2001:470:f9d1:9001::/64` pool, plus optional MTU / DNS / search-domain
overrides. This package owns the device-UUID -> identity lookup. It does
NOT own client-cert parsing or password verification (those live in
`internal/auth`) and has no AnyConnect wire-protocol concerns
(`internal/cstp` calls in via the `Resolver` interface re-declared there).

## Contract

- **`Identity`** — `{DeviceID, IPv6 (/128), MTU, DNS, DefaultDomain}`.
  Distinct from `cstp.Identity` so the dependency arrow stays one-way; the
  CONNECT handler copies the fields it needs.
- **`Resolver`** — `Resolve(ctx, deviceID) (Identity, error)`. The only
  surface the rest of the daemon consumes.
- **`TPMResolver`** — production implementation. Backed by TPM's
  authenticated provisioning HTTP API (ADR 0054), reads
  `provisioning.ClientConfig.SourceIPv6Native` (ADR 0035 / 0036) to extract
  the native /128. Constructed via `NewTPMResolver`; missing
  `BaseURL` / `ServiceToken` panic on construction because both are
  load-bearing for every call.
- **`MockResolver`** — in-memory, exported so downstream tests pre-seed
  identities without a network round-trip.
- **Sentinel errors** — `ErrDeviceNotFound`, `ErrNoTunnel`, `ErrUpstream`.
  Match with `errors.Is`. `ErrNoTunnel` is distinct from `ErrDeviceNotFound`
  so callers can surface "device exists but never got a /128" differently
  from "device unknown to TPM".
- **`DefaultPoolPrefix`** — `2001:470:f9d1:9001::/64`. Any /128 returned by
  TPM must fall inside this prefix (configurable via
  `TPMResolverConfig.PoolPrefix`); anything else is rejected with
  `ErrUpstream`.

## Dependencies

Standard library plus `golang.org/x/sync/singleflight` for upstream call
coalescing. No third-party HTTP / JSON / cache library — the surface is
narrow enough that `net/http` + `encoding/json` + a hand-rolled cache is
clearer than pulling in a framework.

## Invariants

Callers MUST:

- Treat the service token as a secret. `TPMResolver` never logs it; do not
  echo it into structured logs or error messages from the caller side
  either.
- Tolerate transient `ErrUpstream`. The resolver returns hard-cached values
  during a brief upstream blip (one extra TTL window past soft expiry); a
  hard failure after that surfaces as `ErrUpstream`. The CSTP layer maps
  this to HTTP 502 on the CONNECT response so the client retries cleanly.
- Not mutate `Identity.DNS` after construction. The slice is returned by
  reference for zero-copy reasons; callers that need to extend it must
  copy first.

Callers MUST NOT:

- Cache the resolved `Identity` for longer than the resolver's own TTL.
  TPM is the source of truth for the /128 binding; an externally cached
  value can outlive a deprovisioned device and keep a stale session up.

## Threading model

- `TPMResolver` is safe for concurrent use. Concurrent `Resolve` calls for
  the same device id collapse to one upstream HTTP via `singleflight.Group`;
  the cache is guarded by a single mutex.
- Cache reads and writes both take that mutex; contention is bounded by the
  resolve rate (single-digit per second per gateway).
- `MockResolver` uses an `sync.RWMutex` over the in-memory map.

## Testing model

- `tpm_resolver_test.go` drives every cache and singleflight branch
  (`fakeClock` for deterministic TTL expiry, atomic counter to assert
  request coalescing), all sentinel-mapping branches (404 / 401 / 5xx /
  malformed JSON / pool-validation failure), and the panic-on-missing-
  configuration paths.
- Downstream packages inject `MockResolver` (or a custom `Resolver`
  implementation) rather than mocking HTTP. Production wiring constructs a
  `TPMResolver` and passes it directly to `cstp.Config.Resolver`.

## Cross-refs

- Protocol doc — [§4 Identity lookup](../../docs/architecture/era-ocserv-protocol.md#4-identity-resolution)
  (request / response shape, error semantics).
- ADR 0057 §5 — identity-store integration via TPM provisioning API.
- ADR 0035 / 0036 — per-device native /128 binding and pool model.
- ADR 0054 — TPM provisioning HTTP API and `tpmsvc1_` service tokens.
