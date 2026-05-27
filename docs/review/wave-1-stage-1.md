# Wave 1 + Stage 1 review (2026-05-27)

## Summary

Wave 1 (tun, auth, iam, cstp) and Stage 1 integration (`cmd/era-ocserv`)
are in good shape overall: the protocol wire format matches the spec
byte-for-byte; the auth, iam, and frame layers have credible unit
coverage; the CSTP state machine plus heartbeat/idle paths are sound;
the era-facade UDP first-byte demux (sibling change `5235273` in
`feat/udp-dtls-demux`) is well-factored and tested. Two findings,
however, must be fixed before any live deploy: the phase-3 CONNECT
handler never re-binds the inbound mTLS cert to the session minted at
phase 2 (spec §1.8 explicitly requires it, ADR 0057 §4 is the security
basis for the binding), and the tunnel→tun bridge does not enforce the
inner source-address anti-spoof rule (spec §6.1). Beyond those, there
are several P1 robustness items (session-table reaper, advertising
`X-DTLS-*` headers in Stage 1 where no DTLS server is listening,
shutdown leaks hijacked connections) and a handful of P2 nits.

## Findings

### [P0] Phase-3 CONNECT does not re-bind cert to session

**File:** `internal/cstp/connect.go:32-45`
**Branch:** `feat/internal-cstp` @ `c785986` (kept on `feat/stage-1-integration` @ `b924505`)

Description: `handleConnect` looks up the session by the `webvpn`
cookie and then uses `sess.deviceID` (the deviceID captured at phase 2)
to drive `Resolver.Resolve` and the `Identity` published on the tunnel.
The deviceID extracted from the *current* CONNECT request's mTLS cert
(stashed by the `certMiddleware` in `cmd/era-ocserv/main.go:280-295`)
is never consulted. Protocol spec §1.8 is explicit: "If the server
still holds the session ... **and the client cert in the new TLS
handshake matches the one bound to the session**, the same /128 and
all state continues. Otherwise the cookie is treated as invalid." ADR
0057 §4 frames mTLS+password as a two-factor binding; only verifying
mTLS at the TLS layer + cookie at the CSTP layer collapses that to
"either factor + a leaked cookie". Once Stage 1 ships reconnect (§1.8)
on a different TCP, a leaked session token plus *any* validly-signed
ERA device cert is enough to take over another device's /128. The
session struct (`internal/cstp/cookie.go:26-33`) already has nowhere to
store the bound deviceID, so this is also a schema gap, not just a
missing comparison.

Suggested fix: thread the mTLS-validated deviceID through into the
CSTP `Verifier` plumbing (it is already passed in for phase 2 via
`certBoundVerifier`), persist it on the `session` row at `promote`
time, and reject the CONNECT (401 + close) when the resolved cert
deviceID does not equal `sess.deviceID`. The same check has to be
applied to the reconnect-via-cookie path on `/` once it lands.

---

### [P0] Bridge writes tunnel-received packets to tun without source-address anti-spoof

**File:** `cmd/era-ocserv/bridge.go:80-120`
**Branch:** `feat/stage-1-integration` @ `b924505`

Description: `pumpTunnel` reads a payload from `Tunnel.ReadPacket`,
picks a tun queue round-robin, and writes the raw IP packet straight
to the kernel tun. There is no inner-source-IP validation against the
device's assigned /128 or the CLAT placeholder `192.0.0.1`. Spec §6.1
is unambiguous: "we verify the inner source IP matches the device's
assigned /128 (or the CLAT placeholder `192.0.0.1`) and drop spoofed
frames silently. This is the same anti-spoof discipline kernel
WireGuard's `AllowedIPs` provides." Without it, an authenticated
client can write packets sourced from any inner address — escaping the
per-device identity model that ADR 0035/0036 (referenced from ADR 0057
§5) relies on, and trivially spoofing other devices' /128s inside the
ERA fabric (or even the `2001:470:f9d1:9001::/64` infrastructure
prefix outside the per-device pool).

Suggested fix: add a parser in `bridge.go` (or a small helper in
`internal/cstp` exposed via the Tunnel) that pulls the IP version, then
the source address (`buf[8:24]` for IPv6, `buf[12:16]` for IPv4) and
checks against either `t.Identity().IPv6.Addr()` (for the v6 family) or
the hard-coded `192.0.0.1` (for v4). Drop + counter on mismatch.
Identical discipline applies to the v4 case where only the single
CLAT-owning client may source `192.0.0.1`; the bridge's
`atomic.Pointer[client]` for that case (mentioned in ADR 0057 §3) is
also not yet wired.

---

### [P1] Stage 1 advertises `X-DTLS-*` whenever the PSK exporter succeeds, even with no DTLS server listening

**File:** `internal/cstp/connect.go:32-62`, `internal/cstp/connect.go:207-228`
**Branch:** `feat/internal-cstp` @ `c785986`

Description: `handleConnect` calls `deriveDTLSSecret` which only checks
`r.TLS != nil` + `ExportKeyingMaterial` works. If both succeed (the
production path always will once mTLS is wired), `emitDTLSHeaders` is
called unconditionally — emitting `X-DTLS-Master-Secret`,
`X-DTLS-CipherSuite: PSK-NEGOTIATE`, `X-DTLS-Port: 443`, etc. Stage 1
intentionally ships no DTLS server (`internal/dtls` only lives on
`feat/internal-dtls`, Stage 2). Clients that read these headers will
try the UDP handshake against era-facade → era-ocserv loopback UDP and
sit on a timeout before falling back to TCP. macOS Cisco SC in
particular (per protocol §3.2 "more aggressive about retrying DTLS
than Windows; if the first UDP datagram doesn't get a response within
a few hundred ms the client will fall back to TCP and not retry DTLS
for the session") is documented to disable DTLS for the whole session
on that timeout. Worse, spec §2.2 requires the server to omit *all*
`X-DTLS-*` headers when the client did not offer `PSK-NEGOTIATE` in
`X-DTLS-CipherSuite`; the implementation never reads the client's
`X-DTLS-CipherSuite` at all.

Suggested fix: gate `emitDTLSHeaders` on a new `Config` field
(`AdvertiseDTLS bool`, default false in Stage 1, flipped true in Stage
2 when the DTLS server is wired) AND on a check that the client's
`X-DTLS-CipherSuite` header actually contains `PSK-NEGOTIATE`. Until
Stage 2, Stage 1 traffic should run TCP-only at the wire level, which
is the explicitly supported degraded mode in §2.2.

---

### [P1] Bridge displacement leaves a window where stale `*activeClient` is reachable; LoadOrStore + Store split is not atomic

**File:** `cmd/era-ocserv/bridge.go:80-97`
**Branch:** `feat/stage-1-integration` @ `b924505`

Description: when two CSTP tunnels for the same inner /128 land
(e.g. a TCP-only reconnect before the prior tunnel's readLoop has
observed the TLS close), `pumpTunnel` does

```go
if prev, loaded := b.clients.LoadOrStore(inner, ac); loaded {
    old := prev.(*activeClient)
    old.tunnel.Close()
    b.clients.Store(inner, ac)
}
```

`LoadOrStore` with `loaded=true` does NOT install `ac`; the followup
`Store` is racy. Between `old.tunnel.Close()` and `b.clients.Store`,
the map still points at `old`, whose tunnel is now closed — `pumpTunQueue`
will load it, call `WritePacket` on the closed tunnel, hit `errTunnelClosed`,
and drop the packet. The defer at `bridge.go:93-97` uses
`CompareAndDelete(inner, ac)` which is correct, but if three or more
displacements race (rare, but reachable on a reconnect storm) the goroutine
whose `Store` lost the race still runs `pumpTunnel` while its `ac` is
not the map entry — its `CompareAndDelete` then no-ops and the map is
left pointing at whichever Store ran last (which may be the
intermediate one).

Suggested fix: replace the LoadOrStore + Store pattern with a single
critical section: drop `sync.Map` for this map and use an explicit
`sync.Mutex` around `map[netip.Addr]*activeClient`, so that
"atomically swap and grab the old" is one operation. Or keep
`sync.Map` and use `LoadAndDelete` + `LoadOrStore` in a loop. The
hotter path (`pumpTunQueue`) only does `Load`, so the lock contention
on a plain map+mutex is acceptable for the steady-state.

---

### [P1] Session table has no reaper; expired pre-auth sessions linger forever if never looked up

**File:** `internal/cstp/cookie.go:40-55`, `internal/cstp/cookie.go:64-81`
**Branch:** `feat/internal-cstp` @ `c785986`

Description: `sessionTable` only reaps expired rows inline on lookup
(`lookupOpaque` / `lookupToken`). A pre-auth row created in phase 2a
that never sees a phase 2b POST is never visited again — the only
codepath that touches `byOpaque` is `handleAuth`'s lookup keyed by the
opaque id, which by definition only happens when the client comes
back. An unauthenticated attacker can POST `/` repeatedly to mint
sessions and walk away; `byOpaque` grows without bound. Per
`cstp.go:130-138`, the table is also re-allocated only at `NewServer`,
so the leak persists for the lifetime of the process. `SessionTimeout`
default 1h × even a modest 100 init POSTs/s = 360k stale rows / hour =
gigabytes after a day under abuse.

Suggested fix: start a janitor goroutine in `NewServer` that walks
`byOpaque` and `byToken` periodically (every `SessionTimeout / 4`)
under the same mutex and deletes rows where `now.After(expiresAt)`.
Stop it from `Server.Close`. Alternatively: bound the table size and
reject new opaque mints with `503 Service Unavailable` past a
configured cap (this also addresses the unbounded-DoS surface on `/`).

---

### [P1] Shutdown leaks hijacked tunnel connections; `Server.Close` does not tear down accepted tunnels

**File:** `internal/cstp/cstp.go:162-172`, `cmd/era-ocserv/main.go:154-161`
**Branch:** `feat/internal-cstp` @ `c785986`, `feat/stage-1-integration` @ `b924505`

Description: `Server.Close` only closes the accept channel; tunnels
already handed out via `Accept` are not registered anywhere in the
Server, so they keep running. `cmd/era-ocserv/main.go`'s shutdown
goroutine does `httpSrv.Shutdown(shutdownCtx); srv.Close()`. But
`http.Server.Shutdown` documentation states it does **not** affect
hijacked connections; the Go runtime just leaks the goroutines and
fds. The bridge's `pumpTunnel` goroutines block on `t.ReadPacket`
until the TLS read fails — which only happens when the client closes
the conn or when `dev.Close()` indirectly impacts the chain (it
doesn't, the tun fds and TLS conns are independent). On SIGTERM the
process will exit when `httpSrv.Serve` returns, but any in-flight
tunnel goroutines are abandoned mid-write; observed-state from the
client side is unclean (no `AC_PKT_DISCONN` / `AC_PKT_TERM_SERVER`
sent), so the client treats it as a hang.

Suggested fix: have `Server` track issued tunnels (a `sync.Map` keyed
by token, or a `[]*Tunnel` under a mutex). On `Close`, range over the
set and call `t.closeWithErr(...)` on each (ideally after writing
`AC_PKT_TERM_SERVER` so the client knows not to auto-reconnect).
`cmd/era-ocserv` then waits for the bridge's `run` to return before
unwinding `dev.Close()`.

---

### [P1] DTLS rekey advertised but server-side TLS renegotiation is disabled

**File:** `cmd/era-ocserv/main.go:218-238`, `internal/cstp/connect.go:196-197`
**Branch:** `feat/stage-1-integration` @ `b924505`

Description: `emitCSTPHeaders` advertises
`X-CSTP-Rekey-Time: 28800` and `X-CSTP-Rekey-Method: ssl`, which per
spec §1.6 means the client will trigger an inline TLS renegotiation at
the 8-hour mark and expect the session to continue without
reconnecting. `loadTLS` does not set `Renegotiation` on the
`*tls.Config`, so Go's default `RenegotiateNever` applies and the
renegotiation attempt is rejected, dropping every long-lived session
at exactly 8 hours.

Suggested fix: either set
`tlsCfg.Renegotiation = tls.RenegotiateFreelyAsClient`-equivalent for
the server (Go does not expose a separate server-side knob; the
practical answer is to advertise `X-CSTP-Rekey-Method: new-tunnel`
instead, which lets the client open a fresh TCP+TLS connection and
reconnect via the session cookie — this dovetails with the §1.8
reconnect work item) or to lower `X-CSTP-Rekey-Time` such that the
8-hour cap is academic in Stage 1. Note ADR 0057 §6 already mandates
the 8h cap for DTLS as defense-in-depth against the CVE-2026-26014
nonce-reuse — that cap should apply to TLS too.

---

### [P2] `lookupToken` linear scan defeats both performance and its own constant-time goal

**File:** `internal/cstp/cookie.go:129-145`
**Branch:** `feat/internal-cstp` @ `c785986`

Description: `lookupToken` iterates `t.byToken` and runs
`subtle.ConstantTimeCompare` against every entry. The intent (per the
comment) is timing-attack resistance, but session tokens are 256 bits
of CSPRNG output (`randURLSafe(_, 32)`) — brute-forcing or timing-
oracling them is infeasible. The linear scan turns CONNECT lookup
from O(1) to O(n), and the constant-time compare on each row is only
"constant-time per row" — the *total* time is still proportional to
the number of sessions before the match, leaking information about
table position. So this approach gives up O(1) lookup while not
actually providing the security property it claims.

Suggested fix: revert to `s, ok := t.byToken[token]` then return
`s` if ok and not expired. The map lookup's timing variation on a
256-bit random key carries no useful signal. If a future audit wants
constant-time-anyway, the standard pattern is to do the constant-time
compare against the matched entry, not against every entry.

---

### [P2] `MockCall.Password` keeps the cleartext password on the call log

**File:** `internal/auth/mock.go:39-42`, `internal/auth/mock.go:76-93`
**Branch:** `feat/internal-auth` @ `08513ca`

Description: `MockVerifier.Calls()` returns a `[]MockCall` whose
`Password string` is the raw submitted password. The doc says "tests
are responsible for not logging the struct", but the type is exported
and any future test that does `t.Logf("%+v", calls)` will dump
passwords to test logs / CI output. Test fixtures that get committed
sometimes leak through into integration logs.

Suggested fix: drop `Password` from `MockCall` entirely — assertions
that care about which password was tried can compare against a
boolean (`MatchedExpected`) computed inside `Verify`, or compare a
SHA-256 truncated digest. The username is fine to keep.

---

### [P2] `emitDTLSHeaders` emits a random `X-DTLS-Session-ID` per CONNECT; could be omitted entirely under PSK-NEGOTIATE

**File:** `internal/cstp/connect.go:217-228`
**Branch:** `feat/internal-cstp` @ `c785986`

Description: the function generates a 32-byte random hex and emits it
as `X-DTLS-Session-ID` "so the header set looks complete to clients
that parse it without using it". Real Cisco Secure Client and
OpenConnect ignore this under PSK-NEGOTIATE (the field is a leftover
from the legacy fake-resumption variant, which §2.2 explicitly drops).
The `randHex(nil, 32)` consumes 32 bytes of CSPRNG per CONNECT for no
behaviour difference, and a future audit of "what does this hex tie
to?" will lead to confusion.

Suggested fix: omit `X-DTLS-Session-ID` entirely; document the
omission inline with a back-reference to spec §2.2. If a Stage 4
client matrix test discovers a specific Cisco SC version that hard-
requires the header, add it back under a guard.

---

### [P2] `extractDeviceID` only inspects `OU[0]`; cert with multiple OUs masks the rest

**File:** `internal/auth/cert.go:124-138`
**Branch:** `feat/internal-auth` @ `08513ca`

Description: when `SubjectField=OU`, only the first OU value is
checked. ERA's idgen device-ids are unique per cert so this is fine
today, but a cert intentionally issued with `OU=garbage` followed by
`OU=dev_<valid>` would fail validation while a human reading the cert
would assume the device id is present. The CN path doesn't have this
issue because `Subject.CommonName` is already a single string.

Suggested fix: iterate `Subject.OrganizationalUnit` and return the
first value that satisfies `validDeviceID`. This also matches how the
issuing PKI is likely to evolve (auxiliary OUs for environment / role
tags would otherwise force ordering invariants on the CA).

---

### [P2] `negotiateInnerMTU` floor is 576 (IPv4 min) but ERA's tunnel inner is IPv6-default; should be 1280

**File:** `internal/cstp/connect.go:121-138`
**Branch:** `feat/internal-cstp` @ `c785986`

Description: the comment cites "RFC 791 minimum reassembly buffer that
any IPv4 host accepts" — but the device's primary inner address is
IPv6 (`X-CSTP-Address-IP6` from `id.IPv6`). RFC 8200 §5 requires every
IPv6 link to handle MTU ≥ 1280. Advertising 576 would only be reached
in a misconfigured deployment, but if it ever happens IPv6 inner
packets will black-hole at the tun. The floor is also "below the
maximum CSTP frame headers", which is fine, but the wrong floor.

Suggested fix: floor at `max(576, 1280)` when the device has an IPv6
identity, or unconditionally at 1280 since every device gets an IPv6
/128 (ADR 0057 §5). Same change applies to `dtlsMTU` in
`emitDTLSHeaders`.

---

### [P2] `parseAuthRequest` accepts an unbounded XML body (`http.MaxBytesReader` limits the HTTP body but the XML decoder still allocates per element)

**File:** `internal/cstp/server.go:56-66`, `internal/cstp/xml.go:112-133`
**Branch:** `feat/internal-cstp` @ `c785986`

Description: the body is capped at 64 KiB by `http.MaxBytesReader`,
which is fine for size, but the XML decoder doesn't cap element
nesting depth. A pathological client could send a 64 KiB body of
deeply-nested elements (e.g. 30 KiB of `<a><a><a>...</a></a></a>`)
causing recursive descent allocation. Stage 1's exposure here is
modest (the body is 64 KiB) but it's a soft DoS amplification factor.

Suggested fix: set `dec.Strict = true` (probably already default) and
add a manual depth counter via a `xml.TokenReader` wrapper, capping
nesting at e.g. 32 levels.

---

### [P2] Bridge ignores `len(b.dev.Queues()) == 0` only after the displacement window opens

**File:** `cmd/era-ocserv/bridge.go:99-102`
**Branch:** `feat/stage-1-integration` @ `b924505`

Description: `pumpTunnel` puts itself into `b.clients` *before*
checking `len(queues) == 0`. If queues is empty (only possible on a
non-Linux build or a partially-initialised device), the goroutine
returns and the defer correctly removes the map entry — but during
the displacement path (lines 85-90) it would have already closed an
old tunnel for no good reason. The net result on a queueless device
is "old tunnels die instantly on every reconnect attempt". Stage 1
only runs on Linux so this is academic, but the ordering reads as a
small bug.

Suggested fix: move the queue check above the `LoadOrStore` block.
Better: turn the `tun.Device.Queues()` empty case into an explicit
error at `Open` time so the bridge never sees an empty-queue device.

## Notes (non-findings)

- **Spec adherence on the wire is excellent.** The 8-byte CSTP frame
  header (`internal/cstp/frame.go:36`), the magic bytes, the BE-uint16
  length, the trailing zero, and the full packet-type enum all match
  the spec §1.5 table exactly. Frame fragmentation across reads is
  handled by `io.ReadFull` and explicitly tested
  (`TestReadFrameFragmentedAcrossReads`).

- **TLS Write serialisation** in `writeFrame` (`tunnel.go:312-343`)
  correctly takes `writeMu` around the bufio.Writer write+Flush,
  matching the requirement that `crypto/tls.(*Conn).Write` is not safe
  for concurrent use. The heartbeat and `WritePacket` paths share the
  lock.

- **The cert validator re-verifies the chain.** `internal/auth/cert.go`
  explicitly builds intermediates from `state.PeerCertificates[1:]`
  and uses `ExtKeyUsageClientAuth` rather than trusting crypto/tls's
  own verification. This is the right defense-in-depth pattern; the
  test matrix (`cert_test.go`) covers expired, untrusted, wrong-EKU,
  and 3-tier-chain paths.

- **`TPMResolver`** has a thorough cache + singleflight + degraded-mode
  design and the test suite covers happy / soft-expiry / hard-expiry /
  upstream-error / pool-validation / concurrent-coalesce. The
  `panic` on missing config in `NewTPMResolver` is the right call —
  failing fast at startup beats nil-deref at first request.

- **`HTTPVerifier`** correctly maps 401 → `ErrBadCredentials`, 423 →
  `ErrAccountLocked`, 5xx → `ErrUpstream`, caps the response body at
  8 KiB, sets `DisallowUnknownFields`, and validates the returned
  device id against the same `validDeviceID` regex the cert path
  uses. Bearer token is never logged. Response body is fully drained
  + closed in a `defer`.

- **`certBoundVerifier` in `cmd/era-ocserv/main.go:306-324`** is a
  nice seam: it composes the phase-2 password verifier with the
  phase-2 cert verifier and rejects mismatches with a `slog.Warn`.
  This makes the phase 2 → phase 3 binding gap (P0 above) all the
  more notable — the binding *infrastructure* is in place, the cert
  comparison is just not re-run at CONNECT.

- **`internal/tun`** is small and reads like it has been written by
  someone who has had to debug tun before: `IFF_TUN | IFF_NO_PI |
  IFF_MULTI_QUEUE`, EEXIST tolerated on address add, the netlink
  helper is hand-rolled rather than pulling in a third-party
  dependency, the multi-queue queue fds are independently closeable.
  The non-Linux stub keeps developer workstations compiling.

- **`era-facade` `feat/udp-dtls-demux` (commit `5235273`)** is the
  shared infrastructure side and is well-factored. The first-byte
  classifier (`internal/front/udpfront/transport.go`) does the
  DTLS-first two-byte check (`0x16 0xfe`) so it cannot misclassify a
  malformed UDP datagram with a `0x96` first byte. The Kind
  discriminator on `UDPMatchRule` keeps DTLS rows from being picked
  up by the QUIC SNI/ALPN matcher. PROXY v2 wrapping is reused on
  the first DTLS datagram so era-ocserv sees the real client IP via
  the same code path covertfront uses today. The test list is
  comprehensive (classifier, routing, drops, sticky flows, mixed-
  kind concurrency, config validation). No findings on the facade
  side beyond noting that none of the era-ocserv P0/P1 findings
  above depend on the demux behaviour.

- **Stage 2 is on the critical path for fixing the P1 DTLS-headers
  issue.** Once `feat/internal-dtls` lands and the UDP listener is
  wired, the right gate becomes "we have a DTLS server listening on
  the loopback UDP port" rather than "PSK exporter worked". The
  Stage 2 work-in-progress commit `a61b20f` (`wip(dtls): stage 2 in
  progress — server + cstp AttachDTLS hooks`) on `feat/internal-dtls`
  is the right place to land that gate.

- **Reconnect-via-cookie (§1.8) is documented but not yet
  implemented** (`server.go:48-55` calls out the hook). When it lands,
  the cert-binding fix from the P0 above must apply to the reconnect
  path identically — the spec text in §1.8 is the security basis for
  the whole reconnect feature.
