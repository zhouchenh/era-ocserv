# era-ocserv — agent notes

Go AnyConnect-compatible L3 VPN gateway (CSTP + DTLS), sibling of era-wg. Behind
era-facade (Shape A): facade terminates TLS/QUIC/DTLS at `eracloud.app:443` and
hands era-ocserv plaintext over UDS + PROXY-v2 + TLVs. Also runs a legacy direct-TLS
mode on `:1443` for testing. ADR 0057 (architecture), ADR-F-DTLS-TO-FACADE (DTLS
lives in facade), DEC-anyconnect-own-128 (data plane).

## Current state (2026-06-02) — branch `feat/anyconnect-clat-phase2`

Real iPhone (Cisco Secure Client) E2E PROVEN on the covert `eracloud.app:443` path:
- **CSTP/TLS** (TCP control+data) works; **DTLS** (UDP perf channel) works via Cisco
  LEGACY injected-premaster resumption — the facade's pion `dtls.Server` resumes with
  era-ocserv's published 48-B master secret + 32-B Session-ID (see
  `internal/cstp/connect.go` `emitLegacyDTLSHeaders`/`parseClientMasterSecret`,
  `internal/dtlsuds`). 216 Mbps over DTLS on Wi-Fi.
- **Inner-v4 CLAT Phase 2** (server-side SIIT, `internal/clat` vendored from
  wireguard-go-clat + `internal/clatxlat` wrapper) deployed: 2× /128 per device
  (native `ocserv_ipv6` + CLAT-source `ocserv_clat_ipv6`); `cmd/era-ocserv/bridge.go`
  demuxes the return path by DESTINATION /128 (CLAT /128 → SIIT64→v4; native /128 →
  passthrough). CLAT-only; `64:ff9b::/96` egresses via the default v6 route → external
  464PLAT (DEC-clat-plat-external; NO new NAT64, TAYGA banned).

## LOCKED L3 MTU model — DEC-l3-mtu-model (do NOT re-derive)

- Wire (advertised) is ALWAYS **1400**: `X-CSTP-MTU = X-DTLS-MTU = 1400`, both from the
  locked const — `negotiateInnerMTU` returns `clatInnerMTUCap` (`connect.go`), ignoring
  base-80/want/device. Equal MTUs keep the client's single utun safe across DTLS↔CSTP
  failover.
- `era-ocserv-tun` MTU = **1420** (`-tun-mtu`, `deploy/era-ocserv-launch.sh`) — SERVER-SIDE
  only, to hold the post-SIIT46 (+20) CLAT v6. The ±20 is entirely server-side; it never
  touches the client wire (no +20 on any DTLS/CSTP datagram).
- nft MSS clamp on `era-ocserv-tun` (`deploy/era-ocserv-mss-clamp.sh`): **v6 1340, v4 1360**
  (= 1400 − IP − TCP). Outer `:443` transport clamp (1200, BBR) is separate, untouched.
- **Server-side ICMPv6 PTB origination** (`internal/icmp6` + `bridge.go` `pumpTunQueue`):
  drop a tun→client packet over its link MTU (native 1400 / CLAT 1420, pre-SIIT64) and
  originate a Packet-Too-Big to its v6 source for dynamic PMTUD — never a silent drop, never
  shrink the static 1400/1420. (This is the mechanism the model assumes.)

## Build / test

Pure Go, no CGO. Cross-compile: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...`.
- Host-runnable tests on Windows: `internal/cstp`, `internal/auth`, `internal/udsserve`,
  `internal/iam` (Win10+ AF_UNIX), `internal/icmp6` (pure-Go PTB builder + KATs),
  `internal/clatxlat`/`internal/clat` (pure-Go SIIT). Run with `go test ./internal/cstp/ ...`.
- Linux-only (cross-compile build + `go vet` only; runtime tests need a Linux host —
  cross-compile `go test -c` + run on `.47`): `internal/tun` (netlink), `internal/dtlsuds`,
  `cmd/era-ocserv`, the bridge (PTB origination call-site lives here).
- gofmt note: the repo checks out CRLF on Windows (`core.autocrlf=true`, no `.gitattributes`);
  `gofmt -l` flags every file. Verify CONTENT with `tr -d '\r' < file | gofmt -d` (expect empty).
  Git normalizes to LF on commit.

## Deploy (`.47`)

- Prod UDS service runs OLD `b11f5103` (no CSTP fixes). `:1443` direct-TLS is the TEST path
  (CSTP-over-TCP; DTLS off there). Covert path = facade `:443` → UDS handoff (anyconnect-cstp.sock /
  anyconnect-dtls.sock) → era-ocserv. Build: `... go build -trimpath -ldflags "-s -w" -o ... ./cmd/era-ocserv`.
- **Guarded deploy only on an operator go-point.** Back up the live binary, sha-verify the staged
  build, atomic swap (cp-to-sidecar + `mv -f` to dodge ETXTBSY), 60s readiness, auto-rollback on
  any CSTP regression.

## Known caveats / follow-ups

- **`serverCertSHA1` (`internal/cstp/profile.go`) is a `:443` deploy gate (medium).** The webvpnc
  `sh:` gateway-cert pin (`525FB9...`) is correct on `:1443` (era-ocserv terminates TLS) but is
  the WRONG leaf on the covert `:443` path, where the facade terminates TLS and era-ocserv never
  sees the public leaf. Before the `:443` cutover, re-pin to the facade leaf, or have the facade
  pass its leaf SHA-1 via a handoff TLV (ADR-F-DTLS-TO-FACADE / C1).
- Deferred CSTP hardening (pre-existing in `b6237d6`, not regressions): opaque rotation on promote
  (session-fixation), replay-`/auth` re-promote token churn, bulk `X-CSTP-*` Go-canonical casing,
  hardcoded `X-DTLS-Port: 443`.
- Commits: no model/tool/vendor branding (workspace standard). Stage specific paths, never `git add -A`
  (the cutover tree has an untracked `dist/`).

See `_program/` at the workspace root (PORTFOLIO_REGISTRY, OPEN_ITEMS, DECISION_LOG, STANDARDS) and
the `-tpm` memory store (`project_era_ocserv_plan.md`) for the full picture.
