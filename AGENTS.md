# era-ocserv — agent notes

Go AnyConnect-compatible L3 VPN gateway (CSTP + DTLS), sibling of era-wg. Behind
era-facade (Shape A): facade terminates TLS/QUIC/DTLS at `eracloud.app:443` and
hands era-ocserv plaintext over UDS + PROXY-v2 + TLVs. Also runs a legacy direct-TLS
mode on `:1443` for testing. ADR 0057 (architecture), ADR-F-DTLS-TO-FACADE (DTLS
lives in facade), DEC-anyconnect-own-128 (data plane).

## Active branches (2026-05-30)

- **`feat/cstp-ios-interop-clean`** (`ede9585`, pushed, **PR #5**) — the reviewed,
  WIP-free iOS Cisco Secure Client CSTP win, rebuilt on parent `1f314f1`.
  **Supersedes `b6237d6`'s CSTP changes** (which bundled un-reviewed usage telemetry
  + debug `log.Printf` scaffolding). Adversarial review: 0 wire regressions vs `b6237d6`.
  This is the deploy source for the CSTP fixes; `feat/eracloud-app-cutover @ b6237d6`
  is NOT to be deployed as-is.
- **`feat/anyconnect-own-128`** (`fa72552`, off the clean win) — data-plane Phase 1:
  `internal/iam/tpm_resolver.go` reads `source_ipv6_ocserv` (prefer) / `source_ipv6_native`
  (fallback). Ships together with tpm + era-node-reconciler (DEC-anyconnect-own-128).

## Build / test

Pure Go, no CGO. Cross-compile: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...`.
- Host-runnable tests on Windows: `internal/cstp`, `internal/auth`, `internal/udsserve`,
  `internal/iam` (Win10+ AF_UNIX). Run with `go test ./internal/cstp/ ...`.
- Linux-only (cross-compile build + `go vet` only; runtime tests need a Linux host):
  `internal/tun` (netlink), `internal/dtlsuds`, `cmd/era-ocserv`, the bridge.
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
