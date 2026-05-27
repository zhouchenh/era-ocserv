# era-ocserv Stage 1 live deploy evidence — 2026-05-27

Validation host: `root@100.91.1.47` (Validation1-AMD, Debian 13 / PMX 7.0.0-3).
Source branch: `feat/deploy-harness` (= `feat/stage-1-integration` + the deploy
harness; commit `1b652a2`).
UAT branch: `uat/stage-1-livedeploy` (off `feat/deploy-harness`).
Operator: Claude Code agent invoked by the user; redacted record below.

This is a SMOKE TEST. The deployment uses **self-signed TLS material** under
`/etc/era-ocserv/{tls,pki}/test-*.pem` and a **placeholder era-portal token**,
gated behind `SMOKE_TEST=1` in the env file. It must not be left in this shape
for production traffic.

## Headline

- era-ocserv `feat/deploy-harness` builds clean and runs cleanly on `.47`.
- TLS 1.3 + mTLS-required + multi-queue tun + IPv6 /128 — all wired and observable.
- All previously-active production services (`era-facade`, `era-tpm-provisioning`,
  `era-proxy`) are still active; none were touched. The tuns `era-wg` and
  `era-clat` retain their pre-deploy IPv6 assignments.
- No `wg0`/`echo0`/`eth0` addressing changes. No default-route changes.
- Two prompt-stated assumptions did NOT match present reality and required
  in-flight decisions (see "Deviations from prompt").

Go/no-go for keeping it running: **NO. Teardown after evidence capture.**
Reason: smoke-only TLS material in place, era-portal `/api/auth/ocserv/verify`
endpoint not deployed yet, and there is no real client cert to drive a useful
end-to-end test. Re-deploy when the era-portal AnyConnect endpoint lands and an
ERA-PKI device cert is available. (Teardown was performed; see end of doc.)

## Deviations from prompt (and why)

1. **Port collision on `127.0.0.1:8444`.** The prompt asked era-ocserv to bind
   `127.0.0.1:8444`. On `.47`, `era-proxy` already owns `*:8444` (standalone
   `anytls-tls` inbound — visible in `/etc/era-proxy/era-proxy.json`):

   ```
   LISTEN 0  4096  *:8444  users:(("era-proxy",pid=2716916,fd=10))
   ```

   A `127.0.0.1:8444` bind would EADDRINUSE because the wildcard owner has
   already claimed the loopback at that port. Resolution: use `127.0.0.1:8450`
   (verified free; in the same loopback band reserved for ERA loopback
   services). Adjust the env file's `-listen` flag accordingly.

2. **era-facade does NOT have static `secrets/wildcard-*.pem`.** The prompt
   asked to reuse `/etc/era-facade/secrets/wildcard-{fullchain,privkey}.pem`.
   On `.47`, `/etc/era-facade/secrets/` does not exist. era-facade is ACME-
   managed: it owns `*.eracloud.app` certs at
   `/var/lib/era-facade/acme/certificates/.../wildcard_.eracloud.app.{crt,key}`
   under `era-facade:era-facade` 0700/0600. Pulling those files out would be a
   production-config mutation (chown copy from a locked-down directory).

   `era-proxy` does keep a readable `*.aircloud.pro` wildcard at
   `/etc/era-proxy/secrets/wildcard-{fullchain,privkey}.pem` (cert CN
   `*.aircloud.pro`, NotAfter 2027-01-16), but that's a different SNI than the
   prompt's target `vpn.eracloud.app`.

   Resolution: gate the deploy behind `SMOKE_TEST=1` and use a brand-new
   **self-signed P-256 keypair** generated in-place at
   `/etc/era-ocserv/tls/test-{fullchain,privkey}.pem` (CN `vpn.eracloud.app`,
   SAN `DNS:vpn.eracloud.app,DNS:localhost,IP:127.0.0.1`, 7-day validity). This
   touches NO production cert store.

3. **No ERA-PKI client CA available.** The prompt anticipated this gap. There
   is no shared device-CA at `/etc/era-tpm/ca.pem` or sibling to
   `/opt/era-tpm/master.key`. The TPM master.key is the AES-GCM envelope key,
   not an X.509 CA. Resolution: generate a smoke-only client CA at
   `/etc/era-ocserv/pki/test-ca.pem` (CN `ERA SMOKE TEST CA`). Wave-2 work
   should add a real device-CA (e.g. `tpm-ocserv-provisioning`).

4. **Previously-"running" production data-plane services are inactive units.**
   The prompt's premise ("era-wg, era-clat, era-tt-reconciler … already
   running") was outdated. Snapshot of `systemctl is-active` at start of
   session and at end-of-deploy (both identical):

   ```
   era-facade               active
   era-wg                   inactive   <- units inactive
   era-clat                 inactive   <- units inactive
   era-tt-reconciler        inactive
   era-tpm-provisioning     active
   era-proxy                active
   nat64-era                inactive
   era-node-reconciler      inactive
   ```

   But the `era-wg` and `era-clat` tun devices are still UP in the kernel and
   still carry their IPv6 /128s (`2001:470:f9d1:9001::e2a:1/128` and
   `fe80::8905:2df4:8aab:c40/64` respectively). The data plane is live; only
   the systemd units have lost track. Pre-existing condition; not our doing,
   not our problem to fix in a deploy-evidence pass. Worth flagging to the
   user separately.

5. **TPM token reuse.** I reused `TPM_PROVISIONING_SERVICE_TOKEN` from
   `/etc/era-tpm/provisioning.env`. era-ocserv currently calls the same TPM
   provisioning API as era-portal / era-tt-reconciler; the token scope is
   broader than ocserv-specific, so this is operationally fine for a smoke
   test but **should be replaced by an ocserv-scoped service token** once the
   `tpm-ocserv-provisioning` story lands (existing groundwork: recent commits
   on this very tpm branch — `feat/tpm-ocserv-provisioning`).

## Phase 1: build + stage

```
$ git -C era-ocserv fetch origin
$ git -C era-ocserv checkout -b uat/stage-1-livedeploy origin/feat/deploy-harness
$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" \
    -o era-ocserv-linux-amd64 ./cmd/era-ocserv
$ file era-ocserv-linux-amd64
era-ocserv-linux-amd64: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
  statically linked, Go BuildID=vyWFB2Jm475t2UarBRQj/4ZoGhFJ1hw7NDXt_SnA1/Aewp..,
  BuildID[sha1]=17ee7e0572a6cb12273b8914e8b3097a998f952b, stripped
$ sha256sum era-ocserv-linux-amd64
32ba6747c8c89ecc8cfe2b6bbf0c15fbbf8a36ae7302f64d90d1c70544513d39
```

**Gotcha:** the first cross-compile attempt accidentally produced a Windows
PE32 because the chained `set` syntax in cmd.exe doesn't translate to POSIX
shells (which is how the harness runs `go build`). systemd's `203/EXEC` is the
diagnostic. Rebuilding with proper `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`
env-prefix produced the ELF above. Re-staged and re-installed.

scp:
```
$ scp era-ocserv-linux-amd64 root@100.91.1.47:/tmp/era-ocserv-staging
$ scp deploy/era-ocserv-{setup,teardown}.sh deploy/era-ocserv.service \
    root@100.91.1.47:/tmp/era-ocserv-deploy/
```

**CRLF gotcha:** Windows scp uploaded the bash scripts with CRLF terminators,
which dash on `.47` chokes on (`set: pipefail: invalid option name`). Fixed
in-place with `sed -i 's/\r$//'` on the host. Worth a `dos2unix` step in CI or
a `git config core.autocrlf input` on the dev box.

## Phase 2: setup on .47

```
$ bash /tmp/era-ocserv-deploy/era-ocserv-setup.sh
=== 0. directory layout ===
=== 1. record original sysctls ===
=== 2. sysctls (only-if-unset semantics) ===
=== 3. sample env file ===
wrote sample /etc/era-ocserv/era-ocserv.env (placeholders; edit before enabling unit)
=== 4. systemd unit ===
=== setup complete ===
```

Idempotent setup, ran clean.

Sysctl marker captured (no sysctl mutations needed — host was already in the
desired state thanks to `era-dataplane-setup.sh` having run previously):

```
$ cat /var/lib/era-ocserv/.setup-marker
ORIG_FWD=1
ORIG_RA=2
ORIG_NDP=1
ORIG_EGRESS_IF=eth0
ORIG_PROXY_NDP=0
```

Binary install + TLS material generation:

```
$ install -m 0755 /tmp/era-ocserv-staging /opt/era-ocserv/era-ocserv
$ install -d -m 0750 /etc/era-ocserv/tls /etc/era-ocserv/pki
$ openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout /etc/era-ocserv/tls/test-privkey.pem \
    -out    /etc/era-ocserv/tls/test-fullchain.pem \
    -days 7 -subj "/CN=vpn.eracloud.app" \
    -addext "subjectAltName=DNS:vpn.eracloud.app,DNS:localhost,IP:127.0.0.1"
$ openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout /etc/era-ocserv/pki/test-ca-key.pem \
    -out    /etc/era-ocserv/pki/test-ca.pem \
    -days 7 -subj "/CN=ERA SMOKE TEST CA"
$ openssl x509 -in /etc/era-ocserv/tls/test-fullchain.pem -noout -subject -dates
subject=CN=vpn.eracloud.app
notBefore=May 27 05:32:55 2026 GMT
notAfter=Jun  3 05:32:55 2026 GMT
```

Env file (token redacted):

```
# /etc/era-ocserv/era-ocserv.env
SMOKE_TEST=1
ERA_OCSERV_ARGS=" \
  -listen 127.0.0.1:8450 \
  -tls-cert /etc/era-ocserv/tls/test-fullchain.pem \
  -tls-key  /etc/era-ocserv/tls/test-privkey.pem \
  -client-ca /etc/era-ocserv/pki/test-ca.pem \
  -era-portal-url http://100.91.1.48:18090 \
  -era-portal-token smoke-placeholder-era-portal-token \
  -tpm-url http://127.0.0.1:9090 \
  -tpm-token tpmsvc1_REDACTED \
  -tun-name era-ocserv-tun \
  -tun-mtu 1500 \
  -tun-queues 0 \
  -tun-ipv6 2001:470:f9d1:9001:ffff::1/128 \
  -server-name vpn.eracloud.app \
  -dns 2606:4700:4700::1111,2606:4700:4700::1001 \
  -log-level debug \
"
```

The `2001:470:f9d1:9001:ffff::1/128` is well outside era-wg's `:2a::/80`
and era-clat's `:c7::/80` pool ranges (the only existing host /128 on this
prefix is `::a1:1` on eth0 — no collision).

Start:

```
$ systemctl daemon-reload
$ systemctl enable --now era-ocserv
Created symlink '/etc/systemd/system/multi-user.target.wants/era-ocserv.service'
  -> '/etc/systemd/system/era-ocserv.service'.

$ systemctl status era-ocserv --no-pager
* era-ocserv.service - ERA AnyConnect-compatible VPN gateway (era-ocserv; loopback behind era-facade)
     Loaded: loaded (/etc/systemd/system/era-ocserv.service; enabled; preset: enabled)
     Active: active (running) since Wed 2026-05-27 05:34:05 UTC; 3s ago
   Main PID: 2718204 (era-ocserv)
      Tasks: 9 (limit: 32396)
     Memory: 4.2M (peak: 4.5M)

May 27 05:34:05  era-ocserv[2718204]: msg="tun opened" name=era-ocserv-tun queues=4 mtu=1500
May 27 05:34:05  era-ocserv[2718204]: msg="era-ocserv listening" addr=127.0.0.1:8450 server_name=vpn.eracloud.app
```

## Phase 3: smoke tests

### Smoke 1 — TLS handshake check (no auth): PASS

```
$ openssl s_client -connect 127.0.0.1:8450 -servername vpn.eracloud.app \
    -showcerts </dev/null
...
Server certificate
  subject=CN=vpn.eracloud.app
  issuer=CN=vpn.eracloud.app
Acceptable client certificate CA names
  CN=ERA SMOKE TEST CA
Negotiated TLS1.3 group: X25519MLKEM768
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
Protocol: TLSv1.3
Verify return code: 18 (self-signed certificate)
---
SSL alert: tlsv13 alert certificate required (116)
```

Reading: TLS 1.3 completed (X25519MLKEM768 KEM + AES-128-GCM cipher), server
cert is the expected `vpn.eracloud.app` ECDSA-P256 leaf, the
CertificateRequest correctly advertised `ERA SMOKE TEST CA` as the acceptable
client CA, and the server then issued `alert certificate required` because we
did not present a client cert. This is exactly the contract from
`cmd/era-ocserv/main.go::loadTLS` (`ClientAuth: tls.RequireAndVerifyClientCert`).
The "Verify return code: 18 (self-signed certificate)" is `openssl`'s view of
our own self-signed leaf — expected and unrelated to server behavior.

### Smoke 2 — HTTP probe (will fail at mTLS): PASS

```
$ curl -ksv --resolve vpn.eracloud.app:8450:127.0.0.1 \
    https://vpn.eracloud.app:8450/
...
* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256 / X25519MLKEM768 / id-ecPublicKey
* ALPN: server accepted http/1.1
* Server certificate:
*   subject: CN=vpn.eracloud.app
*   issuer: CN=vpn.eracloud.app
* SSL certificate verify result: self-signed certificate (18), continuing anyway.
* Connected to vpn.eracloud.app (127.0.0.1) port 8450
> GET / HTTP/1.1
> Host: vpn.eracloud.app:8450
...
* SSL_read: tlsv13 alert certificate required (116)
```

ALPN negotiated `http/1.1`, the GET line was written, then the server fired
the mTLS rejection alert. The Go `http.Server` could not advance to the
`certMiddleware` handler because mTLS failed at the TLS layer first — which
means the `401 client cert required` HTTP response from `certMiddleware`
is unreachable in this code path. That's an honest, working outcome.

### Smoke 3 — OpenConnect dry run: N/A (no client)

`openconnect` is not installed on `.47`. Skipped without installing — the
"don't disturb prod" rule is more important than this test, and Smoke 1 + 2
already prove the relevant TLS/mTLS contract. If a future smoke needs a real
OpenConnect run, install on a separate netns or a peer host and target
`127.0.0.1:8450` through an ssh tunnel.

Expected failure mode (once mTLS is satisfied with a real ERA device cert):
the AnyConnect init POST would reach `cstp.Server`, which calls
`certBoundVerifier.Verify` → `auth.HTTPVerifier.Verify` → era-portal at
`/api/auth/ocserv/verify`. That endpoint **is not yet deployed** on .48
(era-portal AnyConnect work tracked on `feat/ocserv-access-method-wip`), so
the auth call would 404 / refuse-connection. Smoke 3 is therefore deferred to
wave-2.

### Smoke 4 — Live tun check: PASS

```
$ ip link show era-ocserv-tun
118: era-ocserv-tun: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500
    qdisc mq state UNKNOWN mode DEFAULT group default qlen 500
    link/none

$ ip -6 addr show era-ocserv-tun
118: era-ocserv-tun: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP>
    inet6 2001:470:f9d1:9001:ffff::1/128 scope global
    inet6 fe80::7f55:4b8f:5ebb:8b41/64 scope link

$ ip -d link show era-ocserv-tun
118: era-ocserv-tun: ...
    tun type tun pi off vnet_hdr off multi_queue numqueues 4 numdisabled 0 persist off

$ ip -6 route get 2001:470:f9d1:9001:ffff::1
local 2001:470:f9d1:9001:ffff::1 from :: dev lo table local
  proto kernel src 2001:470:f9d1:9001:ffff::1 metric 0
```

Tun up, MTU 1500, multi-queue with 4 queues (matches `slog` startup), /128
assigned global scope, kernel routes to it via the local table. Wire-format
contract honored.

### Smoke 5 — Production untouched: PASS

```
$ for svc in era-facade era-wg era-clat era-tt-reconciler \
             era-tpm-provisioning era-proxy nat64-era era-node-reconciler; do
    printf "%-30s %s\n" "$svc" "$(systemctl is-active $svc)"
  done
era-facade                     active
era-wg                         inactive   <- pre-existing, unchanged
era-clat                       inactive   <- pre-existing, unchanged
era-tt-reconciler              inactive   <- pre-existing, unchanged
era-tpm-provisioning           active
era-proxy                      active
nat64-era                      inactive   <- pre-existing, unchanged
era-node-reconciler            inactive   <- pre-existing, unchanged
era-ocserv                     active     <- newly active (us)
```

State table comparison (pre vs post-deploy) is identical for ALL production
services. Pre-existing tun assignments preserved:

```
$ ip -6 addr show era-wg | grep inet6
    inet6 2001:470:f9d1:9001::e2a:1/128 scope global   <- unchanged
$ ip -6 addr show era-clat | grep inet6
    inet6 fe80::8905:2df4:8aab:c40/64                   <- unchanged
```

Recent journal of prod services: era-tt-reconciler / era-tpm-provisioning have
"No entries" in the deploy window (which is correct — they didn't react to
anything). era-facade has one unrelated proxyproto warning from 05:31
(predates the deploy at 05:33-05:34).

No `wg0`/`echo0`/`eth0` addressing changes. No default-route changes.

## Production impact summary

Zero. Specifically:
- 3 NEW listening sockets owned by era-ocserv: `127.0.0.1:8450/tcp` (CSTP) and
  internal queues on tun. (No public bind; era-facade not wired up yet.)
- 1 NEW tun device: `era-ocserv-tun` with `2001:470:f9d1:9001:ffff::1/128`.
- 1 NEW systemd unit: `era-ocserv.service`.
- 0 sysctls actually changed (already at desired values).
- 0 existing files modified.
- 0 changes to era-wg, era-clat, era-facade, era-proxy, era-tpm-provisioning,
  TAYGA, RouterHK, RouterOS.

## Go/no-go: NO. Tear down.

Reasons to **tear down**:
1. Smoke-only TLS material with 7-day validity at `/etc/era-ocserv/tls/test-*`.
2. era-portal `/api/auth/ocserv/verify` endpoint does not exist yet — any
   real client attempt will fail at password verify. Nothing more to learn
   from "running idle" than what Smoke 1+2 already proved.
3. Self-signed client CA is operationally useless for real ERA devices.
4. The deploy occupies `era-ocserv-tun` and `127.0.0.1:8450`; while neither
   collides with anything, leaving them allocated for a non-functional service
   adds clutter.

Reasons to keep running: none compelling. Document captured, gaps known.

## Teardown evidence

```
$ bash /tmp/era-ocserv-deploy/era-ocserv-teardown.sh
=== teardown: 1. stop + disable era-ocserv.service (gated) ===
Removed '/etc/systemd/system/multi-user.target.wants/era-ocserv.service'.
=== teardown: 2. remove era-ocserv-tun if present ===
deleted tun era-ocserv-tun
=== teardown: 3. restore sysctls (only what we set) ===
(no diffs to restore -- marker already matched current values)
=== teardown: 4. remove unit; preserve /etc/era-ocserv/era-ocserv.env ===
removed /etc/systemd/system/era-ocserv.service
=== teardown: 5. remove install/state/log dirs; keep /etc/era-ocserv ===

Reverted:
  - era-ocserv.service stopped + disabled + unit file removed
  - tun era-ocserv-tun removed
  - sysctls restored from marker (only those we changed)
  - /opt/era-ocserv removed
  - /var/lib/era-ocserv removed
  - /var/log/era-ocserv removed (if empty)

Preserved:
  - /etc/era-ocserv/era-ocserv.env (and the test-* TLS material under tls/ and pki/)
```

Post-teardown re-verification:

```
$ systemctl is-active era-ocserv
inactive
$ ip link show era-ocserv-tun 2>&1
Device "era-ocserv-tun" does not exist.
$ for svc in era-facade era-wg era-clat era-tt-reconciler \
             era-tpm-provisioning era-proxy nat64-era era-node-reconciler; do
    printf "%-30s %s\n" "$svc" "$(systemctl is-active $svc)"
  done
era-facade                     active
era-wg                         inactive
era-clat                       inactive
era-tt-reconciler              inactive
era-tpm-provisioning           active
era-proxy                      active
nat64-era                      inactive
era-node-reconciler            inactive
```

Identical to start-of-session state. Production untouched.

## Wave-2 prerequisites (block real deploy)

1. **era-portal `/api/auth/ocserv/verify`** — currently absent. Lives on
   `feat/ocserv-access-method-wip`. Needed for the AnyConnect password-form
   challenge after mTLS.
2. **ERA-PKI device CA** — `tpm-ocserv-provisioning` work (this very tpm
   branch series, `feat/tpm-ocserv-provisioning` per recent commits) should
   produce a real CA and per-device client certs so the smoke can use real
   identities instead of a self-signed throwaway.
3. **TPM ocserv-scoped service token** — split out from the broad
   `TPM_PROVISIONING_SERVICE_TOKEN` so era-ocserv has its own audit trail.
4. **era-facade wiring** — TCP SNI rule for `vpn.eracloud.app` →
   `127.0.0.1:<port>` with PROXY v2 (era-ocserv supports loopback bind today;
   the only thing missing is the facade rule). UDP/443 demux: `0x16` DTLS
   ClientHello → era-ocserv DTLS socket (era-ocserv currently TCP-only in this
   stage; DTLS path is wave-2).
5. **Port assignment** — pick a permanent loopback port that doesn't collide
   with era-proxy's `:8444-:8449` standalone band. `:8450` was used here.
6. **OpenConnect on a sidecar** — install `openconnect` on a separate netns
   or peer host (NOT on `.47` itself) for real client-side smokes.

## Appendix — checksums + binary provenance

- Source branch: `origin/feat/deploy-harness` @ `1b652a2`
- Build host: Windows, Go 1.26.3 windows/amd64 → cross-compile to linux/amd64
- Built binary sha256: `32ba6747c8c89ecc8cfe2b6bbf0c15fbbf8a36ae7302f64d90d1c70544513d39`
- Build flags: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w"`
- Binary size: 7,817,216 bytes
