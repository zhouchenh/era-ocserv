# era-ocserv deploy (covert UDS path, inner-v4 CLAT)

Source of truth for the data-plane host (`.47`). The actual apply is a **gated**
guarded swap — never deploy without an operator go-point and a `DEPLOYS.md` row.
The working CSTP / DTLS / native-IPv6 path MUST survive every step; `wg0`/`echo0`
are never touched.

## Files
- `era-ocserv-launch.sh` → `/usr/local/bin/era-ocserv-launch.sh` — UDS-mode launch,
  metrics-clean (no `-metrics-*`; those crash start). No CLAT flag needed — the
  CLAT-source /128 is per-device via the tpm client-config (`source_ipv6_clat`
  preferred, `source_ipv6_ocserv_clat` accepted during rollout).
- `era-ocserv-mss-clamp.sh` → `/usr/local/bin/era-ocserv-mss-clamp.sh` — idempotent;
  adds `era-ocserv-tun` to the host TCP-MSS clamp (`inet era_nat64` forward chain)
  so inner-v4 large TCP does not blackhole.
- `era-ocserv.service` → `/etc/systemd/system/era-ocserv.service` — runs the launch
  wrapper and ensures the MSS clamp via `ExecStartPost`.

## How the inner-v4 CLAT works (CLAT-only; no NAT64/NAT44/TAYGA)
era-ocserv translates the client's inner IPv4 (placeholder `192.0.0.1`) to/from
IPv6 statelessly (SIIT, RFC 6145/7915), sourced from the device's CLAT-source
`/128`: client `192.0.0.1 → D4` becomes `CLAT/128 → 64:ff9b::D4`, written to
`era-ocserv-tun`. There is **no** host `64:ff9b::/96` route — it falls through the
default IPv6 RA route on `eth0` to the existing external 464PLAT. The reverse
(`64:ff9b::D4 → CLAT/128`) is routed back to `era-ocserv-tun` by the reconciler
(it routes BOTH the native and the CLAT `/128` + proxy-NDPs both on `eth0`) and
SIIT'd back to `D4 → 192.0.0.1` for the client.

## Gated deploy order (guarded swap, one holder at a time)
1. **tpm trio** (`.47`, migration-bearing → backup binary **and** DB `.bak.<ts>`):
   `tpm`, `era-node-reconciler`, `tpmctl` — built from the SAME checkout so the
   embedded migrations (incl. `0025_address_assignment_ocserv_clat_kind`) match.
   `systemctl stop` → `install -m0755` → sha256 host==local → `systemctl start` →
   check reconciler journal `reconcile pass … failed=0` + `era-ep-sync.log`.
2. **era-ocserv** (`.47`): backup binary → `systemctl stop era-ocserv` →
   `install -m0755 era-ocserv /usr/local/bin/era-ocserv` → install the three deploy
   files above → `systemctl daemon-reload` → `systemctl start era-ocserv` →
   readiness poll; auto-rollback on failure.
3. **Re-provision the test device** (device 38 / `dev_OC`) so it gets its
   `ocserv_clat_ipv6` /128: deprovision + reprovision via tpm; confirm the
   reconciler now routes BOTH `/128`s `dev era-ocserv-tun` + proxy-NDP on `eth0`.
   Transparent to the iPhone (server-assigned /128 + `192.0.0.1`; no profile change).

## Acceptance (harness on `.48`)
- `oc-v6test.sh` still PASSES (no native regression).
- `oc-v4test.sh` ping `1.1.1.1` through the tunnel = 0% loss (the gap closed).
- TCP large-transfer through the tunnel (MSS-clamp proof — pages fully load).
- Real iPhone Cisco Secure Client (`eracloud.app`, `dev_OC` id + secret) holds
  **indefinitely** with full v4 + v6.
