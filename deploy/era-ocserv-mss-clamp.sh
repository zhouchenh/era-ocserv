#!/bin/sh
# Ensure era-ocserv-tun is in the host TCP-MSS clamp. Idempotent; safe on every
# start. Without this, the tunnel's inner v4 (CLAT/SIIT) blackholes large TCP
# ("pages half-load") because SIIT46 grows each packet by 20 bytes.
#
# The shared `inet era_nat64` forward chain (owned by the WG/CLAT data-plane
# deploy) clamps era-wg / era-clat / nat64-era via INLINE anonymous sets, which
# cannot be extended with `nft add element`. So we add two comment-tagged rules
# for era-ocserv-tun and never touch the WG/CLAT rules. `iifname`/`oifname` match
# by name, so the rules are valid even before the tun device exists.
#
# We clamp to a FIXED MSS, not `set rt mtu`. The WG path can use `rt mtu` because
# its traffic routes via era-clat (a 1280-MTU iface). era-ocserv instead SIITs the
# inner packet and routes it out eth0 (MTU 1500), so `rt mtu` would resolve to
# 1500 and miss the real bottleneck: the AnyConnect client is reached over
# DTLS-in-UDP (the covert :443 path) plus the SIIT +20 must fit the path MTU.
# Per DEC-l3-mtu-model the inner MTU is LOCKED at 1400, so the inner TCP MSS is the
# plain MTU-derived value per family: v6 1340 (1400-40-20), v4 1360 (1400-20-20) —
# see the per-family vars below. Without this, the TCP handshake completes but the
# first full-size data segment blackholes.
set -eu

# --- Outer AnyConnect MSS clamp (covert :443 path) ---------------------------
# The iOS AnyConnect client reaches the covert apex over an OUTER TCP/TLS to
# :443, and that single CSTP/TLS stream carries ALL tunnel data — so on a lossy
# 5G link it is MSS-bound (Mathis: throughput ~ MSS/(RTT*sqrt(loss))). The rule
# was originally an over-conservative MSS 900; raising it to 1200 measured ~+40%
# and, combined with BBR, took a real iPhone 5G run from 6.3 -> 24.5 Mbps,
# validated safe under 466 MB of load (path PMTU 1500, zero black-hole). 1200 ->
# ~1260 B packet stays under the IPv6 1280 floor so any v6 path carries it, and
# PMTUD lowers it further on smaller paths. Lives in its own `inet era_mss`
# table, created here if absent (it is NOT in /etc/nftables.conf, which flushes
# the ruleset on load). Runs BEFORE the era_nat64 early-exit so the outer clamp
# is ensured even on a host where the WG/CLAT table is absent.
OUTER_TABLE="inet era_mss"
OUTER_CHAIN="prerouting"
OUTER_TAG="era-ac-outer-mss"
OUTER_MSS="1200"
nft add table $OUTER_TABLE 2>/dev/null || true
nft add chain $OUTER_TABLE $OUTER_CHAIN '{ type filter hook prerouting priority mangle; policy accept; }' 2>/dev/null || true
nft -a list chain $OUTER_TABLE $OUTER_CHAIN 2>/dev/null \
  | grep "comment \"$OUTER_TAG\"" \
  | grep -oE 'handle [0-9]+' | awk '{print $2}' \
  | while read -r h; do nft delete rule $OUTER_TABLE $OUTER_CHAIN handle "$h"; done
nft add rule $OUTER_TABLE $OUTER_CHAIN tcp dport 443 tcp flags syn counter tcp option maxseg size set $OUTER_MSS comment "$OUTER_TAG"
echo "era-ocserv-mss-clamp: outer :443 MSS clamp ensured ($OUTER_MSS)"

TABLE="inet era_nat64"
CHAIN="forward"
TAG="era-ocserv-clat"
# LOCKED L3 MTU model (DEC-l3-mtu-model): inner MTU 1400, so MSS = MTU - IP - TCP,
# per family. NO CLAT pre-shrink (we do NOT subtract the SIIT +20 here) — the
# server owns the v4->v6 growth on egress; this clamp only sizes inner TCP to the
# 1400 tunnel MTU. Replaces the old over-conservative 1280 (set while DTLS broke).
MSS6="1340"   # 1400 - 40 (IPv6 hdr) - 20 (TCP hdr)
MSS4="1360"   # 1400 - 20 (IPv4 hdr) - 20 (TCP hdr)

if ! nft list table $TABLE >/dev/null 2>&1; then
  echo "era-ocserv-mss-clamp: table '$TABLE' absent (WG/CLAT deploy owns it); skipping" >&2
  exit 0
fi

# Idempotency: delete any previously-installed tagged rules, then re-add fresh.
nft -a list chain $TABLE $CHAIN 2>/dev/null \
  | grep "comment \"$TAG\"" \
  | grep -oE 'handle [0-9]+' | awk '{print $2}' \
  | while read -r h; do nft delete rule $TABLE $CHAIN handle "$h"; done

nft add rule $TABLE $CHAIN iifname "era-ocserv-tun" meta nfproto ipv6 tcp flags syn tcp option maxseg size set $MSS6 comment "$TAG"
nft add rule $TABLE $CHAIN oifname "era-ocserv-tun" meta nfproto ipv6 tcp flags syn tcp option maxseg size set $MSS6 comment "$TAG"
nft add rule $TABLE $CHAIN iifname "era-ocserv-tun" meta nfproto ipv4 tcp flags syn tcp option maxseg size set $MSS4 comment "$TAG"
nft add rule $TABLE $CHAIN oifname "era-ocserv-tun" meta nfproto ipv4 tcp flags syn tcp option maxseg size set $MSS4 comment "$TAG"
echo "era-ocserv-mss-clamp: era-ocserv-tun MSS clamp ensured (v6 $MSS6 / v4 $MSS4)"
