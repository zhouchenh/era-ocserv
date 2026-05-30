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
set -eu

TABLE="inet era_nat64"
CHAIN="forward"
TAG="era-ocserv-clat"

if ! nft list table $TABLE >/dev/null 2>&1; then
  echo "era-ocserv-mss-clamp: table '$TABLE' absent (WG/CLAT deploy owns it); skipping" >&2
  exit 0
fi

# Idempotency: delete any previously-installed tagged rules, then re-add fresh.
nft -a list chain $TABLE $CHAIN 2>/dev/null \
  | grep "comment \"$TAG\"" \
  | grep -oE 'handle [0-9]+' | awk '{print $2}' \
  | while read -r h; do nft delete rule $TABLE $CHAIN handle "$h"; done

nft add rule $TABLE $CHAIN iifname "era-ocserv-tun" tcp flags syn tcp option maxseg size set rt mtu comment "$TAG"
nft add rule $TABLE $CHAIN oifname "era-ocserv-tun" tcp flags syn tcp option maxseg size set rt mtu comment "$TAG"
echo "era-ocserv-mss-clamp: era-ocserv-tun MSS clamp ensured"
