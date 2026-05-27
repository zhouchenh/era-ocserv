#!/usr/bin/env bash
# era-ocserv host setup: idempotent prep for the .47 (or any) data-plane host.
#
# Creates the directory layout under /opt /etc /var, lands a placeholder env
# file (no secrets), enables the sysctls era-ocserv needs to route IPv6 client
# traffic, and writes a marker so teardown can revert ONLY what we set.
#
# DESIGN INVARIANTS:
#  - era-wg / era-clat / era-tt-reconciler must not be disturbed. Different tun
#    name (era-ocserv-tun), different ports (era-ocserv listens 127.0.0.1:8444
#    via era-facade splice; udp DTLS comes from era-facade :443 demux).
#  - Idempotent. Running this twice converges to the same state.
#  - Re-uses sysctls already set by era-dataplane-setup.sh (forwarding=1,
#    accept_ra=2). We DO NOT fight those - we only set them if missing.
#  - Marker file at /var/lib/era-ocserv/.setup-marker records the original
#    sysctl values so teardown can restore them.
#
# WHAT THIS DOES NOT DO:
#  - Does not install the binary. Operator scp's it to /opt/era-ocserv/.
#  - Does not populate real secrets. The env file ships with placeholders.
#  - Does not enable / start the unit. Operator runs systemctl after editing
#    /etc/era-ocserv/era-ocserv.env.
set -euo pipefail

EGRESS_IF="${EGRESS_IF:-eth0}"
PROXY_NDP="${PROXY_NDP:-0}"            # 1 to set proxy_ndp on EGRESS_IF
INSTALL_ROOT=/opt/era-ocserv
ETC_DIR=/etc/era-ocserv
STATE_DIR=/var/lib/era-ocserv
LOG_DIR=/var/log/era-ocserv
ENV_FILE="${ETC_DIR}/era-ocserv.env"
UNIT_SRC="$(cd "$(dirname "$0")" && pwd)/era-ocserv.service"
UNIT_DST=/etc/systemd/system/era-ocserv.service
MARKER="${STATE_DIR}/.setup-marker"

log(){ printf '\n=== %s ===\n' "$*"; }

if [ "$(id -u)" != "0" ]; then
  echo "FATAL: era-ocserv-setup.sh must run as root" >&2
  exit 1
fi

# ---- 0. directories + perms ----
log "0. directory layout"
install -d -m 0755 "$INSTALL_ROOT"
install -d -m 0750 "$ETC_DIR"
install -d -m 0750 "$STATE_DIR"
install -d -m 0755 "$LOG_DIR"

# ---- 1. record original sysctls BEFORE we touch them (idempotent) ----
# We only write the marker on first run. Subsequent runs preserve the original
# values so teardown always sees the pre-setup state.
log "1. record original sysctls"
if [ ! -f "$MARKER" ]; then
  ORIG_FWD="$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 0)"
  ORIG_RA="$(cat /proc/sys/net/ipv6/conf/${EGRESS_IF}/accept_ra 2>/dev/null || echo 1)"
  ORIG_NDP="$(cat /proc/sys/net/ipv6/conf/${EGRESS_IF}/proxy_ndp 2>/dev/null || echo 0)"
  cat > "$MARKER" <<EOF
# era-ocserv setup marker. DO NOT EDIT.
# Captured pre-setup sysctls so teardown can restore them.
ORIG_FWD=${ORIG_FWD}
ORIG_RA=${ORIG_RA}
ORIG_NDP=${ORIG_NDP}
ORIG_EGRESS_IF=${EGRESS_IF}
ORIG_PROXY_NDP=${PROXY_NDP}
EOF
  chmod 0600 "$MARKER"
fi

# ---- 2. sysctls (only push if not already set) ----
# IPv6 forwarding: required so the kernel routes client v6 traffic through us.
# accept_ra=2: with forwarding=1 the kernel ignores RA-learned routes UNLESS
# accept_ra=2. The host receives its v6 default route via RA on .47 so without
# this the default route lapses and host v6 (and our egress) breaks. Same hack
# era-dataplane-setup.sh applies; safe to set twice.
log "2. sysctls (only-if-unset semantics)"
cur_fwd="$(cat /proc/sys/net/ipv6/conf/all/forwarding)"
[ "$cur_fwd" = "1" ] || sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
cur_ra="$(cat /proc/sys/net/ipv6/conf/${EGRESS_IF}/accept_ra 2>/dev/null || echo 1)"
[ "$cur_ra" = "2" ] || sysctl -w net.ipv6.conf.${EGRESS_IF}.accept_ra=2 >/dev/null

if [ "$PROXY_NDP" = "1" ]; then
  # Optional: era-wg already proxy-NDPs the global /64 sub-pool it owns. Only
  # enable this if era-ocserv's /128 pool is NOT covered by an existing era-wg
  # proxy_ndp regime (consult tpm desired state). Otherwise leave PROXY_NDP=0.
  cur_ndp="$(cat /proc/sys/net/ipv6/conf/${EGRESS_IF}/proxy_ndp 2>/dev/null || echo 0)"
  [ "$cur_ndp" = "1" ] || sysctl -w net.ipv6.conf.${EGRESS_IF}.proxy_ndp=1 >/dev/null
fi

# ---- 3. sample env file (placeholders only; do not overwrite an existing) ----
log "3. sample env file"
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<'EOF'
# era-ocserv environment file. Loaded by era-ocserv.service via EnvironmentFile=.
# Operator: replace REPLACE_ME placeholders with real values before enabling
# the unit. Permissions 0600, root:root.
#
# All era-ocserv flags ride in ERA_OCSERV_ARGS; the systemd ExecStart only
# expands this single variable so wrapping/quoting stays simple.

ERA_OCSERV_ARGS=" \
  -listen 127.0.0.1:8444 \
  -tls-cert /etc/era-ocserv/tls/fullchain.pem \
  -tls-key  /etc/era-ocserv/tls/privkey.pem \
  -client-ca /etc/era-ocserv/pki/era-client-ca.pem \
  -era-portal-url https://portal.internal.eracloud.app \
  -era-portal-token REPLACE_ME_ERA_PORTAL_SERVICE_TOKEN \
  -tpm-url http://127.0.0.1:9090 \
  -tpm-token REPLACE_ME_TPM_SERVICE_TOKEN \
  -tun-name era-ocserv-tun \
  -tun-mtu  1500 \
  -tun-queues 0 \
  -tun-ipv6 2001:470:f9d1:9001:ffff::1/128 \
  -server-name vpn.eracloud.app \
  -dns 2606:4700:4700::1111,2606:4700:4700::1001 \
  -log-level info \
"
EOF
  chmod 0600 "$ENV_FILE"
  echo "wrote sample ${ENV_FILE} (placeholders; edit before enabling unit)"
else
  echo "preserved existing ${ENV_FILE} (no overwrite)"
fi

# ---- 4. install the systemd unit ----
log "4. systemd unit"
if [ ! -f "$UNIT_SRC" ]; then
  echo "FATAL: unit source ${UNIT_SRC} missing; run from deploy/" >&2
  exit 1
fi
install -m 0644 "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload

# ---- 5. next steps ----
log "setup complete"
cat <<EOF
Next steps for the operator:

  1. Copy the era-ocserv binary into place:
       install -m 0755 era-ocserv ${INSTALL_ROOT}/era-ocserv

  2. Populate ${ENV_FILE} with real values (TLS cert + key, ERA PKI client CA,
     era-portal + TPM service tokens). The file ships with REPLACE_ME placeholders.

  3. Drop the TLS material:
       install -m 0644 fullchain.pem /etc/era-ocserv/tls/fullchain.pem
       install -m 0600 privkey.pem  /etc/era-ocserv/tls/privkey.pem
       install -m 0644 era-client-ca.pem /etc/era-ocserv/pki/era-client-ca.pem
     (Create /etc/era-ocserv/tls and /etc/era-ocserv/pki first if absent.)

  4. Enable + start:
       systemctl enable --now era-ocserv
       systemctl status era-ocserv

  5. Front the gateway via era-facade:
       - TCP/443 SNI rule for vpn.eracloud.app -> 127.0.0.1:8444, PROXY v2 on
       - UDP/443 demux: 0x16 ClientHello -> era-ocserv DTLS loopback socket
     (No collision with era-wg :51821/udp or era-clat :51822/udp.)

If PROXY_NDP=1 was passed and era-wg already proxies the global /64, undo with:
  PROXY_NDP=0 ${0}  # plus a manual sysctl revert via the teardown script
EOF
