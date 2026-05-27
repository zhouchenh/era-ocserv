#!/usr/bin/env bash
# era-ocserv host teardown: revert only what era-ocserv-setup.sh created.
#
# Idempotent and safe to run after a partial/aborted setup. Reads
# /var/lib/era-ocserv/.setup-marker to restore the ORIGINAL sysctl values we
# captured at first setup. The env file at /etc/era-ocserv/era-ocserv.env is
# DELIBERATELY preserved - operators may want to keep credentials in place
# across re-installs. To wipe credentials, delete /etc/era-ocserv manually.
#
# Does NOT touch era-wg / era-clat / era-tt-reconciler. They share the host
# but live behind different tun names and unit files.
set -uo pipefail

INSTALL_ROOT=/opt/era-ocserv
ETC_DIR=/etc/era-ocserv
STATE_DIR=/var/lib/era-ocserv
LOG_DIR=/var/log/era-ocserv
ENV_FILE="${ETC_DIR}/era-ocserv.env"
UNIT_DST=/etc/systemd/system/era-ocserv.service
MARKER="${STATE_DIR}/.setup-marker"
TUN_NAME="${TUN_NAME:-era-ocserv-tun}"

log(){ printf '\n=== teardown: %s ===\n' "$*"; }

if [ "$(id -u)" != "0" ]; then
  echo "FATAL: era-ocserv-teardown.sh must run as root" >&2
  exit 1
fi

# ---- 1. stop + disable the unit if it exists ----
log "1. stop + disable era-ocserv.service (gated)"
if systemctl list-unit-files era-ocserv.service >/dev/null 2>&1; then
  systemctl stop era-ocserv.service 2>/dev/null || true
  systemctl disable era-ocserv.service 2>/dev/null || true
else
  echo "(unit not installed; skipping)"
fi

# ---- 2. remove a leftover tun interface (only if it still exists) ----
log "2. remove ${TUN_NAME} if present"
if ip link show "$TUN_NAME" >/dev/null 2>&1; then
  ip link del "$TUN_NAME" 2>/dev/null || true
  echo "deleted tun ${TUN_NAME}"
else
  echo "(no ${TUN_NAME}; skipping)"
fi

# ---- 3. restore sysctls if we recorded the pre-setup state ----
# We ONLY revert what the marker says we changed. If era-dataplane-setup.sh
# also relies on forwarding=1 or accept_ra=2 those are already-set and we
# leave them alone (the marker's ORIG_FWD/ORIG_RA would already be 1/2).
log "3. restore sysctls (only what we set)"
if [ -f "$MARKER" ]; then
  # shellcheck disable=SC1090
  . "$MARKER"
  EGRESS_IF="${ORIG_EGRESS_IF:-eth0}"

  cur_fwd="$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 1)"
  if [ "${ORIG_FWD:-1}" != "$cur_fwd" ]; then
    sysctl -w net.ipv6.conf.all.forwarding="${ORIG_FWD}" >/dev/null
    echo "restored net.ipv6.conf.all.forwarding=${ORIG_FWD}"
  fi

  cur_ra="$(cat /proc/sys/net/ipv6/conf/${EGRESS_IF}/accept_ra 2>/dev/null || echo 1)"
  if [ "${ORIG_RA:-1}" != "$cur_ra" ]; then
    sysctl -w net.ipv6.conf.${EGRESS_IF}.accept_ra="${ORIG_RA}" >/dev/null
    echo "restored net.ipv6.conf.${EGRESS_IF}.accept_ra=${ORIG_RA}"
  fi

  if [ "${ORIG_PROXY_NDP:-0}" = "1" ]; then
    cur_ndp="$(cat /proc/sys/net/ipv6/conf/${EGRESS_IF}/proxy_ndp 2>/dev/null || echo 0)"
    if [ "${ORIG_NDP:-0}" != "$cur_ndp" ]; then
      sysctl -w net.ipv6.conf.${EGRESS_IF}.proxy_ndp="${ORIG_NDP}" >/dev/null
      echo "restored net.ipv6.conf.${EGRESS_IF}.proxy_ndp=${ORIG_NDP}"
    fi
  fi
else
  echo "(no marker at ${MARKER}; leaving sysctls untouched)"
fi

# ---- 4. remove the systemd unit + reload (preserve env file) ----
log "4. remove unit; preserve ${ENV_FILE}"
if [ -f "$UNIT_DST" ]; then
  rm -f "$UNIT_DST"
  systemctl daemon-reload
  echo "removed ${UNIT_DST}"
fi

# ---- 5. remove our state + (empty) log dir + install root; KEEP /etc dir ----
# Install root: takes the binary the operator placed there.
# State dir: only holds our marker.
# Log dir: empty unless we ever grow file logging.
# /etc/era-ocserv: PRESERVED so credentials survive teardown.
log "5. remove install/state/log dirs; keep ${ETC_DIR}"
rm -rf "$STATE_DIR" 2>/dev/null || true
rmdir "$LOG_DIR" 2>/dev/null || true   # only if empty; never -rf on a log dir
rm -rf "$INSTALL_ROOT" 2>/dev/null || true

# ---- 6. summary ----
log "teardown complete"
cat <<EOF
Reverted:
  - era-ocserv.service stopped + disabled + unit file removed
  - tun ${TUN_NAME} removed (if it lingered)
  - sysctls restored from marker (only those we changed)
  - ${INSTALL_ROOT} removed
  - ${STATE_DIR} removed
  - ${LOG_DIR} removed (if empty)

Preserved (operator must remove manually if desired):
  - ${ENV_FILE} (and any other content under ${ETC_DIR})
  - /etc/era-ocserv/tls and /etc/era-ocserv/pki, if you placed material there

era-wg / era-clat / era-tt-reconciler untouched.
EOF
