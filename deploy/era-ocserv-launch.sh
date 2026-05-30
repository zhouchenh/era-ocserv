#!/bin/sh
# Canonical era-ocserv launch wrapper for the covert UDS path behind era-facade.
# This is the source of truth for /usr/local/bin/era-ocserv-launch.sh on the
# data-plane host (.47). Keep it in sync; never hand-edit only the host copy.
#
# IMPORTANT: no -metrics-listen / -metrics-token flags. The cleaned CSTP lineage
# dropped the metrics listener; passing those flags makes era-ocserv exit
# 2/INVALIDARGUMENT on start. Do NOT reintroduce them.
#
# The inner-v4 CLAT (SIIT) needs NO launch flag: each device's CLAT-source /128
# arrives per-session from the tpm client-config (source_ipv6_ocserv_clat) via
# the iam resolver. The host TUN stays MTU 1500; era-ocserv advertises the inner
# MTU (1400) to the client itself.
set -eu

ERA_PORTAL_TOKEN=$(cat /etc/era-ocserv/portal-token)
TPM_TOKEN=$(cat /etc/era-ocserv/tpm-token)
FACADE_ADMIN_TOKEN=$(cat /etc/era-ocserv/facade-admin-token)

exec /usr/local/bin/era-ocserv \
  -mode=uds \
  -uds-socket /var/run/era-facade/handoffs/anyconnect-cstp.sock \
  -dtls-uds-socket /var/run/era-facade/handoffs/anyconnect-dtls.sock \
  -facade-admin-url http://127.0.0.1:8780 \
  -facade-admin-token "$FACADE_ADMIN_TOKEN" \
  -era-portal-url http://100.91.1.48:9080 \
  -era-portal-token "$ERA_PORTAL_TOKEN" \
  -tpm-url http://127.0.0.1:9090 \
  -tpm-token "$TPM_TOKEN" \
  -tun-name era-ocserv-tun \
  -tun-mtu 1500 \
  -tun-queues 0 \
  -tun-ipv6 2001:470:f9d1:9001:ffff::1/128 \
  -server-name eracloud.app \
  -dns 2606:4700:4700::1111,2606:4700:4700::1001 \
  -log-level debug
