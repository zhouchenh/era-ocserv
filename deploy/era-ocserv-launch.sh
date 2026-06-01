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
  -dns 2001:470:f9d1:6666::64 \
  -log-level debug
#
# -dns MUST be the DNS64 resolver (2001:470:f9d1:6666::64), NOT a plain v6
# recursive resolver. The data plane is CLAT-only (464XLAT): the client has no
# native v4 route, so every v4-only destination has to be reached as a
# synthesized 64:ff9b::<v4> AAAA over the v6 tunnel. A non-DNS64 resolver (e.g.
# Cloudflare 2606:4700:4700::1111) returns real A records the client cannot
# route, so v4-only sites silently fail. The DNS64 resolver synthesizes the
# 64:ff9b::/96 AAAAs the host NAT64 then translates. Keep this in lockstep with
# the NAT64 prefix and the reconciler route.
