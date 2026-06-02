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
# the iam resolver.
#
# -tun-mtu 1420: LOCKED L3 MTU model per DEC-l3-mtu-model (_program/DECISION_LOG.md).
# This is the SERVER-SIDE tun MTU only. The WIRE advertised to the client is ALWAYS
# 1400 (X-CSTP-MTU = X-DTLS-MTU = 1400, set in code: negotiateInnerMTU returns the
# locked const, INDEPENDENT of this flag). The tun is 1420 because a CLAT v4 packet,
# after the on-server v4->v6 SIIT (+20), becomes a 1420-B IPv6 packet that must
# transit this tun toward the Internet (1400 inner v4 -> 1420 v6 == IPv6OutboundMTU,
# fits the clean 1500 datacenter egress). Native IPv6 has ZERO translation and is
# 1400 everywhere. The ±20 is ENTIRELY server-side and never touches the client
# wire; no DTLS/CSTP datagram is sized with the +20.
# MSS clamp off the 1400 wire: v6 1340 (1400-60), v4 1360 (1400-40) — nft on
# era-ocserv-tun. Dynamic PMTUD for constrained tails (cellular, v6-outer) is
# driven by server-side ICMPv6-PTB origination (DEC-l3-mtu-model); do NOT shrink
# the static 1400/1420 to compensate.
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
  -tun-mtu 1420 \
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
