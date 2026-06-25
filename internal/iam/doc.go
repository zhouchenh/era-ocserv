// Package iam resolves a device UUID to the per-device identity era-ocserv
// needs to set up a session: the assigned IPv6 /128 from ERA's
// 2001:470:f9d1:9001::/64 pool, optional MTU/DNS/search-domain overrides.
//
// This package OWNS the device-UUID -> identity lookup. It does NOT own:
//
//   - client cert parsing / chain validation (internal/auth)
//   - password-form challenge verification (internal/auth)
//   - any AnyConnect wire-protocol concerns (internal/cstp)
//
// The TPMResolver is backed by TPM's authenticated provisioning HTTP API
// (ADR 0054) and reads the per-device client-config to extract the assigned
// IPv6 /128 (ADR 0035 / ADR 0036). Behavior contract:
//
//   - Endpoint: GET <BaseURL>/v1/provision/device/<deviceID>/client-config
//   - Auth: Authorization: Bearer <ServiceToken> (a tpmsvc1_-prefixed token,
//     ADR 0054). The token is never logged.
//   - The returned /128 MUST fall inside 2001:470:f9d1:9001::/64; anything
//     else is rejected with ErrUpstream. The allowlist is configurable.
//   - The client-config advertises two source fields:
//     provisioning.ClientConfig.SourceIPv6Ocserv ("source_ipv6_ocserv",
//     PREFERRED — the AnyConnect device's OWN /128, kind ocserv_ipv6, routed
//     to era-ocserv-tun per DEC-anyconnect-own-128) and SourceIPv6Native
//     ("source_ipv6_native", FALLBACK for a TPM that predates the ocserv
//     field). The resolver prefers ocserv and falls back to native, parsing
//     the result as a netip.Prefix. Per DEC-anyconnect-own-128 an AnyConnect
//     device gets its own /128 and may coexist with a WireGuard binding; this
//     package only READS the binding.
//   - A CLAT-enabled AnyConnect device also advertises source_ipv6_clat
//     (preferred, current TPM main) or source_ipv6_ocserv_clat (legacy
//     deployed TPM branch). The resolver accepts both and prefers the shared
//     source_ipv6_clat field.
//
// Subject to revision: the endpoint path or response shape may evolve when
// the era-ocserv tpmctl subcommands land (a separate agent's work). If a
// dedicated era-ocserv binding endpoint is added later, swap the URL builder
// here; the Resolver interface should stay stable.
//
// The resolver maintains a small in-memory cache keyed by device id with a
// short TTL, and uses singleflight to coalesce concurrent lookups for the
// same device id. On an upstream error during a refresh, a non-hard-expired
// cached value is served (one TTL of buffer) so a brief TPM blip does not
// flap live sessions.
package iam
