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
// (ADR 0054) and reads the per-device client-config to extract the native
// IPv6 /128 (ADR 0035 / ADR 0036). Behavior contract:
//
//   - Endpoint: GET <BaseURL>/v1/provision/device/<deviceID>/client-config
//   - Auth: Authorization: Bearer <ServiceToken> (a tpmsvc1_-prefixed token,
//     ADR 0054). The token is never logged.
//   - The returned /128 MUST fall inside 2001:470:f9d1:9001::/64; anything
//     else is rejected with ErrUpstream. The allowlist is configurable.
//   - The TPM endpoint shape is the field returned by
//     provisioning.ClientConfig.SourceIPv6Native ("source_ipv6_native" in
//     JSON), parsed as a netip.Prefix. The allocation model (one /128 per
//     device, single-transport binding) is set by the tpm provisioning
//     orchestrator; this package only READS the binding.
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
