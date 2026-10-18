# Explicit ocserv CLAT source compatibility

The resolver prefers `source_ipv6_ocserv_clat` when present. It validates that
field as a nonempty IPv6 /128 within the configured pool. Present null, empty,
wrong-type, malformed, wrong-family or out-of-pool values fail closed, even if
a valid shared `source_ipv6_clat` exists. Only absence allows shared legacy
fallback. Native address selection and transport/cache behavior are unchanged.

TPM's additive schema-3 producer keeps existing field values. On dual-bound
devices the shared field is WireGuard's CLAT source, while the explicit field
identifies ocserv's distinct assignment. On ocserv-only devices both match.
Schema numbers alone do not establish this capability.

Fixtures in `internal/iam/testdata/tpm-clat` come from the real TPM disposable
allocator and ClientConfig serialization at the tree in `provenance.json`.
The normal HTTP resolver consumes those exact bytes through localhost httptest.
The dual-bound fixture has different shared/explicit values. Synthetic identities,
public keys and documentation IPv6 prefixes are used; no host/router operations.

Mixed-version boundary: a new producer with an old shared-first consumer still
selects the wrong CLAT identity on dual-bound records. A new consumer with an old
producer retains shared fallback for ocserv-only compatibility, but cannot prove
a dual-bound shared value belongs to ocserv. Both upgraded ends and integration
qualification are required before claiming dual-bound readiness. This change is
not deployment authorization or traffic proof and does not change Cloud's
separate projection.
