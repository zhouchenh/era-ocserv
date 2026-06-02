package iam

import (
	"context"
	"errors"
	"net/netip"
)

// Identity is the per-device data era-ocserv needs to set up a session.
//
// IPv6 is the device's assigned native /128 from ERA's pool (ADR 0035 /
// 0036). MTU, DNS and DefaultDomain are optional overrides; a zero/empty
// value means "main wiring should use its config default".
type Identity struct {
	// DeviceID is the device UUID, e.g. "dev_<26 base32 chars>".
	DeviceID string
	// IPv6 is the assigned /128. The prefix length is always 128; the
	// address is always inside the configured pool.
	IPv6 netip.Prefix
	// IPv6CLAT is the device's SECOND /128 (kind ocserv_clat_ipv6),
	// advertised by TPM as source_ipv6_ocserv_clat. It is the source
	// address era-ocserv's stateless SIIT engine uses for the client's
	// inner-IPv4 (CLAT) traffic: the placeholder 192.0.0.1 is translated to
	// 64:ff9b::<v4dst> sourced from this /128. An invalid (zero) value means
	// the device has no CLAT /128 — CLAT is disabled and the session runs
	// v6-only, exactly as before. When valid the prefix length is always
	// 128 and the address is inside the configured pool.
	IPv6CLAT netip.Prefix
	// MTU is an optional per-device MTU override. Zero means default.
	MTU int
	// DNS is an optional override of the DNS resolvers to push as
	// X-CSTP-DNS. Empty means use the main wiring default.
	DNS []netip.Addr
	// DefaultDomain is an optional X-CSTP-Default-Domain override.
	// Empty means do not emit the header.
	DefaultDomain string
	// DTLSDisabled, when true, opts THIS device out of the DTLS (UDP) data
	// channel: era-ocserv advertises no X-DTLS-* headers, so the AnyConnect
	// client runs its data plane over CSTP/TLS (TCP) only. AnyConnect always
	// prefers DTLS when offered, so this is the per-device escape hatch for
	// networks where UDP is throttled/deprioritized. Sourced from the tpm
	// snapshot field "ocserv_dtls_disabled"; absent/false ⇒ DTLS offered as
	// usual. Intended future control surface: a user toggle in the ERA PWA.
	DTLSDisabled bool
}

// Resolver looks up an Identity for a device UUID. Implementations are
// safe for concurrent use.
type Resolver interface {
	// Resolve returns the Identity for deviceID. It returns
	// ErrDeviceNotFound when the device is unknown to TPM,
	// ErrNoTunnel when the device has no provisioned WG tunnel (so no
	// /128 has been allocated), and ErrUpstream wrapping the underlying
	// cause for any other failure (network, decode, validation).
	Resolve(ctx context.Context, deviceID string) (Identity, error)
}

// Error sentinels. Callers should test with errors.Is.
var (
	// ErrDeviceNotFound is returned when TPM does not know the device.
	ErrDeviceNotFound = errors.New("iam: device not found in TPM")
	// ErrNoTunnel is returned when TPM knows the device but there is no
	// active WG peer / no native /128 assigned to it. era-ocserv shares
	// the era-wg pool so a device with no peer cannot connect via the
	// AnyConnect transport either (ADR 0057 5).
	ErrNoTunnel = errors.New("iam: device has no provisioned WG/oc tunnel")
	// ErrUpstream wraps any other failure talking to TPM (HTTP/network,
	// JSON decode, address pool validation, etc.). The underlying cause
	// is wrapped with %w so callers can drill in if they need to.
	ErrUpstream = errors.New("iam: upstream TPM error")
)

// DefaultPoolPrefix is ERA's IPv6 pool the per-device /128s are drawn from
// (ADR 0035 / 0036; the same pool era-wg uses). Any /128 returned by TPM
// MUST be contained in this prefix; anything else is treated as a
// configuration error and rejected by the resolver.
var DefaultPoolPrefix = netip.MustParsePrefix("2001:470:f9d1:9001::/64")
