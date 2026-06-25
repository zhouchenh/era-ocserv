package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultCacheTTL is the in-memory cache TTL when TPMResolverConfig.CacheTTL
// is zero. Short enough that a TPM-side change (e.g. operator deprovisions a
// device) propagates promptly; long enough to absorb a flap.
const DefaultCacheTTL = 60 * time.Second

// DefaultHTTPTimeout is the per-request timeout used when the caller does
// not supply an HTTPClient.
const DefaultHTTPTimeout = 5 * time.Second

// userAgent is sent on every TPM call so an operator reading TPM access
// logs can attribute lookups to era-ocserv.
const userAgent = "era-ocserv/iam"

// TPMResolverConfig configures a TPMResolver. BaseURL and ServiceToken are
// required; other fields take their documented defaults when zero.
type TPMResolverConfig struct {
	// BaseURL is the TPM provisioning HTTP endpoint root, e.g.
	// http://100.91.1.47:9090. Any trailing slash is tolerated.
	BaseURL *url.URL
	// ServiceToken is a tpmsvc1_-prefixed bearer token (ADR 0054). It
	// is sent verbatim as Authorization: Bearer <token>. The resolver
	// never logs the token.
	ServiceToken string
	// DisableCache, when true, suppresses the in-memory cache entirely
	// (every Resolve hits the upstream). Default is ENABLED — the zero
	// value of TPMResolverConfig gives you a working cache, per the
	// spec's "default true" convention.
	DisableCache bool
	// CacheTTL overrides the cache lifetime. Zero means DefaultCacheTTL.
	CacheTTL time.Duration
	// HTTPClient is the http.Client to use. Nil means a default client
	// with a DefaultHTTPTimeout request timeout.
	HTTPClient *http.Client
	// PoolPrefix is the IPv6 prefix the returned /128 must fall inside.
	// Zero value means DefaultPoolPrefix (ERA's
	// 2001:470:f9d1:9001::/64).
	PoolPrefix netip.Prefix
	// Now is the time source for cache expiry checks. Injected for
	// deterministic tests; production leaves it nil (time.Now).
	Now func() time.Time
}

// TPMResolver resolves device identity by calling TPM's authenticated
// provisioning HTTP API. It is safe for concurrent use.
type TPMResolver struct {
	baseURL      *url.URL
	serviceToken string
	httpClient   *http.Client
	pool         netip.Prefix
	cacheEnabled bool
	cacheTTL     time.Duration
	now          func() time.Time

	sf singleflight.Group

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// cacheEntry holds a successfully-resolved identity plus its expiry. We
// keep both a soft and a hard expiry: soft is the normal TTL; hard is
// 2*TTL, the window in which a refresh failure may serve the cached value
// (degraded-but-not-stale-forever).
type cacheEntry struct {
	id         Identity
	softExpiry time.Time
	hardExpiry time.Time
}

// NewTPMResolver constructs a TPMResolver. The configuration is validated
// strictly: a nil BaseURL or empty ServiceToken panics, because both are
// load-bearing for every call and silent fallback would mask a wiring bug
// from the caller.
func NewTPMResolver(cfg TPMResolverConfig) *TPMResolver {
	if cfg.BaseURL == nil {
		panic("iam: TPMResolverConfig.BaseURL is required")
	}
	if strings.TrimSpace(cfg.ServiceToken) == "" {
		panic("iam: TPMResolverConfig.ServiceToken is required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	pool := cfg.PoolPrefix
	if !pool.IsValid() {
		pool = DefaultPoolPrefix
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	// Default Cache=false (zero value) means ENABLED per the doc-comment
	// rationale; only DisableCache turns it off.
	enabled := !cfg.DisableCache
	r := &TPMResolver{
		baseURL:      copyURLNoFragment(cfg.BaseURL),
		serviceToken: cfg.ServiceToken,
		httpClient:   hc,
		pool:         pool,
		cacheEnabled: enabled,
		cacheTTL:     ttl,
		now:          now,
	}
	if enabled {
		r.cache = map[string]cacheEntry{}
	}
	return r
}

// Resolve implements Resolver.
//
// Lookup discipline:
//
//  1. Check the cache. If a soft-fresh entry exists, return it.
//  2. Otherwise singleflight a fetch (so 100 concurrent Resolves for the
//     same device id collapse to one upstream call).
//  3. On a successful fetch, install in the cache and return.
//  4. On a fetch failure, if a hard-not-expired cached entry exists serve
//     it (degraded mode); otherwise return the wrapped error.
func (r *TPMResolver) Resolve(ctx context.Context, deviceID string) (Identity, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return Identity{}, fmt.Errorf("%w: empty device id", ErrUpstream)
	}

	if r.cacheEnabled {
		if id, ok := r.cacheGetSoft(deviceID); ok {
			return id, nil
		}
	}

	type result struct {
		id  Identity
		err error
	}
	v, err, _ := r.sf.Do(deviceID, func() (any, error) {
		// Re-check the cache after entering the critical section: a
		// concurrent winner may have populated it while we were
		// waiting on the singleflight gate.
		if r.cacheEnabled {
			if id, ok := r.cacheGetSoft(deviceID); ok {
				return result{id: id}, nil
			}
		}
		id, ferr := r.fetch(ctx, deviceID)
		if ferr == nil {
			r.cachePut(deviceID, id)
			return result{id: id}, nil
		}
		// On terminal "not found" / "no tunnel", do not serve a stale
		// cache: the device is genuinely gone, and serving the old
		// /128 would let a deprovisioned device keep an AnyConnect
		// session up.
		if errors.Is(ferr, ErrDeviceNotFound) || errors.Is(ferr, ErrNoTunnel) {
			r.cacheDelete(deviceID)
			return result{err: ferr}, nil
		}
		// Transient (network / 5xx / decode) error: try to serve a
		// hard-fresh cached value. ErrUpstream-wrapped only.
		if r.cacheEnabled {
			if id, ok := r.cacheGetHard(deviceID); ok {
				return result{id: id}, nil
			}
		}
		return result{err: ferr}, nil
	})
	if err != nil {
		// singleflight only surfaces a non-nil error when the work
		// function panicked / returned an error directly. Our work
		// function always returns nil here (errors travel through the
		// result struct), so this branch is defensive.
		return Identity{}, fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	res := v.(result)
	return res.id, res.err
}

// fetch performs one upstream call to TPM and returns either an Identity
// or one of the sentinel-wrapped errors.
func (r *TPMResolver) fetch(ctx context.Context, deviceID string) (Identity, error) {
	endpoint := r.endpointFor(deviceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: build request: %v", ErrUpstream, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Authorization", "Bearer "+r.serviceToken)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: do request: %v", ErrUpstream, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusOK:
		// fall through
	case resp.StatusCode == http.StatusNotFound:
		return Identity{}, ErrDeviceNotFound
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return Identity{}, fmt.Errorf("%w: tpm rejected service token (%d)", ErrUpstream, resp.StatusCode)
	case resp.StatusCode >= 500 && resp.StatusCode <= 599:
		return Identity{}, fmt.Errorf("%w: tpm responded %d", ErrUpstream, resp.StatusCode)
	default:
		return Identity{}, fmt.Errorf("%w: tpm responded %d", ErrUpstream, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Identity{}, fmt.Errorf("%w: read body: %v", ErrUpstream, err)
	}
	// The TPM response shape is provisioning.ClientConfig
	// (internal/provisioning/clientconfig.go in github.com/zhouchenh/tpm).
	// We deliberately decode only the fields we need so an additive change
	// upstream does not break us; UnknownFields are tolerated.
	var raw struct {
		DeviceID             string `json:"device_id"`
		SourceIPv6Native     string `json:"source_ipv6_native"`
		SourceIPv6CLAT       string `json:"source_ipv6_clat"`
		SourceIPv6Ocserv     string `json:"source_ipv6_ocserv"`
		SourceIPv6OcservClat string `json:"source_ipv6_ocserv_clat"`
		// Per-device DTLS opt-out (CONTRACT field). When true, era-ocserv
		// advertises no DTLS and the client uses CSTP/TLS (TCP) only. Additive +
		// optional; absent ⇒ false ⇒ DTLS offered as usual. tpm/era-portal/PWA
		// emit this in a follow-up; era-ocserv reads + enforces it today.
		OcservDTLSDisabled bool `json:"ocserv_dtls_disabled"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return Identity{}, fmt.Errorf("%w: decode client-config: %v", ErrUpstream, err)
	}

	// Per DEC-anyconnect-own-128 the AnyConnect device has its OWN /128
	// (kind ocserv_ipv6), advertised as source_ipv6_ocserv and routed to
	// era-ocserv-tun. Prefer it; fall back to source_ipv6_native for
	// compatibility with a TPM that predates the ocserv field (and during
	// rollout, before tpm+reconciler ship the ocserv pass).
	prefix := strings.TrimSpace(raw.SourceIPv6Ocserv)
	field := "source_ipv6_ocserv"
	if prefix == "" {
		prefix = strings.TrimSpace(raw.SourceIPv6Native)
		field = "source_ipv6_native"
	}
	if prefix == "" {
		// TPM knows the device but no /128 has been allocated: no
		// provisioned tunnel for this device.
		return Identity{}, ErrNoTunnel
	}
	p, perr := r.validatePoolHost128(field, prefix)
	if perr != nil {
		return Identity{}, perr
	}

	id := Identity{
		DeviceID:     deviceIDOrFallback(raw.DeviceID, deviceID),
		IPv6:         p,
		DTLSDisabled: raw.OcservDTLSDisabled,
	}

	// Decode the device's CLAT-source /128 (kind ocserv_clat_ipv6).
	// Current TPM emits the shared CLAT-source field source_ipv6_clat; the
	// older live branch emitted the method-specific source_ipv6_ocserv_clat.
	// Prefer the shared field so this resolver matches current TPM main, but
	// keep the legacy fallback to avoid breaking a staggered rollout.
	clatPrefix := strings.TrimSpace(raw.SourceIPv6CLAT)
	clatField := "source_ipv6_clat"
	if clatPrefix == "" {
		clatPrefix = strings.TrimSpace(raw.SourceIPv6OcservClat)
		clatField = "source_ipv6_ocserv_clat"
	}
	// An empty value means CLAT is disabled for this device (the session runs
	// v6-only); only a present-but-malformed value is an error.
	if clatPrefix != "" {
		clatP, clatErr := r.validatePoolHost128(clatField, clatPrefix)
		if clatErr != nil {
			return Identity{}, clatErr
		}
		id.IPv6CLAT = clatP
	}

	return id, nil
}

// validatePoolHost128 parses prefix and enforces the IPv6 + /128 + in-pool
// invariants shared by the native and CLAT source addresses. field names the
// JSON key in error messages.
func (r *TPMResolver) validatePoolHost128(field, prefix string) (netip.Prefix, error) {
	p, perr := netip.ParsePrefix(prefix)
	if perr != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %s is not a valid prefix (%q): %v", ErrUpstream, field, prefix, perr)
	}
	if !p.Addr().Is6() {
		return netip.Prefix{}, fmt.Errorf("%w: %s is not IPv6 (%q)", ErrUpstream, field, prefix)
	}
	if p.Bits() != 128 {
		return netip.Prefix{}, fmt.Errorf("%w: %s is not a /128 (%q)", ErrUpstream, field, prefix)
	}
	if !r.pool.Contains(p.Addr()) {
		return netip.Prefix{}, fmt.Errorf("%w: %s %s is outside pool %s", ErrUpstream, field, p, r.pool)
	}
	return p, nil
}

// endpointFor builds the TPM URL for a device. The deviceID is path-
// escaped defensively; ERA's idgen device-ids are pure base32 + an
// underscore prefix so this should never actually transform them.
func (r *TPMResolver) endpointFor(deviceID string) string {
	u := *r.baseURL
	// Compose a clean path: strip any trailing slash on the base path,
	// then append the device endpoint. We do not use url.JoinPath
	// because we want the deviceID to be a single segment (no
	// implicit escaping of an embedded slash, which would silently
	// hide a malformed input).
	base := strings.TrimRight(u.Path, "/")
	u.Path = base + "/v1/provision/device/" + url.PathEscape(deviceID) + "/client-config"
	return u.String()
}

func deviceIDOrFallback(fromBody, fromArg string) string {
	if s := strings.TrimSpace(fromBody); s != "" {
		return s
	}
	return fromArg
}

// --- cache helpers ----------------------------------------------------------

func (r *TPMResolver) cacheGetSoft(deviceID string) (Identity, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[deviceID]
	if !ok {
		return Identity{}, false
	}
	if r.now().After(e.softExpiry) {
		return Identity{}, false
	}
	return e.id, true
}

func (r *TPMResolver) cacheGetHard(deviceID string) (Identity, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[deviceID]
	if !ok {
		return Identity{}, false
	}
	if r.now().After(e.hardExpiry) {
		// Hard-expired: drop so we don't keep it around indefinitely.
		delete(r.cache, deviceID)
		return Identity{}, false
	}
	return e.id, true
}

func (r *TPMResolver) cachePut(deviceID string, id Identity) {
	if !r.cacheEnabled {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.cache[deviceID] = cacheEntry{
		id:         id,
		softExpiry: now.Add(r.cacheTTL),
		hardExpiry: now.Add(2 * r.cacheTTL),
	}
}

func (r *TPMResolver) cacheDelete(deviceID string) {
	if !r.cacheEnabled {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, deviceID)
}

func copyURLNoFragment(u *url.URL) *url.URL {
	c := *u
	c.Fragment = ""
	c.RawFragment = ""
	return &c
}
