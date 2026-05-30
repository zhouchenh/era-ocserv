package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testDeviceID = "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	testToken    = "tpmsvc1_test_token_value"
)

// helper: build the JSON shape internal/provisioning.ClientConfig emits.
// We mirror the field names exactly so the resolver's decode path is
// genuinely exercised.
type fakeClientConfig struct {
	SchemaVersion        int    `json:"schema_version"`
	DeviceID             string `json:"device_id"`
	UserID               string `json:"user_id"`
	Username             string `json:"username"`
	DeviceName           string `json:"device_name"`
	PeerID               string `json:"peer_id"`
	ClientPublicKey      string `json:"client_public_key"`
	SourceIPv6Native     string `json:"source_ipv6_native,omitempty"`
	SourceIPv6CLAT       string `json:"source_ipv6_clat,omitempty"`
	SourceIPv6Ocserv     string `json:"source_ipv6_ocserv,omitempty"`
	SourceIPv6OcservClat string `json:"source_ipv6_ocserv_clat,omitempty"`
	// other fields elided
}

// newTestResolver wires a TPMResolver against a test server with the
// supplied handler. The returned cleanup func closes the server.
func newTestResolver(t *testing.T, h http.HandlerFunc, mut func(*TPMResolverConfig)) (*TPMResolver, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	cfg := TPMResolverConfig{
		BaseURL:      u,
		ServiceToken: testToken,
		CacheTTL:     50 * time.Millisecond,
	}
	if mut != nil {
		mut(&cfg)
	}
	return NewTPMResolver(cfg), srv
}

// assertAuth checks the bearer header on a request the handler received.
func assertAuth(t *testing.T, r *http.Request) {
	t.Helper()
	got := r.Header.Get("Authorization")
	want := "Bearer " + testToken
	if got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
}

func TestTPMResolverHappyPath(t *testing.T) {
	var requests int32
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&requests, 1)
		assertAuth(t, req)
		if got, want := req.Method, http.MethodGet; got != want {
			t.Errorf("method = %s, want %s", got, want)
		}
		wantPath := "/v1/provision/device/" + testDeviceID + "/client-config"
		if req.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", req.URL.Path, wantPath)
		}
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion:    1,
			DeviceID:         testDeviceID,
			SourceIPv6Native: "2001:470:f9d1:9001:dead:beef::1/128",
		})
	}, nil)

	id, err := r.Resolve(context.Background(), testDeviceID)
	if err != nil {
		t.Fatalf("Resolve err = %v", err)
	}
	if id.DeviceID != testDeviceID {
		t.Errorf("DeviceID = %q, want %q", id.DeviceID, testDeviceID)
	}
	want := netip.MustParsePrefix("2001:470:f9d1:9001:dead:beef::1/128")
	if id.IPv6 != want {
		t.Errorf("IPv6 = %v, want %v", id.IPv6, want)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Errorf("upstream requests = %d, want 1", got)
	}
}

func TestTPMResolverPrefersOcservAddress(t *testing.T) {
	// A device that coexists WG + AnyConnect carries BOTH a native (WG) /128
	// and an ocserv /128. The resolver must use the ocserv /128 (kind
	// ocserv_ipv6, routed to era-ocserv-tun) so AnyConnect return traffic does
	// not egress via era-wg (DEC-anyconnect-own-128).
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		assertAuth(t, req)
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion:    2,
			DeviceID:         testDeviceID,
			SourceIPv6Native: "2001:470:f9d1:9001:dead:beef::1/128",
			SourceIPv6Ocserv: "2001:470:f9d1:9001:0c5e:7777::9/128",
		})
	}, nil)

	id, err := r.Resolve(context.Background(), testDeviceID)
	if err != nil {
		t.Fatalf("Resolve err = %v", err)
	}
	want := netip.MustParsePrefix("2001:470:f9d1:9001:0c5e:7777::9/128")
	if id.IPv6 != want {
		t.Errorf("IPv6 = %v, want ocserv /128 %v", id.IPv6, want)
	}
}

func TestTPMResolverDecodesOcservCLAT(t *testing.T) {
	// A CLAT-enabled AnyConnect device carries a SECOND ocserv /128
	// (source_ipv6_ocserv_clat). The resolver decodes it into IPv6CLAT while
	// the native ocserv /128 stays in IPv6.
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		assertAuth(t, req)
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion:        2,
			DeviceID:             testDeviceID,
			SourceIPv6Ocserv:     "2001:470:f9d1:9001:0c5e:7777::9/128",
			SourceIPv6OcservClat: "2001:470:f9d1:9001:c1a7::1/128",
		})
	}, nil)

	id, err := r.Resolve(context.Background(), testDeviceID)
	if err != nil {
		t.Fatalf("Resolve err = %v", err)
	}
	if want := netip.MustParsePrefix("2001:470:f9d1:9001:0c5e:7777::9/128"); id.IPv6 != want {
		t.Errorf("IPv6 = %v, want native ocserv /128 %v", id.IPv6, want)
	}
	if want := netip.MustParsePrefix("2001:470:f9d1:9001:c1a7::1/128"); id.IPv6CLAT != want {
		t.Errorf("IPv6CLAT = %v, want CLAT /128 %v", id.IPv6CLAT, want)
	}
}

func TestTPMResolverToleratesAbsentCLAT(t *testing.T) {
	// CLAT disabled: no source_ipv6_ocserv_clat. The native /128 resolves and
	// IPv6CLAT stays zero (the session runs v6-only).
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		assertAuth(t, req)
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion:    2,
			DeviceID:         testDeviceID,
			SourceIPv6Ocserv: "2001:470:f9d1:9001:0c5e:7777::9/128",
		})
	}, nil)

	id, err := r.Resolve(context.Background(), testDeviceID)
	if err != nil {
		t.Fatalf("Resolve err = %v", err)
	}
	if id.IPv6CLAT.IsValid() {
		t.Errorf("IPv6CLAT = %v, want zero (CLAT disabled)", id.IPv6CLAT)
	}
}

func TestTPMResolverRejectsBadCLAT(t *testing.T) {
	// A present-but-malformed / out-of-pool CLAT /128 is an error, mirroring
	// the native /128 validation. A /64 CLAT prefix is not a /128.
	cases := map[string]string{
		"not-a-128":   "2001:470:f9d1:9001:c1a7::/64",
		"out-of-pool": "2001:db8::1/128",
		"not-ipv6":    "192.0.2.1/32",
		"unparseable": "garbage",
	}
	for name, clat := range cases {
		t.Run(name, func(t *testing.T) {
			r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
				writeFakeConfig(t, w, fakeClientConfig{
					SchemaVersion:        2,
					DeviceID:             testDeviceID,
					SourceIPv6Ocserv:     "2001:470:f9d1:9001:0c5e:7777::9/128",
					SourceIPv6OcservClat: clat,
				})
			}, nil)
			if _, err := r.Resolve(context.Background(), testDeviceID); !errors.Is(err, ErrUpstream) {
				t.Fatalf("err = %v, want ErrUpstream for CLAT %q", err, clat)
			}
		})
	}
}

func TestTPMResolverNotFound(t *testing.T) {
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		assertAuth(t, req)
		http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
	}, nil)

	_, err := r.Resolve(context.Background(), testDeviceID)
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("err = %v, want ErrDeviceNotFound", err)
	}
}

func TestTPMResolverNoTunnel(t *testing.T) {
	// 200 OK but source_ipv6_native is empty (no peer / no /128).
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		assertAuth(t, req)
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion: 1,
			DeviceID:      testDeviceID,
			// SourceIPv6Native left "" — simulates TPM responding 200
			// with a client-config that has no native assignment yet.
		})
	}, nil)

	_, err := r.Resolve(context.Background(), testDeviceID)
	if !errors.Is(err, ErrNoTunnel) {
		t.Fatalf("err = %v, want ErrNoTunnel", err)
	}
}

func TestTPMResolverUpstreamError(t *testing.T) {
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}, nil)

	_, err := r.Resolve(context.Background(), testDeviceID)
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v, want it to mention 500", err)
	}
}

func TestTPMResolverAuthFailureMapsToUpstream(t *testing.T) {
	// 401 / 403 from TPM are not the same as device-not-found; they are
	// configuration / token errors that the caller must treat as
	// transient + alarm-worthy, but they MUST NOT be ErrDeviceNotFound
	// (which would silently bounce a legitimate device).
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprintf("HTTP_%d", code), func(t *testing.T) {
			r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
				http.Error(w, "no", code)
			}, nil)
			_, err := r.Resolve(context.Background(), testDeviceID)
			if !errors.Is(err, ErrUpstream) {
				t.Fatalf("err = %v, want ErrUpstream", err)
			}
			if errors.Is(err, ErrDeviceNotFound) {
				t.Errorf("err must not be ErrDeviceNotFound")
			}
		})
	}
}

func TestTPMResolverCacheHit(t *testing.T) {
	var requests int32
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&requests, 1)
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion:    1,
			DeviceID:         testDeviceID,
			SourceIPv6Native: "2001:470:f9d1:9001::1/128",
		})
	}, nil)

	for i := 0; i < 5; i++ {
		if _, err := r.Resolve(context.Background(), testDeviceID); err != nil {
			t.Fatalf("Resolve[%d] err = %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Errorf("upstream requests = %d, want 1 (cache should serve 4/5)", got)
	}
}

func TestTPMResolverCacheTTLExpiry(t *testing.T) {
	var requests int32
	// We drive time with a synthetic clock so the test is deterministic.
	clock := newFakeClock(time.Unix(1_700_000_000, 0))
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&requests, 1)
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion:    1,
			DeviceID:         testDeviceID,
			SourceIPv6Native: "2001:470:f9d1:9001::1/128",
		})
	}, func(cfg *TPMResolverConfig) {
		cfg.CacheTTL = 60 * time.Second
		cfg.Now = clock.Now
	})

	if _, err := r.Resolve(context.Background(), testDeviceID); err != nil {
		t.Fatalf("first resolve err = %v", err)
	}
	// Within TTL: still a cache hit.
	clock.Advance(30 * time.Second)
	if _, err := r.Resolve(context.Background(), testDeviceID); err != nil {
		t.Fatalf("within-TTL resolve err = %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Errorf("after within-TTL: requests = %d, want 1", got)
	}
	// Past soft TTL: must refetch.
	clock.Advance(90 * time.Second)
	if _, err := r.Resolve(context.Background(), testDeviceID); err != nil {
		t.Fatalf("post-TTL resolve err = %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Errorf("after post-TTL: requests = %d, want 2", got)
	}
}

func TestTPMResolverCacheDisabled(t *testing.T) {
	var requests int32
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&requests, 1)
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion:    1,
			DeviceID:         testDeviceID,
			SourceIPv6Native: "2001:470:f9d1:9001::1/128",
		})
	}, func(cfg *TPMResolverConfig) {
		cfg.DisableCache = true
	})
	for i := 0; i < 3; i++ {
		if _, err := r.Resolve(context.Background(), testDeviceID); err != nil {
			t.Fatalf("Resolve[%d] err = %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&requests); got != 3 {
		t.Errorf("requests = %d, want 3 (cache disabled)", got)
	}
}

// TestTPMResolverDegradedServeOnTransientError: a soft-expired but
// hard-fresh cached value MUST be served when the upstream returns a
// transient error. A genuine 404 (deprovision) must NOT serve the stale.
func TestTPMResolverDegradedServeOnTransientError(t *testing.T) {
	clock := newFakeClock(time.Unix(1_700_000_000, 0))

	var mode atomic.Int32 // 0 = ok, 1 = 500, 2 = 404
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		switch mode.Load() {
		case 0:
			writeFakeConfig(t, w, fakeClientConfig{
				SchemaVersion:    1,
				DeviceID:         testDeviceID,
				SourceIPv6Native: "2001:470:f9d1:9001::1/128",
			})
		case 1:
			http.Error(w, "boom", http.StatusInternalServerError)
		case 2:
			http.Error(w, "gone", http.StatusNotFound)
		}
	}, func(cfg *TPMResolverConfig) {
		cfg.CacheTTL = 60 * time.Second
		cfg.Now = clock.Now
	})

	// Seed the cache.
	if _, err := r.Resolve(context.Background(), testDeviceID); err != nil {
		t.Fatalf("seed err = %v", err)
	}

	// Past soft TTL but within hard TTL (2 * 60 = 120s).
	clock.Advance(90 * time.Second)
	mode.Store(1)
	id, err := r.Resolve(context.Background(), testDeviceID)
	if err != nil {
		t.Fatalf("degraded resolve err = %v, want served from cache", err)
	}
	if got, want := id.IPv6.String(), "2001:470:f9d1:9001::1/128"; got != want {
		t.Errorf("degraded IPv6 = %s, want %s (served from cache)", got, want)
	}

	// Now 404: device truly gone. Cache must be evicted, error must
	// surface. Move past hard TTL would also work but we want to test
	// the "404 wins even within hard TTL" rule.
	mode.Store(2)
	if _, err := r.Resolve(context.Background(), testDeviceID); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("404 err = %v, want ErrDeviceNotFound (even with hard-fresh cache)", err)
	}
	// And a subsequent call hits upstream again (cache was cleared).
	mode.Store(0)
	if _, err := r.Resolve(context.Background(), testDeviceID); err != nil {
		t.Fatalf("recovery resolve err = %v", err)
	}
}

// TestTPMResolverHardExpiryEvictsAndSurfacesError: when both the soft and
// hard TTLs have passed, a transient upstream error must surface (no stale
// /128 from the discarded cache entry).
func TestTPMResolverHardExpiryEvictsAndSurfacesError(t *testing.T) {
	clock := newFakeClock(time.Unix(1_700_000_000, 0))
	var mode atomic.Int32 // 0 = ok, 1 = 500
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		if mode.Load() == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion:    1,
			DeviceID:         testDeviceID,
			SourceIPv6Native: "2001:470:f9d1:9001::1/128",
		})
	}, func(cfg *TPMResolverConfig) {
		cfg.CacheTTL = 60 * time.Second
		cfg.Now = clock.Now
	})

	// Seed.
	if _, err := r.Resolve(context.Background(), testDeviceID); err != nil {
		t.Fatalf("seed err = %v", err)
	}
	// Past hard TTL (2 * 60 = 120s).
	clock.Advance(200 * time.Second)
	mode.Store(1)
	if _, err := r.Resolve(context.Background(), testDeviceID); !errors.Is(err, ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream (hard-expired cache must not be served)", err)
	}
}

func TestTPMResolverSingleflightCoalesce(t *testing.T) {
	var requests int32
	// Make the handler block long enough that all 100 goroutines line
	// up behind the singleflight gate.
	releaseChan := make(chan struct{})
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&requests, 1)
		<-releaseChan
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion:    1,
			DeviceID:         testDeviceID,
			SourceIPv6Native: "2001:470:f9d1:9001::1/128",
		})
	}, nil)

	const N = 100
	var wg sync.WaitGroup
	wg.Add(N)
	errCh := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, err := r.Resolve(context.Background(), testDeviceID)
			errCh <- err
		}()
	}
	// Give the goroutines a moment to enqueue on the singleflight gate.
	// We poll briefly: the moment any in-flight request has registered
	// with the handler, the rest are guaranteed to coalesce.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&requests) < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if atomic.LoadInt32(&requests) < 1 {
		close(releaseChan)
		wg.Wait()
		t.Fatal("no upstream request observed within deadline")
	}
	close(releaseChan)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Errorf("Resolve err = %v", err)
		}
	}
	// The contract: 100 concurrent Resolves for the same device id
	// produce exactly one upstream call.
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Errorf("upstream requests = %d, want 1 (singleflight should coalesce)", got)
	}
}

func TestTPMResolverPoolValidation(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
	}{
		{"WrongPool", "2001:db8::1/128"},
		{"IPv4Address", "192.0.2.1/32"},
		{"NotASlash128", "2001:470:f9d1:9001::/64"},
		{"Malformed", "this is not an address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
				writeFakeConfig(t, w, fakeClientConfig{
					SchemaVersion:    1,
					DeviceID:         testDeviceID,
					SourceIPv6Native: tc.prefix,
				})
			}, nil)
			_, err := r.Resolve(context.Background(), testDeviceID)
			if !errors.Is(err, ErrUpstream) {
				t.Fatalf("err = %v, want ErrUpstream", err)
			}
		})
	}
}

func TestTPMResolverCustomPoolPrefix(t *testing.T) {
	// Operator may want to point era-ocserv at a different pool (e.g.
	// a staging environment). The custom prefix passes; a /128 inside
	// the default pool is then rejected.
	const customPool = "2001:db8::/32"
	const inCustom = "2001:db8::dead/128"
	const inDefault = "2001:470:f9d1:9001::1/128"

	var which atomic.Pointer[string]
	first := inCustom
	which.Store(&first)
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion:    1,
			DeviceID:         testDeviceID,
			SourceIPv6Native: *which.Load(),
		})
	}, func(cfg *TPMResolverConfig) {
		cfg.PoolPrefix = netip.MustParsePrefix(customPool)
		cfg.DisableCache = true
	})

	if _, err := r.Resolve(context.Background(), testDeviceID); err != nil {
		t.Fatalf("in-custom-pool err = %v", err)
	}
	second := inDefault
	which.Store(&second)
	if _, err := r.Resolve(context.Background(), testDeviceID); !errors.Is(err, ErrUpstream) {
		t.Fatalf("in-default-pool against custom pool err = %v, want ErrUpstream", err)
	}
}

func TestTPMResolverEmptyDeviceID(t *testing.T) {
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		t.Errorf("upstream should not be called for empty deviceID")
	}, nil)
	if _, err := r.Resolve(context.Background(), ""); !errors.Is(err, ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream", err)
	}
}

func TestTPMResolverEndpointPathRespectsBaseURLPath(t *testing.T) {
	// Some deployments terminate TPM behind a reverse proxy with a path
	// prefix. The resolver MUST append /v1/... onto whatever path the
	// BaseURL already has, without dropping or doubling slashes.
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		seenPath = req.URL.Path
		writeFakeConfig(t, w, fakeClientConfig{
			SchemaVersion:    1,
			DeviceID:         testDeviceID,
			SourceIPv6Native: "2001:470:f9d1:9001::1/128",
		})
	}))
	t.Cleanup(srv.Close)

	u, _ := url.Parse(srv.URL + "/tpm/")
	r := NewTPMResolver(TPMResolverConfig{
		BaseURL:      u,
		ServiceToken: testToken,
		DisableCache: true,
	})
	if _, err := r.Resolve(context.Background(), testDeviceID); err != nil {
		t.Fatalf("Resolve err = %v", err)
	}
	want := "/tpm/v1/provision/device/" + testDeviceID + "/client-config"
	if seenPath != want {
		t.Errorf("seen path = %q, want %q", seenPath, want)
	}
}

func TestTPMResolverBadJSON(t *testing.T) {
	r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}, nil)
	if _, err := r.Resolve(context.Background(), testDeviceID); !errors.Is(err, ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream", err)
	}
}

func TestNewTPMResolverPanicsOnMissingBaseURL(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when BaseURL is nil")
		}
	}()
	NewTPMResolver(TPMResolverConfig{ServiceToken: testToken})
}

func TestNewTPMResolverPanicsOnMissingToken(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when ServiceToken is empty")
		}
	}()
	u, _ := url.Parse("http://127.0.0.1:1")
	NewTPMResolver(TPMResolverConfig{BaseURL: u, ServiceToken: "   "})
}

// TestTPMResolverImplementsResolver is a compile-time assertion.
func TestTPMResolverImplementsResolver(t *testing.T) {
	var _ Resolver = (*TPMResolver)(nil)
}

// --- helpers ---------------------------------------------------------------

func writeFakeConfig(t *testing.T, w http.ResponseWriter, c fakeClientConfig) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(c); err != nil {
		t.Errorf("encode fake config: %v", err)
	}
}

// fakeClock is a tiny test clock used to drive cache expiry deterministically.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
