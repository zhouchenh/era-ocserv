// Package cstp implements the AnyConnect CSTP control protocol used by
// era-ocserv. It owns the HTTP-shaped negotiation (init / auth / CONNECT)
// and the post-CONNECT 8-byte-framed binary tunnel that carries inner IP
// packets between an AnyConnect-compatible client and the gateway.
//
// The package does NOT own TLS termination, mTLS validation, password
// verification, the identity store, or the host tun device. Those
// dependencies are injected through the Config struct (Verifier,
// Resolver) or supplied by the caller (TLS conn, tun reader/writer).
//
// Wire shape and header set follow
// docs/architecture/era-ocserv-protocol.md §1 and IETF draft
// draft-mavrogiannopoulos-openconnect-04.
package cstp

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Verifier authenticates a username + password pair. The implementation
// lives in internal/auth; cstp consumes it through this interface so the
// CSTP layer remains agnostic of the credential backend (portal, RADIUS
// stub, in-memory testing, etc.).
//
// On success, Verify returns a stable device ID string that uniquely
// identifies the authenticated device for downstream identity resolution.
type Verifier interface {
	Verify(ctx context.Context, username, password string) (deviceID string, err error)
}

// Resolver maps an authenticated device ID to its assigned inner IP
// configuration (a /128 from the era-wg pool plus MTU). The
// implementation lives in internal/iam.
type Resolver interface {
	Resolve(ctx context.Context, deviceID string) (Identity, error)
}

// Identity is the per-device configuration handed to the CONNECT phase
// so era-ocserv can emit X-CSTP-Address-IP6 / X-CSTP-MTU correctly.
type Identity struct {
	// DeviceID is the stable identifier returned by Verifier.Verify.
	DeviceID string
	// IPv6 is the /128 prefix assigned to this device. The address
	// inside is the inner source IP the client uses on the tunnel.
	IPv6 netip.Prefix
	// IPv6CLAT is the device's CLAT-source /128 (kind ocserv_clat_ipv6).
	// When valid, the bridge builds a per-session SIIT translator from it so
	// the client's inner-IPv4 (placeholder 192.0.0.1) egresses as
	// 64:ff9b::<v4dst> sourced from this address; the same *activeClient is
	// also registered under this /128 so 64:ff9b:: replies route back. An
	// invalid (zero) value means CLAT is disabled and the session runs
	// v6-only. The address, when valid, is a /128 inside the pool.
	IPv6CLAT netip.Prefix
	// MTU is the inner-frame MTU advertised via X-CSTP-MTU. If zero the
	// server falls back to Config.DefaultMTU.
	MTU int
}

// Config is the construction-time configuration for a CSTP Server. All
// fields are optional except Verifier, Resolver, and ServerName. Zero
// values for numeric tuning knobs are filled in with safe defaults
// matching the protocol doc §1.6.
type Config struct {
	// Verifier authenticates phase 2 auth-reply credentials. Required.
	Verifier Verifier
	// Resolver maps the authenticated device ID to its inner IP
	// configuration during phase 3. Required.
	Resolver Resolver

	// ServerName is the canonical hostname emitted as X-CSTP-Hostname
	// on the CONNECT response. Cisco Secure Client refuses a connection
	// where this header is empty, so the value must be non-empty for
	// real deployments. Required for production use.
	ServerName string

	// ServerCertSHA1 is the uppercase-hex SHA-1 of the public TLS leaf cert for
	// the webvpnc sh: pin; empty = built-in default constant. Set on the covert
	// :443 path to the facade's live leaf.
	ServerCertSHA1 string

	// DNS is the set of recursive resolvers to push to the client via
	// repeated X-CSTP-DNS headers. Optional.
	DNS []netip.Addr
	// DefaultDomain is the DNS search domain pushed via
	// X-CSTP-Default-Domain. Optional.
	DefaultDomain string
	// SplitInclude is the optional set of split-tunnel inclusion
	// routes emitted as X-CSTP-Split-Include headers. An empty slice
	// implies a default route per protocol convention.
	SplitInclude []netip.Prefix

	// DPDInterval, KeepaliveInterval, and IdleTimeout are advertised in
	// the X-CSTP-DPD, X-CSTP-Keepalive, X-CSTP-Idle-Timeout headers and
	// drive the internal heartbeat goroutine. Zero falls back to
	// protocol-doc defaults (30 / 20 / 1800 seconds respectively).
	DPDInterval       int
	KeepaliveInterval int
	IdleTimeout       int

	// DefaultMTU is the MTU advertised when Identity.MTU is zero. Zero
	// falls back to 1406 (the value the protocol doc uses for the
	// typical 1500 base MTU).
	DefaultMTU int

	// SessionTimeout caps the lifetime of an issued session cookie. A
	// zero value uses 1 hour, which is generous for the auth->CONNECT
	// window but bounded enough to avoid stale-cookie reuse.
	SessionTimeout time.Duration

	// Now allows tests to inject a deterministic clock. Production
	// leaves it nil and the package falls back to time.Now.
	Now func() time.Time

	// RandRead allows tests to inject a deterministic CSPRNG. Production
	// leaves it nil and the package falls back to crypto/rand.Read.
	RandRead func(p []byte) (int, error)

	// DTLSBindingInstaller, when non-nil, enables shared-edge DTLS by publishing
	// the CSTP-authenticated DTLS binding into era-facade's admin API.
	DTLSBindingInstaller DTLSBindingInstaller
	DTLSBindingSource    func(*http.Request, Identity) (DTLSBinding, bool)
	// DTLSBindingRefreshInterval controls how often an established CSTP tunnel
	// refreshes its DTLS binding in the background so the facade-side 5-minute
	// binding TTL stays alive as long as the CSTP leg does.
	DTLSBindingRefreshInterval time.Duration

	// DTLSDisabled, when true, suppresses ALL DTLS advertisement in the CONNECT
	// response (no binding publish, no X-DTLS-* headers) so the client carries
	// its data plane over CSTP/TLS (TCP) only. Diagnostic/fallback switch for
	// paths where the DTLS-over-UDP leg cannot round-trip (e.g. a public-edge
	// UDP NAT that drops the return datagrams). CSTP keepalive/DPD still drive
	// liveness.
	DTLSDisabled bool
}

// Server is an http.Handler that drives the CSTP phase-2 XML
// negotiation, accepts the phase-3 CONNECT upgrade, and hands the
// resulting binary tunnels to the caller via Accept.
//
// A Server is safe for concurrent use by the HTTP server. Closing a
// Server cancels Accept and tears down outstanding tunnels.
type Server struct {
	cfg Config

	// webvpnc is the precomputed value of the post-auth webvpnc directive cookie
	// with the DEFAULT base URL ("/", standalone). The facade path rebuilds it
	// per-request with the group-url base via buildWebVPNC(webVPNCBaseFor(r),
	// certSHA1); see handleAuth. certSHA1 is kept so that rebuild needs no
	// re-resolution.
	webvpnc  string
	certSHA1 string

	sessions *sessionTable

	tunnels chan *Tunnel
	closeCh chan struct{}
	closeMu sync.Mutex
	closed  bool
}

// NewServer builds a Server with the supplied configuration. Required
// fields (Verifier, Resolver, ServerName) are not checked here so that
// tests can supply partial configs; callers that ship real traffic
// should validate the config themselves.
func NewServer(cfg Config) *Server {
	cfg = cfg.withDefaults()
	// The webvpnc sh: pin defaults to the built-in eracloud.app constant; a
	// non-empty (whitespace-trimmed) ServerCertSHA1 overrides it for the covert
	// :443 path, where the facade terminates TLS with its own live leaf.
	certSHA1 := serverCertSHA1
	if override := strings.TrimSpace(cfg.ServerCertSHA1); override != "" {
		certSHA1 = override
	}
	return &Server{
		cfg:      cfg,
		webvpnc:  buildWebVPNC("/", certSHA1),
		certSHA1: certSHA1,
		sessions: newSessionTable(cfg.SessionTimeout, cfg.Now),
		tunnels:  make(chan *Tunnel, 32),
		closeCh:  make(chan struct{}),
	}
}

// Accept blocks until a tunnel finishes phase 3 and enters binary mode,
// or until ctx is canceled, or until the Server is closed. The returned
// Tunnel must be drained by the caller; the heartbeat goroutine has
// already started.
func (s *Server) Accept(ctx context.Context) (*Tunnel, error) {
	select {
	case t, ok := <-s.tunnels:
		if !ok {
			return nil, ErrServerClosed
		}
		return t, nil
	case <-s.closeCh:
		return nil, ErrServerClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close stops accepting new tunnels. Tunnels that have already been
// handed to Accept callers are left intact and must be Close'd by
// their owners. Close is idempotent.
func (s *Server) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.closeCh)
	close(s.tunnels)
	return nil
}

// ErrServerClosed is returned by Accept once Close has been called.
var ErrServerClosed = errors.New("cstp: server closed")

func (c Config) withDefaults() Config {
	if c.DPDInterval <= 0 {
		c.DPDInterval = 30
	}
	if c.KeepaliveInterval <= 0 {
		c.KeepaliveInterval = 20
	}
	if c.IdleTimeout < 0 {
		c.IdleTimeout = 0
	} else if c.IdleTimeout == 0 {
		c.IdleTimeout = 1800
	}
	if c.DefaultMTU <= 0 {
		c.DefaultMTU = 1406
	}
	if c.SessionTimeout <= 0 {
		c.SessionTimeout = time.Hour
	}
	if c.DTLSBindingRefreshInterval <= 0 {
		c.DTLSBindingRefreshInterval = 2 * time.Minute
	}
	return c
}

func (s *Server) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now()
}
