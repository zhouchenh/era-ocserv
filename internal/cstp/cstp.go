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
	"net/netip"
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
}

// Server is an http.Handler that drives the CSTP phase-2 XML
// negotiation, accepts the phase-3 CONNECT upgrade, and hands the
// resulting binary tunnels to the caller via Accept.
//
// A Server is safe for concurrent use by the HTTP server. Closing a
// Server cancels Accept and tears down outstanding tunnels.
type Server struct {
	cfg Config

	sessions *sessionTable

	// dtlsTunnels is the live registry of tunnels keyed by their
	// session token (the same token the client carries in the
	// `webvpn` cookie on the CONNECT request). The DTLS server uses
	// this through LookupSession to map an incoming DTLS handshake's
	// PSK identity to the PSK derived from the outer TLS exporter
	// and the Tunnel that should adopt the new data channel.
	// Entries are added by handleConnect on successful CONNECT and
	// removed by the Tunnel close path via forgetTunnel.
	dtlsTunnels sync.Map // map[string]*dtlsRegistration

	tunnels chan *Tunnel
	closeCh chan struct{}
	closeMu sync.Mutex
	closed  bool
}

// dtlsRegistration is the per-session bundle the DTLS server fetches
// via LookupSession to authenticate and route an incoming DTLS
// handshake. The psk slice holds the 32-byte RFC 5705 keying material
// derived from the outer TLS connection at CONNECT time using the
// `EXPORTER-openconnect-psk` label; it is the same byte sequence the
// client received hex-encoded in the X-DTLS-Master-Secret response
// header and that both ends now agree on as the DTLS PSK.
type dtlsRegistration struct {
	psk    []byte
	tunnel *Tunnel
}

// NewServer builds a Server with the supplied configuration. Required
// fields (Verifier, Resolver, ServerName) are not checked here so that
// tests can supply partial configs; callers that ship real traffic
// should validate the config themselves.
func NewServer(cfg Config) *Server {
	cfg = cfg.withDefaults()
	return &Server{
		cfg:      cfg,
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
	return c
}

func (s *Server) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now()
}

// LookupSession resolves the bundle the internal/dtls package needs to
// accept and route an incoming DTLS handshake. sessionID is the PSK
// identity the DTLS client put in its ClientKeyExchange (which the
// AnyConnect protocol equates with the long-lived `webvpn` session
// cookie). On success the returned psk is the 32-byte RFC 5705
// exporter output computed at CSTP CONNECT time, and tunnel is the
// active Tunnel that should adopt the new DTLS data channel.
//
// LookupSession returns ok=false if the session is unknown, has not
// completed CONNECT yet, has been torn down, or otherwise has no live
// Tunnel. The returned psk MUST NOT be mutated by callers; a fresh
// copy is returned so internal storage cannot be observed across
// concurrent lookups.
//
// LookupSession implements the SessionRegistry contract used by
// internal/dtls.NewServer.
func (s *Server) LookupSession(sessionID string) (psk []byte, tunnel *Tunnel, ok bool) {
	if sessionID == "" {
		return nil, nil, false
	}
	v, found := s.dtlsTunnels.Load(sessionID)
	if !found {
		return nil, nil, false
	}
	reg := v.(*dtlsRegistration)
	if reg == nil || reg.tunnel == nil {
		return nil, nil, false
	}
	// Guard against a race where the tunnel has already been closed
	// but forgetTunnel has not yet observed the close. The dtls
	// server can safely reject in this window; the client retries
	// over CSTP.
	select {
	case <-reg.tunnel.closeCh:
		return nil, nil, false
	default:
	}
	out := make([]byte, len(reg.psk))
	copy(out, reg.psk)
	return out, reg.tunnel, true
}

// registerTunnel records a fresh tunnel + PSK in the DTLS lookup
// table. Called from handleConnect once the CONNECT phase has
// completed and the Tunnel goroutines are running. psk is the
// 32-byte exporter material the same client just received hex-encoded
// in X-DTLS-Master-Secret; if psk is nil (TLS exporter unavailable on
// the request, e.g. test path), the tunnel is not registered and
// DTLS is silently unavailable for this session.
func (s *Server) registerTunnel(sessionToken string, psk []byte, t *Tunnel) {
	if sessionToken == "" || len(psk) == 0 || t == nil {
		return
	}
	cp := make([]byte, len(psk))
	copy(cp, psk)
	s.dtlsTunnels.Store(sessionToken, &dtlsRegistration{psk: cp, tunnel: t})
}

// forgetTunnel removes a tunnel from the DTLS lookup table. Called by
// the Tunnel close path so that a closing TLS-side session is no
// longer reachable for new DTLS handshakes. Safe to call when no
// matching entry exists.
func (s *Server) forgetTunnel(sessionToken string) {
	if sessionToken == "" {
		return
	}
	s.dtlsTunnels.Delete(sessionToken)
}
