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
	"crypto/tls"
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

// CertValidator extracts the ERA device ID from an mTLS-validated
// client certificate. It is consumed by the CONNECT handler to
// re-bind the cert to the session minted at phase 2 (protocol spec
// §1.8, ADR 0057 §4): we require the cert presented on the CONNECT
// TLS handshake to be the same one that authenticated the phase-2
// auth-reply. Without this re-check, a leaked session token plus any
// validly-signed ERA device cert could take over another device's
// /128.
//
// The concrete production implementation is internal/auth.CertValidator;
// tests inject their own. A nil CertValidator on cstp.Config disables
// the re-bind check (useful for unit tests that exercise CONNECT over
// non-TLS net.Pipe).
type CertValidator interface {
	Validate(state tls.ConnectionState) (deviceID string, err error)
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

	// CertValidator re-extracts the device ID from the mTLS client
	// certificate on the phase-3 CONNECT request. If non-nil, the
	// CONNECT handler rejects the request with 401 when the cert
	// deviceID does not equal the deviceID bound at phase 2 promote
	// time. Leave nil only in tests that drive CONNECT over a non-TLS
	// transport (net.Pipe); production wiring always supplies a
	// validator.
	CertValidator CertValidator

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

	// DTLSAdvertise controls whether the CONNECT handler emits the
	// X-DTLS-* header set. Stage 1 ships no DTLS server, so the
	// default false keeps the server TCP-only at the wire level (the
	// explicitly supported degraded mode per protocol spec §2.2).
	// Stage 2 flips this true once the loopback UDP DTLS listener is
	// wired (see ADR 0057 §6). Without this gate, clients that read
	// X-DTLS-Master-Secret / X-DTLS-Port will sit on a UDP handshake
	// timeout before falling back to TCP — macOS Cisco Secure Client
	// in particular disables DTLS for the rest of the session after
	// the first timeout (protocol spec §3.2).
	DTLSAdvertise bool

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

	tunnels chan *Tunnel
	closeCh chan struct{}
	closeMu sync.Mutex
	closed  bool

	// active tracks every tunnel that has been published to a caller
	// via Accept and has not yet been observed closed. Server.Close
	// walks this set and sends TERM_SERVER on each so the client
	// knows the disconnect is server-initiated and not retryable
	// (spec §1.5 frame type 9). Mutex guards both the map and the
	// "closed" flag (above) so register/unregister stays consistent
	// with the close sweep.
	activeMu sync.Mutex
	active   map[*Tunnel]struct{}
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
		active:   make(map[*Tunnel]struct{}),
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

// Close stops accepting new tunnels and tears down every active
// tunnel. On each active tunnel we send a TERM_SERVER frame (spec
// §1.5 type 9) so the client knows the disconnect is server-
// initiated and not retryable; the tunnel is then closed
// idempotently. Close itself is idempotent.
//
// Without this teardown, http.Server.Shutdown does not affect
// hijacked connections (documented Go runtime behaviour) and tunnel
// goroutines would be abandoned mid-write on SIGTERM; observed-state
// from the client side would be a hang rather than a clean
// disconnect. Wave-1 review P1 #2.
//
// We deliberately do not close the s.tunnels channel. Closing it
// would race with a concurrent handleConnect that already lost the
// select-race against closeCh and is in the act of sending; Go would
// panic on the close. Closing closeCh is enough: it unblocks Accept
// (returns ErrServerClosed) and signals registerTunnel to reject new
// tunnels.
func (s *Server) Close() error {
	// Take activeMu while marking closed so any concurrent
	// registerTunnel either sees closed=false (and is in the
	// snapshot we sweep below) or sees closed=true (and returns
	// false). Without this ordering, a register that runs between
	// "mark closed" and "snapshot active" leaks the tunnel.
	s.activeMu.Lock()
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		s.activeMu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closeCh)
	s.closeMu.Unlock()
	s.activeMu.Unlock()

	// Drain anything sitting in the accept channel that has not yet
	// been picked up by a caller. These tunnels are already in
	// s.active (newTunnel registers before publishing) so the
	// active-set sweep below would also tear them down, but draining
	// here keeps the channel empty so we don't leave dangling
	// references for the GC.
drain:
	for {
		select {
		case <-s.tunnels:
			// Tunnel is in s.active; teardownTunnel happens in the
			// sweep below.
		default:
			break drain
		}
	}

	// Take a snapshot of active tunnels under the lock; release the
	// lock before issuing any I/O so a tunnel's own goroutine can
	// still call unregisterTunnel without deadlocking.
	s.activeMu.Lock()
	snapshot := make([]*Tunnel, 0, len(s.active))
	for t := range s.active {
		snapshot = append(snapshot, t)
	}
	s.activeMu.Unlock()

	for _, t := range snapshot {
		s.teardownTunnel(t)
	}
	return nil
}

// teardownTunnel sends a best-effort TERM_SERVER frame, then closes
// the tunnel. Both calls are idempotent; either may fail silently if
// the peer has already disappeared.
func (s *Server) teardownTunnel(t *Tunnel) {
	// Single-byte payload of zero matches what ocserv emits on
	// shutdown. Some clients log the payload; an empty one would
	// also work but is unconventional.
	_ = t.writeFrame(pktTermServer, []byte{0})
	_ = t.Close()
}

// registerTunnel records a tunnel in the active set. Called from
// newTunnel before the tunnel is published to s.tunnels. If the
// server is mid-close we skip registration and return false; the
// caller closes the tunnel immediately. The closed check and the
// map mutation happen under the same lock so a register that races
// with Close either adds to the set that Close is about to sweep,
// or returns false.
func (s *Server) registerTunnel(t *Tunnel) bool {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	s.closeMu.Lock()
	closed := s.closed
	s.closeMu.Unlock()
	if closed {
		return false
	}
	s.active[t] = struct{}{}
	return true
}

// unregisterTunnel drops a tunnel from the active set. Called by the
// tunnel itself once readLoop / heartbeatLoop has observed close.
// Tolerates a tunnel that was never registered (race with Close).
func (s *Server) unregisterTunnel(t *Tunnel) {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	delete(s.active, t)
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
