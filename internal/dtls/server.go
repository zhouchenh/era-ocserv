package dtls

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	piondtls "github.com/pion/dtls/v3"

	"github.com/zhouchenh/era-ocserv/internal/cstp"
)

// SessionRegistry is the contract the DTLS server uses to look up the
// PSK and active Tunnel for an incoming DTLS handshake. It is
// satisfied by *cstp.Server.LookupSession.
//
// The sessionID argument is the PSK identity carried by the client in
// its DTLS ClientKeyExchange. In the AnyConnect protocol this is the
// same string as the long-lived session token the CSTP server issued
// in the auth-complete response, which the client also echoes as the
// `webvpn` cookie on the CONNECT request.
//
// Implementations return ok=false when the session is unknown, has
// not finished CSTP CONNECT yet, has been torn down, or has no live
// Tunnel for any other reason; on ok=false the DTLS server alerts
// the client with InternalError, which the client treats as a
// retryable failure and falls back to CSTP-over-TLS for data.
type SessionRegistry interface {
	LookupSession(sessionID string) (psk []byte, tunnel *cstp.Tunnel, ok bool)
}

// Config configures a DTLS Server. Listen and Registry are required;
// all other fields have safe defaults.
type Config struct {
	// Listen is the UDP address to bind. Loopback by default — the
	// era-facade UDP demux is expected to forward 0x16 ClientHello
	// datagrams to us on this socket.
	Listen string

	// Registry maps PSK identities to (psk, *cstp.Tunnel). Required.
	Registry SessionRegistry

	// HandshakeTimeout caps how long a single handshake may run.
	// A misbehaving client must not be able to tie up server
	// resources indefinitely. Defaults to 30s.
	HandshakeTimeout time.Duration

	// RekeyAfter is the wall-clock budget for a single DTLS conn
	// before the server tears it down to force a fresh handshake.
	// Defaults to 8 hours (matches X-DTLS-Rekey-Time advertised on
	// the CSTP CONNECT response).
	RekeyAfter time.Duration

	// RekeyAfterBytes is the bidirectional byte budget for a single
	// DTLS conn before the server tears it down to force a fresh
	// handshake. Defaults to 8 GiB. Set to math.MaxUint64 to
	// disable the byte cap.
	RekeyAfterBytes uint64

	// IdleTimeout is the per-conn read idle deadline. The DTLS
	// control loop relies on the CSTP control channel for keepalive,
	// but if the DTLS conn itself goes silent past this window we
	// detach it so the client gets a chance to rebuild. Defaults to
	// 300 seconds; set to 0 to disable.
	IdleTimeout time.Duration

	// Logger is the slog logger for diagnostics. nil falls back to
	// slog.Default with a "dtls" group.
	Logger *slog.Logger

	// nowFn allows tests to inject a deterministic clock; production
	// callers leave it nil and the package uses time.Now.
	nowFn func() time.Time
}

const (
	defaultHandshakeTimeout = 30 * time.Second
	defaultRekeyAfter       = 8 * time.Hour
	defaultRekeyAfterBytes  = 8 * 1024 * 1024 * 1024 // 8 GiB
	defaultIdleTimeout      = 5 * time.Minute
)

// Server is the DTLS data-channel listener.
//
// A Server is not reusable after Close: callers must construct a new
// one. ListenAndServe runs the accept loop synchronously and is
// expected to be invoked from a goroutine.
type Server struct {
	cfg      Config
	listener net.Listener

	closeOnce sync.Once
	closeCh   chan struct{}

	// active is the live set of accepted conns the server is driving.
	// Close walks it to tear conns down promptly.
	active sync.Map // map[*piondtls.Conn]*connState

	log *slog.Logger
}

// connState is the per-accepted-conn bookkeeping the server keeps so
// it can enforce the rekey/idle deadlines and clean up on shutdown.
type connState struct {
	conn      *piondtls.Conn
	tunnel    *cstp.Tunnel
	sessionID string

	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64

	startedAt time.Time
}

// NewServer constructs a Server. Listen and Registry must be set;
// missing fields are filled with defaults. NewServer does NOT bind
// the listener — that happens lazily inside ListenAndServe so a
// caller can construct the Server without holding a UDP socket
// across long config-build paths.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Listen == "" {
		return nil, errors.New("dtls: Listen is required")
	}
	if cfg.Registry == nil {
		return nil, errors.New("dtls: Registry is required")
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.RekeyAfter <= 0 {
		cfg.RekeyAfter = defaultRekeyAfter
	}
	if cfg.RekeyAfterBytes == 0 {
		cfg.RekeyAfterBytes = defaultRekeyAfterBytes
	}
	if cfg.IdleTimeout < 0 {
		cfg.IdleTimeout = 0
	} else if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.nowFn == nil {
		cfg.nowFn = time.Now
	}
	return &Server{
		cfg:     cfg,
		closeCh: make(chan struct{}),
		log:     cfg.Logger.With(slog.String("component", "dtls")),
	}, nil
}

// ListenAndServe binds the UDP socket configured by cfg.Listen,
// installs the narrow PSK-NEGOTIATE / AES-128-GCM-SHA256 policy, and
// drives the accept loop until ctx is canceled or Close is called.
//
// Each accepted connection runs in its own goroutine; on graceful
// exit the goroutine cleans up its DTLS attachment and removes the
// conn from the live set. ListenAndServe returns nil once the accept
// loop unwinds cleanly; otherwise it returns the underlying error.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("dtls: resolve %s: %w", s.cfg.Listen, err)
	}

	pcfg := s.buildPionConfig()
	ln, err := piondtls.Listen("udp", addr, pcfg)
	if err != nil {
		return fmt.Errorf("dtls: listen %s: %w", s.cfg.Listen, err)
	}
	s.listener = ln
	defer ln.Close() //nolint:errcheck // best-effort on shutdown

	// Bridge ctx cancellation to listener close so Accept returns.
	stopCtx, stopCancel := context.WithCancel(ctx)
	defer stopCancel()
	go func() {
		select {
		case <-stopCtx.Done():
		case <-s.closeCh:
		}
		_ = ln.Close()
	}()

	s.log.Info("dtls listening", slog.String("addr", s.cfg.Listen))

	for {
		conn, err := ln.Accept()
		if err != nil {
			if isClosedErr(err) || ctx.Err() != nil || s.isClosed() {
				return nil
			}
			s.log.Warn("dtls accept", slog.Any("err", err))
			continue
		}
		dconn, ok := conn.(*piondtls.Conn)
		if !ok {
			s.log.Warn("dtls accept: not a *dtls.Conn", slog.String("type", fmt.Sprintf("%T", conn)))
			_ = conn.Close()
			continue
		}
		go s.handleConn(ctx, dconn)
	}
}

// Close shuts the listener down and tears any in-flight conns down
// cleanly. It is safe to call multiple times.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.active.Range(func(k, v any) bool {
			st := v.(*connState)
			_ = st.conn.Close()
			return true
		})
	})
	return nil
}

func (s *Server) isClosed() bool {
	select {
	case <-s.closeCh:
		return true
	default:
		return false
	}
}

// buildPionConfig assembles the pion DTLS configuration that pins our
// narrow profile: DTLS 1.2 (pion v3 only implements 1.2), PSK only,
// single cipher suite TLS_PSK_WITH_AES_128_GCM_SHA256, and a PSK
// callback that defers to the SessionRegistry. The hint we send is
// constant ("era-ocserv") and is ignored by OpenConnect / Cisco SC,
// which use the PSK identity in the ClientKeyExchange to demux.
func (s *Server) buildPionConfig() *piondtls.Config {
	return &piondtls.Config{
		PSK: func(identity []byte) ([]byte, error) {
			if len(identity) == 0 {
				return nil, errUnknownSession
			}
			psk, _, ok := s.cfg.Registry.LookupSession(string(identity))
			if !ok {
				return nil, errUnknownSession
			}
			return psk, nil
		},
		PSKIdentityHint: []byte("era-ocserv"),
		CipherSuites: []piondtls.CipherSuiteID{
			piondtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		},
		ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
	}
}

// errUnknownSession is the error returned from the PSK callback when
// the registry does not recognise the identity. pion turns this into
// an alert.InternalError to the client.
var errUnknownSession = errors.New("dtls: unknown session")

// isClosedErr returns true when err indicates the listener has been
// closed; we treat that as a graceful shutdown signal rather than a
// real failure.
func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// pion wraps the closed-listener error; surface text match
	// catches the wrapped form too.
	s := err.Error()
	return s == "use of closed network connection" ||
		s == "listener closed"
}
