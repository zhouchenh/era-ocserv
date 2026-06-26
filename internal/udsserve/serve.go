package udsserve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
	"github.com/zhouchenh/era-ocserv/internal/udshandoff"
)

// DefaultSocketPath is the canonical socket path the AnyConnect-CSTP
// row of the Stage 1 spec §2.1 nails down. Operators MAY override via
// Options.SocketPath but the default matches every other facade backend.
const DefaultSocketPath = udshandoff.SocketRoot + "/anyconnect-cstp.sock"

// Options configures a Server.
type Options struct {
	// SocketPath is the UDS path to bind. Defaults to DefaultSocketPath.
	SocketPath string

	// Logger is the slog logger for per-stream lifecycle events. Required.
	Logger *slog.Logger

	// Metrics is the udshandoff metric target. Optional (nil is a no-op).
	// Reused across UDS listeners so an operator can scrape one Snapshot
	// that covers every facade-backend protocol the era-ocserv binary
	// listens for.
	Metrics *udshandoff.Metrics

	// Handler is the HTTP handler the bridge invokes for each accepted
	// stream. Typically *cstp.Server. Required.
	Handler http.Handler

	// ReadHeaderTimeout caps the time the http.Server spends reading the
	// CSTP request headers before timing out a stream. Defaults to 10s,
	// matching the legacy loopback path.
	ReadHeaderTimeout time.Duration

	// PreboundListener, when non-nil, replaces the socket-binding step
	// (used by tests that supply an in-memory net.Listener). When set
	// SocketPath is only used for diagnostic logging.
	PreboundListener net.Listener
}

// Server is the UDS-mode CSTP bridge. One instance owns one UDS socket
// + one long-lived http.Server.
type Server struct {
	opts     Options
	queue    *connQueue
	uds      *udshandoff.StreamListener
	httpSrv  *http.Server
	wg       sync.WaitGroup
	closing  sync.Once
	closeErr error
}

// Listen binds the UDS socket, starts the http.Server, and returns the
// running Server. The caller calls Close to shut it down.
func Listen(ctx context.Context, opts Options) (*Server, error) {
	if opts.Handler == nil {
		return nil, errors.New("udsserve: Options.Handler is required")
	}
	if opts.Logger == nil {
		return nil, errors.New("udsserve: Options.Logger is required")
	}
	if opts.SocketPath == "" {
		opts.SocketPath = DefaultSocketPath
	}
	if opts.ReadHeaderTimeout <= 0 {
		opts.ReadHeaderTimeout = 10 * time.Second
	}

	s := &Server{
		opts:  opts,
		queue: newConnQueue(),
	}

	s.httpSrv = &http.Server{
		Handler:           wrapHandler(opts.Handler, opts.Logger),
		ReadHeaderTimeout: opts.ReadHeaderTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if hc, ok := c.(*handoffConn); ok {
				return contextWithInfo(ctx, hc.Info())
			}
			return ctx
		},
		// http.Server only triggers HTTP/2 upgrade over TLS; UDS is
		// plaintext so h2 is unreachable here regardless of
		// TLSNextProto. We leave that field nil.
		ErrorLog: nil, // handled via slog through the udshandoff layer
	}

	spec := udshandoff.LookupProtocol(udshandoff.ProtoAnyConnectCSTP)
	if spec == nil {
		return nil, errors.New("udsserve: ProtoAnyConnectCSTP not registered in udshandoff matrix")
	}

	uds, err := udshandoff.ListenStream(ctx, udshandoff.ListenerOptions{
		Logger:           opts.Logger.With(slog.String("listener", "udsserve")),
		Metrics:          opts.Metrics,
		Spec:             spec,
		SocketPath:       opts.SocketPath,
		PreboundListener: opts.PreboundListener,
	}, s.handle)
	if err != nil {
		return nil, fmt.Errorf("udsserve: ListenStream: %w", err)
	}
	s.uds = uds

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.httpSrv.Serve(s.queue); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			opts.Logger.Warn("udsserve: http.Serve exited", slog.String("err", err.Error()))
		}
	}()

	opts.Logger.Info("udsserve: listening",
		slog.String("socket", opts.SocketPath),
		slog.String("protocol", string(spec.Name)),
	)
	return s, nil
}

// handle is the udshandoff StreamHandler. The framework has already
// validated the matrix; we only have to extract the per-stream TLVs
// into a HandoffInfo, wrap the conn, and hand it to the http.Server's
// accept queue.
func (s *Server) handle(_ context.Context, acc *udshandoff.AcceptedStream) error {
	info, err := buildHandoffInfo(acc)
	if err != nil {
		s.opts.Logger.Warn("udsserve: handoff info invalid",
			slog.String("err", err.Error()),
			slog.String("trace_id", acc.TraceID()),
		)
		// Returning the error makes the udshandoff framework log a
		// flow_error line + close the conn. We've already double-logged
		// via Warn above for clarity (the framework's log line is
		// generic; ours names the specific field).
		return err
	}
	hc := newHandoffConn(acc, info)
	if !s.queue.push(hc) {
		// http.Server is shutting down or backpressure tripped. Close
		// the wrapper so the facade sees an immediate disconnect and
		// can reconnect.
		_ = hc.Close()
		return errors.New("udsserve: http.Server accept queue closed or full")
	}
	// Block until http.Server (or, post-hijack, the CSTP tunnel
	// goroutine) Close's the wrapped conn. The udshandoff framework
	// runs a `defer conn.Close()` after this handler returns; waiting
	// here defers that to the moment the consumer is done. The wrapped
	// Close is CAS-protected so the eventual no-op is safe.
	hc.waitClosed()
	return nil
}

// buildHandoffInfo extracts the AnyConnect-CSTP TLVs from a validated
// AcceptedStream. The matrix has already enforced TOKEN, DEVICE_ID,
// USER_ID, SOURCE_HINT_V6, MTLS_SUBJECT_DN, SPEC_VERSION, TRACE_ID are
// present, so we expect to find each; missing fields here are an
// internal-consistency error (framework + validator drift).
func buildHandoffInfo(acc *udshandoff.AcceptedStream) (*HandoffInfo, error) {
	info := &HandoffInfo{
		ClientSrc:   acc.Header.Src,
		OriginalDst: acc.Header.Dst,
		TraceID:     acc.Fields.TraceID,
		UserID:      acc.Fields.UserID,
	}
	if v := acc.Header.Lookup(proxyproto.EraTLVMTLSSubjectDN); len(v) > 0 {
		info.SubjectDN = string(v)
	} else {
		return nil, errors.New("missing ERA_TLV_MTLS_SUBJECT_DN (0xED)")
	}
	if v := acc.Header.Lookup(proxyproto.EraTLVDeviceID); len(v) > 0 {
		info.DeviceID = string(v)
	}
	if v := acc.Header.Lookup(proxyproto.EraTLVToken); len(v) == 12 {
		info.Token = append([]byte(nil), v...)
	}
	if v := acc.Header.Lookup(proxyproto.EraTLVSourceHintV6); len(v) == 16 {
		var arr [16]byte
		copy(arr[:], v)
		info.SourceHintV6 = netip.AddrFrom16(arr)
	}
	if v := acc.Header.Lookup(proxyproto.EraTLVOrigSNI); len(v) > 0 {
		info.OrigSNI = string(v)
	}
	if v := acc.Header.Lookup(proxyproto.EraTLVALPNDetail); len(v) > 0 {
		info.ALPNDetail = string(v)
	}
	return info, nil
}

// Close shuts the listener stack down in the right order:
//
//  1. Close the conn-queue so http.Server.Serve breaks out of its
//     accept loop on the next iteration (and so udshandoff's per-stream
//     handler short-circuits any future push attempts).
//  2. http.Server.Shutdown gracefully closes idle conns. CSTP tunnels
//     that have already hijacked the conn are out of http.Server's
//     control; they stay up until the cstp.Server closes them.
//  3. Close the UDS listener so no new handoffs arrive. The per-stream
//     goroutines that are still waiting on `hc.waitClosed()` (i.e. the
//     hijacked tunnels) will release when their tunnels close — that
//     is the cstp.Server's job, called separately by main.
//
// Close is idempotent.
func (s *Server) Close() error {
	s.closing.Do(func() {
		if s.queue != nil {
			_ = s.queue.Close()
		}
		if s.httpSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.httpSrv.Shutdown(ctx); err != nil {
				s.closeErr = err
			}
		}
		if s.uds != nil {
			if err := s.uds.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		}
		s.wg.Wait()
	})
	return s.closeErr
}

// SocketPath returns the socket path the server bound to. Useful for
// tests that want to confirm the default was applied.
func (s *Server) SocketPath() string { return s.opts.SocketPath }
