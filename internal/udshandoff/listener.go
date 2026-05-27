package udshandoff

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
)

// SocketRoot is the canonical UDS handoff directory per spec §2.1.
// "/var/run/era-facade/handoffs/" is the production path on Linux; the
// constant lets a deployment override the prefix (e.g. for tests on
// platforms without /var/run).
const SocketRoot = "/var/run/era-facade/handoffs"

// SocketFileMode is the per-spec UDS socket file permission (§2.2). The
// default is "0600 + supplementary-group membership"; deployments may
// alternatively pick 0660 with `chgrp era-backend`. The framework writes
// 0600; if the operator requires 0660 they bind the socket themselves and
// pass it in via *ListenerOptions.PreboundListener.
//
// systemd-side socket-activation deployments should:
//   - User=era-facade Group=era-facade for the facade unit.
//   - User=<backend> Group=era-backend SupplementaryGroups=era-facade for the
//     backend unit. (Backend reads/writes the 0600 socket via group
//     membership.)
//   - Directory mode 0710 owned era-facade:era-backend (§2.2).
const SocketFileMode os.FileMode = 0o600

// HeaderReadTimeout bounds how long the listener waits for the PROXY-v2 +
// TLV prefix on a freshly-accepted UDS connection before giving up. The
// facade emits the prefix immediately on connect; this is purely a safety
// net against a stalled / silent peer.
var HeaderReadTimeout = 5 * time.Second

// ListenerOptions configures a StreamListener or DatagramListener.
type ListenerOptions struct {
	// Logger is the slog logger used for lifecycle events. Required.
	Logger *slog.Logger
	// Metrics is the metric counter target. Optional (a nil Metrics is a
	// no-op).
	Metrics *Metrics
	// Spec is the protocol matrix row this listener enforces. Required.
	// The framework rejects any flow whose TLVs do not satisfy
	// Spec.Mandatory / Spec.Forbidden, with the right counter tag.
	Spec *Spec
	// SocketPath is the filesystem path the UDS socket is bound at. If
	// PreboundListener / PreboundPacketConn is non-nil, SocketPath is used
	// only for diagnostic logging.
	SocketPath string
	// PreboundListener, when non-nil, is used instead of binding a new
	// listener (e.g. when the operator uses systemd socket activation or
	// the test injects a custom listener). Only StreamListener.
	PreboundListener net.Listener
	// PreboundPacketConn, when non-nil, is the analogous override for
	// DatagramListener.
	PreboundPacketConn net.PacketConn
	// ReadDeadline is the per-flow header-read deadline; defaults to
	// HeaderReadTimeout.
	ReadDeadline time.Duration
}

// ListenStream binds a SOCK_STREAM UDS socket at opts.SocketPath (or uses
// opts.PreboundListener), accepts connections, parses + validates each
// connection's PROXY-v2 + TLV prefix, and hands the accepted stream off to
// handler.
//
// handler runs in its own goroutine per-connection. The framework owns the
// PROXY-v2 + TLV parse; the handler owns the post-prefix bytestream (which
// is the plaintext payload per spec §3.3). When the handler returns the
// framework closes the connection IF the handler did not already.
//
// The function returns a *StreamListener that the caller closes to stop the
// accept loop. On any non-recoverable Accept error (e.g. socket file
// removed) the listener returns from its accept goroutine and emits an
// `accept_loop_exit` log line.
func ListenStream(ctx context.Context, opts ListenerOptions, handler StreamHandler) (*StreamListener, error) {
	if opts.Spec == nil {
		return nil, errors.New("udshandoff: ListenStream: opts.Spec is required")
	}
	if opts.Spec.L4 != "tcp" {
		return nil, fmt.Errorf("udshandoff: protocol %q has L4=%s, not tcp — use ListenDatagram", opts.Spec.Name, opts.Spec.L4)
	}
	if opts.Logger == nil {
		return nil, errors.New("udshandoff: ListenStream: opts.Logger is required")
	}
	if handler == nil {
		return nil, errors.New("udshandoff: ListenStream: handler is required")
	}
	deadline := opts.ReadDeadline
	if deadline <= 0 {
		deadline = HeaderReadTimeout
	}
	var ln net.Listener
	if opts.PreboundListener != nil {
		ln = opts.PreboundListener
	} else {
		l, err := bindStream(opts.SocketPath)
		if err != nil {
			return nil, fmt.Errorf("udshandoff: bind %s: %w", opts.SocketPath, err)
		}
		ln = l
	}
	sl := &StreamListener{
		inner:    ln,
		opts:     opts,
		handler:  handler,
		deadline: deadline,
		done:     make(chan struct{}),
		closing:  false,
	}
	sl.wg.Add(1)
	go sl.acceptLoop(ctx)
	return sl, nil
}

// bindStream creates the socket-file directory if missing, removes any stale
// socket file, binds, listens, and `chmod`s the socket to SocketFileMode.
func bindStream(path string) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("empty socket path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o710); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// Best-effort remove of a stale socket file. On non-Linux dev hosts the
	// path may simply not exist; that's fine.
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix %s: %w", path, err)
	}
	if err := os.Chmod(path, SocketFileMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}
	return ln, nil
}

// StreamListener is the wrapper returned by ListenStream.
type StreamListener struct {
	inner    net.Listener
	opts     ListenerOptions
	handler  StreamHandler
	deadline time.Duration

	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
	done    chan struct{}
}

// Addr returns the bound socket's address.
func (s *StreamListener) Addr() net.Addr { return s.inner.Addr() }

// Close stops the accept loop, closes the underlying listener, waits for
// in-flight handler goroutines to return, and removes the socket file.
func (s *StreamListener) Close() error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	s.mu.Unlock()
	err := s.inner.Close()
	close(s.done)
	s.wg.Wait()
	// Best-effort removal of the socket file. The OS will have already
	// unlinked the inode on Close on Linux, but a stale path may exist.
	if s.opts.SocketPath != "" && s.opts.PreboundListener == nil {
		_ = os.Remove(s.opts.SocketPath)
	}
	return err
}

// acceptLoop is the per-listener accept goroutine.
func (s *StreamListener) acceptLoop(ctx context.Context) {
	defer s.wg.Done()
	logger := s.opts.Logger.With(
		slog.String("component", "udshandoff.stream"),
		slog.String("protocol", string(s.opts.Spec.Name)),
		slog.String("socket", s.opts.SocketPath),
	)
	go func() {
		// Honour ctx cancellation as a shutdown signal: closing the listener
		// unblocks the Accept call. We don't block on this; if the caller
		// closes the listener directly, this goroutine is a no-op.
		select {
		case <-ctx.Done():
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if !closing {
				_ = s.Close()
			}
		case <-s.done:
		}
	}()
	for {
		conn, err := s.inner.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing {
				return
			}
			// Net.Listener.Close races with Accept; some impls return EINVAL
			// or "use of closed network connection". Treat those as shutdown.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Warn("accept failed", slog.String("err", err.Error()))
			return
		}
		s.wg.Add(1)
		go s.handle(ctx, conn, logger)
	}
}

// handle is the per-connection goroutine: header read, validate, call handler.
func (s *StreamListener) handle(ctx context.Context, conn net.Conn, logger *slog.Logger) {
	defer s.wg.Done()
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(s.deadline))
	br := bufio.NewReader(conn)
	hdr, err := proxyproto.ReadHeaderV2WithTLVsBuffered(br)
	// Clear deadline once header read; payload phase uses caller-controlled
	// deadlines.
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		s.onHeaderError(err, logger)
		return
	}
	// Run protocol-matrix validation.
	res := s.opts.Spec.Validate(hdr.TLVs)
	fields := LogFields{
		Protocol:    s.opts.Spec.Name,
		ClientSrc:   hdr.Src,
		OriginalDst: hdr.Dst,
	}
	fields.FromTLVs(hdr.TLVs)
	if !res.OK {
		s.onValidationFailure(res, fields, logger)
		return
	}
	// Log unknown-ERA-TLV occurrences (skip-with-log per spec §4.4).
	for _, t := range res.UnknownERA {
		s.opts.Metrics.IncUnknownERATLV(t, s.opts.Spec.Name)
		logger.Debug("unknown ERA TLV skipped",
			slog.String("trace_id", fields.TraceID),
			slog.String("device_id", fields.DeviceID),
			slog.String("tlv_type", fmt.Sprintf("0x%02x", byte(t))),
		)
	}
	s.opts.Metrics.IncHandoffAccept(s.opts.Spec.Name)
	fields.Event = EventHandoffStart
	fields.EmitTo(logger, slog.LevelInfo, "stream handoff accepted")

	// Hand off to handler. Wrap conn so the bufio'd reader (with any
	// post-header bytes already buffered) is what the handler reads from.
	acc := &AcceptedStream{
		Conn:    conn,
		Reader:  br,
		Header:  hdr,
		Spec:    s.opts.Spec,
		Logger:  logger,
		Fields:  fields,
		Metrics: s.opts.Metrics,
	}
	start := time.Now()
	herr := handlerStreamSafe(ctx, s.handler, acc)
	fields.Duration = time.Since(start)
	fields.BytesIn = acc.bytesIn.Load()
	fields.BytesOut = acc.bytesOut.Load()
	if herr != nil {
		fields.Event = EventFlowError
		fields.Extra = append(fields.Extra, slog.String("err", herr.Error()))
		fields.EmitTo(logger, slog.LevelWarn, "stream handler failed")
		return
	}
	fields.Event = EventFlowClosed
	fields.EmitTo(logger, slog.LevelInfo, "stream flow closed")
}

// handlerStreamSafe runs the handler and converts a panic into an error so
// one bad handler does not take down the accept loop.
func handlerStreamSafe(ctx context.Context, h StreamHandler, acc *AcceptedStream) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("handler panic: %v", r)
		}
	}()
	return h(ctx, acc)
}

// onHeaderError dispatches to the right counter + log line for a header-
// reading failure.
func (s *StreamListener) onHeaderError(err error, logger *slog.Logger) {
	var herr *proxyproto.HeaderErr
	if errors.As(err, &herr) {
		switch herr.Kind {
		case proxyproto.ErrSignatureInvalid:
			s.opts.Metrics.IncProxyV2InvalidSignature()
		case proxyproto.ErrIncompleteHeader:
			s.opts.Metrics.IncIncompleteHeader()
		}
	} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		s.opts.Metrics.IncIncompleteHeader()
	}
	s.opts.Metrics.IncHandoffInvalid(s.opts.Spec.Name)
	logger.Warn("PROXY-v2 header read failed",
		slog.String("err", err.Error()),
	)
}

// onValidationFailure handles a header that parsed cleanly but failed the
// per-protocol matrix. The metric counter (handoff_invalid) is bumped; a
// structured WARN line with per-spec §8.1 fields is emitted.
func (s *StreamListener) onValidationFailure(res ValidateResult, fields LogFields, logger *slog.Logger) {
	s.opts.Metrics.IncHandoffInvalid(s.opts.Spec.Name)
	extra := make([]slog.Attr, 0, 3)
	if len(res.MissingMandatory) > 0 {
		extra = append(extra, slog.Any("missing_mandatory", typesToHex(res.MissingMandatory)))
	}
	if len(res.PresentForbidden) > 0 {
		extra = append(extra, slog.Any("present_forbidden", typesToHex(res.PresentForbidden)))
	}
	if len(res.ValueErrors) > 0 {
		ve := make([]string, 0, len(res.ValueErrors))
		for _, e := range res.ValueErrors {
			ve = append(ve, fmt.Sprintf("0x%02x:%s", byte(e.Type), e.Err))
		}
		extra = append(extra, slog.Any("value_errors", ve))
	}
	fields.Event = EventHandoffInvalid
	fields.Extra = extra
	fields.EmitTo(logger, slog.LevelWarn, "PROXY-v2 + TLV validation failed")
}

// typesToHex formats a slice of TLV types as `0xNN` strings for log payload.
func typesToHex(types []proxyproto.TLVType) []string {
	out := make([]string, 0, len(types))
	for _, t := range types {
		out = append(out, fmt.Sprintf("0x%02x", byte(t)))
	}
	return out
}
