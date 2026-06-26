package udshandoff

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
)

// StreamHandler is the per-flow callback for a SOCK_STREAM UDS connection.
// It runs in its own goroutine; when it returns the framework closes the
// connection (if the handler did not already) and emits the flow_closed log
// line.
//
// Errors returned from the handler are surfaced in the flow_error log line
// with the handler's err string attached as the `err` field. A non-nil error
// does NOT cause the framework to close — the conn close is unconditional
// (defer in the listener).
type StreamHandler func(ctx context.Context, acc *AcceptedStream) error

// DatagramHandler is the per-datagram callback for a SOCK_DGRAM UDS socket.
// It runs in a goroutine sized by the listener's worker pool (Stage 1: one
// goroutine per datagram, no pool — sufficient for the protocol's flow rate
// and bounded by the UDS receive buffer). Errors propagate to a flow_error
// log line.
type DatagramHandler func(ctx context.Context, acc *AcceptedDatagram) error

// AcceptedStream is the value handed to a StreamHandler. It wraps the
// underlying UDS net.Conn with the parsed header, a bufio.Reader holding any
// post-header bytes already in the kernel buffer, byte counters wired into
// the flow_closed log line, and convenience accessors for the canonical
// ERA TLVs.
type AcceptedStream struct {
	// Conn is the raw UDS connection (post-header). Writes go directly to
	// Conn (no buffering); reads should go through Reader so the bufio
	// catches any bytes that arrived alongside the header.
	Conn net.Conn
	// Reader is the bufio'd reader on Conn. Holds zero or more bytes that
	// arrived in the same recv as the header.
	Reader *bufio.Reader
	// Header is the parsed PROXY-v2 + TLV view.
	Header *proxyproto.HeaderV2
	// Spec is the matrix row this flow was validated against.
	Spec *Spec
	// Logger is the per-flow logger (already has protocol + socket attrs).
	// Handlers can use it for trace-correlated per-flow events.
	Logger *slog.Logger
	// Fields carries the per-flow log payload (trace_id, device_id, …) so
	// the handler can emit its own lifecycle events with consistent fields.
	Fields LogFields
	// Metrics is the listener's metric counter target. Handlers can bump
	// per-protocol counters (e.g. bytes transferred) via the existing
	// telemetry.Collector — this field is the wire-shape metric surface.
	Metrics *Metrics

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// Read reads from the bufio'd reader, accumulating into the bytes_in counter.
func (a *AcceptedStream) Read(p []byte) (int, error) {
	n, err := a.Reader.Read(p)
	if n > 0 {
		a.bytesIn.Add(int64(n))
	}
	return n, err
}

// Write writes directly to Conn, accumulating into the bytes_out counter.
func (a *AcceptedStream) Write(p []byte) (int, error) {
	n, err := a.Conn.Write(p)
	if n > 0 {
		a.bytesOut.Add(int64(n))
	}
	return n, err
}

// Close closes the underlying conn.
func (a *AcceptedStream) Close() error { return a.Conn.Close() }

// CopyTo streams the post-header bytestream into dst, accumulating bytes
// into bytes_out. Convenience for handlers that want the simple "splice
// to upstream" shape.
func (a *AcceptedStream) CopyTo(dst io.Writer) (int64, error) {
	n, err := io.Copy(dst, a.Reader)
	a.bytesIn.Add(n)
	return n, err
}

// CopyFrom is the inverse: it streams src into Conn, accumulating bytes into
// bytes_in. (Direction-naming follows the bytes_in/bytes_out spec §8.3
// convention: bytes_in == bytes received from client; bytes_out == bytes
// sent to client. So Copy from upstream → Write to UDS conn = bytes_out.)
func (a *AcceptedStream) CopyFrom(src io.Reader) (int64, error) {
	n, err := io.Copy(a.Conn, src)
	a.bytesOut.Add(n)
	return n, err
}

// TraceID returns the parsed trace ID from the header.
func (a *AcceptedStream) TraceID() string { return a.Fields.TraceID }

// DeviceID returns the parsed device UUID.
func (a *AcceptedStream) DeviceID() string { return a.Fields.DeviceID }

// UserID returns the parsed user identifier.
func (a *AcceptedStream) UserID() string { return a.Fields.UserID }

// AcceptedDatagram is the value handed to a DatagramHandler.
type AcceptedDatagram struct {
	// Frame is the parsed view.
	Frame *DGramFrame
	// Spec is the matrix row this datagram was validated against.
	Spec *Spec
	// Logger is the per-listener logger (datagram cardinality is too high
	// for per-flow loggers — handlers add trace_id explicitly).
	Logger *slog.Logger
	// Metrics is the listener's metric counter target.
	Metrics *Metrics
	// Fields carries the per-flow log payload.
	Fields LogFields
	// PeerAddr is the kernel-observed UDS peer (the facade's UDS connect
	// addr). Unused by most handlers; included for diagnostic completeness.
	PeerAddr net.Addr
	// Reply, when called, writes a datagram back to the facade with the
	// `fl` bit-0 set to DirBackendToFacade and the inner PROXY-v2 envelope's
	// addresses unchanged. The handler passes raw payload bytes; the
	// framework re-wraps with the fixed header + TLVs.
	Reply ReplyFunc
}

// ReplyFunc is the writer the framework hands the datagram handler. It
// re-uses the same TLV set the inbound carried (the response goes back to
// the facade with the same trace_id / device_id / source_hint etc. — the
// facade routes by ConnID for QUIC or 4-tuple for DTLS, per spec §5.5).
type ReplyFunc func(payload []byte) error
