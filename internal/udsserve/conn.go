package udsserve

import (
	"bufio"
	"net"
	"sync/atomic"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/udshandoff"
)

// handoffConn wraps a UDS net.Conn to (a) replay any bytes already
// buffered in the udshandoff.AcceptedStream's bufio.Reader (post-header
// payload that landed in the same recv as the PROXY-v2 prefix), (b)
// carry the parsed HandoffInfo so http.Server.ConnContext can pull it
// out and inject it into the request context, and (c) signal a `done`
// channel on Close so the udshandoff stream-handler goroutine can wait
// for http.Server (or the post-hijack tunnel goroutine) to finish with
// the conn before its `defer conn.Close()` fires.
//
// The wrapper implements net.Conn so http.Server can drive it directly.
// LocalAddr / RemoteAddr / SetDeadline pass through to the underlying
// UDS conn — the http.Server only needs them for diagnostic shape; the
// Stage 1 spec considers the conn's identity to be carried by the
// parsed PROXY-v2 header + TLVs, not by the UDS kernel-observed addrs.
type handoffConn struct {
	net.Conn
	br      *bufio.Reader // holds zero or more post-header bytes from the accept
	info    *HandoffInfo
	rxBytes atomic.Int64
	txBytes atomic.Int64
	closed  atomic.Bool
	done    chan struct{} // signalled exactly once when Close is called
}

// newHandoffConn wraps a udshandoff.AcceptedStream as a net.Conn ready
// for http.Server to serve.
func newHandoffConn(acc *udshandoff.AcceptedStream, info *HandoffInfo) *handoffConn {
	return &handoffConn{
		Conn: acc.Conn,
		br:   acc.Reader,
		info: info,
		done: make(chan struct{}),
	}
}

func (c *handoffConn) Read(p []byte) (int, error) {
	n, err := c.br.Read(p)
	if n > 0 {
		c.rxBytes.Add(int64(n))
	}
	return n, err
}

func (c *handoffConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.txBytes.Add(int64(n))
	}
	return n, err
}

func (c *handoffConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		err := c.Conn.Close()
		close(c.done)
		return err
	}
	return nil
}

// waitClosed blocks until Close has been called on this conn. The
// udshandoff stream-handler goroutine uses this to defer its
// `defer conn.Close()` until http.Server (or, after hijack, the CSTP
// tunnel goroutine) has finished with the conn.
func (c *handoffConn) waitClosed() { <-c.done }

// SetDeadline / SetReadDeadline / SetWriteDeadline pass through to the
// underlying conn so http.Server's per-request deadlines work.
func (c *handoffConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *handoffConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *handoffConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }

// info returns the parsed handoff metadata. Exposed for the ConnContext
// callback in serve.go.
func (c *handoffConn) Info() *HandoffInfo { return c.info }

// connQueue is a tiny FIFO that lets the UDS accept loop hand conns to
// a long-lived http.Server.Serve(). One queue per Serve invocation. The
// queue itself implements net.Listener so http.Server can drive it.
type connQueue struct {
	ch     chan net.Conn
	addr   net.Addr
	closed atomic.Bool
}

func newConnQueue() *connQueue {
	return &connQueue{
		ch:   make(chan net.Conn, 64),
		addr: queueAddr{},
	}
}

func (q *connQueue) Accept() (net.Conn, error) {
	c, ok := <-q.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (q *connQueue) Close() error {
	if q.closed.CompareAndSwap(false, true) {
		close(q.ch)
	}
	return nil
}

func (q *connQueue) Addr() net.Addr { return q.addr }

// push enqueues a conn for the http.Server's accept loop. Returns false
// if the queue is already closed (so the caller closes the conn instead
// of leaking it).
func (q *connQueue) push(c net.Conn) bool {
	if q.closed.Load() {
		return false
	}
	select {
	case q.ch <- c:
		return true
	default:
		// Backpressure: drop the conn and let the facade reconnect via
		// the §2.5 retry policy. In practice the buffer (64) is far
		// above the protocol's expected concurrent-flow count
		// (low-tens for a single facade); reaching this branch implies
		// a stuck handler.
		return false
	}
}

type queueAddr struct{}

func (queueAddr) Network() string { return "uds-handoff" }
func (queueAddr) String() string  { return "anyconnect-cstp" }
