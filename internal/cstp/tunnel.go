package cstp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Tunnel is the post-CONNECT binary frame stream. After phase 3
// completes, the underlying TLS connection is no longer a stream of
// HTTP requests; it carries 8-byte-framed CSTP packets in both
// directions.
//
// The Tunnel runs an internal heartbeat goroutine that
//
//   - sends X-CSTP-DPD-shaped DPD requests every cfg.DPDInterval
//     seconds when the inbound channel has been silent,
//   - sends X-CSTP-Keepalive zero-length probes when the outbound
//     channel has been silent for cfg.KeepaliveInterval seconds with no
//     data and no DPD already in flight,
//   - answers inbound DPD requests with a DPD-resp echoing the payload,
//   - watches for inbound disconnect and term-server frames and tears
//     the tunnel down on either.
//
// Data frames (AC_PKT_DATA) are surfaced through ReadPacket /
// WritePacket. Compressed frames are rejected with errCompressedFrame
// because era-ocserv does not negotiate CSTP compression per ADR 0057.
type Tunnel struct {
	server *Server
	conn   net.Conn
	bw     *bufio.Writer
	br     *bufio.Reader

	identity  Identity
	sessionID string
	dtls      *dtlsBindingState

	// dataCh carries inbound AC_PKT_DATA frames from the reader
	// goroutine to ReadPacket callers. Buffered modestly to absorb
	// short bursts without blocking the reader.
	dataCh chan []byte

	// writeMu serializes Writes to the underlying conn. The heartbeat
	// goroutine and WritePacket both need to emit frames; the
	// underlying TLS conn is not safe for concurrent Write.
	writeMu sync.Mutex

	// lastInbound / lastOutbound are unix nanos updated by the reader
	// and writer hot paths. The heartbeat goroutine polls them through
	// atomic load to decide when to fire DPD vs keepalive.
	lastInbound  atomic.Int64
	lastOutbound atomic.Int64

	closeOnce sync.Once
	closeCh   chan struct{}
	closeErr  atomic.Pointer[error]

	dpdInterval       time.Duration
	keepaliveInterval time.Duration
	idleTimeout       time.Duration
	nowFn             func() time.Time
}

type dtlsBindingState struct {
	installer       DTLSBindingInstaller
	binding         DTLSBinding
	refreshInterval time.Duration
	lastRefreshUnix atomic.Int64
	refreshing      atomic.Bool
}

// errCompressedFrame is returned to the caller via ReadPacket if the
// client sends a compressed frame even though we did not advertise
// any compression. Real Cisco SC and OpenConnect respect our omission
// and never send these; this is a defense-in-depth abort.
var errCompressedFrame = errors.New("cstp: unexpected compressed frame (compression not negotiated)")

// errTunnelClosed is returned by ReadPacket and WritePacket after the
// tunnel has been closed.
var errTunnelClosed = errors.New("cstp: tunnel closed")

// errClientDisconnect is recorded as the close cause when the peer
// sends AC_PKT_DISCONN.
var errClientDisconnect = errors.New("cstp: client requested disconnect")

// newTunnel builds a Tunnel around the hijacked net.Conn and starts
// the reader + heartbeat goroutines. The bufio.ReadWriter handed to
// us by hijack already contains the post-CONNECT bytes the http server
// buffered; we reuse it to avoid losing those bytes.
func (s *Server) newTunnel(conn net.Conn, rw *bufio.ReadWriter, id Identity, sessionToken string, dtlsState *dtlsBindingState) *Tunnel {
	now := s.now()
	t := &Tunnel{
		server:            s,
		conn:              conn,
		bw:                rw.Writer,
		br:                rw.Reader,
		identity:          id,
		sessionID:         sessionToken,
		dtls:              dtlsState,
		dataCh:            make(chan []byte, 64),
		closeCh:           make(chan struct{}),
		dpdInterval:       time.Duration(s.cfg.DPDInterval) * time.Second,
		keepaliveInterval: time.Duration(s.cfg.KeepaliveInterval) * time.Second,
		idleTimeout:       time.Duration(s.cfg.IdleTimeout) * time.Second,
		nowFn:             s.cfg.Now,
	}
	t.lastInbound.Store(now.UnixNano())
	t.lastOutbound.Store(now.UnixNano())
	if t.dtls != nil {
		t.dtls.lastRefreshUnix.Store(now.UnixNano())
	}

	go t.readLoop()
	go t.heartbeatLoop()
	return t
}

// Identity returns the resolved per-device identity for this tunnel.
// Callers route packets to the tunnel using this.
func (t *Tunnel) Identity() Identity { return t.identity }

// SessionID returns the long-lived session token associated with the
// tunnel. Used by the caller for logging / audit correlation.
func (t *Tunnel) SessionID() string { return t.sessionID }

// ReadPacket reads the next inbound data-frame payload into p, returns
// (n, nil) on success or (0, err) on close / error. The returned
// payload is a raw IP packet ready to write to a tun device.
func (t *Tunnel) ReadPacket(p []byte) (int, error) {
	select {
	case pkt, ok := <-t.dataCh:
		if !ok {
			return 0, t.closeCauseOr(io.EOF)
		}
		if len(pkt) > len(p) {
			// Caller's buffer is too small. Return what we can and
			// drop the rest: matching tun behavior where a truncated
			// read is preferable to dropping the whole frame.
			n := copy(p, pkt)
			return n, io.ErrShortBuffer
		}
		return copy(p, pkt), nil
	case <-t.closeCh:
		return 0, t.closeCauseOr(errTunnelClosed)
	}
}

// WritePacket frames p as an AC_PKT_DATA frame and writes it on the
// CSTP channel. Concurrent calls are safe; they serialize through an
// internal mutex.
func (t *Tunnel) WritePacket(p []byte) (int, error) {
	if err := t.writeFrame(pktData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close stops the heartbeat goroutine, closes the underlying conn,
// and unblocks readers. Close is idempotent.
func (t *Tunnel) Close() error {
	return t.closeWithErr(nil)
}

func (t *Tunnel) closeWithErr(cause error) error {
	t.closeOnce.Do(func() {
		if cause != nil {
			t.closeErr.Store(&cause)
		}
		close(t.closeCh)
		_ = t.conn.Close()
	})
	return nil
}

func (t *Tunnel) closeCauseOr(fallback error) error {
	if ep := t.closeErr.Load(); ep != nil {
		return *ep
	}
	return fallback
}

func (t *Tunnel) now() time.Time {
	if t.nowFn != nil {
		return t.nowFn()
	}
	return time.Now()
}

// readLoop runs on a dedicated goroutine and demuxes the inbound CSTP
// stream by frame type. Data frames go to dataCh; control frames are
// handled inline (DPD response, disconnect ack). A malformed frame
// tears the tunnel down because the stream is no longer aligned.
func (t *Tunnel) readLoop() {
	defer func() {
		// Closing dataCh wakes ReadPacket callers with the
		// closeCause. We deliberately do not nil-out t.dataCh; the
		// receive side handles the closed-channel case.
		close(t.dataCh)
	}()

	hdr := make([]byte, frameHeaderLen)
	buf := make([]byte, 1<<16) // max possible CSTP payload
	for {
		typ, n, err := readFrame(t.br, hdr, buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				_ = t.closeWithErr(io.EOF)
			} else {
				_ = t.closeWithErr(err)
			}
			return
		}
		t.lastInbound.Store(t.now().UnixNano())
		slog.Debug("cstp frame in", "device", t.identity.DeviceID, "type", typ, "len", n)

		switch typ {
		case pktData:
			// Copy so the caller can hold the payload independently
			// of our scratch buffer.
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case t.dataCh <- pkt:
			case <-t.closeCh:
				return
			}
		case pktDPDOut:
			// RFC behavior: echo payload verbatim as DPD-resp.
			echo := make([]byte, n)
			copy(echo, buf[:n])
			if err := t.writeFrame(pktDPDResp, echo); err != nil {
				_ = t.closeWithErr(err)
				return
			}
		case pktDPDResp:
			// Liveness witnessed via lastInbound update above; no
			// further action needed.
		case pktKeepalive:
			// Same; updating lastInbound suffices.
		case pktDisconnect:
			// TEMP DIAGNOSTIC: AnyConnect puts a reason string in the
			// AC_PKT_DISCONN payload; surface it so we can see why a strict
			// iOS client tears the tunnel down right after CONNECT.
			slog.Info("cstp client disconnect frame",
				"device", t.identity.DeviceID, "len", n,
				"payload", string(buf[:n]), "hex", fmt.Sprintf("%x", buf[:n]))
			_ = t.closeWithErr(errClientDisconnect)
			return
		case pktTermServer:
			// Should not be sent by client; treat as disconnect.
			_ = t.closeWithErr(errClientDisconnect)
			return
		case pktCompressed:
			_ = t.closeWithErr(errCompressedFrame)
			return
		default:
			// Unknown frame type: ignore per the principle of being
			// liberal in what we accept. The session stays alive.
		}
	}
}

// heartbeatLoop drives server-initiated liveness on the CSTP channel.
//
// A strict AnyConnect client (Cisco Secure Client) waits to RECEIVE server
// traffic soon after CONNECT to confirm the gateway is reachable both ways
// before it commits to sending its own data; if it sees only silence it
// declares "the secure gateway has rejected the connection" at ~20 s even
// though the data plane is fine. Stock ocserv avoids this because its clients
// drive DPD over DTLS — but on the facade-fronted CSTP path the client does
// NOT initiate DPD, so era-ocserv must. We send a DPD-request whenever our
// outbound channel has been idle for the heartbeat interval (a quarter of the
// keepalive window, ~5 s), which lands the first probe well before the
// client's ~20 s establishment deadline and keeps a recent liveness witness in
// front of the client whenever we have no data of our own to send. The client
// answers each DPD with a DPD-resp, which also keeps our inbound liveness fresh.
func (t *Tunnel) heartbeatLoop() {
	hb := t.keepaliveInterval / 4
	if t.dpdInterval > 0 && t.dpdInterval/4 < hb {
		hb = t.dpdInterval / 4
	}
	if hb < 2*time.Second {
		hb = 2 * time.Second
	}

	ticker := time.NewTicker(hb)
	defer ticker.Stop()

	var dpdSeq uint32
	for {
		select {
		case <-t.closeCh:
			return
		case <-ticker.C:
			now := t.now()
			lastIn := time.Unix(0, t.lastInbound.Load())
			lastOut := time.Unix(0, t.lastOutbound.Load())
			t.maybeRefreshDTLSBinding(now)

			if t.idleTimeout > 0 && now.Sub(lastIn) > t.idleTimeout {
				_ = t.writeFrame(pktDisconnect, []byte{0})
				_ = t.closeWithErr(errTunnelClosed)
				return
			}

			// Server-initiated DPD when our outbound channel has been idle.
			// Eight-byte opaque payload: high four bytes are a monotonic
			// counter so DPD responses can be correlated in logs.
			if now.Sub(lastOut) >= hb {
				dpdSeq++
				payload := []byte{
					byte(dpdSeq >> 24), byte(dpdSeq >> 16),
					byte(dpdSeq >> 8), byte(dpdSeq),
					'D', 'P', 'D', '!',
				}
				if err := t.writeFrame(pktDPDOut, payload); err != nil {
					_ = t.closeWithErr(err)
					return
				}
			}
		}
	}
}

func (t *Tunnel) maybeRefreshDTLSBinding(now time.Time) {
	if t.dtls == nil || t.dtls.installer == nil || t.dtls.refreshInterval <= 0 {
		return
	}
	last := time.Unix(0, t.dtls.lastRefreshUnix.Load())
	if now.Sub(last) < t.dtls.refreshInterval {
		return
	}
	if !t.dtls.refreshing.CompareAndSwap(false, true) {
		return
	}
	go func(binding DTLSBinding) {
		defer t.dtls.refreshing.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := t.dtls.installer.Upsert(ctx, binding); err == nil {
			t.dtls.lastRefreshUnix.Store(time.Now().UnixNano())
		}
	}(t.dtls.binding)
}

// writeFrame frames typ + payload as a CSTP frame and flushes it on
// the underlying conn. Serialized through writeMu because crypto/tls
// is not safe for concurrent Write.
func (t *Tunnel) writeFrame(typ byte, payload []byte) error {
	if len(payload) > maxFramePayload {
		return errFrameTooLarge
	}
	slog.Debug("cstp frame out", "device", t.identity.DeviceID, "type", typ, "len", len(payload))

	// Local scratch so concurrent calls don't share state.
	buf := make([]byte, frameHeaderLen+len(payload))
	n, err := encodeFrame(buf, typ, payload)
	if err != nil {
		return err
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	select {
	case <-t.closeCh:
		return errTunnelClosed
	default:
	}

	if _, err := t.bw.Write(buf[:n]); err != nil {
		_ = t.closeWithErr(err)
		return err
	}
	if err := t.bw.Flush(); err != nil {
		_ = t.closeWithErr(err)
		return err
	}
	t.lastOutbound.Store(t.now().UnixNano())
	return nil
}
