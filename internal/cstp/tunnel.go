package cstp

import (
	"bufio"
	"errors"
	"io"
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
//
// Data plane (DTLS attachment). When a DTLS data channel has been
// completed for the same session (see AttachDTLS), subsequent
// WritePacket calls emit a 1-byte-typed DTLS-framed packet on the
// attached UDP conn instead of an 8-byte CSTP frame on the TLS conn.
// Control frames (DPD/keepalive/disconnect) continue to be emitted on
// the CSTP/TLS channel via the heartbeat goroutine. Inbound DTLS data
// is fed back into the same dataCh by the DTLS server via
// InjectInbound, so ReadPacket consumers do not need to be aware of
// which channel a given frame arrived on.
type Tunnel struct {
	server *Server
	conn   net.Conn
	bw     *bufio.Writer
	br     *bufio.Reader

	identity  Identity
	sessionID string

	// dataCh carries inbound AC_PKT_DATA frames from the reader
	// goroutines (CSTP readLoop and, when attached, the DTLS server)
	// to ReadPacket callers. Buffered modestly to absorb short bursts
	// without blocking the reader.
	dataCh chan []byte

	// writeMu serializes Writes to the underlying CSTP/TLS conn. The
	// heartbeat goroutine and WritePacket both need to emit frames;
	// the underlying TLS conn is not safe for concurrent Write.
	writeMu sync.Mutex

	// dtls holds the active DTLS data-channel attachment when present.
	// Loaded atomically by WritePacket to decide whether to emit a
	// DTLS-framed packet (preferred when set) or a CSTP-framed packet
	// on the TLS conn. Mutated under attachMu so AttachDTLS/DetachDTLS
	// observe a single in-flight transition at a time.
	dtls     atomic.Pointer[dtlsAttachment]
	attachMu sync.Mutex

	// lastInbound / lastOutbound are unix nanos updated by the reader
	// and writer hot paths. The heartbeat goroutine polls them through
	// atomic load to decide when to fire DPD vs keepalive.
	lastInbound  atomic.Int64
	lastOutbound atomic.Int64

	closeOnce  sync.Once
	closeCh    chan struct{}
	dataChOnce sync.Once
	closeErr   atomic.Pointer[error]

	dpdInterval       time.Duration
	keepaliveInterval time.Duration
	idleTimeout       time.Duration
	nowFn             func() time.Time
}

// dtlsAttachment is the per-tunnel handle the DTLS server installs
// on a Tunnel after a successful PSK handshake. The conn is a
// pion/dtls *Conn (satisfying net.Conn). writeMu serializes
// concurrent Write calls because the DTLS conn, like a TLS conn,
// is not safe for parallel Write.
type dtlsAttachment struct {
	conn    net.Conn
	writeMu sync.Mutex
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
func (s *Server) newTunnel(conn net.Conn, rw *bufio.ReadWriter, id Identity, sessionToken string) *Tunnel {
	now := s.now()
	t := &Tunnel{
		server:            s,
		conn:              conn,
		bw:                rw.Writer,
		br:                rw.Reader,
		identity:          id,
		sessionID:         sessionToken,
		dataCh:            make(chan []byte, 64),
		closeCh:           make(chan struct{}),
		dpdInterval:       time.Duration(s.cfg.DPDInterval) * time.Second,
		keepaliveInterval: time.Duration(s.cfg.KeepaliveInterval) * time.Second,
		idleTimeout:       time.Duration(s.cfg.IdleTimeout) * time.Second,
		nowFn:             s.cfg.Now,
	}
	t.lastInbound.Store(now.UnixNano())
	t.lastOutbound.Store(now.UnixNano())

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

// WritePacket frames p as an AC_PKT_DATA packet and writes it on the
// preferred data channel: the attached DTLS conn if AttachDTLS has been
// called and the conn is still alive, otherwise the original CSTP/TLS
// conn. Concurrent calls are safe; each path serializes through its
// own mutex.
//
// If a DTLS write fails (transient UDP issue, peer reset), the failure
// is returned to the caller and the attachment is left in place — the
// caller (typically the bridge) treats this as a per-frame drop, not a
// session failure. Permanent DTLS failures are detected by the DTLS
// server's per-conn read loop, which calls DetachDTLS to fall back to
// CSTP for subsequent writes.
func (t *Tunnel) WritePacket(p []byte) (int, error) {
	if att := t.dtls.Load(); att != nil {
		if err := t.writeDTLSFrame(att, pktData, p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if err := t.writeFrame(pktData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// AttachDTLS swaps the tunnel's data plane from CSTP-over-TLS to the
// supplied DTLS conn. After this call returns, WritePacket emits
// 1-byte-typed DTLS frames on conn instead of 8-byte CSTP frames on
// the TLS conn. Control-plane frames (DPD, keepalive, disconnect)
// continue to be emitted on the TLS conn by the heartbeat goroutine
// for stability — the AnyConnect protocol assumes the TCP control
// channel stays alive even when DTLS is the data path.
//
// The returned prev is the conn that was acting as the data channel
// immediately before AttachDTLS — for the typical "first DTLS handshake
// for a tunnel" path this is the original TLS conn. The caller does not
// need to do anything with prev: control traffic still uses it via the
// tunnel's existing read/write paths. prev is returned for diagnostics
// and to make rare DTLS-replaces-DTLS transitions observable in tests.
//
// AttachDTLS does not start any reader on conn; the caller (the DTLS
// server) drives reads itself and pushes inbound data frames through
// InjectInbound.
func (t *Tunnel) AttachDTLS(conn net.Conn) (prev net.Conn) {
	if conn == nil {
		return nil
	}
	t.attachMu.Lock()
	defer t.attachMu.Unlock()
	// Refuse to attach to a tunnel that has already closed; the
	// caller (the DTLS server) checks the return for nil and closes
	// its conn. Without this guard a late attachment would linger
	// past closeWithErr and prevent garbage collection of the DTLS
	// conn until the next WritePacket attempt.
	select {
	case <-t.closeCh:
		return nil
	default:
	}
	if old := t.dtls.Swap(&dtlsAttachment{conn: conn}); old != nil {
		return old.conn
	}
	return t.conn
}

// DetachDTLS reverts the data plane to CSTP-over-TLS. Subsequent
// WritePacket calls emit CSTP frames on the original TLS conn again.
// Called by the DTLS server's per-conn loop when the DTLS conn closes
// (clean shutdown, idle timeout, or read error). The tunnel itself
// stays alive — only the data-plane preference is unwound. If no
// DTLS attachment is active, DetachDTLS is a no-op.
func (t *Tunnel) DetachDTLS() {
	t.attachMu.Lock()
	defer t.attachMu.Unlock()
	t.dtls.Store(nil)
}

// InjectInbound delivers a payload p (a raw IP packet decoded from a
// DTLS data frame on the attached conn) to ReadPacket consumers. The
// payload is copied so the caller can reuse its scratch buffer
// immediately. Returns false if the tunnel has been closed (the
// caller should also exit its DTLS read loop).
//
// Inbound DTLS control frames (DPD/keepalive/disconnect) are NOT
// routed through this method; the DTLS server handles them itself
// per the protocol (echo DPD, drop keepalive, signal disconnect).
func (t *Tunnel) InjectInbound(p []byte) bool {
	if len(p) == 0 {
		return true
	}
	pkt := make([]byte, len(p))
	copy(pkt, p)
	t.lastInbound.Store(t.now().UnixNano())
	select {
	case t.dataCh <- pkt:
		return true
	case <-t.closeCh:
		return false
	}
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
		// Drop the DTLS attachment and close the DTLS conn if any,
		// so the DTLS server's per-conn loop unblocks promptly.
		if att := t.dtls.Swap(nil); att != nil {
			_ = att.conn.Close()
		}
		_ = t.conn.Close()
		// Close dataCh exactly once so all producers (CSTP readLoop
		// and any DTLS-side InjectInbound caller) observe a clean
		// shutdown without panicking on a closed channel.
		t.dataChOnce.Do(func() { close(t.dataCh) })
		// Drop the tunnel from the DTLS lookup so a late-arriving
		// DTLS handshake on this session token gets an unknown-session
		// answer rather than a freshly-closed tunnel.
		if t.server != nil {
			t.server.forgetTunnel(t.sessionID)
		}
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
	// dataCh is closed centrally in closeWithErr so that DTLS-side
	// producers (InjectInbound) and the CSTP readLoop can both exit
	// safely without racing on close. ReadPacket already selects on
	// closeCh as a secondary wakeup path, so the channel close itself
	// is mainly a hygiene signal.

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

// heartbeatLoop fires DPD requests when the inbound channel is silent
// and keepalive frames when the outbound channel has been silent
// without data of its own. Granularity is the smaller of the two
// intervals, floored at 1s.
func (t *Tunnel) heartbeatLoop() {
	tick := t.dpdInterval
	if t.keepaliveInterval > 0 && t.keepaliveInterval < tick {
		tick = t.keepaliveInterval
	}
	if tick <= 0 {
		tick = time.Second
	}

	ticker := time.NewTicker(tick / 2)
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

			if t.idleTimeout > 0 && now.Sub(lastIn) > t.idleTimeout {
				_ = t.writeFrame(pktDisconnect, []byte{0})
				_ = t.closeWithErr(errTunnelClosed)
				return
			}

			// DPD if inbound has been silent for a full interval.
			if t.dpdInterval > 0 && now.Sub(lastIn) >= t.dpdInterval {
				// Eight-byte opaque payload: high four bytes are a
				// monotonic counter so we can correlate responses in
				// logs if we ever need to.
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
				continue
			}

			// Keepalive when outbound has been silent but we have not
			// just fired a DPD. Zero-length payload.
			if t.keepaliveInterval > 0 && now.Sub(lastOut) >= t.keepaliveInterval {
				if err := t.writeFrame(pktKeepalive, nil); err != nil {
					_ = t.closeWithErr(err)
					return
				}
			}
		}
	}
}

// writeDTLSFrame frames typ + payload as a DTLS-side AnyConnect packet
// (1-byte type + raw payload, per protocol doc §2.3) and writes it as
// a single datagram on the DTLS conn held in att. Writes are
// serialized through att.writeMu because pion's *dtls.Conn (like
// crypto/tls) is not safe for concurrent Write.
//
// On write error the caller (WritePacket) returns the error to the
// bridge but does NOT detach the DTLS attachment automatically: a
// transient EAGAIN on the underlying UDP socket is not a session
// failure. Permanent failures are surfaced by the DTLS server's
// per-conn read loop.
func (t *Tunnel) writeDTLSFrame(att *dtlsAttachment, typ byte, payload []byte) error {
	if len(payload) > maxFramePayload {
		return errFrameTooLarge
	}
	buf := make([]byte, 1+len(payload))
	buf[0] = typ
	copy(buf[1:], payload)

	att.writeMu.Lock()
	defer att.writeMu.Unlock()

	select {
	case <-t.closeCh:
		return errTunnelClosed
	default:
	}

	if _, err := att.conn.Write(buf); err != nil {
		return err
	}
	t.lastOutbound.Store(t.now().UnixNano())
	return nil
}

// writeFrame frames typ + payload as a CSTP frame and flushes it on
// the underlying conn. Serialized through writeMu because crypto/tls
// is not safe for concurrent Write.
func (t *Tunnel) writeFrame(typ byte, payload []byte) error {
	if len(payload) > maxFramePayload {
		return errFrameTooLarge
	}

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
