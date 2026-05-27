package dtls

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"

	piondtls "github.com/pion/dtls/v3"
)

// Packet-type codes carried in byte 0 of the AnyConnect DTLS frame.
// Values match the CSTP enum in internal/cstp and the protocol doc
// (§1.5 + §2.3 — same enum, different framing).
const (
	pktData       byte = 0
	pktDPDOut     byte = 3
	pktDPDResp    byte = 4
	pktDisconnect byte = 5
	pktKeepalive  byte = 7
	pktCompressed byte = 8
	pktTermServer byte = 9
)

// dtlsReadBufSize bounds a single DTLS datagram inbound read. The
// AnyConnect inner MTU advertised on the CONNECT response is well
// under 1500; we round up to a comfortable 2 KiB to absorb any
// unexpected jumbo path. Allocations are per-loop-iteration on the
// hot path; a 2 KiB stack-sized buffer is cheap.
const dtlsReadBufSize = 2048

// handleConn drives a single accepted DTLS conn: handshake, attach to
// the Tunnel via PSK identity, read loop with byte/idle/rekey
// deadlines, and finally detach on exit. handleConn never closes the
// Tunnel — the CSTP/TLS side is the authoritative session, and a
// DTLS conn going away is a normal occurrence (network change,
// client reset, rekey budget).
func (s *Server) handleConn(ctx context.Context, conn *piondtls.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	// 1. Handshake with a bounded timeout. pion runs the handshake
	// either eagerly on first Read or via HandshakeContext; we drive
	// it explicitly so failure modes show up here rather than on the
	// first data read where we have a Tunnel attached.
	hsCtx, hsCancel := context.WithTimeout(ctx, s.cfg.HandshakeTimeout)
	hsErr := conn.HandshakeContext(hsCtx)
	hsCancel()
	if hsErr != nil {
		s.log.Debug("dtls handshake failed",
			slog.String("remote", remoteAddrString(conn)),
			slog.Any("err", hsErr))
		return
	}

	// 2. Resolve the Tunnel from the PSK identity the client sent in
	// flight 5 ClientKeyExchange. pion stores it on State.IdentityHint.
	state, ok := conn.ConnectionState()
	if !ok || len(state.IdentityHint) == 0 {
		s.log.Warn("dtls post-handshake state missing PSK identity",
			slog.String("remote", remoteAddrString(conn)))
		return
	}
	sessionID := string(state.IdentityHint)
	_, tunnel, regOK := s.cfg.Registry.LookupSession(sessionID)
	if !regOK || tunnel == nil {
		// The session went away between the PSK callback and now.
		// Drop cleanly; the client retries on next opportunity.
		s.log.Info("dtls session vanished post-handshake",
			slog.String("remote", remoteAddrString(conn)),
			slog.String("session_id", redactSessionID(sessionID)))
		return
	}

	st := &connState{
		conn:      conn,
		tunnel:    tunnel,
		sessionID: sessionID,
		startedAt: s.cfg.nowFn(),
	}
	s.active.Store(conn, st)
	defer s.active.Delete(conn)

	// 3. Hand the data plane over. Subsequent tunnel.WritePacket calls
	// now go out as DTLS frames on this conn. AttachDTLS returns nil
	// if the Tunnel raced to close between the lookup above and the
	// attach call — we drop cleanly in that case.
	prev := tunnel.AttachDTLS(conn)
	if prev == nil {
		s.log.Info("dtls tunnel closed during attach; aborting",
			slog.String("session_id", redactSessionID(sessionID)))
		return
	}
	defer tunnel.DetachDTLS()

	s.log.Info("dtls attached",
		slog.String("device", tunnel.Identity().DeviceID),
		slog.String("remote", remoteAddrString(conn)),
		slog.String("session_id", redactSessionID(sessionID)),
		slog.String("prev_kind", connKind(prev)))

	// 4. Drive the read loop until error, idle, rekey, or shutdown.
	exitErr := s.readLoop(ctx, st)
	if exitErr != nil && !errors.Is(exitErr, io.EOF) && !errors.Is(exitErr, net.ErrClosed) {
		s.log.Debug("dtls read loop exit",
			slog.String("device", tunnel.Identity().DeviceID),
			slog.Any("err", exitErr))
	} else {
		s.log.Info("dtls detached",
			slog.String("device", tunnel.Identity().DeviceID),
			slog.Uint64("bytes_in", st.bytesIn.Load()),
			slog.Uint64("bytes_out", st.bytesOut.Load()))
	}
}

// readLoop reads DTLS datagrams off conn, decodes the 1-byte type
// header, and routes the payload: data frames go to the Tunnel via
// InjectInbound; control frames (DPD/keepalive/disconnect/term) are
// handled in-band.
//
// readLoop also enforces the rekey deadlines: the wall-clock budget
// (cfg.RekeyAfter) drives a context-bound timeout; the byte budget
// (cfg.RekeyAfterBytes) is checked on every successful read. The
// idle deadline (cfg.IdleTimeout) is enforced via SetReadDeadline so
// a silent socket eventually unblocks the Read.
//
// On any exit path the conn is closed by handleConn's defer, so the
// underlying UDP path tears down promptly.
func (s *Server) readLoop(parent context.Context, st *connState) error {
	rekeyDeadline := st.startedAt.Add(s.cfg.RekeyAfter)
	rekeyCtx, rekeyCancel := context.WithDeadline(parent, rekeyDeadline)
	defer rekeyCancel()

	// Bridge the rekey/parent cancellation into a read-side wakeup:
	// pion's Conn.Read respects SetReadDeadline, so we periodically
	// nudge the deadline forward. The simplest pattern is a goroutine
	// that closes the conn when the deadline fires.
	closeOnDone := make(chan struct{})
	defer close(closeOnDone)
	go func() {
		select {
		case <-rekeyCtx.Done():
			_ = st.conn.Close()
		case <-closeOnDone:
		}
	}()

	buf := make([]byte, dtlsReadBufSize)
	for {
		if s.cfg.IdleTimeout > 0 {
			_ = st.conn.SetReadDeadline(s.cfg.nowFn().Add(s.cfg.IdleTimeout))
		}
		n, err := st.conn.Read(buf)
		if err != nil {
			// Distinguish rekey-budget exit (parent ctx still alive,
			// but the rekey deadline has fired) from genuine read
			// errors so the caller can log it as a budget event.
			if rekeyCtx.Err() != nil && parent.Err() == nil && !s.isClosed() {
				s.log.Info("dtls rekey budget hit",
					slog.String("device", st.tunnel.Identity().DeviceID),
					slog.Duration("age", s.cfg.nowFn().Sub(st.startedAt)),
					slog.Uint64("bytes_in", st.bytesIn.Load()),
					slog.Uint64("bytes_out", st.bytesOut.Load()))
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}
		st.bytesIn.Add(uint64(n))
		if st.bytesIn.Load()+st.bytesOut.Load() >= s.cfg.RekeyAfterBytes {
			s.log.Info("dtls byte budget hit",
				slog.String("device", st.tunnel.Identity().DeviceID),
				slog.Uint64("bytes_in", st.bytesIn.Load()),
				slog.Uint64("bytes_out", st.bytesOut.Load()))
			return nil
		}

		typ := buf[0]
		payload := buf[1:n]
		switch typ {
		case pktData:
			if !st.tunnel.InjectInbound(payload) {
				return errors.New("dtls: tunnel closed")
			}
		case pktDPDOut:
			// Echo the opaque payload verbatim as DPD-resp on the
			// DTLS conn. Per protocol doc §2.3 the response carries
			// the same body as the request.
			if err := s.writeDTLSFrame(st, pktDPDResp, payload); err != nil {
				return err
			}
		case pktDPDResp:
			// Liveness signal; nothing to do. Read already updated
			// the read deadline.
		case pktKeepalive:
			// Silent keepalive; no echo, no action.
		case pktDisconnect, pktTermServer:
			s.log.Info("dtls client disconnect",
				slog.String("device", st.tunnel.Identity().DeviceID))
			return nil
		case pktCompressed:
			// We never negotiate DTLS compression. Treat as a
			// protocol violation and tear down DTLS; CSTP picks the
			// data plane back up.
			return errors.New("dtls: unexpected compressed frame")
		default:
			// Liberal in what we accept: unknown frame types are
			// silently dropped. The client may have learnt a new
			// type we have not implemented yet.
		}
	}
}

// writeDTLSFrame is the server-side companion to
// Tunnel.writeDTLSFrame, used for emitting control frames (DPD-resp)
// out of the DTLS read loop. It accounts the write against bytesOut
// so the byte budget includes our outbound traffic.
func (s *Server) writeDTLSFrame(st *connState, typ byte, payload []byte) error {
	buf := make([]byte, 1+len(payload))
	buf[0] = typ
	copy(buf[1:], payload)
	if _, err := st.conn.Write(buf); err != nil {
		return err
	}
	st.bytesOut.Add(uint64(len(buf)))
	return nil
}

// remoteAddrString returns the conn's remote address as a printable
// string, or "?" if the conn does not have one (e.g. a fake test
// pipe).
func remoteAddrString(conn net.Conn) string {
	if conn == nil {
		return "?"
	}
	if a := conn.RemoteAddr(); a != nil {
		return a.String()
	}
	return "?"
}

// redactSessionID returns a short, log-safe rendering of a session
// token. We do not want long random tokens in logs because they
// authenticate the client; even a partial leak helps an attacker
// confirm a guessed value.
func redactSessionID(s string) string {
	if len(s) <= 8 {
		return "<short>"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

// connKind labels a conn for log output: "tls", "dtls", or "?". Used
// to record what was being replaced on AttachDTLS.
func connKind(c net.Conn) string {
	if c == nil {
		return "?"
	}
	if _, ok := c.(*piondtls.Conn); ok {
		return "dtls"
	}
	// Heuristic: a *tls.Conn is the typical other case but we do not
	// import crypto/tls just to type-assert. The fallback label is
	// "tls" because that is the only other connection type the
	// Tunnel currently holds.
	return "tls"
}
