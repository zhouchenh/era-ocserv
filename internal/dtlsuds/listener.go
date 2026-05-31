package dtlsuds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/iam"
	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
	"github.com/zhouchenh/era-ocserv/internal/udshandoff"
)

// DefaultSocketPath is the canonical AnyConnect-DTLS UDS socket path
// (spec §2.1: `/var/run/era-facade/handoffs/anyconnect-dtls.sock`).
const DefaultSocketPath = udshandoff.SocketRoot + "/anyconnect-dtls.sock"

// DefaultHeartbeatInterval is how often the listener proactively sends a DTLS
// DPD-request to every active session. The AnyConnect client declares the
// gateway dead if it receives NO server traffic within its DPD/keepalive
// window (advertised X-DTLS-Keepalive=20 / X-DTLS-DPD=30). A real Cisco client
// with no app traffic of its own relies entirely on this server-initiated
// liveness — without it the tunnel collapses at ~20 s ("gateway rejected").
// 10 s keeps a witness well inside the client's window with ample margin.
const DefaultHeartbeatInterval = 10 * time.Second

// PacketSink is the bridge-side interface the DTLS listener calls to inject
// inbound L3 plaintext into the host TUN device. era-ocserv supplies a
// thin wrapper around its existing multi-queue tun bridge.
//
// WritePacket SHOULD be non-blocking on the happy path; the listener calls
// it inline in the receive loop and a slow sink will throttle every DTLS
// session sharing this listener.
type PacketSink interface {
	// WritePacket pushes one IP packet into the tun device. It is called
	// in the listener's receive-goroutine; implementations MUST NOT panic.
	WritePacket(p []byte) (int, error)
}

// SessionPacketSink is an OPTIONAL richer PacketSink the listener prefers
// when the supplied Sink implements it. It hands the originating *Session
// alongside the packet so the bridge can apply per-session CLAT translation
// (the client's inner-IPv4 → the device CLAT /128 SIIT source) before TUN
// injection. A Sink that does not implement this interface keeps the plain
// WritePacket behaviour (the native v6-only path is unchanged).
type SessionPacketSink interface {
	PacketSink
	// WritePacketFromSession pushes one IP packet from a known session into
	// the tun device. Same goroutine / non-panic contract as WritePacket.
	WritePacketFromSession(s *Session, p []byte) (int, error)
}

// SessionLifecycle is the bridge-side hook surface the listener notifies
// when sessions are admitted and evicted.
//
// OnAdmit is invoked synchronously the first time a 4-tuple appears in
// the session table; the bridge typically registers the inner-IPv6 →
// session mapping so its TUN-read loop can find the session for egress.
//
// OnEvict is invoked synchronously when a session leaves the table
// (idle timeout or listener Close); the bridge typically deregisters the
// inner-IPv6 mapping. The Session's reply closure has already been
// detach()'d by the time OnEvict fires, so any pending TUN-side writes
// will surface ErrSessionGone.
//
// Both hooks are called while the listener (or table) holds internal
// state — implementations MUST be fast and non-blocking. They MUST NOT
// re-enter the listener.
type SessionLifecycle interface {
	OnAdmit(*Session)
	OnEvict(*Session)
}

// noopLifecycle is the SessionLifecycle used when the caller does not
// supply one. Convenient for tests that only care about packet flow.
type noopLifecycle struct{}

func (noopLifecycle) OnAdmit(*Session) {}
func (noopLifecycle) OnEvict(*Session) {}

// Options configures a Listener.
type Options struct {
	// SocketPath is the UDS DGRAM socket to bind. Defaults to
	// DefaultSocketPath if empty.
	SocketPath string

	// Resolver maps a device UUID (from ERA_TLV_DEVICE_ID) to its
	// assigned identity (inner /128). Required.
	Resolver iam.Resolver

	// Sink is the TUN-injection target for inbound L3 plaintext.
	// Required.
	Sink PacketSink

	// Lifecycle, if non-nil, receives OnAdmit / OnEvict callbacks for
	// session table changes. Optional.
	Lifecycle SessionLifecycle

	// Logger is the slog target. Required.
	Logger *slog.Logger

	// Metrics is the udshandoff metric counter target. Optional (nil ⇒
	// no-op).
	Metrics *udshandoff.Metrics

	// IdleTimeout is the per-session inactivity window. Zero ⇒
	// DefaultIdleTimeout (300 s, spec §5.3).
	IdleTimeout time.Duration

	// EvictionTick is the eviction-walker cadence. Zero ⇒ DefaultEvictionTick.
	EvictionTick time.Duration

	// Now allows tests to inject a deterministic clock for the session
	// table. Production leaves it nil and the table falls back to time.Now.
	Now func() time.Time

	// PreboundPacketConn lets tests inject a custom net.PacketConn so they
	// can drive the listener without binding a real UDS socket. When set,
	// SocketPath is only used for diagnostic logging.
	PreboundPacketConn net.PacketConn

	// ResolveTimeout caps how long iam.Resolver.Resolve may block when
	// admitting a new session. Zero ⇒ 2 s.
	ResolveTimeout time.Duration

	// HeartbeatInterval is the cadence at which the listener proactively
	// sends a DTLS DPD-request to every active session so the AnyConnect
	// client always has a recent server-liveness witness. Zero ⇒
	// DefaultHeartbeatInterval (10 s). A negative value disables the
	// heartbeat (used by tests that drive liveness deterministically).
	HeartbeatInterval time.Duration
}

// Listener is the AnyConnect-DTLS UDS DGRAM consumer. One Listener owns
// one UDS socket + one session table + one underlying udshandoff
// DatagramListener.
type Listener struct {
	opts  Options
	uds   *udshandoff.DatagramListener
	table *Table

	logger *slog.Logger
	now    func() time.Time

	socketPath     string
	resolveTimeout time.Duration

	// sessionSink is opts.Sink narrowed to SessionPacketSink, or nil when
	// the supplied Sink only implements the plain PacketSink. Cached at
	// construction so the hot data path avoids a per-packet type assertion.
	sessionSink SessionPacketSink

	// heartbeat machinery: a goroutine that periodically sends a DTLS
	// DPD-request to every active session. heartbeatStop/heartbeatDone
	// coordinate shutdown; dpdSeq is a monotonic correlator placed in the
	// DPD payload (mirrors the CSTP heartbeat).
	heartbeatInterval time.Duration
	heartbeatStop     chan struct{}
	heartbeatDone     chan struct{}
	dpdSeq            atomic.Uint32
}

// Listen binds the UDS socket, starts the session table eviction loop,
// and returns the running Listener. The caller calls Close to shut it
// down.
func Listen(ctx context.Context, opts Options) (*Listener, error) {
	if opts.Resolver == nil {
		return nil, errors.New("dtlsuds: Options.Resolver is required")
	}
	if opts.Sink == nil {
		return nil, errors.New("dtlsuds: Options.Sink is required")
	}
	if opts.Logger == nil {
		return nil, errors.New("dtlsuds: Options.Logger is required")
	}
	if opts.SocketPath == "" {
		opts.SocketPath = DefaultSocketPath
	}
	if opts.ResolveTimeout <= 0 {
		opts.ResolveTimeout = 2 * time.Second
	}
	if opts.HeartbeatInterval == 0 {
		opts.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if opts.Lifecycle == nil {
		opts.Lifecycle = noopLifecycle{}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	spec := udshandoff.LookupProtocol(udshandoff.ProtoAnyConnectDTLS)
	if spec == nil {
		return nil, errors.New("dtlsuds: ProtoAnyConnectDTLS not registered in udshandoff matrix")
	}

	l := &Listener{
		opts:           opts,
		logger:         opts.Logger.With(slog.String("component", "dtlsuds")),
		now:            now,
		socketPath:     opts.SocketPath,
		resolveTimeout: opts.ResolveTimeout,
	}
	if ss, ok := opts.Sink.(SessionPacketSink); ok {
		l.sessionSink = ss
	}
	l.table = NewTable(TableOptions{
		IdleTimeout:  opts.IdleTimeout,
		EvictionTick: opts.EvictionTick,
		Now:          now,
		OnEvict: func(s *Session) {
			opts.Lifecycle.OnEvict(s)
			l.logger.Info("dtls session evicted",
				slog.String("trace_id", s.traceID),
				slog.String("device_id", s.deviceID),
				slog.String("inner", s.inner.String()),
				slog.String("four_tuple", s.key.String()),
				slog.Int64("age_ms", time.Since(s.createdAt).Milliseconds()),
			)
		},
	})
	l.table.Start()

	uds, err := udshandoff.ListenDatagram(ctx, udshandoff.ListenerOptions{
		Logger:             opts.Logger.With(slog.String("listener", "dtlsuds")),
		Metrics:            opts.Metrics,
		Spec:               spec,
		SocketPath:         opts.SocketPath,
		PreboundPacketConn: opts.PreboundPacketConn,
	}, l.handle)
	if err != nil {
		l.table.Stop()
		return nil, fmt.Errorf("dtlsuds: ListenDatagram: %w", err)
	}
	l.uds = uds

	// Proactive DTLS liveness: a real AnyConnect client with no app traffic
	// of its own relies on server-initiated DPD to stay up. Start the
	// heartbeat unless explicitly disabled (negative interval, for tests).
	if opts.HeartbeatInterval > 0 {
		l.heartbeatInterval = opts.HeartbeatInterval
		l.heartbeatStop = make(chan struct{})
		l.heartbeatDone = make(chan struct{})
		go l.heartbeatLoop()
	}

	l.logger.Info("dtlsuds: listening",
		slog.String("socket", opts.SocketPath),
		slog.String("protocol", string(spec.Name)),
		slog.Duration("idle_timeout", l.table.idleTimeout),
		slog.Duration("heartbeat", l.heartbeatInterval),
	)
	return l, nil
}

// heartbeatLoop periodically sends a DTLS DPD-request to every active session
// so an idle AnyConnect client always has a recent server-liveness witness.
// The client answers with a DPD-response (handled in forwardPacket) and, more
// importantly, resets its own "gateway is alive" timer on receipt — without
// this the client tears the tunnel down at ~20 s when it has no traffic of its
// own to elicit a reply. Mirrors the CSTP heartbeat (internal/cstp/tunnel.go)
// for the DTLS data channel, which previously had no proactive liveness.
func (l *Listener) heartbeatLoop() {
	defer close(l.heartbeatDone)
	ticker := time.NewTicker(l.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.heartbeatStop:
			return
		case <-ticker.C:
			for _, s := range l.table.Snapshot() {
				seq := l.dpdSeq.Add(1)
				payload := []byte{
					byte(seq >> 24), byte(seq >> 16),
					byte(seq >> 8), byte(seq),
					'D', 'P', 'D', '!',
				}
				if err := l.replyAnyConnect(s, pktDPDOut, payload); err != nil {
					// Session evicted mid-sweep (ErrSessionGone) or a
					// transient write error; skip and continue the sweep.
					continue
				}
				l.logger.Debug("dtls dpd sent",
					slog.String("device_id", s.deviceID),
					slog.String("four_tuple", s.key.String()),
					slog.Uint64("seq", uint64(seq)),
				)
			}
		}
	}
}

// SocketPath returns the path the listener bound to. Useful for tests.
func (l *Listener) SocketPath() string { return l.socketPath }

// Table returns the underlying session table. Callers MAY use it to
// drive deterministic eviction in tests (via RunEvictionPass).
func (l *Listener) Table() *Table { return l.table }

// RunEvictionPass triggers the table's eviction walker once, synchronously.
// Useful for tests that need deterministic eviction without waiting for
// the EvictionTick. Production code relies on the periodic walker.
func (l *Listener) RunEvictionPass() { l.table.runEvictionPass() }

// Close stops the UDS receive loop, evicts every session (firing
// OnEvict for each), and removes the socket file. Idempotent.
func (l *Listener) Close() error {
	var firstErr error
	if l.heartbeatStop != nil {
		close(l.heartbeatStop)
		<-l.heartbeatDone
		l.heartbeatStop = nil
	}
	if l.uds != nil {
		if err := l.uds.Close(); err != nil {
			firstErr = err
		}
	}
	l.table.Stop()
	return firstErr
}

// handle is the udshandoff.DatagramHandler. The framework has already
// validated the per-protocol TLV matrix (TOKEN + DEVICE_ID + USER_ID +
// DTLS_PSK + SOURCE_HINT_V6 + MTLS_SUBJECT_DN + SpecVersion + TraceID
// are present and pass per-type validation). We extract the per-session
// identity, look up or create the table entry, and forward the L3
// plaintext payload to the TUN sink.
func (l *Listener) handle(ctx context.Context, acc *udshandoff.AcceptedDatagram) error {
	key := FourTuple{
		Src: acc.Frame.Inner.Src,
		Dst: acc.Frame.Inner.Dst,
	}.normalised()

	if existing, ok := l.table.Get(key); ok {
		existing.touch(l.now())
		return l.forwardPacket(existing, acc)
	}

	// New session — extract identity from TLVs, resolve inner /128, and
	// admit. The matrix has enforced presence of DTLS_PSK on first
	// datagram, so this branch can rely on it.
	deviceID := stringTLV(acc.Frame.Inner.TLVs, proxyproto.EraTLVDeviceID, acc.Frame.ERA)
	userID := stringTLV(acc.Frame.Inner.TLVs, proxyproto.EraTLVUserID, acc.Frame.ERA)
	traceID := stringTLV(acc.Frame.Inner.TLVs, proxyproto.EraTLVTraceID, acc.Frame.ERA)
	subjectDN := stringTLV(acc.Frame.Inner.TLVs, proxyproto.EraTLVMTLSSubjectDN, acc.Frame.ERA)
	pskBytes := bytesTLV(acc.Frame.Inner.TLVs, proxyproto.EraTLVDTLSPSK, acc.Frame.ERA)
	if len(pskBytes) != 32 {
		// Should be unreachable: the matrix declares DTLS_PSK mandatory
		// and ValidateTLV enforces the 32-byte length. Defence in depth.
		return fmt.Errorf("dtlsuds: ERA_TLV_DTLS_PSK missing or wrong length on first datagram (got %d)", len(pskBytes))
	}
	if deviceID == "" {
		return errors.New("dtlsuds: ERA_TLV_DEVICE_ID missing on first datagram")
	}
	var psk [32]byte
	copy(psk[:], pskBytes)

	resolveCtx, cancel := context.WithTimeout(ctx, l.resolveTimeout)
	defer cancel()
	ident, err := l.opts.Resolver.Resolve(resolveCtx, deviceID)
	if err != nil {
		l.logger.Warn("dtls resolve failed",
			slog.String("trace_id", traceID),
			slog.String("device_id", deviceID),
			slog.String("err", err.Error()),
		)
		return fmt.Errorf("resolve device %s: %w", deviceID, err)
	}
	inner := ident.IPv6.Addr()
	if !inner.IsValid() {
		return fmt.Errorf("dtlsuds: resolver returned invalid IPv6 for %s", deviceID)
	}
	// The CLAT-source /128 is optional: a device without a second /128 (or a
	// TPM that predates the field) leaves it zero, and the session runs
	// v6-only. When present it is already validated as an in-pool /128 by
	// the resolver.
	var clatV6 netip.Addr
	if ident.IPv6CLAT.IsValid() {
		clatV6 = ident.IPv6CLAT.Addr()
	}

	// Capture the framework-supplied Reply closure for the session
	// lifetime. The closure re-uses the first datagram's PROXY-v2
	// inner envelope (which encodes the 4-tuple — the facade routes
	// DTLS replies by 4-tuple per spec §5.5).
	reply := acc.Reply
	now := l.now()

	session, existed := l.table.LoadOrCreate(key, func() *Session {
		return newSession(key, deviceID, userID, traceID, subjectDN, inner, clatV6, psk, reply, now)
	})
	if existed {
		// Lost the admission race; the other goroutine constructed the
		// authoritative session. Use it.
		session.touch(now)
		return l.forwardPacket(session, acc)
	}
	l.opts.Lifecycle.OnAdmit(session)
	l.logger.Info("dtls session admitted",
		slog.String("trace_id", traceID),
		slog.String("device_id", deviceID),
		slog.String("user_id", userID),
		slog.String("inner", inner.String()),
		slog.String("four_tuple", key.String()),
		slog.String("psk_fp", pskFingerprint(psk)),
	)
	return l.forwardPacket(session, acc)
}

// forwardPacket dispatches the post-DTLS plaintext payload by its AnyConnect
// type byte (see `frame.go`):
//
//   - AC_PKT_DATA (0x00): the rest is a raw IP packet — push to the TUN sink.
//   - AC_PKT_DPD_OUT (0x03): echo as AC_PKT_DPD_RESP with the same payload.
//   - AC_PKT_DPD_RESP / KEEPALIVE: lastSeen has already been touched; no-op.
//   - AC_PKT_DISCONN (0x05): evict the session from the table.
//   - Other / unknown: ignore (the AnyConnect protocol is liberal in this
//     direction).
//
// An empty payload datagram is treated as a no-op too; the lastSeen update
// the caller has already performed suffices as the liveness signal.
func (l *Listener) forwardPacket(s *Session, acc *udshandoff.AcceptedDatagram) error {
	typ, body, ok := parseDTLSPlaintext(acc.Frame.Payload)
	if !ok {
		return nil
	}
	switch typ {
	case pktData:
		if len(body) == 0 {
			return nil
		}
		// Prefer the session-aware sink so the bridge can apply per-session
		// CLAT client->tun translation (inner v4 → device CLAT /128 SIIT
		// source). When the sink is plain, fall back to a raw write — the
		// native v6-only path is unchanged.
		var writeErr error
		if l.sessionSink != nil {
			_, writeErr = l.sessionSink.WritePacketFromSession(s, body)
		} else {
			_, writeErr = l.opts.Sink.WritePacket(body)
		}
		if writeErr != nil {
			l.logger.Debug("tun write failed",
				slog.String("trace_id", s.traceID),
				slog.String("device_id", s.deviceID),
				slog.String("err", writeErr.Error()),
			)
			return writeErr
		}
		return nil
	case pktDPDOut:
		// Echo the opaque payload back as DPD-resp so the client sees a
		// liveness witness. WritePacket prepends the AnyConnect type byte
		// internally so we hand it the bare body.
		l.logger.Debug("dtls dpd-req from client",
			slog.String("device_id", s.deviceID), slog.String("four_tuple", s.key.String()))
		return l.replyAnyConnect(s, pktDPDResp, body)
	case pktDPDResp, pktKeepalive:
		// lastSeen already touched by the caller; nothing more to do. Logged
		// so we can confirm the client answers our server-initiated DPD.
		l.logger.Debug("dtls liveness from client",
			slog.String("device_id", s.deviceID), slog.Int("type", int(typ)))
		return nil
	case pktDisconnect:
		l.logger.Info("dtls disconnect received",
			slog.String("trace_id", s.traceID),
			slog.String("device_id", s.deviceID),
			slog.String("four_tuple", s.key.String()),
		)
		l.table.Remove(s.key)
		return nil
	default:
		// Unknown type code: be liberal and drop silently. A counter
		// could be added if we ever need to spot misbehaving clients.
		return nil
	}
}

// replyAnyConnect writes a backend->facade datagram carrying an AnyConnect
// type-prefixed payload. Used by the DPD-resp echo path; external callers
// (the TUN bridge) go through Session.WritePacket which always uses the
// AC_PKT_DATA type code.
func (l *Listener) replyAnyConnect(s *Session, typ byte, body []byte) error {
	reply := s.loadReply()
	if reply == nil {
		return ErrSessionGone
	}
	return reply(encodeDTLSPlaintext(typ, body))
}

// normalised returns a FourTuple with both AddrPort values unmapped
// (IPv4-in-IPv6 → IPv4) so the table key is canonical.
func (k FourTuple) normalised() FourTuple {
	return FourTuple{
		Src: netip.AddrPortFrom(k.Src.Addr().Unmap(), k.Src.Port()),
		Dst: netip.AddrPortFrom(k.Dst.Addr().Unmap(), k.Dst.Port()),
	}
}

// pskFingerprint returns the lower-cased hex of a SHA-256 prefix over the
// PSK material. Used for log correlation; never expose the PSK itself.
// 16 hex chars (8 bytes / 64 bits) is enough for human eyeballing and
// short enough not to drown log lines.
func pskFingerprint(psk [32]byte) string {
	h := sha256.Sum256(psk[:])
	return hex.EncodeToString(h[:8])
}

// stringTLV returns the first TLV value matching t (as a UTF-8 string)
// or "" if absent. Walks both the inner PROXY-v2 TLVs and the post-
// envelope ERA TLV block (the facade may emit either; the matrix
// validator does not care which).
func stringTLV(inner []proxyproto.TLV, t proxyproto.TLVType, era []proxyproto.TLV) string {
	if v := lookupTLV(inner, t); v != nil {
		return string(v)
	}
	if v := lookupTLV(era, t); v != nil {
		return string(v)
	}
	return ""
}

// bytesTLV returns the first TLV value matching t (as raw bytes) or nil
// if absent. Walks both the inner PROXY-v2 TLVs and the post-envelope
// ERA TLV block.
func bytesTLV(inner []proxyproto.TLV, t proxyproto.TLVType, era []proxyproto.TLV) []byte {
	if v := lookupTLV(inner, t); v != nil {
		return v
	}
	if v := lookupTLV(era, t); v != nil {
		return v
	}
	return nil
}

// lookupTLV returns the first matching TLV's value or nil.
func lookupTLV(tlvs []proxyproto.TLV, t proxyproto.TLVType) []byte {
	for i := range tlvs {
		if tlvs[i].Type == t {
			return tlvs[i].Value
		}
	}
	return nil
}
