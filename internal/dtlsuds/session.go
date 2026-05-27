package dtlsuds

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"time"
)

// FourTuple is the (src IP+port, dst IP+port) pair that keys a DTLS session
// per spec §5.3 (DTLS 1.2 has no Connection ID; the inbound 4-tuple is the
// only stable session identifier).
//
// The struct is comparable, so it works directly as a map key. Both
// netip.AddrPort values are stored in their unmapped form (IPv4-in-IPv6
// addresses are normalised to IPv4) so two semantically equal 4-tuples
// always hash identically.
type FourTuple struct {
	// Src is the real client's address:port (announced via the PROXY-v2
	// inner envelope's src fields).
	Src netip.AddrPort
	// Dst is the original facade-side destination (typically
	// `eracloud.app`-resolved IPv6 + :443/udp).
	Dst netip.AddrPort
}

// String returns a "src->dst" form suitable for log lines. The empty
// FourTuple stringifies as "<invalid>->...".
func (k FourTuple) String() string {
	return k.Src.String() + "->" + k.Dst.String()
}

// Session is the per-4-tuple state era-ocserv maintains for one active
// DTLS connection terminated upstream by the facade.
//
// Fields are populated on first contact and never overwritten — a Session's
// identity is bound to the 4-tuple for the table-entry's lifetime. (If the
// same client opens a new DTLS session at a different source port, it is a
// different Session.) The two pieces that mutate over the Session's life
// are the lastSeen counter (updated on every inbound packet) and the reply
// closure (cleared via detach() when the table evicts the session).
type Session struct {
	// key is the 4-tuple this Session is keyed under. Read-only after construction.
	key FourTuple
	// deviceID is the device UUID announced via ERA_TLV_DEVICE_ID. Read-only.
	deviceID string
	// userID is the ERA Cloud user identifier (ERA_TLV_USER_ID). Read-only.
	userID string
	// inner is the device's assigned /128 IPv6 (resolved from deviceID via
	// the iam.Resolver). The address inside is the tunnel-inner source IP
	// the client uses on its TUN packets. Read-only.
	inner netip.Addr
	// psk is the 32-byte DTLS pre-shared key the facade derived during CSTP
	// auth and forwarded via ERA_TLV_DTLS_PSK on the FIRST datagram. We
	// cache it purely for audit / future debug; era-facade owns DTLS
	// crypto so this value is opaque to era-ocserv.
	psk [32]byte
	// subjectDN is the client cert Subject DN from ERA_TLV_MTLS_SUBJECT_DN.
	subjectDN string
	// traceID is the facade-assigned trace correlation id (ULID). Read-only.
	traceID string
	// createdAt is the wall-clock time the session entered the table.
	createdAt time.Time
	// lastSeen is the unix-nanos timestamp of the most recent inbound packet.
	// Atomic to allow lock-free reads from the eviction goroutine.
	lastSeen atomic.Int64
	// reply is the closure the listener installs so callers can write
	// backend->facade datagrams. Stored via atomic.Pointer so detach()
	// can clear it concurrently with WritePacket / listener DPD echo.
	reply atomic.Pointer[replyFunc]
}

// replyFunc is the function the listener installs for backend->facade
// writes. Wrapped in a named type so we can store it via atomic.Pointer.
type replyFunc func(payload []byte) error

// newSession constructs a Session from the metadata gathered out of a
// validated first-datagram. The lastSeen timestamp is initialised to now.
func newSession(key FourTuple, deviceID, userID, traceID, subjectDN string, inner netip.Addr, psk [32]byte, reply func([]byte) error, now time.Time) *Session {
	s := &Session{
		key:       key,
		deviceID:  deviceID,
		userID:    userID,
		inner:     inner,
		psk:       psk,
		subjectDN: subjectDN,
		traceID:   traceID,
		createdAt: now,
	}
	s.lastSeen.Store(now.UnixNano())
	if reply != nil {
		fn := replyFunc(reply)
		s.reply.Store(&fn)
	}
	return s
}

// Key returns the 4-tuple this Session is keyed under.
func (s *Session) Key() FourTuple { return s.key }

// DeviceID returns the device UUID this Session is bound to.
func (s *Session) DeviceID() string { return s.deviceID }

// UserID returns the ERA Cloud user identifier.
func (s *Session) UserID() string { return s.userID }

// InnerIPv6 returns the device's assigned /128 (used by the TUN bridge to
// route outbound packets toward this session).
func (s *Session) InnerIPv6() netip.Addr { return s.inner }

// TraceID returns the facade-assigned correlation id.
func (s *Session) TraceID() string { return s.traceID }

// SubjectDN returns the client cert Subject DN (RFC 4514 string).
func (s *Session) SubjectDN() string { return s.subjectDN }

// CreatedAt returns the wall-clock time the Session was first seen.
func (s *Session) CreatedAt() time.Time { return s.createdAt }

// LastSeen returns the wall-clock time of the most recent inbound packet.
func (s *Session) LastSeen() time.Time {
	return time.Unix(0, s.lastSeen.Load())
}

// touch updates lastSeen to the supplied time. Called on every inbound
// packet attributed to this session.
func (s *Session) touch(now time.Time) {
	s.lastSeen.Store(now.UnixNano())
}

// WritePacket frames a backend->facade L3 packet in the §5.1 SOCK_DGRAM
// envelope (with fl bit-0 set to DirBackendToFacade) and writes it back
// to the facade via the listener's UDS socket. The IP packet is prefixed
// with the AnyConnect AC_PKT_DATA (0x00) type code per the DTLS data-plane
// frame format (`tpm/docs/architecture/era-ocserv-protocol.md` §2.3).
//
// Returns ErrSessionGone if the session has been evicted from the table.
//
// Concurrent calls are safe; the underlying writer (net.PacketConn.WriteTo)
// is goroutine-safe through the udshandoff framework.
func (s *Session) WritePacket(p []byte) (int, error) {
	reply := s.loadReply()
	if reply == nil {
		return 0, ErrSessionGone
	}
	framed := make([]byte, 1+len(p))
	framed[0] = pktData
	copy(framed[1:], p)
	if err := reply(framed); err != nil {
		return 0, err
	}
	return len(p), nil
}

// loadReply atomically reads the current reply closure. Returns nil if
// detach() has fired.
func (s *Session) loadReply() func([]byte) error {
	p := s.reply.Load()
	if p == nil {
		return nil
	}
	return *p
}

// detach disconnects the reply closure so subsequent WritePacket / listener
// DPD-echo calls surface ErrSessionGone. Called by the table when the
// Session is evicted (idle timeout or listener Close) so a racing
// TUN-side writer cannot continue to attempt sends on a stale Session.
func (s *Session) detach() {
	s.reply.Store(nil)
}

// ErrSessionGone is returned by Session.WritePacket after the Session has
// been evicted from the table. It is the DTLS-side analogue of
// `cstp.errTunnelClosed` so callers can treat the two transports uniformly.
var ErrSessionGone = errors.New("dtlsuds: session evicted")
