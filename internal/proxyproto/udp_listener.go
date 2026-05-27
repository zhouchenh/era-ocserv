package proxyproto

// PROXY protocol v2 UDP receive-side support.
//
// Unlike the TCP variant, PROXY v2 over UDP is delivered as a one-shot prefix on
// the FIRST datagram per 5-tuple flow: header bytes precede the actual payload
// in that single datagram, and every subsequent datagram in the same flow has
// NO header. The wrapping PacketConn therefore parses + strips on first contact,
// caches the announced real source addr per (kernel-observed) source 5-tuple,
// and from then on returns the cached real addr for every datagram that arrives
// from the same kernel source.
//
// Wire format (per HAProxy spec; see internal/proxyproto/proxyproto.go for the
// TCP variant):
//
//	12-byte magic                  : 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A
//	1-byte version+command         : 0x21 (v2 | PROXY)
//	1-byte family+protocol         : 0x12 (AF_INET  | DGRAM) or 0x22 (AF_INET6 | DGRAM)
//	2-byte length (BE)             : number of bytes that follow the header before payload
//	addr-pair                      : v4 = 4+4+2+2 = 12 bytes, v6 = 16+16+2+2 = 36 bytes
//	optional TLVs                  : skipped; the parser only reads "length" bytes total
//
// Backward compat: a datagram that does not start with the v2 magic is returned
// as-is with the raw kernel source addr (so a direct, un-spliced client still
// reaches QUIC). A malformed-but-magic-prefixed datagram is also returned as-is
// (the parser refuses to swallow bytes it can't account for).

import (
	"container/list"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	// famUDP4 / famUDP6 are the family+protocol bytes for PROXY v2 over UDP. The
	// upper nibble names the address family (1=AF_INET, 2=AF_INET6); the lower
	// nibble names the transport protocol (2=DGRAM/UDP).
	famUDP4 = 0x12
	famUDP6 = 0x22

	// udpHeaderFixed is the fixed prefix length: 12-byte magic + 1 verCmd + 1
	// family + 2 length = 16 bytes. The variable addr-pair (+ TLVs) follows.
	udpHeaderFixed = 16

	// addrPairV4 / addrPairV6 are the addr-pair sizes (src+dst addr, src+dst
	// port, big-endian). TLVs MAY follow; the parser uses length to step past
	// anything beyond the addr pair.
	addrPairV4 = 12 // 4+4+2+2
	addrPairV6 = 36 // 16+16+2+2

	// DefaultUDPIdleTimeout is how long a flow-state entry stays cached after
	// the last seen datagram in that flow. era-facade emits the PROXY header
	// once per flow; subsequent datagrams have no header and the wrapper must
	// remember the announced source for the lifetime of the flow.
	DefaultUDPIdleTimeout = 60 * time.Second

	// DefaultUDPMaxFlows bounds the per-listener flow-state map so a flood of
	// spoofed initial datagrams cannot grow the map without bound. On overflow
	// the LRU (least-recently-used) entry is evicted.
	DefaultUDPMaxFlows = 100_000
)

// UDPListenerOptions configures a UDPListener.
type UDPListenerOptions struct {
	// IdleTimeout is the per-flow idle eviction period. Zero ⇒ DefaultUDPIdleTimeout.
	IdleTimeout time.Duration
	// MaxFlows bounds the flow-state map; LRU evict on overflow. Zero ⇒ DefaultUDPMaxFlows.
	MaxFlows int
	// OnError, when set, is called with a per-datagram diagnostic (e.g. a malformed
	// header that was returned as-is). Optional; for diagnostics only.
	OnError func(error)
	// now, when set, overrides time.Now for tests (fake clock for idle eviction).
	now func() time.Time
}

// UDPListener wraps a net.PacketConn so the one-shot PROXY v2 UDP header is
// parsed off the first datagram per flow, its announced source is cached, and
// every subsequent datagram from the same kernel 5-tuple is returned with the
// cached source as RemoteAddr. Datagrams without a header are returned as-is —
// the wrapper is backward-compatible with direct (un-spliced) clients.
//
// The wrapper ALSO translates the return path: WriteTo(announced_addr) is
// rewritten to WriteTo(kernel_addr) so server responses reach the actual
// splicer (loopback) rather than the announced external client address, which
// the server may not be able to reach directly. WriteTo to an addr the wrapper
// does not recognise is passed through unchanged.
//
// Use ONLY behind a trusted splicer (e.g. era-facade's loopback frontdemux). On
// a directly client-facing socket an attacker could spoof a header.
type UDPListener struct {
	net.PacketConn

	idleTimeout time.Duration
	maxFlows    int
	onError     func(error)
	now         func() time.Time

	mu      sync.Mutex
	flows   map[netip.AddrPort]*list.Element // kernel src key -> *flowEntry
	reverse map[netip.AddrPort]*list.Element // announced src key -> SAME *flowEntry
	lru     *list.List                       // front = MRU, back = LRU
}

// flowEntry is one cached PROXY-announced source for a kernel source 5-tuple.
type flowEntry struct {
	key         netip.AddrPort // kernel source seen on the wire
	realAddr    *net.UDPAddr   // PROXY-announced source (what the wrapper reports)
	realAddrKey netip.AddrPort // realAddr as netip.AddrPort (for the reverse-map key)
	kernelAddr  *net.UDPAddr   // kernel src as *net.UDPAddr (for the return-path WriteTo)
	lastSeen    time.Time
}

// NewUDPListener wraps inner with a PROXY v2 UDP parser. See UDPListener for the
// flow-state semantics. Options may be zero (defaults applied).
func NewUDPListener(inner net.PacketConn, opts UDPListenerOptions) *UDPListener {
	idle := opts.IdleTimeout
	if idle <= 0 {
		idle = DefaultUDPIdleTimeout
	}
	max := opts.MaxFlows
	if max <= 0 {
		max = DefaultUDPMaxFlows
	}
	nowFn := opts.now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &UDPListener{
		PacketConn:  inner,
		idleTimeout: idle,
		maxFlows:    max,
		onError:     opts.OnError,
		now:         nowFn,
		flows:       make(map[netip.AddrPort]*list.Element),
		reverse:     make(map[netip.AddrPort]*list.Element),
		lru:         list.New(),
	}
}

// ReadFrom reads the next datagram from the underlying socket. If the datagram
// arrives from a kernel source already cached as "saw PROXY v2 from this peer",
// it is returned as-is with the CACHED real addr as RemoteAddr. Otherwise the
// wrapper attempts to parse a PROXY v2 UDP header off the front: on success the
// header bytes are stripped, the announced source is cached, and the REMAINDER
// of the datagram is returned with the announced source as RemoteAddr; on a
// magic-mismatch the datagram is returned as-is with the raw kernel source (so
// a directly connecting client still reaches QUIC).
//
// If a parsed header is the WHOLE datagram (no payload piggybacked behind it),
// the wrapper SKIPS that datagram and reads the next one from the socket —
// returning zero bytes would look to QUIC like an empty datagram and trip it up.
func (l *UDPListener) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := l.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		// Kernel source as a comparable key. ReadFrom on a UDPConn always returns
		// *net.UDPAddr; defend against other PacketConn impls anyway.
		key, kok := addrKey(addr)
		if !kok {
			// Unknown addr shape — pass through unchanged.
			return n, addr, nil
		}
		kernelUDP, _ := addr.(*net.UDPAddr)
		if kernelUDP == nil {
			// Should not happen for a UDP socket; defend by skipping the cache.
			return n, addr, nil
		}

		// Fast path: cached flow. Return the cached real addr, no parsing, no strip.
		if cached, ok := l.lookup(key); ok {
			return n, cached, nil
		}

		// Slow path: try to parse a leading PROXY v2 UDP header.
		realAddr, hdrLen, parseErr := parseProxyV2UDPHeader(p[:n])
		if parseErr != nil {
			if errors.Is(parseErr, errNotProxyV2) {
				// No magic ⇒ direct client. Backward compat: return as-is.
				return n, addr, nil
			}
			// Magic matched but malformed (bad length / truncated / unknown family).
			// Don't swallow — surface as-is and let the upper layer reject it.
			if l.onError != nil {
				l.onError(parseErr)
			}
			return n, addr, nil
		}
		if realAddr == nil {
			// LOCAL command: header consumed, no announced addr. Strip header
			// (or skip the datagram entirely if header-only) but keep the raw
			// kernel src — there is nothing to translate / cache.
			if hdrLen == n {
				continue
			}
			copy(p[:n-hdrLen], p[hdrLen:n])
			return n - hdrLen, addr, nil
		}

		// Cache the kernel source -> announced source mapping (and its inverse
		// for the return-path WriteTo translation) for subsequent datagrams in
		// this flow (they will carry no header).
		l.remember(key, kernelUDP, realAddr)

		// Strip the header. If the datagram had piggybacked payload, surface it
		// at the start of p. If header WAS the whole datagram (rare init-only
		// shape), skip it and read the next datagram.
		if hdrLen == n {
			continue
		}
		copy(p[:n-hdrLen], p[hdrLen:n])
		return n - hdrLen, realAddr, nil
	}
}

// WriteTo translates the destination address from a known announced (real)
// client addr back to its kernel-observed source addr, then writes to the
// underlying socket. This is the return-path inverse of the receive-side
// header parsing: the upper layer (quic-go) believes its peer is at the
// announced addr, but the actual reachable peer is the splicer at the kernel
// addr. Destinations the wrapper does not recognise are passed through
// unchanged, preserving backward compat for un-spliced clients.
//
// PROXY v2 does NOT roundtrip a header on the return path: only the address is
// re-translated, no bytes are added.
func (l *UDPListener) WriteTo(p []byte, addr net.Addr) (int, error) {
	if target, ok := l.reverseLookup(addr); ok {
		return l.PacketConn.WriteTo(p, target)
	}
	return l.PacketConn.WriteTo(p, addr)
}

// reverseLookup returns the kernel addr for an announced addr if cached, also
// refreshing the LRU position so an active return flow does not idle-evict
// against a quieter ingress.
func (l *UDPListener) reverseLookup(addr net.Addr) (*net.UDPAddr, bool) {
	key, ok := addrKey(addr)
	if !ok {
		return nil, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.reverse[key]
	if !ok {
		return nil, false
	}
	fe := el.Value.(*flowEntry)
	now := l.now()
	if now.Sub(fe.lastSeen) > l.idleTimeout {
		l.removeEntry(el, fe)
		return nil, false
	}
	fe.lastSeen = now
	l.lru.MoveToFront(el)
	return fe.kernelAddr, true
}

// LocalAddr / Close / SetDeadline / SetReadDeadline / SetWriteDeadline are
// inherited from the embedded PacketConn — no behaviour change.

// lookup returns the cached real addr for the kernel source if present, refreshing
// the LRU position. It also opportunistically evicts entries that have aged past
// the idle timeout so a long-idle stale mapping never resurfaces.
func (l *UDPListener) lookup(key netip.AddrPort) (*net.UDPAddr, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.flows[key]
	if !ok {
		return nil, false
	}
	fe := el.Value.(*flowEntry)
	now := l.now()
	if now.Sub(fe.lastSeen) > l.idleTimeout {
		// Stale — evict and treat as a miss so the next datagram re-parses.
		l.removeEntry(el, fe)
		return nil, false
	}
	fe.lastSeen = now
	l.lru.MoveToFront(el)
	return fe.realAddr, true
}

// remember caches the (kernel source -> announced source) mapping, refreshing
// the LRU position if it already exists. On overflow the LRU entry is evicted.
// Both forward (kernel -> announced) and reverse (announced -> kernel) maps
// are updated so WriteTo can translate the return path.
func (l *UDPListener) remember(kernelKey netip.AddrPort, kernelAddr, real *net.UDPAddr) {
	realKey, rok := addrKey(real)
	if !rok {
		// Should not happen — real is built by the parser from validated bytes.
		// Defend by not caching.
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if el, ok := l.flows[kernelKey]; ok {
		fe := el.Value.(*flowEntry)
		// If the announced addr changed (rare; the splicer might re-announce a
		// different real client on the same kernel 5-tuple), drop the old
		// reverse mapping before installing the new one.
		if fe.realAddrKey != realKey {
			if rel, rok := l.reverse[fe.realAddrKey]; rok && rel == el {
				delete(l.reverse, fe.realAddrKey)
			}
			fe.realAddr = real
			fe.realAddrKey = realKey
			l.reverse[realKey] = el
		}
		fe.kernelAddr = kernelAddr
		fe.lastSeen = now
		l.lru.MoveToFront(el)
		return
	}
	for len(l.flows) >= l.maxFlows {
		back := l.lru.Back()
		if back == nil {
			break
		}
		bfe := back.Value.(*flowEntry)
		l.removeEntry(back, bfe)
	}
	fe := &flowEntry{
		key:         kernelKey,
		realAddr:    real,
		realAddrKey: realKey,
		kernelAddr:  kernelAddr,
		lastSeen:    now,
	}
	el := l.lru.PushFront(fe)
	l.flows[kernelKey] = el
	// If two different kernel sources announce the SAME real client (e.g. NAT
	// rebinding plus a re-announce, or test contention), the reverse map keeps
	// the latest. The older mapping's forward entry still works for cached
	// reads; only its return path gets overwritten. This is the same write-wins
	// policy the kernel itself uses for arp / neighbour entries.
	l.reverse[realKey] = el
}

// removeEntry deletes one flow entry from both maps + the LRU list. Caller
// must hold l.mu.
func (l *UDPListener) removeEntry(el *list.Element, fe *flowEntry) {
	l.lru.Remove(el)
	delete(l.flows, fe.key)
	if rel, ok := l.reverse[fe.realAddrKey]; ok && rel == el {
		delete(l.reverse, fe.realAddrKey)
	}
}

// flowCount returns the current number of cached flow entries. Test-only.
func (l *UDPListener) flowCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.flows)
}

// evictIdle walks the LRU back-to-front evicting entries past the idle timeout.
// Test-only helper for the fake-clock idle-eviction test (production lookups
// evict on access; this lets a test prove eviction without a pending read).
func (l *UDPListener) evictIdle() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for {
		back := l.lru.Back()
		if back == nil {
			return
		}
		fe := back.Value.(*flowEntry)
		if now.Sub(fe.lastSeen) <= l.idleTimeout {
			return
		}
		l.removeEntry(back, fe)
	}
}

// addrKey extracts a comparable netip.AddrPort key from a net.Addr. Returns
// (zero, false) for an addr shape that has no host:port form (shouldn't happen
// for a UDP PacketConn but defended for safety).
func addrKey(a net.Addr) (netip.AddrPort, bool) {
	if ua, ok := a.(*net.UDPAddr); ok {
		ip, ok := netip.AddrFromSlice(ua.IP)
		if !ok {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(ua.Port)), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// errNotProxyV2 is returned by parseProxyV2UDPHeader when the magic preamble is
// absent (or the datagram is too short to even contain the fixed header). The
// caller treats this as "backward compat: pass through as-is".
var errNotProxyV2 = errors.New("proxyproto: not a PROXY v2 UDP datagram")

// parseProxyV2UDPHeader inspects the leading bytes of a datagram. If they form a
// valid PROXY v2 UDP header it returns the announced source addr + the total
// header length (so the caller can strip it). If the leading bytes have no v2
// magic it returns errNotProxyV2 (signal: backward compat, pass through). If
// the magic matches but the rest is malformed it returns a descriptive error
// (signal: surface as-is to the upper layer; do not swallow).
func parseProxyV2UDPHeader(buf []byte) (src *net.UDPAddr, headerLen int, err error) {
	if len(buf) < udpHeaderFixed {
		return nil, 0, errNotProxyV2
	}
	if [12]byte(buf[0:12]) != v2Signature {
		return nil, 0, errNotProxyV2
	}
	verCmd := buf[12]
	fam := buf[13]
	addrLen := int(binary.BigEndian.Uint16(buf[14:16]))

	total := udpHeaderFixed + addrLen
	if len(buf) < total {
		return nil, 0, errors.New("proxyproto: UDP header truncated")
	}

	switch verCmd {
	case verCmdLocal:
		// LOCAL command: no announced address. Strip the header and keep the
		// real peer.
		return nil, total, nil
	case verCmdProxy:
		// continue below
	default:
		return nil, 0, errors.New("proxyproto: UDP header: unsupported version/command")
	}

	addr := buf[udpHeaderFixed : udpHeaderFixed+addrLen]
	switch fam {
	case famUDP4:
		if addrLen < addrPairV4 {
			return nil, 0, errors.New("proxyproto: UDP4 addr block too short")
		}
		ip := net.IP(append([]byte(nil), addr[0:4]...))
		port := int(binary.BigEndian.Uint16(addr[8:10]))
		return &net.UDPAddr{IP: ip, Port: port}, total, nil
	case famUDP6:
		if addrLen < addrPairV6 {
			return nil, 0, errors.New("proxyproto: UDP6 addr block too short")
		}
		ip := net.IP(append([]byte(nil), addr[0:16]...))
		port := int(binary.BigEndian.Uint16(addr[32:34]))
		return &net.UDPAddr{IP: ip, Port: port}, total, nil
	default:
		// Magic matched + verCmd PROXY but family is neither UDP4 nor UDP6.
		// Don't swallow — surface as-is.
		return nil, 0, errors.New("proxyproto: UDP header: unsupported address family")
	}
}

// WriteHeaderV2UDP encodes a PROXY v2 UDP header announcing src as the original
// source and dst as the original destination. It is exposed for tests + for any
// future emitter that lives inside era-proxy; the production splicer (era-facade)
// has its own copy. Returns the encoded bytes (one-shot prefix prepended to the
// first datagram in a flow).
func WriteHeaderV2UDP(src, dst *net.UDPAddr) ([]byte, error) {
	if src == nil || dst == nil {
		return nil, errors.New("proxyproto: nil addr")
	}
	sip, sok := netip.AddrFromSlice(src.IP)
	dip, dok := netip.AddrFromSlice(dst.IP)
	if !sok || !dok {
		return nil, errors.New("proxyproto: bad addr bytes")
	}
	sip = sip.Unmap()
	dip = dip.Unmap()
	if sip.Is4() != dip.Is4() {
		return nil, errors.New("proxyproto: source/dest IP family mismatch")
	}
	var buf []byte
	buf = append(buf, v2Signature[:]...)
	buf = append(buf, verCmdProxy)
	if sip.Is4() {
		buf = append(buf, famUDP4)
		buf = binary.BigEndian.AppendUint16(buf, addrPairV4)
		s4, d4 := sip.As4(), dip.As4()
		buf = append(buf, s4[:]...)
		buf = append(buf, d4[:]...)
	} else {
		buf = append(buf, famUDP6)
		buf = binary.BigEndian.AppendUint16(buf, addrPairV6)
		s16, d16 := sip.As16(), dip.As16()
		buf = append(buf, s16[:]...)
		buf = append(buf, d16[:]...)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(src.Port))
	buf = binary.BigEndian.AppendUint16(buf, uint16(dst.Port))
	return buf, nil
}
