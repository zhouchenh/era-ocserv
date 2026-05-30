// Package clatxlat is the era-ocserv driver around the vendored stateless
// SIIT engine in internal/clat. It owns the per-session address mapping and
// the buffer-headroom discipline the in-place translators require, exposing
// two direction-specific helpers the bridge calls on the data path.
//
// CLAT-only: there is NO NAT64, NO NAT44, NO TAYGA. The client's inner IPv4
// (placeholder 192.0.0.1) is translated to/from IPv6 via stateless SIIT
// (RFC 6145 / 7915) and sourced from the device's CLAT /128 so it egresses
// to 64:ff9b::<v4dst> through the existing external 464PLAT default route.
//
// Buffer-headroom contract (mirrored from
// wireguard-go-clat clat/siit46_test.go, siit64_test.go and
// device/receive.go + device/send.go):
//
//	buffer = [ reservedSpaceSize bytes headroom ]
//	         [ MessageTransportHeaderSize (16) byte transport gap ]
//	         [ IP packet ]
//
// The packet always starts at offset reservedSpaceSize+16. The translators
// grow/shrink the IP header in place by moving the packet start LEFTWARD
// (SIIT46, v4->v6, +20 or +28 bytes of header) or RIGHTWARD (SIIT64,
// v6->v4, -20 bytes of header) and rewriting reservedSpaceSize so the new
// packet still begins at reservedSpaceSize+16. We therefore reserve the
// default 48-byte headroom (40-byte IPv6 fixed header + 8-byte IPv6
// fragment header — the worst-case v4->v6 growth) plus the 16-byte
// transport gap before every translation, and re-slice from the rewritten
// reservedSpaceSize afterward.
package clatxlat

import (
	"net/netip"

	"github.com/zhouchenh/era-ocserv/internal/clat"
)

const (
	// reservedSpaceSizeDefault is the leftward-growth headroom reserved
	// before the transport gap. It matches wireguard-go-clat's
	// device.ClatReservedSpaceSizeDefault (IPv6FixedHeaderSize(40) +
	// IPv6FragmentHeaderSize(8)) — the worst-case header expansion a v4->v6
	// translation can need.
	reservedSpaceSizeDefault = 48
	// transportGap is the per-packet scratch region the in-place
	// translators reserve between the headroom and the packet. It mirrors
	// clat.MessageTransportHeaderSize.
	transportGap = clat.MessageTransportHeaderSize
	// packetStartOffset is where the IP packet begins inside a fresh
	// scratch buffer, before any translation moves it.
	packetStartOffset = reservedSpaceSizeDefault + transportGap

	// ipv6SrcOffset / ipv6DstOffset are the byte offsets of the source and
	// destination address fields inside an IPv6 header (clat constants).
	ipv6SrcOffset = clat.IPv6SourceAddressOffset      // 8
	ipv6DstOffset = clat.IPv6DestinationAddressOffset // 24

	// ipMinHeader is the smallest IP header we are willing to inspect for a
	// version nibble.
	ipMinHeader = 20
)

// Translator performs the per-session CLAT translation between the client's
// inner IPv4 (placeholder 192.0.0.1) and the device's CLAT-sourced IPv6.
//
// A Translator is immutable after construction and safe for concurrent use:
// the SIIT engine is stateless and every call works on a caller-private
// scratch buffer. Callers that translate concurrently must each hold their
// own Translator-derived call (the methods allocate their own scratch).
type Translator struct {
	// placeholderV4 is the client's inner source IPv4 (192.0.0.1), 4 bytes.
	placeholderV4 [4]byte
	// clatV6 is the device's CLAT /128 (16 bytes) used as the SIIT source.
	clatV6 [16]byte
	// clatPlaceholderV6 is SIITPrefix||placeholderV4 (64:ff9b::192.0.0.1),
	// the SIIT-form IPv6 destination a reply carries before SIIT64.
	clatPlaceholderV6 [16]byte
}

// New builds a Translator for one session. placeholderV4 is the inner IPv4
// the client uses (192.0.0.1); clatV6 is the device's CLAT /128 address.
// Both must be the right family or New returns ok=false (the caller then
// runs v6-only with no translation for this session).
func New(placeholderV4 netip.Addr, clatV6 netip.Addr) (*Translator, bool) {
	if !placeholderV4.Is4() || !clatV6.Is6() {
		return nil, false
	}
	t := &Translator{
		placeholderV4: placeholderV4.As4(),
		clatV6:        clatV6.As16(),
	}
	// clatPlaceholderV6 = 64:ff9b:: prefix (first 12 bytes) || placeholderV4.
	copy(t.clatPlaceholderV6[:clat.SIITPrefixSize], clat.SIITPrefix[:clat.SIITPrefixSize])
	copy(t.clatPlaceholderV6[clat.SIITPrefixSize:], t.placeholderV4[:])
	return t, true
}

// ClatV6 returns the device's CLAT /128 as a netip.Addr. The bridge keys the
// session registry under this address so 64:ff9b:: replies (dst == clatV6)
// resolve to the right client.
func (t *Translator) ClatV6() netip.Addr { return netip.AddrFrom16(t.clatV6) }

// ClientToTun translates a packet arriving from the client toward the TUN.
//
//   - version 4 (the CLAT path): SIIT46 v4->v6, then NAT66 rewrites the IPv6
//     source to the device CLAT /128. On success it returns the v6 packet
//     (src=clatV6, dst=64:ff9b::<v4dst>) and ok=true. A packet SIIT46 leaves
//     untranslated or drops fails closed (ok=false) so a malformed or
//     unsupported inner v4 packet cannot leak onto the TUN.
//   - version 6 (the native path): passed through unchanged (ok=true). This
//     preserves the pre-CLAT v6-only data path byte-for-byte.
//
// The returned slice aliases an internal scratch buffer owned by this call;
// callers must finish using it (write it to the TUN queue) before the next
// ClientToTun call on the same goroutine. Because each call allocates its
// own scratch, concurrent calls are independent.
func (t *Translator) ClientToTun(pkt []byte) (out []byte, ok bool) {
	if len(pkt) < 1 {
		return nil, false
	}
	switch pkt[0] >> 4 {
	case 6:
		// Native IPv6 inner traffic: no translation, pass through.
		return pkt, true
	case 4:
		return t.translate46(pkt)
	default:
		return nil, false
	}
}

// translate46 runs the v4->v6 SIIT46 + NAT66 source rewrite.
func (t *Translator) translate46(pkt []byte) (out []byte, ok bool) {
	// Lay the v4 packet into a scratch buffer at packetStartOffset, leaving
	// the 48-byte leftward-growth headroom + 16-byte transport gap in front.
	buf := make([]byte, packetStartOffset+len(pkt))
	copy(buf[packetStartOffset:], pkt)

	reserved := uint8(reservedSpaceSizeDefault)
	switch clat.SIIT46InPlaceTranslate(buf, &reserved) {
	case clat.SIIT46Translated:
		// SIIT46 grew the header leftward: the new packet starts at
		// reserved+16 and runs to the original buffer end.
		v6 := buf[int(reserved)+transportGap:]
		// Rewrite the IPv6 source (offset 8) to the device CLAT /128. The
		// SIIT46 output has src = 64:ff9b::<placeholderV4>; NAT66 repairs
		// the transport checksum as it swaps the address.
		clat.NAT66InPlaceTranslateAddress(v6, t.clatV6[:], ipv6SrcOffset)
		return v6, true
	default:
		// SIIT46Untranslated or SIIT46Dropped: fail closed.
		return nil, false
	}
}

// TunToClient translates a packet arriving from the TUN toward the client.
//
// The caller guarantees the packet is IPv6 with dst == this session's CLAT
// /128 (the bridge checks that before dispatching). We rewrite the IPv6
// destination (offset 24) from clatV6 to 64:ff9b::<placeholderV4> via NAT66,
// then run SIIT64 v6->v4. On success it returns the v4 packet
// (src=<realV4>, dst=192.0.0.1) and ok=true. A packet SIIT64 declines fails
// closed (ok=false).
//
// The returned slice aliases an internal scratch buffer owned by this call;
// see ClientToTun for the aliasing contract.
func (t *Translator) TunToClient(v6 []byte) (out []byte, ok bool) {
	if len(v6) < clat.IPv6DestinationAddressOffset+16 {
		return nil, false
	}
	// Lay the v6 packet into a scratch buffer at packetStartOffset. SIIT64
	// shrinks the header rightward (40->20), so the 48-byte headroom is
	// more than enough and reserved only grows.
	buf := make([]byte, packetStartOffset+len(v6))
	copy(buf[packetStartOffset:], v6)
	pkt := buf[packetStartOffset:]

	// Rewrite the IPv6 destination (offset 24) from the device CLAT /128 to
	// the SIIT form 64:ff9b::<placeholderV4> so SIIT64 maps it back to the
	// client's placeholder 192.0.0.1. NAT66 repairs the transport checksum.
	clat.NAT66InPlaceTranslateAddress(pkt, t.clatPlaceholderV6[:], ipv6DstOffset)

	reserved := uint(reservedSpaceSizeDefault)
	if !clat.SIIT64InPlaceTranslate(buf, &reserved) {
		return nil, false
	}
	// SIIT64 shrank the header: the new v4 packet starts at reserved+16 and
	// runs to the original buffer end.
	return buf[int(reserved)+transportGap:], true
}
