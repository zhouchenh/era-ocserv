// Package icmp6 builds ICMPv6 control messages the AnyConnect data plane
// originates. It is pure-Go (gvisor header/checksum, no syscalls) so it is
// host-testable and platform-independent; the bridge/origination layer
// (cmd/era-ocserv) wraps it with the tun write.
package icmp6

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// QuoteCap is RFC 4443 §3.2: a Packet-Too-Big quotes "as much of the invoking
// packet as possible without the ICMPv6 packet exceeding the minimum IPv6 MTU"
// (1280): 1280 − 40 (IPv6 hdr) − 8 (ICMPv6 hdr) = 1232.
const QuoteCap = header.IPv6MinimumMTU - header.IPv6FixedHeaderSize - header.ICMPv6MinimumSize

// BuildPacketTooBig constructs a complete IPv6 + ICMPv6 Packet-Too-Big datagram
// (RFC 4443 §3.2) ready to write to a tun as a raw IP packet.
//
//   - src: the PTB source — the inner /128 the oversize packet was addressed to
//     (the tunnel endpoint that could not forward).
//   - dst: the oversize packet's IPv6 source (the node to notify, so PMTUD
//     shrinks it).
//   - mtu: the next-hop link MTU to advertise.
//   - orig: the oversize IPv6 packet; up to QuoteCap bytes are quoted so the PTB
//     itself never exceeds the 1280-byte IPv6 minimum MTU.
//
// src and dst must be 16-byte (IPv6) addresses.
func BuildPacketTooBig(src, dst netip.Addr, mtu uint32, orig []byte) []byte {
	quoteLen := len(orig)
	if quoteLen > QuoteCap {
		quoteLen = QuoteCap
	}
	icmpLen := header.ICMPv6MinimumSize + quoteLen
	out := make([]byte, header.IPv6FixedHeaderSize+icmpLen)

	// ICMPv6 Packet-Too-Big: type 2, code 0, the MTU, then the quoted prefix.
	icmp := header.ICMPv6(out[header.IPv6FixedHeaderSize:])
	icmp.SetType(header.ICMPv6PacketTooBig)
	icmp.SetCode(header.ICMPv6UnusedCode)
	icmp.SetMTU(mtu)
	copy(out[header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize:], orig[:quoteLen])

	// Outer IPv6 header (IPv6 carries no header checksum).
	srcAddr := tcpip.AddrFrom16(src.As16())
	dstAddr := tcpip.AddrFrom16(dst.As16())
	header.IPv6(out).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(icmpLen),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
	})

	// ICMPv6 checksum over the pseudo-header (src||dst||len||proto) + body.
	icmp.SetChecksum(0)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmp[:header.ICMPv6MinimumSize],
		Src:         srcAddr,
		Dst:         dstAddr,
		PayloadCsum: checksum.Checksum(icmp[header.ICMPv6MinimumSize:], 0),
		PayloadLen:  quoteLen,
	}))
	return out
}

// PacketTooBigFor builds the PTB to send for an oversize IPv6 packet `orig` that
// was addressed to the inner /128 `dstKey` and could not be forwarded to the
// client. The notify target is orig's IPv6 source; it returns ok=false (no PTB)
// when that source is not a notifiable global-unicast IPv6 address (unspecified /
// multicast / link-local / mapped) or equals dstKey (which would loop a PTB back
// to ourselves). mtu is the link MTU to advertise.
func PacketTooBigFor(dstKey netip.Addr, mtu uint32, orig []byte) (pkt []byte, ok bool) {
	if len(orig) < header.IPv6FixedHeaderSize {
		return nil, false
	}
	src, parsed := netip.AddrFromSlice(orig[8:24]) // IPv6 source of the oversize pkt
	if !parsed || !src.Is6() || src.Is4In6() || !src.IsGlobalUnicast() || src == dstKey {
		return nil, false
	}
	return BuildPacketTooBig(dstKey, src, mtu, orig), true
}
