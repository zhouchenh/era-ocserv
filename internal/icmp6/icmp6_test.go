package icmp6

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// makeIPv6 crafts a deterministic IPv6 UDP packet (40-B header + payloadLen bytes
// of payload where byte i == i&0xff) for use as the oversize "invoking packet".
func makeIPv6(t *testing.T, src, dst netip.Addr, payloadLen int) []byte {
	t.Helper()
	pkt := make([]byte, header.IPv6FixedHeaderSize+payloadLen)
	header.IPv6(pkt).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLen),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16(src.As16()),
		DstAddr:           tcpip.AddrFrom16(dst.As16()),
	})
	for i := 0; i < payloadLen; i++ {
		pkt[header.IPv6FixedHeaderSize+i] = byte(i & 0xff)
	}
	return pkt
}

// assertValidChecksum independently verifies the ICMPv6 checksum via the standard
// identity: the ones-complement sum of the pseudo-header + the entire ICMPv6
// message (INCLUDING its stored checksum field) folds to 0xFFFF.
func assertValidChecksum(t *testing.T, out []byte, src, dst netip.Addr) {
	t.Helper()
	icmpFull := out[header.IPv6FixedHeaderSize:]
	pseudo := header.PseudoHeaderChecksum(
		header.ICMPv6ProtocolNumber,
		tcpip.AddrFrom16(src.As16()),
		tcpip.AddrFrom16(dst.As16()),
		uint16(len(icmpFull)),
	)
	if got := checksum.Checksum(icmpFull, pseudo); got != 0xFFFF {
		t.Fatalf("ICMPv6 checksum invalid: folded=0x%04x, want 0xffff", got)
	}
}

// assertCommonPTB checks the invariant shape of a PTB regardless of cap/family.
func assertCommonPTB(t *testing.T, out []byte, src, dst netip.Addr, wantMTU uint32, orig []byte) {
	t.Helper()
	if len(out) > header.IPv6MinimumMTU {
		t.Fatalf("PTB len %d exceeds IPv6 min MTU %d (RFC 4443 §3.2)", len(out), header.IPv6MinimumMTU)
	}
	ip := header.IPv6(out)
	if ip.NextHeader() != uint8(header.ICMPv6ProtocolNumber) {
		t.Fatalf("next header = %d, want %d (ICMPv6)", ip.NextHeader(), header.ICMPv6ProtocolNumber)
	}
	if ip.HopLimit() != 64 {
		t.Fatalf("hop limit = %d, want 64", ip.HopLimit())
	}
	if got := netip.AddrFrom16(ip.SourceAddress().As16()); got != src {
		t.Fatalf("PTB src = %v, want %v (the /128 that could not forward)", got, src)
	}
	if got := netip.AddrFrom16(ip.DestinationAddress().As16()); got != dst {
		t.Fatalf("PTB dst = %v, want %v (the oversize packet's source)", got, dst)
	}
	icmp := header.ICMPv6(out[header.IPv6FixedHeaderSize:])
	if icmp.Type() != header.ICMPv6PacketTooBig {
		t.Fatalf("ICMPv6 type = %d, want %d (PacketTooBig)", icmp.Type(), header.ICMPv6PacketTooBig)
	}
	if icmp.Code() != 0 {
		t.Fatalf("ICMPv6 code = %d, want 0", icmp.Code())
	}
	if icmp.MTU() != wantMTU {
		t.Fatalf("PTB MTU = %d, want %d", icmp.MTU(), wantMTU)
	}
	if int(ip.PayloadLength()) != len(out)-header.IPv6FixedHeaderSize {
		t.Fatalf("IPv6 PayloadLength = %d, want %d", ip.PayloadLength(), len(out)-header.IPv6FixedHeaderSize)
	}
	// Embedded prefix is a verbatim copy of the leading bytes of the original.
	wantQuote := len(orig)
	if wantQuote > QuoteCap {
		wantQuote = QuoteCap
	}
	quoted := out[header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize:]
	if len(quoted) != wantQuote {
		t.Fatalf("quoted len = %d, want %d", len(quoted), wantQuote)
	}
	for i := 0; i < wantQuote; i++ {
		if quoted[i] != orig[i] {
			t.Fatalf("quoted[%d] = 0x%02x, want 0x%02x", i, quoted[i], orig[i])
		}
	}
	assertValidChecksum(t, out, src, dst)
}

// TestBuildPacketTooBig_Native is KAT-A: an oversize native-v6 packet (cap 1400).
func TestBuildPacketTooBig_Native(t *testing.T) {
	sender := netip.MustParseAddr("2001:db8::1")                         // Internet sender
	native := netip.MustParseAddr("2001:470:f9d1:9001:3223:bcff:fb47:7a53") // client native /128
	orig := makeIPv6(t, sender, native, 1460)                           // 1500-byte packet
	out := BuildPacketTooBig(native, sender, 1400, orig)

	// 1500 > 1232 ⇒ quoted is clamped: total == 40 + 8 + 1232 == 1280.
	if len(out) != header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize+QuoteCap {
		t.Fatalf("len(out) = %d, want %d", len(out), header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize+QuoteCap)
	}
	if len(out) != header.IPv6MinimumMTU {
		t.Fatalf("len(out) = %d, want exactly the 1280 IPv6 floor", len(out))
	}
	assertCommonPTB(t, out, native, sender, 1400, orig)
	if out[header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize]>>4 != 6 {
		t.Fatal("quoted packet is not IPv6")
	}
}

// TestBuildPacketTooBig_CLAT is KAT-B: an oversize pre-SIIT64 CLAT v6 packet (cap
// 1420). The quoted form must be the IPv6 (pre-translation) packet, MTU 1420.
func TestBuildPacketTooBig_CLAT(t *testing.T) {
	plat := netip.MustParseAddr("64:ff9b::808:808")                  // 64:ff9b::8.8.8.8 PLAT-form sender
	clat := netip.MustParseAddr("2001:470:f9d1:9001:c1a7::38")       // client CLAT /128
	orig := makeIPv6(t, plat, clat, 1460)
	out := BuildPacketTooBig(clat, plat, 1420, orig)

	assertCommonPTB(t, out, clat, plat, 1420, orig)
	if out[header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize]>>4 != 6 {
		t.Fatal("quoted CLAT packet must be IPv6 (pre-SIIT64), not v4")
	}
}

// TestBuildPacketTooBig_SmallQuotedWhole is KAT-C: a small invoking packet is
// quoted in full (exercises the len(orig) < QuoteCap branch).
func TestBuildPacketTooBig_SmallQuotedWhole(t *testing.T) {
	sender := netip.MustParseAddr("2001:db8::2")
	native := netip.MustParseAddr("2001:470:f9d1:9001::dead")
	orig := makeIPv6(t, sender, native, 160) // 200-byte packet
	out := BuildPacketTooBig(native, sender, 1400, orig)

	if len(out) != header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize+len(orig) {
		t.Fatalf("len(out) = %d, want %d (whole 200-B packet quoted)", len(out),
			header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize+len(orig))
	}
	assertCommonPTB(t, out, native, sender, 1400, orig)
}

// TestPacketTooBigFor_Guards proves the notify-target guard: a PTB is built only
// for a notifiable global-unicast IPv6 source, never for martian / loop sources.
func TestPacketTooBigFor_Guards(t *testing.T) {
	dstKey := netip.MustParseAddr("2001:470:f9d1:9001::abcd")
	mk := func(src netip.Addr) []byte { return makeIPv6(t, src, dstKey, 1460) }

	cases := []struct {
		name   string
		orig   []byte
		wantOK bool
	}{
		{"global-unicast sender", mk(netip.MustParseAddr("2001:db8::1")), true},
		{"clat-form sender", mk(netip.MustParseAddr("64:ff9b::808:808")), true},
		{"unspecified ::", mk(netip.IPv6Unspecified()), false},
		{"link-local fe80::", mk(netip.MustParseAddr("fe80::1")), false},
		{"multicast ff02::1", mk(netip.MustParseAddr("ff02::1")), false},
		{"loopback to self (src==dstKey)", mk(dstKey), false},
		{"runt (< 40B)", make([]byte, 20), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkt, ok := PacketTooBigFor(dstKey, 1400, c.orig)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if ok && pkt == nil {
				t.Fatal("ok but nil packet")
			}
			if !ok && pkt != nil {
				t.Fatal("not ok but non-nil packet")
			}
		})
	}
}
