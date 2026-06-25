package clat

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestSIIT64TimeExceededTranslatesQuotedUDPToIPv4(t *testing.T) {
	quotedSrc := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1}
	quotedDst := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}
	quotedPacket := buildIPv6UDPPacket(quotedSrc, quotedDst, 1, 12345, 33434, nil)

	outerSrc := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}
	outerDst := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1}
	packet := buildICMPv6ErrorPacket(outerSrc, outerDst, header.ICMPv6TimeExceeded, header.ICMPv6HopLimitExceeded, func(icmp header.ICMPv6) {
		clear(icmp[4:8])
	}, quotedPacket)

	translated := translateSIIT64Packet(t, packet)
	ipv4Packet := header.IPv4(translated)
	if ipv4Packet.Protocol() != uint8(header.ICMPv4ProtocolNumber) {
		t.Fatalf("outer protocol = %d, want ICMPv4", ipv4Packet.Protocol())
	}
	if !ipv4Packet.IsChecksumValid() {
		t.Fatal("outer IPv4 header checksum is invalid")
	}

	icmpv4Packet := header.ICMPv4(ipv4Packet.Payload())
	if checksum.Checksum(icmpv4Packet, 0) != 0xffff {
		t.Fatal("outer ICMPv4 checksum is invalid")
	}
	if icmpv4Packet.Type() != header.ICMPv4TimeExceeded {
		t.Fatalf("outer ICMP type = %d, want time exceeded", icmpv4Packet.Type())
	}

	quotedIPv4 := header.IPv4(icmpv4Packet.Payload())
	if header.IPVersion(quotedIPv4) != header.IPv4Version {
		t.Fatalf("quoted packet version = %d, want IPv4", header.IPVersion(quotedIPv4))
	}
	if !quotedIPv4.IsChecksumValid() {
		t.Fatal("quoted IPv4 header checksum is invalid")
	}
	if got, want := quotedIPv4.SourceAddress(), tcpip.AddrFrom4([4]byte{10, 0, 0, 1}); got != want {
		t.Fatalf("quoted IPv4 source = %s, want %s", got, want)
	}
	if got, want := quotedIPv4.DestinationAddress(), tcpip.AddrFrom4([4]byte{1, 2, 3, 4}); got != want {
		t.Fatalf("quoted IPv4 destination = %s, want %s", got, want)
	}

	quotedUDP := header.UDP(quotedIPv4.Payload())
	if got, want := quotedUDP.SourcePort(), uint16(12345); got != want {
		t.Fatalf("quoted UDP source port = %d, want %d", got, want)
	}
	if got, want := quotedUDP.DestinationPort(), uint16(33434); got != want {
		t.Fatalf("quoted UDP destination port = %d, want %d", got, want)
	}
}

func TestSIIT64PortUnreachableTranslatesQuotedICMPEchoToIPv4(t *testing.T) {
	quotedSrc := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1}
	quotedDst := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}
	quotedPacket := buildIPv6ICMPEchoPacket(quotedSrc, quotedDst, 1, header.ICMPv6EchoRequest, 0x1234, 0x5678, nil)

	outerSrc := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9}
	outerDst := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1}
	packet := buildICMPv6ErrorPacket(outerSrc, outerDst, header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, func(icmp header.ICMPv6) {
		clear(icmp[4:8])
	}, quotedPacket)

	translated := translateSIIT64Packet(t, packet)
	ipv4Packet := header.IPv4(translated)
	icmpv4Packet := header.ICMPv4(ipv4Packet.Payload())
	if icmpv4Packet.Type() != header.ICMPv4DstUnreachable || icmpv4Packet.Code() != header.ICMPv4PortUnreachable {
		t.Fatalf("outer ICMP type/code = %d/%d, want destination unreachable/port unreachable", icmpv4Packet.Type(), icmpv4Packet.Code())
	}
	if checksum.Checksum(icmpv4Packet, 0) != 0xffff {
		t.Fatal("outer ICMPv4 checksum is invalid")
	}

	quotedIPv4 := header.IPv4(icmpv4Packet.Payload())
	if header.IPVersion(quotedIPv4) != header.IPv4Version {
		t.Fatalf("quoted packet version = %d, want IPv4", header.IPVersion(quotedIPv4))
	}
	if !quotedIPv4.IsChecksumValid() {
		t.Fatal("quoted IPv4 header checksum is invalid")
	}

	quotedICMPv4 := header.ICMPv4(quotedIPv4.Payload())
	if quotedICMPv4.Type() != header.ICMPv4Echo {
		t.Fatalf("quoted ICMP type = %d, want echo request", quotedICMPv4.Type())
	}
	if got, want := quotedICMPv4.Ident(), uint16(0x1234); got != want {
		t.Fatalf("quoted ICMP ident = %d, want %d", got, want)
	}
	if got, want := quotedICMPv4.Sequence(), uint16(0x5678); got != want {
		t.Fatalf("quoted ICMP sequence = %d, want %d", got, want)
	}
	if checksum.Checksum(quotedICMPv4, 0) != 0xffff {
		t.Fatal("quoted ICMPv4 checksum is invalid")
	}
}

func TestSIIT64PlainUDPTranslationStillWorks(t *testing.T) {
	src := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1}
	dst := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}
	packet := buildIPv6UDPPacket(src, dst, 64, 1111, 2222, []byte{0xde, 0xad, 0xbe, 0xef})

	translated := translateSIIT64Packet(t, packet)
	ipv4Packet := header.IPv4(translated)
	if header.IPVersion(ipv4Packet) != header.IPv4Version {
		t.Fatalf("packet version = %d, want IPv4", header.IPVersion(ipv4Packet))
	}
	if !ipv4Packet.IsChecksumValid() {
		t.Fatal("outer IPv4 header checksum is invalid")
	}
	if got, want := ipv4Packet.Protocol(), uint8(header.UDPProtocolNumber); got != want {
		t.Fatalf("outer protocol = %d, want UDP", got)
	}

	udpPacket := header.UDP(ipv4Packet.Payload())
	if got, want := udpPacket.SourcePort(), uint16(1111); got != want {
		t.Fatalf("UDP source port = %d, want %d", got, want)
	}
	if got, want := udpPacket.DestinationPort(), uint16(2222); got != want {
		t.Fatalf("UDP destination port = %d, want %d", got, want)
	}
	if !isIPv4TransportChecksumValid(ipv4Packet, udpPacket, uint8(header.UDPProtocolNumber)) {
		t.Fatal("UDP checksum is invalid after translation")
	}
}

func TestSIIT64ShortICMPErrorQuoteSkipsQuoteRewrite(t *testing.T) {
	shortQuote := buildIPv6UDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},
		1,
		12345,
		33434,
		nil,
	)[:24]

	packet := buildICMPv6ErrorPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 4, 4},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		header.ICMPv6TimeExceeded,
		header.ICMPv6HopLimitExceeded,
		func(icmp header.ICMPv6) {
			clear(icmp[4:8])
		},
		shortQuote,
	)

	translated := translateSIIT64Packet(t, packet)
	ipv4Packet := header.IPv4(translated)
	if ipv4Packet.Protocol() != uint8(header.ICMPv4ProtocolNumber) {
		t.Fatalf("outer protocol = %d, want ICMPv4", ipv4Packet.Protocol())
	}

	icmpv4Packet := header.ICMPv4(ipv4Packet.Payload())
	if checksum.Checksum(icmpv4Packet, 0) != 0xffff {
		t.Fatal("outer ICMPv4 checksum is invalid")
	}
	if got := icmpv4Packet.Payload(); !bytes.Equal(got[:len(shortQuote)], shortQuote) {
		t.Fatalf("short quote changed unexpectedly: got %x want %x", got[:len(shortQuote)], shortQuote)
	}
	if got := icmpv4Packet.Payload()[0] >> 4; got != header.IPv6Version {
		t.Fatalf("short quote version nibble = %d, want IPv6", got)
	}
}

func TestSIIT64PacketTooBigTranslatesQuotedUDPToIPv4(t *testing.T) {
	quotedPacket := buildIPv6UDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},
		8,
		12345,
		33434,
		nil,
	)
	packet := buildICMPv6ErrorPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		header.ICMPv6PacketTooBig,
		header.ICMPv6UnusedCode,
		func(icmp header.ICMPv6) {
			icmp.SetMTU(1500)
		},
		quotedPacket,
	)

	translated := translateSIIT64Packet(t, packet)
	icmpv4Packet := header.ICMPv4(header.IPv4(translated).Payload())
	if icmpv4Packet.Type() != header.ICMPv4DstUnreachable || icmpv4Packet.Code() != header.ICMPv4FragmentationNeeded {
		t.Fatalf("outer ICMP type/code = %d/%d, want destination unreachable/fragmentation needed", icmpv4Packet.Type(), icmpv4Packet.Code())
	}
	if got, want := icmpv4Packet.MTU(), uint16(1400); got != want {
		t.Fatalf("translated MTU = %d, want %d", got, want)
	}
	if got := header.IPVersion(header.IPv4(icmpv4Packet.Payload())); got != header.IPv4Version {
		t.Fatalf("quoted packet version = %d, want IPv4", got)
	}
}

func TestSIIT64ParamProblemTranslatesQuotedUDPToIPv4(t *testing.T) {
	quotedPacket := buildIPv6UDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},
		8,
		12345,
		33434,
		nil,
	)
	packet := buildICMPv6ErrorPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		header.ICMPv6ParamProblem,
		header.ICMPv6ErroneousHeader,
		func(icmp header.ICMPv6) {
			clear(icmp[4:8])
			icmp[7] = 24
		},
		quotedPacket,
	)

	translated := translateSIIT64Packet(t, packet)
	icmpv4Packet := header.ICMPv4(header.IPv4(translated).Payload())
	if icmpv4Packet.Type() != header.ICMPv4ParamProblem || icmpv4Packet.Code() != header.ICMPv4UnusedCode {
		t.Fatalf("outer ICMP type/code = %d/%d, want parameter problem/unused", icmpv4Packet.Type(), icmpv4Packet.Code())
	}
	if got, want := icmpv4Packet.Pointer(), byte(16); got != want {
		t.Fatalf("translated pointer = %d, want %d", got, want)
	}
	if got := header.IPVersion(header.IPv4(icmpv4Packet.Payload())); got != header.IPv4Version {
		t.Fatalf("quoted packet version = %d, want IPv4", got)
	}
}

func TestSIIT64UnsupportedQuotedICMPSkipsQuoteRewrite(t *testing.T) {
	quotedPacket := buildICMPv6ErrorPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},
		header.ICMPv6TimeExceeded,
		header.ICMPv6HopLimitExceeded,
		func(icmp header.ICMPv6) {
			clear(icmp[4:8])
		},
		nil,
	)
	packet := buildICMPv6ErrorPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		header.ICMPv6TimeExceeded,
		header.ICMPv6HopLimitExceeded,
		func(icmp header.ICMPv6) {
			clear(icmp[4:8])
		},
		quotedPacket,
	)

	translated := translateSIIT64Packet(t, packet)
	icmpv4Packet := header.ICMPv4(header.IPv4(translated).Payload())
	if got := icmpv4Packet.Payload()[:len(quotedPacket)]; !bytes.Equal(got, quotedPacket) {
		t.Fatalf("unsupported quoted ICMP changed unexpectedly: got %x want %x", got, quotedPacket)
	}
	if got := icmpv4Packet.Payload()[0] >> 4; got != header.IPv6Version {
		t.Fatalf("unsupported quoted ICMP version nibble = %d, want IPv6", got)
	}
}

func TestSIIT64ExtensionHeaderQuoteSkipsQuoteRewrite(t *testing.T) {
	quotedPacket := buildIPv6HopByHopPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},
	)
	packet := buildICMPv6ErrorPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		header.ICMPv6TimeExceeded,
		header.ICMPv6HopLimitExceeded,
		func(icmp header.ICMPv6) {
			clear(icmp[4:8])
		},
		quotedPacket,
	)

	translated := translateSIIT64Packet(t, packet)
	icmpv4Packet := header.ICMPv4(header.IPv4(translated).Payload())
	if got := icmpv4Packet.Payload()[:len(quotedPacket)]; !bytes.Equal(got, quotedPacket) {
		t.Fatalf("extension-header quote changed unexpectedly: got %x want %x", got, quotedPacket)
	}
	if got := icmpv4Packet.Payload()[0] >> 4; got != header.IPv6Version {
		t.Fatalf("extension-header quote version nibble = %d, want IPv6", got)
	}
}

func TestSIIT64FragmentHeaderQuoteSkipsQuoteRewrite(t *testing.T) {
	quotedPacket := buildIPv6FragmentPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},
	)
	packet := buildICMPv6ErrorPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		header.ICMPv6TimeExceeded,
		header.ICMPv6HopLimitExceeded,
		func(icmp header.ICMPv6) {
			clear(icmp[4:8])
		},
		quotedPacket,
	)

	translated := translateSIIT64Packet(t, packet)
	icmpv4Packet := header.ICMPv4(header.IPv4(translated).Payload())
	if got := icmpv4Packet.Payload()[:len(quotedPacket)]; !bytes.Equal(got, quotedPacket) {
		t.Fatalf("fragment-header quote changed unexpectedly: got %x want %x", got, quotedPacket)
	}
	if got := icmpv4Packet.Payload()[0] >> 4; got != header.IPv6Version {
		t.Fatalf("fragment-header quote version nibble = %d, want IPv6", got)
	}
}

func TestSIIT64TooSmallReservedSpaceFailsClosed(t *testing.T) {
	packet := buildIPv6UDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9},
		64,
		4500,
		33434,
		[]byte{0xde, 0xad, 0xbe, 0xef},
	)
	reserved := uint(header.IPv4MinimumSize - 1)
	buffer := make([]byte, int(reserved)+MessageTransportHeaderSize+len(packet))
	copy(buffer[int(reserved)+MessageTransportHeaderSize:], packet)

	if SIIT64InPlaceTranslate(buffer, &reserved) {
		t.Fatal("packet translated with undersized reserved headroom")
	}
}

func translateSIIT64Packet(t *testing.T, packet []byte) []byte {
	t.Helper()

	reserved := uint(header.IPv6FixedHeaderSize + header.IPv6FragmentHeaderSize)
	buffer := make([]byte, int(reserved)+MessageTransportHeaderSize+len(packet))
	copy(buffer[int(reserved)+MessageTransportHeaderSize:], packet)

	if !SIIT64InPlaceTranslate(buffer, &reserved) {
		t.Fatal("packet was not translated")
	}

	translated := header.IPv4(buffer[int(reserved)+MessageTransportHeaderSize:])
	return buffer[int(reserved)+MessageTransportHeaderSize : int(reserved)+MessageTransportHeaderSize+int(translated.TotalLength())]
}

func buildIPv6UDPPacket(src, dst [16]byte, hopLimit uint8, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+header.UDPMinimumSize+len(payload))
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.UDPMinimumSize + len(payload)),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          hopLimit,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})

	udpPacket := header.UDP(ipv6Packet.Payload())
	udpPacket.Encode(&header.UDPFields{
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Length:   uint16(header.UDPMinimumSize + len(payload)),
		Checksum: 0,
	})
	copy(udpPacket.Payload(), payload)
	udpPacket.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ipv6Packet[IPv6SourceAddressOffset:IPv6SourceAddressOffset+IPv6AddressSize*2], 0),
		uint16(len(udpPacket)),
	), uint16(header.UDPProtocolNumber)), checksum.Checksum(udpPacket, 0)))
	return packet
}

func buildIPv6ICMPEchoPacket(src, dst [16]byte, hopLimit uint8, typ header.ICMPv6Type, ident, sequence uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize+len(payload))
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6MinimumSize + len(payload)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          hopLimit,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})

	icmpv6Packet := header.ICMPv6(ipv6Packet.Payload())
	icmpv6Packet.SetType(typ)
	icmpv6Packet.SetCode(header.ICMPv6UnusedCode)
	icmpv6Packet.SetIdent(ident)
	icmpv6Packet.SetSequence(sequence)
	copy(icmpv6Packet.Payload(), payload)
	icmpv6Packet.SetChecksum(0)
	icmpv6Packet.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ipv6Packet[IPv6SourceAddressOffset:IPv6SourceAddressOffset+IPv6AddressSize*2], 0),
		uint16(len(icmpv6Packet)),
	), uint16(header.ICMPv6ProtocolNumber)), checksum.Checksum(icmpv6Packet, 0)))
	return packet
}

func buildICMPv6ErrorPacket(src, dst [16]byte, typ header.ICMPv6Type, code header.ICMPv6Code, rest func(header.ICMPv6), quote []byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize+len(quote))
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6MinimumSize + len(quote)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})

	icmpv6Packet := header.ICMPv6(ipv6Packet.Payload())
	icmpv6Packet.SetType(typ)
	icmpv6Packet.SetCode(code)
	if rest != nil {
		rest(icmpv6Packet)
	}
	copy(icmpv6Packet.Payload(), quote)
	icmpv6Packet.SetChecksum(0)
	icmpv6Packet.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ipv6Packet[IPv6SourceAddressOffset:IPv6SourceAddressOffset+IPv6AddressSize*2], 0),
		uint16(len(icmpv6Packet)),
	), uint16(header.ICMPv6ProtocolNumber)), checksum.Checksum(icmpv6Packet, 0)))
	return packet
}

func buildIPv6HopByHopPacket(src, dst [16]byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+IPv6ExtensionHeaderMinimumSize)
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     IPv6ExtensionHeaderMinimumSize,
		TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6HopByHopOptionsExtHdrIdentifier),
		HopLimit:          1,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})
	packet[header.IPv6FixedHeaderSize+IPv6ExtensionHeaderNextHeaderOffset] = 59
	packet[header.IPv6FixedHeaderSize+IPv6ExtensionHeaderHeaderExtensionLengthOffset] = 0
	return packet
}

func buildIPv6FragmentPacket(src, dst [16]byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize)
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     header.IPv6FragmentHeaderSize,
		TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6FragmentExtHdrIdentifier),
		HopLimit:          1,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})
	packet[header.IPv6FixedHeaderSize] = 59
	packet[header.IPv6FixedHeaderSize+IPv6FragmentExtensionHeaderReservedOffset] = 0
	packet[header.IPv6FixedHeaderSize+2] = 0
	packet[header.IPv6FixedHeaderSize+3] = 0
	packet[header.IPv6FixedHeaderSize+4] = 0
	packet[header.IPv6FixedHeaderSize+5] = 0
	packet[header.IPv6FixedHeaderSize+6] = 0
	packet[header.IPv6FixedHeaderSize+7] = 1
	return packet
}

func isIPv4TransportChecksumValid(ipv4Packet header.IPv4, transport []byte, protocol uint8) bool {
	return checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ipv4Packet[IPv4SourceAddressOffset:IPv4SourceAddressOffset+IPv4AddressSize*2], 0),
		uint16(len(transport)),
	), uint16(protocol)), checksum.Checksum(transport, 0)) == 0xffff
}
