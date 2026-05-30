package clat

import (
	"bytes"
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestSIIT46TimeExceededTranslatesQuotedUDPToIPv6(t *testing.T) {
	quotedPacket := buildIPv4UDPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{1, 2, 3, 4},
		1,
		12345,
		33434,
		nil,
	)
	packet := buildICMPv4ErrorPacket(
		[4]byte{8, 8, 8, 8},
		[4]byte{10, 0, 0, 1},
		header.ICMPv4TimeExceeded,
		header.ICMPv4TTLExceeded,
		func(icmp header.ICMPv4) {
			clear(icmp[4:8])
		},
		quotedPacket,
	)

	translated := translateSIIT46Packet(t, packet)
	ipv6Packet := header.IPv6(translated)
	if got, want := ipv6Packet.NextHeader(), uint8(header.ICMPv6ProtocolNumber); got != want {
		t.Fatalf("outer next header = %d, want %d", got, want)
	}

	icmpv6Packet := header.ICMPv6(ipv6Packet.Payload())
	if got, want := icmpv6Packet.Type(), header.ICMPv6TimeExceeded; got != want {
		t.Fatalf("outer ICMP type = %d, want %d", got, want)
	}
	if got, want := icmpv6Packet.Code(), header.ICMPv6HopLimitExceeded; got != want {
		t.Fatalf("outer ICMP code = %d, want %d", got, want)
	}
	if !isIPv6TransportChecksumValid(ipv6Packet, icmpv6Packet, uint8(header.ICMPv6ProtocolNumber)) {
		t.Fatal("outer ICMPv6 checksum is invalid")
	}

	quotedIPv6 := header.IPv6(icmpv6Packet.Payload())
	if got := header.IPVersion(quotedIPv6); got != header.IPv6Version {
		t.Fatalf("quoted packet version = %d, want IPv6", got)
	}
	if got, want := quotedIPv6.SourceAddress(), tcpip.AddrFrom16([16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1}); got != want {
		t.Fatalf("quoted IPv6 source = %s, want %s", got, want)
	}
	if got, want := quotedIPv6.DestinationAddress(), tcpip.AddrFrom16([16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}); got != want {
		t.Fatalf("quoted IPv6 destination = %s, want %s", got, want)
	}
	if got, want := quotedIPv6.NextHeader(), uint8(header.UDPProtocolNumber); got != want {
		t.Fatalf("quoted IPv6 next header = %d, want %d", got, want)
	}

	quotedUDP := header.UDP(quotedIPv6.Payload())
	if got, want := quotedUDP.SourcePort(), uint16(12345); got != want {
		t.Fatalf("quoted UDP source port = %d, want %d", got, want)
	}
	if got, want := quotedUDP.DestinationPort(), uint16(33434); got != want {
		t.Fatalf("quoted UDP destination port = %d, want %d", got, want)
	}
}

func TestSIIT46PortUnreachableTranslatesQuotedICMPEchoToIPv6(t *testing.T) {
	quotedPacket := buildIPv4ICMPEchoPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{1, 2, 3, 4},
		1,
		header.ICMPv4Echo,
		0x1234,
		0x5678,
		nil,
	)
	packet := buildICMPv4ErrorPacket(
		[4]byte{9, 9, 9, 9},
		[4]byte{10, 0, 0, 1},
		header.ICMPv4DstUnreachable,
		header.ICMPv4PortUnreachable,
		func(icmp header.ICMPv4) {
			clear(icmp[4:8])
		},
		quotedPacket,
	)

	translated := translateSIIT46Packet(t, packet)
	ipv6Packet := header.IPv6(translated)
	icmpv6Packet := header.ICMPv6(ipv6Packet.Payload())
	if got, want := icmpv6Packet.Type(), header.ICMPv6DstUnreachable; got != want {
		t.Fatalf("outer ICMP type = %d, want %d", got, want)
	}
	if got, want := icmpv6Packet.Code(), header.ICMPv6PortUnreachable; got != want {
		t.Fatalf("outer ICMP code = %d, want %d", got, want)
	}
	if !isIPv6TransportChecksumValid(ipv6Packet, icmpv6Packet, uint8(header.ICMPv6ProtocolNumber)) {
		t.Fatal("outer ICMPv6 checksum is invalid")
	}

	quotedIPv6 := header.IPv6(icmpv6Packet.Payload())
	if got := header.IPVersion(quotedIPv6); got != header.IPv6Version {
		t.Fatalf("quoted packet version = %d, want IPv6", got)
	}
	if got, want := quotedIPv6.NextHeader(), uint8(header.ICMPv6ProtocolNumber); got != want {
		t.Fatalf("quoted IPv6 next header = %d, want %d", got, want)
	}

	quotedICMPv6 := header.ICMPv6(quotedIPv6.Payload())
	if got, want := quotedICMPv6.Type(), header.ICMPv6EchoRequest; got != want {
		t.Fatalf("quoted ICMP type = %d, want %d", got, want)
	}
	if got, want := quotedICMPv6.Ident(), uint16(0x1234); got != want {
		t.Fatalf("quoted ICMP ident = %d, want %d", got, want)
	}
	if got, want := quotedICMPv6.Sequence(), uint16(0x5678); got != want {
		t.Fatalf("quoted ICMP sequence = %d, want %d", got, want)
	}
	if !isIPv6TransportChecksumValid(quotedIPv6, quotedICMPv6, uint8(header.ICMPv6ProtocolNumber)) {
		t.Fatal("quoted ICMPv6 checksum is invalid")
	}
}

func TestSIIT46PacketTooBigTranslatesQuotedUDPToIPv6(t *testing.T) {
	quotedPacket := buildIPv4UDPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{1, 2, 3, 4},
		8,
		12345,
		33434,
		nil,
	)
	packet := buildICMPv4ErrorPacket(
		[4]byte{9, 9, 9, 9},
		[4]byte{10, 0, 0, 1},
		header.ICMPv4DstUnreachable,
		header.ICMPv4FragmentationNeeded,
		func(icmp header.ICMPv4) {
			icmp.SetMTU(1400)
		},
		quotedPacket,
	)

	translated := translateSIIT46Packet(t, packet)
	icmpv6Packet := header.ICMPv6(header.IPv6(translated).Payload())
	if got, want := icmpv6Packet.Type(), header.ICMPv6PacketTooBig; got != want {
		t.Fatalf("outer ICMP type = %d, want %d", got, want)
	}
	if got, want := icmpv6Packet.MTU(), uint32(1420); got != want {
		t.Fatalf("translated MTU = %d, want %d", got, want)
	}
	if got := header.IPVersion(header.IPv6(icmpv6Packet.Payload())); got != header.IPv6Version {
		t.Fatalf("quoted packet version = %d, want IPv6", got)
	}
}

func TestSIIT46ParamProblemTranslatesQuotedUDPToIPv6(t *testing.T) {
	quotedPacket := buildIPv4UDPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{1, 2, 3, 4},
		8,
		12345,
		33434,
		nil,
	)
	packet := buildICMPv4ErrorPacket(
		[4]byte{9, 9, 9, 9},
		[4]byte{10, 0, 0, 1},
		header.ICMPv4ParamProblem,
		0,
		func(icmp header.ICMPv4) {
			icmp.SetPointer(9)
		},
		quotedPacket,
	)

	translated := translateSIIT46Packet(t, packet)
	icmpv6Packet := header.ICMPv6(header.IPv6(translated).Payload())
	if got, want := icmpv6Packet.Type(), header.ICMPv6ParamProblem; got != want {
		t.Fatalf("outer ICMP type = %d, want %d", got, want)
	}
	if got, want := binary.BigEndian.Uint32(icmpv6Packet[4:8]), uint32(6); got != want {
		t.Fatalf("translated pointer = %d, want %d", got, want)
	}
	if got := header.IPVersion(header.IPv6(icmpv6Packet.Payload())); got != header.IPv6Version {
		t.Fatalf("quoted packet version = %d, want IPv6", got)
	}
}

func TestSIIT46ShortICMPErrorQuoteSkipsQuoteRewrite(t *testing.T) {
	shortQuote := buildIPv4UDPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{1, 2, 3, 4},
		1,
		12345,
		33434,
		nil,
	)[:24]
	packet := buildICMPv4ErrorPacket(
		[4]byte{8, 8, 4, 4},
		[4]byte{10, 0, 0, 1},
		header.ICMPv4TimeExceeded,
		header.ICMPv4TTLExceeded,
		func(icmp header.ICMPv4) {
			clear(icmp[4:8])
		},
		shortQuote,
	)

	translated := translateSIIT46Packet(t, packet)
	ipv6Packet := header.IPv6(translated)
	icmpv6Packet := header.ICMPv6(ipv6Packet.Payload())
	if !isIPv6TransportChecksumValid(ipv6Packet, icmpv6Packet, uint8(header.ICMPv6ProtocolNumber)) {
		t.Fatal("outer ICMPv6 checksum is invalid")
	}
	if got := icmpv6Packet.Payload()[:len(shortQuote)]; !bytes.Equal(got, shortQuote) {
		t.Fatalf("short quote changed unexpectedly: got %x want %x", got, shortQuote)
	}
	if got := icmpv6Packet.Payload()[0] >> 4; got != header.IPv4Version {
		t.Fatalf("short quote version nibble = %d, want IPv4", got)
	}
}

func TestSIIT46UnsupportedQuotedICMPSkipsQuoteRewrite(t *testing.T) {
	quotedPacket := buildICMPv4ErrorPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{1, 2, 3, 4},
		header.ICMPv4TimeExceeded,
		header.ICMPv4TTLExceeded,
		func(icmp header.ICMPv4) {
			clear(icmp[4:8])
		},
		nil,
	)
	packet := buildICMPv4ErrorPacket(
		[4]byte{8, 8, 8, 8},
		[4]byte{10, 0, 0, 1},
		header.ICMPv4TimeExceeded,
		header.ICMPv4TTLExceeded,
		func(icmp header.ICMPv4) {
			clear(icmp[4:8])
		},
		quotedPacket,
	)

	translated := translateSIIT46Packet(t, packet)
	icmpv6Packet := header.ICMPv6(header.IPv6(translated).Payload())
	if got := icmpv6Packet.Payload()[:len(quotedPacket)]; !bytes.Equal(got, quotedPacket) {
		t.Fatalf("unsupported quoted ICMP changed unexpectedly: got %x want %x", got, quotedPacket)
	}
	if got := icmpv6Packet.Payload()[0] >> 4; got != header.IPv4Version {
		t.Fatalf("unsupported quoted ICMP version nibble = %d, want IPv4", got)
	}
}

func TestSIIT46QuotedFragmentSkipsQuoteRewrite(t *testing.T) {
	quotedPacket := buildIPv4FragmentPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{1, 2, 3, 4},
		uint8(header.UDPProtocolNumber),
		header.IPv4FlagMoreFragments,
		1,
		bytes.Repeat([]byte{0xaa}, header.UDPMinimumSize),
	)
	packet := buildICMPv4ErrorPacket(
		[4]byte{8, 8, 8, 8},
		[4]byte{10, 0, 0, 1},
		header.ICMPv4TimeExceeded,
		header.ICMPv4TTLExceeded,
		func(icmp header.ICMPv4) {
			clear(icmp[4:8])
		},
		quotedPacket,
	)

	translated := translateSIIT46Packet(t, packet)
	icmpv6Packet := header.ICMPv6(header.IPv6(translated).Payload())
	if got := icmpv6Packet.Payload()[:len(quotedPacket)]; !bytes.Equal(got, quotedPacket) {
		t.Fatalf("fragment quote changed unexpectedly: got %x want %x", got, quotedPacket)
	}
	if got := icmpv6Packet.Payload()[0] >> 4; got != header.IPv4Version {
		t.Fatalf("fragment quote version nibble = %d, want IPv4", got)
	}
}

func TestSIIT46QuotedIPv4OptionsSkipQuoteRewrite(t *testing.T) {
	quotedPacket := buildIPv4PacketWithOptions(
		[4]byte{10, 0, 0, 1},
		[4]byte{1, 2, 3, 4},
		uint8(header.UDPProtocolNumber),
	)
	packet := buildICMPv4ErrorPacket(
		[4]byte{8, 8, 8, 8},
		[4]byte{10, 0, 0, 1},
		header.ICMPv4TimeExceeded,
		header.ICMPv4TTLExceeded,
		func(icmp header.ICMPv4) {
			clear(icmp[4:8])
		},
		quotedPacket,
	)

	translated := translateSIIT46Packet(t, packet)
	icmpv6Packet := header.ICMPv6(header.IPv6(translated).Payload())
	if got := icmpv6Packet.Payload()[:len(quotedPacket)]; !bytes.Equal(got, quotedPacket) {
		t.Fatalf("quoted IPv4 options changed unexpectedly: got %x want %x", got, quotedPacket)
	}
	if got := icmpv6Packet.Payload()[0] >> 4; got != header.IPv4Version {
		t.Fatalf("quoted options version nibble = %d, want IPv4", got)
	}
}

func TestSIIT46TooSmallReservedSpaceFailsClosed(t *testing.T) {
	packet := buildIPv4UDPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{203, 0, 113, 9},
		64,
		4500,
		33434,
		[]byte{0xde, 0xad, 0xbe, 0xef},
	)
	reserved := uint8(header.IPv6FixedHeaderSize - 1)
	buffer := make([]byte, int(reserved)+MessageTransportHeaderSize+len(packet))
	copy(buffer[int(reserved)+MessageTransportHeaderSize:], packet)

	if got, want := SIIT46InPlaceTranslate(buffer, &reserved), SIIT46Dropped; got != want {
		t.Fatalf("translation result = %v, want %v", got, want)
	}
}

func translateSIIT46Packet(t *testing.T, packet []byte) []byte {
	t.Helper()

	reserved := uint8(header.IPv6FixedHeaderSize + header.IPv6FragmentHeaderSize)
	buffer := make([]byte, int(reserved)+MessageTransportHeaderSize+len(packet))
	copy(buffer[int(reserved)+MessageTransportHeaderSize:], packet)

	if SIIT46InPlaceTranslate(buffer, &reserved) != SIIT46Translated {
		t.Fatal("packet was not translated")
	}

	translated := header.IPv6(buffer[int(reserved)+MessageTransportHeaderSize:])
	return buffer[int(reserved)+MessageTransportHeaderSize : int(reserved)+MessageTransportHeaderSize+header.IPv6FixedHeaderSize+int(translated.PayloadLength())]
}

func buildIPv4UDPPacket(src, dst [4]byte, ttl uint8, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ipv4Packet := header.IPv4(packet)
	ipv4Packet.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(packet)),
		ID:             0x1234,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            ttl,
		Protocol:       uint8(header.UDPProtocolNumber),
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(src),
		DstAddr:        tcpip.AddrFrom4(dst),
	})

	udpPacket := header.UDP(ipv4Packet.Payload())
	udpPacket.Encode(&header.UDPFields{
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Length:   uint16(header.UDPMinimumSize + len(payload)),
		Checksum: 0,
	})
	copy(udpPacket.Payload(), payload)
	udpPacket.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ipv4Packet[IPv4SourceAddressOffset:IPv4SourceAddressOffset+IPv4AddressSize*2], 0),
		uint16(len(udpPacket)),
	), uint16(header.UDPProtocolNumber)), checksum.Checksum(udpPacket, 0)))

	ipv4Packet.SetChecksum(0)
	ipv4Packet.SetChecksum(^ipv4Packet.CalculateChecksum())
	return packet
}

func buildIPv4ICMPEchoPacket(src, dst [4]byte, ttl uint8, typ header.ICMPv4Type, ident, sequence uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	ipv4Packet := header.IPv4(packet)
	ipv4Packet.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(packet)),
		ID:             0x5678,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            ttl,
		Protocol:       uint8(header.ICMPv4ProtocolNumber),
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(src),
		DstAddr:        tcpip.AddrFrom4(dst),
	})

	icmpv4Packet := header.ICMPv4(ipv4Packet.Payload())
	icmpv4Packet.SetType(typ)
	icmpv4Packet.SetCode(header.ICMPv4UnusedCode)
	icmpv4Packet.SetIdent(ident)
	icmpv4Packet.SetSequence(sequence)
	copy(icmpv4Packet.Payload(), payload)
	icmpv4Packet.SetChecksum(0)
	icmpv4Packet.SetChecksum(^checksum.Checksum(icmpv4Packet, 0))

	ipv4Packet.SetChecksum(0)
	ipv4Packet.SetChecksum(^ipv4Packet.CalculateChecksum())
	return packet
}

func buildICMPv4ErrorPacket(src, dst [4]byte, typ header.ICMPv4Type, code header.ICMPv4Code, rest func(header.ICMPv4), quote []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(quote))
	ipv4Packet := header.IPv4(packet)
	ipv4Packet.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(packet)),
		ID:             0x9abc,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       uint8(header.ICMPv4ProtocolNumber),
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(src),
		DstAddr:        tcpip.AddrFrom4(dst),
	})

	icmpv4Packet := header.ICMPv4(ipv4Packet.Payload())
	icmpv4Packet.SetType(typ)
	icmpv4Packet.SetCode(code)
	if rest != nil {
		rest(icmpv4Packet)
	}
	copy(icmpv4Packet.Payload(), quote)
	icmpv4Packet.SetChecksum(0)
	icmpv4Packet.SetChecksum(^checksum.Checksum(icmpv4Packet, 0))

	ipv4Packet.SetChecksum(0)
	ipv4Packet.SetChecksum(^ipv4Packet.CalculateChecksum())
	return packet
}

func buildIPv4PacketWithOptions(src, dst [4]byte, protocol uint8) []byte {
	packet := make([]byte, header.IPv4MinimumSize+4+header.UDPMinimumSize)
	ipv4Packet := header.IPv4(packet)
	ipv4Packet.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(packet)),
		ID:             0x1357,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            1,
		Protocol:       protocol,
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(src),
		DstAddr:        tcpip.AddrFrom4(dst),
	})
	ipv4Packet.SetHeaderLength(header.IPv4MinimumSize + 4)
	copy(ipv4Packet[header.IPv4MinimumSize:header.IPv4MinimumSize+4], []byte{1, 1, 1, 0})
	ipv4Packet.SetChecksum(0)
	ipv4Packet.SetChecksum(^ipv4Packet.CalculateChecksum())
	return packet
}

func isIPv6TransportChecksumValid(ipv6Packet header.IPv6, transport []byte, protocol uint8) bool {
	return checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ipv6Packet[IPv6SourceAddressOffset:IPv6SourceAddressOffset+IPv6AddressSize*2], 0),
		uint16(len(transport)),
	), uint16(protocol)), checksum.Checksum(transport, 0)) == 0xffff
}
