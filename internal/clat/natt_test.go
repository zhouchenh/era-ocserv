package clat

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestSIIT64NATTUDPCarriagePreservesPortsAndPayload(t *testing.T) {
	src := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1}
	dst := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9}
	tests := []struct {
		name    string
		port    uint16
		payload []byte
	}{
		{name: "IKE500", port: 500, payload: []byte{0x22, 0x20, 0x00, 0x00, 0xde, 0xad}},
		{name: "NonESPMarker4500", port: 4500, payload: []byte{0x00, 0x00, 0x00, 0x00, 0x22, 0x20, 0x00, 0x00}},
		{name: "ESPInUDP4500", port: 4500, payload: []byte{0x00, 0x00, 0x00, 0x01, 0, 0, 0, 2, 0xaa, 0xbb, 0xcc, 0xdd}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := buildIPv6UDPPacket(src, dst, 64, tt.port, tt.port, tt.payload)
			translated := translateSIIT64Packet(t, packet)

			ipv4Packet := header.IPv4(translated)
			if got, want := ipv4Packet.Protocol(), uint8(header.UDPProtocolNumber); got != want {
				t.Fatalf("protocol = %d, want %d", got, want)
			}
			udpPacket := header.UDP(ipv4Packet.Payload())
			if got, want := udpPacket.SourcePort(), tt.port; got != want {
				t.Fatalf("UDP source port = %d, want %d", got, want)
			}
			if got, want := udpPacket.DestinationPort(), tt.port; got != want {
				t.Fatalf("UDP destination port = %d, want %d", got, want)
			}
			if got := udpPacket.Payload(); !bytes.Equal(got, tt.payload) {
				t.Fatalf("UDP payload changed: got %x want %x", got, tt.payload)
			}
			if !isIPv4TransportChecksumValid(ipv4Packet, udpPacket, uint8(header.UDPProtocolNumber)) {
				t.Fatal("UDP checksum is invalid after SIIT64 translation")
			}
		})
	}
}

func TestSIIT46NATTUDPCarriagePreservesPortsAndPayload(t *testing.T) {
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{203, 0, 113, 9}
	tests := []struct {
		name    string
		port    uint16
		payload []byte
	}{
		{name: "IKE500", port: 500, payload: []byte{0x22, 0x20, 0x00, 0x00, 0xde, 0xad}},
		{name: "NonESPMarker4500", port: 4500, payload: []byte{0x00, 0x00, 0x00, 0x00, 0x22, 0x20, 0x00, 0x00}},
		{name: "ESPInUDP4500", port: 4500, payload: []byte{0x00, 0x00, 0x00, 0x01, 0, 0, 0, 2, 0xaa, 0xbb, 0xcc, 0xdd}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := buildIPv4UDPPacket(src, dst, 64, tt.port, tt.port, tt.payload)
			translated := translateSIIT46Packet(t, packet)

			ipv6Packet := header.IPv6(translated)
			if got, want := ipv6Packet.NextHeader(), uint8(header.UDPProtocolNumber); got != want {
				t.Fatalf("next header = %d, want %d", got, want)
			}
			udpPacket := header.UDP(ipv6Packet.Payload())
			if got, want := udpPacket.SourcePort(), tt.port; got != want {
				t.Fatalf("UDP source port = %d, want %d", got, want)
			}
			if got, want := udpPacket.DestinationPort(), tt.port; got != want {
				t.Fatalf("UDP destination port = %d, want %d", got, want)
			}
			if got := udpPacket.Payload(); !bytes.Equal(got, tt.payload) {
				t.Fatalf("UDP payload changed: got %x want %x", got, tt.payload)
			}
			if !isIPv6TransportChecksumValid(ipv6Packet, udpPacket, uint8(header.UDPProtocolNumber)) {
				t.Fatal("UDP checksum is invalid after SIIT46 translation")
			}
		})
	}
}

func TestSIIT46NATTKeepaliveWithZeroChecksumTranslates(t *testing.T) {
	packet := buildIPv4UDPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{203, 0, 113, 9},
		64,
		4500,
		4500,
		[]byte{0xff},
	)
	clearIPv4UDPChecksum(packet)

	translated := translateSIIT46Packet(t, packet)
	ipv6Packet := header.IPv6(translated)
	udpPacket := header.UDP(ipv6Packet.Payload())
	if got, want := udpPacket.SourcePort(), uint16(4500); got != want {
		t.Fatalf("UDP source port = %d, want %d", got, want)
	}
	if got, want := udpPacket.DestinationPort(), uint16(4500); got != want {
		t.Fatalf("UDP destination port = %d, want %d", got, want)
	}
	if got, want := udpPacket.Payload(), []byte{0xff}; !bytes.Equal(got, want) {
		t.Fatalf("UDP payload = %x, want %x", got, want)
	}
	if !isIPv6TransportChecksumValid(ipv6Packet, udpPacket, uint8(header.UDPProtocolNumber)) {
		t.Fatal("UDP checksum is invalid after SIIT46 keepalive translation")
	}
}

func TestSIIT46FragmentedZeroChecksumNATTDrops(t *testing.T) {
	packet := buildIPv4FragmentedUDPFirstPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{203, 0, 113, 9},
		64,
		4500,
		4500,
		24,
		[]byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
	)

	reserved := uint8(header.IPv6FixedHeaderSize + header.IPv6FragmentHeaderSize)
	buffer := make([]byte, int(reserved)+MessageTransportHeaderSize+len(packet))
	copy(buffer[int(reserved)+MessageTransportHeaderSize:], packet)

	if got, want := SIIT46InPlaceTranslate(buffer, &reserved), SIIT46Dropped; got != want {
		t.Fatalf("translation result = %v, want %v", got, want)
	}
}

func TestSIIT64PacketTooBigTranslatesQuotedNATTUDPToIPv4(t *testing.T) {
	quotedPacket := buildIPv6UDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 198, 51, 100, 7},
		8,
		4500,
		4500,
		[]byte{0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44},
	)
	packet := buildICMPv6ErrorPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 10},
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

	quotedIPv4 := header.IPv4(icmpv4Packet.Payload())
	quotedUDP := header.UDP(quotedIPv4.Payload())
	if got, want := quotedUDP.SourcePort(), uint16(4500); got != want {
		t.Fatalf("quoted UDP source port = %d, want %d", got, want)
	}
	if got, want := quotedUDP.DestinationPort(), uint16(4500); got != want {
		t.Fatalf("quoted UDP destination port = %d, want %d", got, want)
	}
}

func TestSIIT46FragmentationNeededQuotedNATTUsesPlateauFallback(t *testing.T) {
	oldIPv4OutboundMTU, oldIPv6OutboundMTU := IPv4OutboundMTU, IPv6OutboundMTU
	IPv4OutboundMTU, IPv6OutboundMTU = 9000, 9000
	defer func() {
		IPv4OutboundMTU, IPv6OutboundMTU = oldIPv4OutboundMTU, oldIPv6OutboundMTU
	}()

	quotedPacket := buildIPv4UDPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{198, 51, 100, 7},
		8,
		4500,
		4500,
		bytes.Repeat([]byte{0xaa}, 1572),
	)
	packet := buildICMPv4ErrorPacket(
		[4]byte{9, 9, 9, 9},
		[4]byte{10, 0, 0, 1},
		header.ICMPv4DstUnreachable,
		header.ICMPv4FragmentationNeeded,
		func(icmp header.ICMPv4) {
			icmp.SetMTU(0)
		},
		quotedPacket,
	)

	translated := translateSIIT46Packet(t, packet)
	icmpv6Packet := header.ICMPv6(header.IPv6(translated).Payload())
	if got, want := icmpv6Packet.Type(), header.ICMPv6PacketTooBig; got != want {
		t.Fatalf("outer ICMP type = %d, want %d", got, want)
	}
	if got, want := icmpv6Packet.MTU(), uint32(1512); got != want {
		t.Fatalf("translated MTU = %d, want %d", got, want)
	}

	quotedIPv6 := header.IPv6(icmpv6Packet.Payload())
	quotedUDP := header.UDP(quotedIPv6.Payload())
	if got, want := quotedUDP.SourcePort(), uint16(4500); got != want {
		t.Fatalf("quoted UDP source port = %d, want %d", got, want)
	}
	if got, want := quotedUDP.DestinationPort(), uint16(4500); got != want {
		t.Fatalf("quoted UDP destination port = %d, want %d", got, want)
	}
}

func clearIPv4UDPChecksum(packet []byte) {
	ipv4Packet := header.IPv4(packet)
	udpPacket := header.UDP(packet[ipv4Packet.HeaderLength():ipv4Packet.TotalLength()])
	udpPacket.SetChecksum(0)
}

func buildIPv4FragmentedUDPFirstPacket(src, dst [4]byte, ttl uint8, srcPort, dstPort, udpLength uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ipv4Packet := header.IPv4(packet)
	ipv4Packet.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(packet)),
		ID:             0x2468,
		Flags:          header.IPv4FlagMoreFragments,
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
		Length:   udpLength,
		Checksum: 0,
	})
	copy(udpPacket.Payload(), payload)

	ipv4Packet.SetChecksum(0)
	ipv4Packet.SetChecksum(^ipv4Packet.CalculateChecksum())
	return packet
}
