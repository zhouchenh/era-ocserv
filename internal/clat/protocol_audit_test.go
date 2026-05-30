package clat

import (
	"bytes"
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	ipv4EncapsulationProtocolNumber = 4
	greProtocolNumber               = 47
	ipsecESPProtocolNumber          = 50
	sctpProtocolNumber              = 132
)

func TestSIIT64DCCPTranslationUpdatesChecksum(t *testing.T) {
	src := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1}
	dst := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9}
	packet := buildIPv6DCCPPacket(src, dst, 64, 1111, 2222, []byte{0xde, 0xad, 0xbe, 0xef})

	translated := translateSIIT64Packet(t, packet)
	ipv4Packet := header.IPv4(translated)
	if got, want := ipv4Packet.Protocol(), uint8(DCCPProtocolNumber); got != want {
		t.Fatalf("protocol = %d, want %d", got, want)
	}
	if !isIPv4TransportChecksumValid(ipv4Packet, ipv4Packet.Payload(), DCCPProtocolNumber) {
		t.Fatal("DCCP checksum is invalid after SIIT64 translation")
	}
}

func TestSIIT64TCPTranslationUpdatesChecksum(t *testing.T) {
	src := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1}
	dst := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9}
	packet := buildIPv6TCPPacket(src, dst, 64, 1111, 2222, []byte{0xde, 0xad, 0xbe, 0xef})

	translated := translateSIIT64Packet(t, packet)
	ipv4Packet := header.IPv4(translated)
	if got, want := ipv4Packet.Protocol(), uint8(header.TCPProtocolNumber); got != want {
		t.Fatalf("protocol = %d, want %d", got, want)
	}
	if !isIPv4TransportChecksumValid(ipv4Packet, ipv4Packet.Payload(), uint8(header.TCPProtocolNumber)) {
		t.Fatal("TCP checksum is invalid after SIIT64 translation")
	}
}

func TestSIIT46DCCPTranslationUpdatesChecksum(t *testing.T) {
	packet := buildIPv4DCCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{203, 0, 113, 9},
		64,
		1111,
		2222,
		[]byte{0xde, 0xad, 0xbe, 0xef},
	)

	translated := translateSIIT46Packet(t, packet)
	ipv6Packet := header.IPv6(translated)
	if got, want := ipv6Packet.NextHeader(), uint8(DCCPProtocolNumber); got != want {
		t.Fatalf("next header = %d, want %d", got, want)
	}
	if !isIPv6TransportChecksumValid(ipv6Packet, ipv6Packet.Payload(), DCCPProtocolNumber) {
		t.Fatal("DCCP checksum is invalid after SIIT46 translation")
	}
}

func TestSIIT46TCPTranslationUpdatesChecksum(t *testing.T) {
	packet := buildIPv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{203, 0, 113, 9}, 1, []byte{0xde, 0xad, 0xbe, 0xef})

	translated := translateSIIT46Packet(t, packet)
	ipv6Packet := header.IPv6(translated)
	if got, want := ipv6Packet.NextHeader(), uint8(header.TCPProtocolNumber); got != want {
		t.Fatalf("next header = %d, want %d", got, want)
	}
	if !isIPv6TransportChecksumValid(ipv6Packet, ipv6Packet.Payload(), uint8(header.TCPProtocolNumber)) {
		t.Fatal("TCP checksum is invalid after SIIT46 translation")
	}
}

func TestNAT44DCCPRewriteUpdatesChecksum(t *testing.T) {
	packet := buildIPv4DCCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 10},
		32,
		1234,
		4321,
		[]byte{1, 2, 3, 4},
	)

	NAT44InPlaceTranslateAddress(packet, []byte{198, 51, 100, 7}, IPv4DestinationAddressOffset)

	ipv4Packet := header.IPv4(packet)
	if !ipv4Packet.IsChecksumValid() {
		t.Fatal("IPv4 header checksum is invalid after NAT44 rewrite")
	}
	if !isIPv4TransportChecksumValid(ipv4Packet, ipv4Packet.Payload(), DCCPProtocolNumber) {
		t.Fatal("DCCP checksum is invalid after NAT44 rewrite")
	}
}

func TestNAT66DCCPRewriteUpdatesChecksum(t *testing.T) {
	packet := buildIPv6DCCPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		32,
		1234,
		4321,
		[]byte{1, 2, 3, 4},
	)

	NAT66InPlaceTranslateAddress(packet, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, IPv6DestinationAddressOffset)

	ipv6Packet := header.IPv6(packet)
	if !isIPv6TransportChecksumValid(ipv6Packet, ipv6Packet.Payload(), DCCPProtocolNumber) {
		t.Fatal("DCCP checksum is invalid after NAT66 rewrite")
	}
}

func TestSIIT64OpaqueProtocolTranslationPreservesPayload(t *testing.T) {
	innerIPv4 := buildIPv4UDPPacket(
		[4]byte{192, 0, 2, 1},
		[4]byte{198, 51, 100, 2},
		17,
		1111,
		2222,
		[]byte{0xaa, 0xbb},
	)
	tests := []struct {
		name     string
		protocol uint8
		payload  []byte
	}{
		{name: "ESP", protocol: ipsecESPProtocolNumber, payload: []byte{0, 0, 0, 1, 0, 0, 0, 2, 0xaa, 0xbb, 0xcc, 0xdd}},
		{name: "GRE", protocol: greProtocolNumber, payload: []byte{0, 0, 0x08, 0x00, 0xaa, 0xbb, 0xcc, 0xdd}},
		{name: "IPInIP", protocol: ipv4EncapsulationProtocolNumber, payload: innerIPv4},
		{name: "SCTP", protocol: sctpProtocolNumber, payload: []byte{0x13, 0x88, 0x00, 0x50, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := buildIPv6OpaquePacket(
				[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
				[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9},
				tt.protocol,
				tt.payload,
			)

			translated := translateSIIT64Packet(t, packet)
			ipv4Packet := header.IPv4(translated)
			if got, want := ipv4Packet.Protocol(), tt.protocol; got != want {
				t.Fatalf("protocol = %d, want %d", got, want)
			}
			if !bytes.Equal(ipv4Packet.Payload(), tt.payload) {
				t.Fatalf("payload changed unexpectedly: got %x want %x", ipv4Packet.Payload(), tt.payload)
			}
		})
	}
}

func TestSIIT46OpaqueProtocolTranslationPreservesPayload(t *testing.T) {
	innerIPv4 := buildIPv4UDPPacket(
		[4]byte{192, 0, 2, 1},
		[4]byte{198, 51, 100, 2},
		17,
		1111,
		2222,
		[]byte{0xaa, 0xbb},
	)
	tests := []struct {
		name     string
		protocol uint8
		payload  []byte
	}{
		{name: "ESP", protocol: ipsecESPProtocolNumber, payload: []byte{0, 0, 0, 1, 0, 0, 0, 2, 0xaa, 0xbb, 0xcc, 0xdd}},
		{name: "GRE", protocol: greProtocolNumber, payload: []byte{0, 0, 0x08, 0x00, 0xaa, 0xbb, 0xcc, 0xdd}},
		{name: "IPInIP", protocol: ipv4EncapsulationProtocolNumber, payload: innerIPv4},
		{name: "SCTP", protocol: sctpProtocolNumber, payload: []byte{0x13, 0x88, 0x00, 0x50, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := buildIPv4OpaquePacket(
				[4]byte{10, 0, 0, 1},
				[4]byte{203, 0, 113, 9},
				tt.protocol,
				tt.payload,
			)

			translated := translateSIIT46Packet(t, packet)
			ipv6Packet := header.IPv6(translated)
			if got, want := ipv6Packet.NextHeader(), tt.protocol; got != want {
				t.Fatalf("next header = %d, want %d", got, want)
			}
			if !bytes.Equal(ipv6Packet.Payload(), tt.payload) {
				t.Fatalf("payload changed unexpectedly: got %x want %x", ipv6Packet.Payload(), tt.payload)
			}
		})
	}
}

func TestSIIT64AHIsRejected(t *testing.T) {
	packet := buildIPv6OpaquePacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9},
		IPsecAuthenticationHeaderProtocolNumber,
		[]byte{1, 2, 3, 4, 5, 6, 7, 8},
	)

	if translated := trySIIT64(packet); translated {
		t.Fatal("AH packet translated unexpectedly")
	}
}

func TestSIIT46AHIsRejected(t *testing.T) {
	packet := buildIPv4OpaquePacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{203, 0, 113, 9},
		IPsecAuthenticationHeaderProtocolNumber,
		[]byte{1, 2, 3, 4, 5, 6, 7, 8},
	)

	if translated := trySIIT46(packet); translated {
		t.Fatal("AH packet translated unexpectedly")
	}
}

func TestSIIT64HopByHopExtensionBeforeUDPTranslates(t *testing.T) {
	packet := buildIPv6HopByHopUDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9},
		1234,
		4321,
		[]byte{0xde, 0xad},
	)

	translated := translateSIIT64Packet(t, packet)
	ipv4Packet := header.IPv4(translated)
	if got, want := ipv4Packet.Protocol(), uint8(header.UDPProtocolNumber); got != want {
		t.Fatalf("protocol = %d, want %d", got, want)
	}
	udpPacket := header.UDP(ipv4Packet.Payload())
	if got, want := udpPacket.SourcePort(), uint16(1234); got != want {
		t.Fatalf("UDP source port = %d, want %d", got, want)
	}
	if got, want := udpPacket.DestinationPort(), uint16(4321); got != want {
		t.Fatalf("UDP destination port = %d, want %d", got, want)
	}
	if !isIPv4TransportChecksumValid(ipv4Packet, udpPacket, uint8(header.UDPProtocolNumber)) {
		t.Fatal("UDP checksum is invalid after extension-header translation")
	}
}

func TestSIIT64DestinationOptionsBeforeUDPTranslates(t *testing.T) {
	packet := buildIPv6SingleExtensionUDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9},
		uint8(header.IPv6DestinationOptionsExtHdrIdentifier),
		0,
		4500,
		4500,
		[]byte{0xde, 0xad},
	)

	translated := translateSIIT64Packet(t, packet)
	ipv4Packet := header.IPv4(translated)
	udpPacket := header.UDP(ipv4Packet.Payload())
	if got, want := ipv4Packet.Protocol(), uint8(header.UDPProtocolNumber); got != want {
		t.Fatalf("protocol = %d, want %d", got, want)
	}
	if got, want := udpPacket.SourcePort(), uint16(4500); got != want {
		t.Fatalf("UDP source port = %d, want %d", got, want)
	}
	if got, want := udpPacket.DestinationPort(), uint16(4500); got != want {
		t.Fatalf("UDP destination port = %d, want %d", got, want)
	}
	if !isIPv4TransportChecksumValid(ipv4Packet, udpPacket, uint8(header.UDPProtocolNumber)) {
		t.Fatal("UDP checksum is invalid after destination-options translation")
	}
}

func TestSIIT64RoutingHeaderSegmentsLeftZeroBeforeUDPTranslates(t *testing.T) {
	packet := buildIPv6SingleExtensionUDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9},
		uint8(header.IPv6RoutingExtHdrIdentifier),
		0,
		1234,
		4321,
		[]byte{0xbe, 0xef},
	)

	translated := translateSIIT64Packet(t, packet)
	ipv4Packet := header.IPv4(translated)
	udpPacket := header.UDP(ipv4Packet.Payload())
	if got, want := ipv4Packet.Protocol(), uint8(header.UDPProtocolNumber); got != want {
		t.Fatalf("protocol = %d, want %d", got, want)
	}
	if got, want := udpPacket.SourcePort(), uint16(1234); got != want {
		t.Fatalf("UDP source port = %d, want %d", got, want)
	}
	if got, want := udpPacket.DestinationPort(), uint16(4321); got != want {
		t.Fatalf("UDP destination port = %d, want %d", got, want)
	}
	if !isIPv4TransportChecksumValid(ipv4Packet, udpPacket, uint8(header.UDPProtocolNumber)) {
		t.Fatal("UDP checksum is invalid after routing-header translation")
	}
}

func TestSIIT64FragmentHeaderReservedClearBeforeUDPTranslates(t *testing.T) {
	packet := buildIPv6FragmentUDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9},
		4500,
		4500,
		[]byte{0xaa, 0xbb, 0xcc, 0xdd},
		0,
		0,
	)

	translated := translateSIIT64Packet(t, packet)
	ipv4Packet := header.IPv4(translated)
	udpPacket := header.UDP(ipv4Packet.Payload())
	if got, want := ipv4Packet.Protocol(), uint8(header.UDPProtocolNumber); got != want {
		t.Fatalf("protocol = %d, want %d", got, want)
	}
	if got, want := udpPacket.SourcePort(), uint16(4500); got != want {
		t.Fatalf("UDP source port = %d, want %d", got, want)
	}
	if got, want := udpPacket.DestinationPort(), uint16(4500); got != want {
		t.Fatalf("UDP destination port = %d, want %d", got, want)
	}
	if !isIPv4TransportChecksumValid(ipv4Packet, udpPacket, uint8(header.UDPProtocolNumber)) {
		t.Fatal("UDP checksum is invalid after fragment-header translation")
	}
}

func TestSIIT64FragmentHeaderReservedBitsRejectPacket(t *testing.T) {
	packet := buildIPv6FragmentUDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9},
		4500,
		4500,
		[]byte{0xaa, 0xbb, 0xcc, 0xdd},
		0x01,
		0,
	)

	if translated := trySIIT64(packet); translated {
		t.Fatal("fragment header with reserved bits translated unexpectedly")
	}
}

func TestSIIT64RoutingHeaderSegmentsLeftRejectsPacket(t *testing.T) {
	packet := buildIPv6RoutingHeaderOnlyPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9},
		1,
	)

	if translated := trySIIT64(packet); translated {
		t.Fatal("routing header with non-zero segments-left translated unexpectedly")
	}
}

func buildIPv6DCCPPacket(src, dst [16]byte, hopLimit uint8, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+DCCPMinimumSize+len(payload))
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(DCCPMinimumSize + len(payload)),
		TransportProtocol: tcpip.TransportProtocolNumber(DCCPProtocolNumber),
		HopLimit:          hopLimit,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})

	dccp := ipv6Packet.Payload()
	binary.BigEndian.PutUint16(dccp[0:2], srcPort)
	binary.BigEndian.PutUint16(dccp[2:4], dstPort)
	dccp[4] = (DCCPMinimumSize / 4) << 4
	dccp[5] = 0
	dccp[8] = 0x02
	copy(dccp[DCCPMinimumSize:], payload)
	binary.BigEndian.PutUint16(dccp[DCCPChecksumOffset:], 0)
	binary.BigEndian.PutUint16(dccp[DCCPChecksumOffset:], ^checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ipv6Packet[IPv6SourceAddressOffset:IPv6SourceAddressOffset+IPv6AddressSize*2], 0),
		uint16(len(dccp)),
	), DCCPProtocolNumber), checksum.Checksum(dccp, 0)))
	return packet
}

func buildIPv6TCPPacket(src, dst [16]byte, hopLimit uint8, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+header.TCPMinimumSize+len(payload))
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.TCPMinimumSize + len(payload)),
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          hopLimit,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})

	tcpPacket := header.TCP(ipv6Packet.Payload())
	tcpPacket.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     1,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 4096,
		Checksum:   0,
	})
	copy(tcpPacket.Payload(), payload)
	tcpPacket.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ipv6Packet[IPv6SourceAddressOffset:IPv6SourceAddressOffset+IPv6AddressSize*2], 0),
		uint16(len(tcpPacket)),
	), uint16(header.TCPProtocolNumber)), checksum.Checksum(tcpPacket, 0)))
	return packet
}

func buildIPv4DCCPPacket(src, dst [4]byte, ttl uint8, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+DCCPMinimumSize+len(payload))
	ipv4Packet := header.IPv4(packet)
	ipv4Packet.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(packet)),
		ID:             1,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            ttl,
		Protocol:       DCCPProtocolNumber,
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(src),
		DstAddr:        tcpip.AddrFrom4(dst),
	})
	ipv4Packet.SetChecksum(0)
	ipv4Packet.SetChecksum(^ipv4Packet.CalculateChecksum())

	dccp := ipv4Packet.Payload()
	binary.BigEndian.PutUint16(dccp[0:2], srcPort)
	binary.BigEndian.PutUint16(dccp[2:4], dstPort)
	dccp[4] = (DCCPMinimumSize / 4) << 4
	dccp[5] = 0
	dccp[8] = 0x02
	copy(dccp[DCCPMinimumSize:], payload)
	binary.BigEndian.PutUint16(dccp[DCCPChecksumOffset:], 0)
	binary.BigEndian.PutUint16(dccp[DCCPChecksumOffset:], ^checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ipv4Packet[IPv4SourceAddressOffset:IPv4SourceAddressOffset+IPv4AddressSize*2], 0),
		uint16(len(dccp)),
	), DCCPProtocolNumber), checksum.Checksum(dccp, 0)))
	return packet
}

func buildIPv6OpaquePacket(src, dst [16]byte, nextHeader uint8, payload []byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+len(payload))
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(payload)),
		TransportProtocol: tcpip.TransportProtocolNumber(nextHeader),
		HopLimit:          32,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})
	copy(ipv6Packet.Payload(), payload)
	return packet
}

func buildIPv4OpaquePacket(src, dst [4]byte, protocol uint8, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+len(payload))
	ipv4Packet := header.IPv4(packet)
	ipv4Packet.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(packet)),
		ID:             7,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            32,
		Protocol:       protocol,
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(src),
		DstAddr:        tcpip.AddrFrom4(dst),
	})
	ipv4Packet.SetChecksum(0)
	ipv4Packet.SetChecksum(^ipv4Packet.CalculateChecksum())
	copy(ipv4Packet.Payload(), payload)
	return packet
}

func buildIPv6HopByHopUDPPacket(src, dst [16]byte, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+IPv6ExtensionHeaderMinimumSize+header.UDPMinimumSize+len(payload))
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(IPv6ExtensionHeaderMinimumSize + header.UDPMinimumSize + len(payload)),
		TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6HopByHopOptionsExtHdrIdentifier),
		HopLimit:          8,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})

	ext := packet[header.IPv6FixedHeaderSize : header.IPv6FixedHeaderSize+IPv6ExtensionHeaderMinimumSize]
	ext[IPv6ExtensionHeaderNextHeaderOffset] = uint8(header.UDPProtocolNumber)
	ext[IPv6ExtensionHeaderHeaderExtensionLengthOffset] = 0

	udpPacket := header.UDP(packet[header.IPv6FixedHeaderSize+IPv6ExtensionHeaderMinimumSize:])
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

func buildIPv6SingleExtensionUDPPacket(src, dst [16]byte, extensionHeaderType uint8, extensionHeaderSegmentsLeft byte, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+IPv6ExtensionHeaderMinimumSize+header.UDPMinimumSize+len(payload))
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(IPv6ExtensionHeaderMinimumSize + header.UDPMinimumSize + len(payload)),
		TransportProtocol: tcpip.TransportProtocolNumber(extensionHeaderType),
		HopLimit:          8,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})

	ext := packet[header.IPv6FixedHeaderSize : header.IPv6FixedHeaderSize+IPv6ExtensionHeaderMinimumSize]
	ext[IPv6ExtensionHeaderNextHeaderOffset] = uint8(header.UDPProtocolNumber)
	ext[IPv6ExtensionHeaderHeaderExtensionLengthOffset] = 0
	ext[IPv6RoutingExtensionHeaderSegmentsLeftOffset] = extensionHeaderSegmentsLeft

	udpPacket := header.UDP(packet[header.IPv6FixedHeaderSize+IPv6ExtensionHeaderMinimumSize:])
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

func buildIPv6FragmentUDPPacket(src, dst [16]byte, srcPort, dstPort uint16, payload []byte, reservedByte, reservedFlags byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize+header.UDPMinimumSize+len(payload))
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.IPv6FragmentHeaderSize + header.UDPMinimumSize + len(payload)),
		TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6FragmentExtHdrIdentifier),
		HopLimit:          8,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})

	fragmentHeader := packet[header.IPv6FixedHeaderSize : header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize]
	clear(fragmentHeader)
	fragmentHeader[IPv6ExtensionHeaderNextHeaderOffset] = uint8(header.UDPProtocolNumber)
	fragmentHeader[IPv6FragmentExtensionHeaderReservedOffset] = reservedByte
	fragmentHeader[IPv6FragmentExtensionHeaderFlagOffset] = reservedFlags
	fragmentHeader[7] = 1

	udpPacket := header.UDP(packet[header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize:])
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

func buildIPv6RoutingHeaderOnlyPacket(src, dst [16]byte, segmentsLeft byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+IPv6ExtensionHeaderMinimumSize)
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     IPv6ExtensionHeaderMinimumSize,
		TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6RoutingExtHdrIdentifier),
		HopLimit:          1,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})
	ext := packet[header.IPv6FixedHeaderSize:]
	ext[IPv6ExtensionHeaderNextHeaderOffset] = 59
	ext[IPv6ExtensionHeaderHeaderExtensionLengthOffset] = 0
	ext[IPv6RoutingExtensionHeaderSegmentsLeftOffset] = segmentsLeft
	return packet
}

func trySIIT64(packet []byte) bool {
	reserved := uint(header.IPv6FixedHeaderSize + header.IPv6FragmentHeaderSize)
	buffer := make([]byte, int(reserved)+MessageTransportHeaderSize+len(packet))
	copy(buffer[int(reserved)+MessageTransportHeaderSize:], packet)
	return SIIT64InPlaceTranslate(buffer, &reserved)
}

func trySIIT46(packet []byte) bool {
	reserved := uint8(header.IPv6FixedHeaderSize + header.IPv6FragmentHeaderSize)
	buffer := make([]byte, int(reserved)+MessageTransportHeaderSize+len(packet))
	copy(buffer[int(reserved)+MessageTransportHeaderSize:], packet)
	return SIIT46InPlaceTranslate(buffer, &reserved) == SIIT46Translated
}
