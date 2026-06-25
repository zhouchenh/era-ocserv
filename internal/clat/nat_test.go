package clat

import (
	"bytes"
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestNAT44TCPRewriteUpdatesChecksumWhenSequenceHighBytesAreZero(t *testing.T) {
	packet := buildIPv4TCPPacket(
		[4]byte{192, 0, 2, 10},
		[4]byte{198, 51, 100, 20},
		0x00001234,
		[]byte{0xde, 0xad, 0xbe, 0xef},
	)

	NAT44InPlaceTranslateAddress(packet, []byte{203, 0, 113, 7}, IPv4DestinationAddressOffset)

	ipv4Packet := header.IPv4(packet)
	if got, want := ipv4Packet.DestinationAddress(), tcpip.AddrFrom4([4]byte{203, 0, 113, 7}); got != want {
		t.Fatalf("destination = %s, want %s", got, want)
	}
	if !ipv4Packet.IsChecksumValid() {
		t.Fatal("IPv4 header checksum is invalid after NAT44 rewrite")
	}
	if !isIPv4TransportChecksumValid(ipv4Packet, ipv4Packet.Payload(), uint8(header.TCPProtocolNumber)) {
		t.Fatal("TCP checksum is invalid after NAT44 rewrite")
	}
}

func TestNAT44NonInitialFragmentPreservesPayload(t *testing.T) {
	packet := buildIPv4FragmentPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{10, 0, 0, 2},
		uint8(header.TCPProtocolNumber),
		header.IPv4FlagMoreFragments,
		8,
		bytes.Repeat([]byte{0xab}, header.TCPMinimumSize),
	)
	originalPayload := append([]byte(nil), packet[header.IPv4MinimumSize:]...)

	NAT44InPlaceTranslateAddress(packet, []byte{10, 0, 0, 99}, IPv4DestinationAddressOffset)

	ipv4Packet := header.IPv4(packet)
	if got, want := ipv4Packet.DestinationAddress(), tcpip.AddrFrom4([4]byte{10, 0, 0, 99}); got != want {
		t.Fatalf("destination = %s, want %s", got, want)
	}
	if !ipv4Packet.IsChecksumValid() {
		t.Fatal("IPv4 header checksum is invalid after NAT44 fragment rewrite")
	}
	if got := packet[header.IPv4MinimumSize:]; !bytes.Equal(got, originalPayload) {
		t.Fatalf("non-initial IPv4 fragment payload changed: got %x want %x", got, originalPayload)
	}
}

func TestNAT66NonInitialFragmentPreservesPayload(t *testing.T) {
	packet := buildIPv6FragmentPayloadPacket(
		[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		uint8(header.TCPProtocolNumber),
		1,
		bytes.Repeat([]byte{0xcd}, header.TCPMinimumSize),
	)
	originalPayload := append([]byte(nil), packet[header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize:]...)

	newSource := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
	NAT66InPlaceTranslateAddress(packet, newSource, IPv6SourceAddressOffset)

	if got := packet[IPv6SourceAddressOffset : IPv6SourceAddressOffset+IPv6AddressSize]; !bytes.Equal(got, newSource) {
		t.Fatalf("source = %x, want %x", got, newSource)
	}
	if got := packet[header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize:]; !bytes.Equal(got, originalPayload) {
		t.Fatalf("non-initial IPv6 fragment payload changed: got %x want %x", got, originalPayload)
	}
}

func TestSIIT46FragmentHeaderClearsReservedByte(t *testing.T) {
	packet := buildIPv4FragmentPacket(
		[4]byte{1, 2, 3, 4},
		[4]byte{5, 6, 7, 8},
		uint8(header.UDPProtocolNumber),
		header.IPv4FlagMoreFragments,
		0,
		bytes.Repeat([]byte{0xef}, 8),
	)

	reserved := uint8(header.IPv6FixedHeaderSize + header.IPv6FragmentHeaderSize)
	buffer := bytes.Repeat([]byte{0xaa}, int(reserved)+MessageTransportHeaderSize+len(packet))
	copy(buffer[int(reserved)+MessageTransportHeaderSize:], packet)

	if SIIT46InPlaceTranslate(buffer, &reserved) != SIIT46Translated {
		t.Fatal("packet was not translated")
	}

	translated := header.IPv6(buffer[int(reserved)+MessageTransportHeaderSize:])
	if got, want := translated.NextHeader(), uint8(header.IPv6FragmentHeader); got != want {
		t.Fatalf("next header = %d, want %d", got, want)
	}
	fragmentHeader := header.IPv6Fragment(translated[header.IPv6FixedHeaderSize : header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize])
	if fragmentHeader[IPv6FragmentExtensionHeaderReservedOffset] != 0 {
		t.Fatalf("fragment reserved byte = 0x%x, want 0", fragmentHeader[IPv6FragmentExtensionHeaderReservedOffset])
	}
	if !fragmentHeader.More() {
		t.Fatal("translated fragment did not keep the more-fragments flag")
	}
}

func buildIPv4TCPPacket(src, dst [4]byte, seq uint32, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(payload))
	ipv4Packet := header.IPv4(packet)
	ipv4Packet.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(packet)),
		ID:             0x1234,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       uint8(header.TCPProtocolNumber),
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(src),
		DstAddr:        tcpip.AddrFrom4(dst),
	})

	tcpPacket := header.TCP(ipv4Packet.Payload())
	tcpPacket.Encode(&header.TCPFields{
		SrcPort:       12345,
		DstPort:       443,
		SeqNum:        seq,
		AckNum:        0,
		DataOffset:    header.TCPMinimumSize,
		Flags:         header.TCPFlagAck,
		WindowSize:    4096,
		Checksum:      0,
		UrgentPointer: 0,
	})
	copy(tcpPacket.Payload(), payload)
	tcpPacket.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ipv4Packet[IPv4SourceAddressOffset:IPv4SourceAddressOffset+IPv4AddressSize*2], 0),
		uint16(len(tcpPacket)),
	), uint16(header.TCPProtocolNumber)), checksum.Checksum(tcpPacket, 0)))

	ipv4Packet.SetChecksum(0)
	ipv4Packet.SetChecksum(^ipv4Packet.CalculateChecksum())
	return packet
}

func buildIPv4FragmentPacket(src, dst [4]byte, protocol uint8, flags uint8, fragmentOffset uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+len(payload))
	ipv4Packet := header.IPv4(packet)
	ipv4Packet.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(packet)),
		ID:             0x0203,
		Flags:          flags,
		FragmentOffset: fragmentOffset,
		TTL:            64,
		Protocol:       protocol,
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(src),
		DstAddr:        tcpip.AddrFrom4(dst),
	})
	copy(ipv4Packet.Payload(), payload)
	ipv4Packet.SetChecksum(0)
	ipv4Packet.SetChecksum(^ipv4Packet.CalculateChecksum())
	return packet
}

func buildIPv6FragmentPayloadPacket(src, dst [16]byte, nextHeader uint8, fragmentOffset uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize+len(payload))
	ipv6Packet := header.IPv6(packet)
	ipv6Packet.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.IPv6FragmentHeaderSize + len(payload)),
		TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6FragmentExtHdrIdentifier),
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})

	fragmentHeader := packet[header.IPv6FixedHeaderSize : header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize]
	clear(fragmentHeader)
	fragmentHeader[IPv6ExtensionHeaderNextHeaderOffset] = nextHeader
	binary.BigEndian.PutUint16(fragmentHeader[2:], fragmentOffset<<3)
	copy(packet[header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize:], payload)
	return packet
}
