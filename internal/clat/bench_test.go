package clat

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func benchmarkSIIT64InPlaceTranslate(b *testing.B, packet []byte) {
	const reservedHeadroom = header.IPv6FixedHeaderSize + header.IPv6FragmentHeaderSize
	buffer := make([]byte, reservedHeadroom+MessageTransportHeaderSize+len(packet))

	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reserved := uint(reservedHeadroom)
		copy(buffer[int(reserved)+MessageTransportHeaderSize:], packet)
		if !SIIT64InPlaceTranslate(buffer[:int(reserved)+MessageTransportHeaderSize+len(packet)], &reserved) {
			b.Fatal("packet was not translated")
		}
	}
}

func benchmarkSIIT46InPlaceTranslate(b *testing.B, packet []byte) {
	const reservedHeadroom = header.IPv6FixedHeaderSize + header.IPv6FragmentHeaderSize
	buffer := make([]byte, reservedHeadroom+MessageTransportHeaderSize+len(packet))

	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reserved := uint8(reservedHeadroom)
		copy(buffer[int(reserved)+MessageTransportHeaderSize:], packet)
		if SIIT46InPlaceTranslate(buffer[:int(reserved)+MessageTransportHeaderSize+len(packet)], &reserved) != SIIT46Translated {
			b.Fatal("packet was not translated")
		}
	}
}

func BenchmarkSIIT64InPlaceTranslateUDP(b *testing.B) {
	packet := buildIPv6UDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9},
		64,
		4500,
		33434,
		[]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe},
	)
	benchmarkSIIT64InPlaceTranslate(b, packet)
}

func BenchmarkSIIT46InPlaceTranslateUDP(b *testing.B) {
	packet := buildIPv4UDPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{203, 0, 113, 9},
		64,
		4500,
		33434,
		[]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe},
	)
	benchmarkSIIT46InPlaceTranslate(b, packet)
}

func BenchmarkSIIT64InPlaceTranslateTCP(b *testing.B) {
	packet := buildIPv6TCPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9},
		64,
		1111,
		2222,
		[]byte{0xde, 0xad, 0xbe, 0xef},
	)
	benchmarkSIIT64InPlaceTranslate(b, packet)
}

func BenchmarkSIIT46InPlaceTranslateTCP(b *testing.B) {
	packet := buildIPv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{203, 0, 113, 9},
		1,
		[]byte{0xde, 0xad, 0xbe, 0xef},
	)
	benchmarkSIIT46InPlaceTranslate(b, packet)
}

func BenchmarkIsIPv6PacketTranslatableUDP(b *testing.B) {
	packet := buildIPv6UDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9},
		64,
		4500,
		33434,
		[]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe},
	)

	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _, _, _, _ := isIPv6PacketTranslatable(packet); !ok {
			b.Fatal("packet was not considered translatable")
		}
	}
}

func BenchmarkIsIPv4PacketTranslatableUDP(b *testing.B) {
	packet := buildIPv4UDPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{203, 0, 113, 9},
		64,
		4500,
		33434,
		[]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe},
	)

	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !isIPv4PacketTranslatable(packet) {
			b.Fatal("packet was not considered translatable")
		}
	}
}

func BenchmarkNAT44InPlaceTranslateAddressUDP(b *testing.B) {
	packet := buildIPv4UDPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{203, 0, 113, 9},
		64,
		4500,
		33434,
		[]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe},
	)
	buffer := make([]byte, len(packet))
	toIPv4 := [4]byte{203, 0, 113, 7}

	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buffer, packet)
		NAT44InPlaceTranslateAddress(buffer, toIPv4[:], IPv4DestinationAddressOffset)
	}
}

func BenchmarkNAT66InPlaceTranslateAddressUDP(b *testing.B) {
	packet := buildIPv6UDPPacket(
		[16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9},
		64,
		4500,
		33434,
		[]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe},
	)
	buffer := make([]byte, len(packet))
	toIPv6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}

	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buffer, packet)
		NAT66InPlaceTranslateAddress(buffer, toIPv6[:], IPv6SourceAddressOffset)
	}
}
