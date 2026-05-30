package clatxlat

import (
	"bytes"
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	placeholderV4 = netip.MustParseAddr("192.0.0.1")
	// clatV6 is a /128 inside ERA's pool, standing in for the device's
	// CLAT-source address.
	clatV6 = netip.MustParseAddr("2001:470:f9d1:9001::c1a7")
	// dstV4 is the public IPv4 destination the client targets.
	dstV4 = [4]byte{1, 1, 1, 1}
	// dstV6 is the SIIT form of dstV4: 64:ff9b::1.1.1.1.
	dstV6 = [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1}
)

// TestRoundTripUDP drives a v4 UDP echo out (client->tun) and the synthesized
// reply back (tun->client), asserting the SIIT mapping in both directions and
// that the UDP payload survives.
func TestRoundTripUDP(t *testing.T) {
	tr, ok := New(placeholderV4, clatV6)
	if !ok {
		t.Fatal("New returned ok=false for valid v4/v6 mapping")
	}

	payload := []byte("clat-roundtrip-udp")
	v4 := buildIPv4UDP([4]byte{192, 0, 0, 1}, dstV4, 64, 4500, 33434, payload)

	// --- client -> tun ---------------------------------------------------
	out, ok := tr.ClientToTun(v4)
	if !ok {
		t.Fatal("ClientToTun declined a valid v4 UDP packet")
	}
	v6 := header.IPv6(out)
	if got := header.IPVersion(out); got != header.IPv6Version {
		t.Fatalf("translated version = %d, want IPv6", got)
	}
	if got, want := v6.SourceAddress(), tcpip.AddrFrom16(clatV6.As16()); got != want {
		t.Fatalf("v6 src = %s, want clatV6 %s", got, want)
	}
	if got, want := v6.DestinationAddress(), tcpip.AddrFrom16(dstV6); got != want {
		t.Fatalf("v6 dst = %s, want 64:ff9b::1.1.1.1 %s", got, want)
	}
	if got, want := v6.NextHeader(), uint8(header.UDPProtocolNumber); got != want {
		t.Fatalf("v6 next header = %d, want UDP", got)
	}
	if int(v6.PayloadLength()) != header.UDPMinimumSize+len(payload) {
		t.Fatalf("v6 payload length = %d, want %d", v6.PayloadLength(), header.UDPMinimumSize+len(payload))
	}
	udp := header.UDP(v6.Payload())
	if got, want := udp.SourcePort(), uint16(4500); got != want {
		t.Fatalf("v6 UDP src port = %d, want %d", got, want)
	}
	if got, want := udp.DestinationPort(), uint16(33434); got != want {
		t.Fatalf("v6 UDP dst port = %d, want %d", got, want)
	}
	if !v6TransportChecksumValid(v6, udp, uint8(header.UDPProtocolNumber)) {
		t.Fatal("v6 UDP checksum invalid after client->tun")
	}
	if !bytes.Equal(udp.Payload(), payload) {
		t.Fatalf("v6 UDP payload = %q, want %q", udp.Payload(), payload)
	}

	// --- synthesize the reply: swap src/dst at the v6 layer --------------
	// The far end replies from dstV6 to clatV6. Build the reply directly so
	// the test does not depend on the outbound buffer.
	reply := buildIPv6UDP(dstV6, clatV6.As16(), 64, 33434, 4500, payload)

	// --- tun -> client ---------------------------------------------------
	back, ok := tr.TunToClient(reply)
	if !ok {
		t.Fatal("TunToClient declined a valid v6 UDP reply")
	}
	v4r := header.IPv4(back)
	if got := header.IPVersion(back); got != header.IPv4Version {
		t.Fatalf("back-translated version = %d, want IPv4", got)
	}
	if !v4r.IsChecksumValid() {
		t.Fatal("v4 header checksum invalid after tun->client")
	}
	if got, want := v4r.SourceAddress(), tcpip.AddrFrom4(dstV4); got != want {
		t.Fatalf("v4 src = %s, want realV4 1.1.1.1 %s", got, want)
	}
	if got, want := v4r.DestinationAddress(), tcpip.AddrFrom4([4]byte{192, 0, 0, 1}); got != want {
		t.Fatalf("v4 dst = %s, want placeholder 192.0.0.1 %s", got, want)
	}
	if got, want := v4r.Protocol(), uint8(header.UDPProtocolNumber); got != want {
		t.Fatalf("v4 protocol = %d, want UDP", got)
	}
	udpr := header.UDP(v4r.Payload())
	if got, want := udpr.SourcePort(), uint16(33434); got != want {
		t.Fatalf("v4 UDP src port = %d, want %d", got, want)
	}
	if got, want := udpr.DestinationPort(), uint16(4500); got != want {
		t.Fatalf("v4 UDP dst port = %d, want %d", got, want)
	}
	if !v4TransportChecksumValid(v4r, udpr, uint8(header.UDPProtocolNumber)) {
		t.Fatal("v4 UDP checksum invalid after tun->client")
	}
	if !bytes.Equal(udpr.Payload(), payload) {
		t.Fatalf("v4 UDP payload = %q, want %q", udpr.Payload(), payload)
	}
}

// TestRoundTripICMPEcho drives a v4 ICMP echo request out and the synthesized
// echo reply back, asserting the address mapping and ICMP type translation
// in both directions.
func TestRoundTripICMPEcho(t *testing.T) {
	tr, ok := New(placeholderV4, clatV6)
	if !ok {
		t.Fatal("New returned ok=false")
	}

	v4 := buildIPv4ICMPEcho([4]byte{192, 0, 0, 1}, dstV4, header.ICMPv4Echo, 0x1234, 0x5678)

	out, ok := tr.ClientToTun(v4)
	if !ok {
		t.Fatal("ClientToTun declined a valid v4 ICMP echo")
	}
	v6 := header.IPv6(out)
	if got, want := v6.SourceAddress(), tcpip.AddrFrom16(clatV6.As16()); got != want {
		t.Fatalf("v6 src = %s, want clatV6 %s", got, want)
	}
	if got, want := v6.DestinationAddress(), tcpip.AddrFrom16(dstV6); got != want {
		t.Fatalf("v6 dst = %s, want 64:ff9b::1.1.1.1 %s", got, want)
	}
	if got, want := v6.NextHeader(), uint8(header.ICMPv6ProtocolNumber); got != want {
		t.Fatalf("v6 next header = %d, want ICMPv6", got)
	}
	icmp6 := header.ICMPv6(v6.Payload())
	if got, want := icmp6.Type(), header.ICMPv6EchoRequest; got != want {
		t.Fatalf("v6 ICMP type = %d, want echo request", got)
	}
	if !v6TransportChecksumValid(v6, icmp6, uint8(header.ICMPv6ProtocolNumber)) {
		t.Fatal("v6 ICMPv6 checksum invalid after client->tun")
	}

	// Reply: echo reply from dstV6 to clatV6.
	reply := buildIPv6ICMPEcho(dstV6, clatV6.As16(), header.ICMPv6EchoReply, 0x1234, 0x5678)

	back, ok := tr.TunToClient(reply)
	if !ok {
		t.Fatal("TunToClient declined a valid v6 ICMP echo reply")
	}
	v4r := header.IPv4(back)
	if !v4r.IsChecksumValid() {
		t.Fatal("v4 header checksum invalid after tun->client")
	}
	if got, want := v4r.SourceAddress(), tcpip.AddrFrom4(dstV4); got != want {
		t.Fatalf("v4 src = %s, want 1.1.1.1 %s", got, want)
	}
	if got, want := v4r.DestinationAddress(), tcpip.AddrFrom4([4]byte{192, 0, 0, 1}); got != want {
		t.Fatalf("v4 dst = %s, want 192.0.0.1 %s", got, want)
	}
	icmp4 := header.ICMPv4(v4r.Payload())
	if got, want := icmp4.Type(), header.ICMPv4EchoReply; got != want {
		t.Fatalf("v4 ICMP type = %d, want echo reply", got)
	}
	if checksum.Checksum(icmp4, 0) != 0xffff {
		t.Fatal("v4 ICMPv4 checksum invalid after tun->client")
	}
}

// TestNativeV6PassThrough confirms a native inner IPv6 packet is returned
// unchanged by ClientToTun (the v6-only data path is preserved).
func TestNativeV6PassThrough(t *testing.T) {
	tr, ok := New(placeholderV4, clatV6)
	if !ok {
		t.Fatal("New returned ok=false")
	}
	native := buildIPv6UDP(clatV6.As16(), [16]byte{0x20, 0x01, 0x4, 0x70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 64, 5000, 6000, []byte("native-v6"))
	out, ok := tr.ClientToTun(native)
	if !ok {
		t.Fatal("ClientToTun declined a native v6 packet")
	}
	if !bytes.Equal(out, native) {
		t.Fatal("native v6 packet was modified on pass-through")
	}
}

// TestNewRejectsWrongFamily confirms New fails closed on swapped families.
func TestNewRejectsWrongFamily(t *testing.T) {
	if _, ok := New(clatV6, placeholderV4); ok {
		t.Fatal("New accepted v6 placeholder + v4 clat")
	}
	if _, ok := New(placeholderV4, placeholderV4); ok {
		t.Fatal("New accepted a v4 clat address")
	}
}

// --- packet builders (mirrored from the vendored clat test helpers) ---------

func buildIPv4UDP(src, dst [4]byte, ttl uint8, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		ID:          0x1234,
		TTL:         ttl,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src),
		DstAddr:     tcpip.AddrFrom4(dst),
	})
	udp := header.UDP(ip.Payload())
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(udp.Payload(), payload)
	udp.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ip[12:20], 0),
		uint16(len(udp)),
	), uint16(header.UDPProtocolNumber)), checksum.Checksum(udp, 0)))
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	return packet
}

func buildIPv4ICMPEcho(src, dst [4]byte, typ header.ICMPv4Type, ident, seq uint16) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		ID:          0x5678,
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src),
		DstAddr:     tcpip.AddrFrom4(dst),
	})
	icmp := header.ICMPv4(ip.Payload())
	icmp.SetType(typ)
	icmp.SetCode(header.ICMPv4UnusedCode)
	icmp.SetIdent(ident)
	icmp.SetSequence(seq)
	icmp.SetChecksum(0)
	icmp.SetChecksum(^checksum.Checksum(icmp, 0))
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	return packet
}

func buildIPv6UDP(src, dst [16]byte, hop uint8, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv6(packet)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.UDPMinimumSize + len(payload)),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          hop,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})
	udp := header.UDP(ip.Payload())
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(udp.Payload(), payload)
	udp.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ip[8:40], 0),
		uint16(len(udp)),
	), uint16(header.UDPProtocolNumber)), checksum.Checksum(udp, 0)))
	return packet
}

func buildIPv6ICMPEcho(src, dst [16]byte, typ header.ICMPv6Type, ident, seq uint16) []byte {
	packet := make([]byte, header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize)
	ip := header.IPv6(packet)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     header.ICMPv6MinimumSize,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16(src),
		DstAddr:           tcpip.AddrFrom16(dst),
	})
	icmp := header.ICMPv6(ip.Payload())
	icmp.SetType(typ)
	icmp.SetCode(header.ICMPv6UnusedCode)
	icmp.SetIdent(ident)
	icmp.SetSequence(seq)
	icmp.SetChecksum(0)
	icmp.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ip[8:40], 0),
		uint16(len(icmp)),
	), uint16(header.ICMPv6ProtocolNumber)), checksum.Checksum(icmp, 0)))
	return packet
}

func v6TransportChecksumValid(ip header.IPv6, transport []byte, protocol uint8) bool {
	return checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ip[8:40], 0),
		uint16(len(transport)),
	), uint16(protocol)), checksum.Checksum(transport, 0)) == 0xffff
}

func v4TransportChecksumValid(ip header.IPv4, transport []byte, protocol uint8) bool {
	return checksum.Combine(checksum.Combine(checksum.Combine(
		checksum.Checksum(ip[12:20], 0),
		uint16(len(transport)),
	), uint16(protocol)), checksum.Checksum(transport, 0)) == 0xffff
}
