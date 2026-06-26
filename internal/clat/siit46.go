// Vendored from wireguard-go-clat@3dfa6e7 (golang.zx2c4.com/wireguard/clat). Do not edit; update by re-vendoring.
package clat

import (
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	// SIIT46 always adds the fixed /96 prefix to both translated IPv6
	// addresses. SIIT64 always strips that fixed prefix from the translated
	// IPv6 source while the destination prefix stays packet-specific.
	siitPrefixChecksum           = checksum.Checksum(SIITPrefix[:SIITPrefixSize], 0)
	siit46TransportChecksumDelta = checksum.Combine(siitPrefixChecksum, siitPrefixChecksum)
	siit64SourceChecksumDelta    = ^siitPrefixChecksum
)

// SIIT46Result reports whether the IPv4-to-IPv6 translator rewrote the packet,
// left it untouched, or rejected a specific packet shape that must fail closed.
type SIIT46Result uint8

const (
	SIIT46Untranslated SIIT46Result = iota
	SIIT46Translated
	SIIT46Dropped
)

type siit46IPv4Metadata struct {
	headerLength   uint8
	totalLength    uint16
	payloadLength  uint16
	protocol       uint8
	flags          uint8
	fragmentOffset uint16
	isFragmented   bool
}

func SIIT46InPlaceTranslate(buffer []byte, reservedSpaceSize *uint8 /*, verbosef func(format string, args ...any), errorf func(format string, args ...any)*/) SIIT46Result {
	//verbosef("SIIT46InPlaceTranslate: original packet buffer:\n%s", hex.Dump(buffer))
	if reservedSpaceSize == nil {
		return SIIT46Dropped
	}
	packetStart := int(*reservedSpaceSize) + MessageTransportHeaderSize
	if int(*reservedSpaceSize) > len(buffer) || packetStart > len(buffer) {
		return SIIT46Dropped
	}
	ipv4Meta, isTranslatable := parseSIIT46IPv4Packet(buffer[packetStart:])
	if !isTranslatable {
		return SIIT46Untranslated
	}
	ipv4Header, ipv6Packet := makeRoomForIPv6Header(buffer, reservedSpaceSize, ipv4Meta)
	if ipv4Header == nil || ipv6Packet == nil {
		return SIIT46Dropped
	}
	//verbosef("SIIT46InPlaceTranslate: length of ipv4Header: %d", len(ipv4Header))
	//verbosef("SIIT46InPlaceTranslate: length of ipv6Packet: %d", len(ipv6Packet))
	//verbosef("SIIT46InPlaceTranslate: isFragmented: %v", ipv4Meta.isFragmented)
	fragmentOffset, transportProtocol := siit46TranslateHeader(ipv4Header, ipv6Packet, ipv4Meta)
	if transportProtocol == uint8(header.ICMPv6ProtocolNumber) {
		ipv6Packet = siit46TranslateICMPTransport(buffer, reservedSpaceSize, ipv6Packet)
	}
	if !siit46UpdateTransportChecksum(ipv6Packet, ipv4Meta, fragmentOffset, transportProtocol) {
		return SIIT46Dropped
	}
	//verbosef("SIIT46InPlaceTranslate: actual length of translated IPv6 packet: %d", header.IPv6FixedHeaderSize+ipv6Packet.PayloadLength())
	//verbosef("SIIT46InPlaceTranslate: translated packet buffer:\n%s", hex.Dump(buffer))
	return SIIT46Translated
}

func siit46TranslateHeader(ipv4Header header.IPv4, ipv6Packet header.IPv6, ipv4Meta siit46IPv4Metadata) (fragmentOffset uint16, transportProtocol uint8) {
	ipv6Packet.SetTOS(ipv4Header.TOS()) // Set IP version to IPv6, translate DSCP and ECN to Traffic Class, and set Flow Label to 0
	ipv6Packet.SetHopLimit(ipv4Header.TTL())
	transportProtocol = ipv4Meta.protocol
	if transportProtocol == uint8(header.ICMPv4ProtocolNumber) {
		transportProtocol = uint8(header.ICMPv6ProtocolNumber)
	}
	if ipv4Meta.isFragmented {
		fragmentOffset = ipv4Meta.fragmentOffset
		ipv6FragmentHeader := header.IPv6Fragment(ipv6Packet[header.IPv6FixedHeaderSize : header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize])
		// This translator reuses in-place buffer space reclaimed from the IPv4
		// header. RFC 8200 requires the IPv6 fragment reserved byte to be zero, so
		// clear the header before populating the translated fields instead of
		// leaking stale bytes from the moved packet.
		clear(ipv6FragmentHeader)
		binary.BigEndian.PutUint32(ipv6FragmentHeader[4:], uint32(ipv4Header.ID()))
		binary.BigEndian.PutUint16(ipv6FragmentHeader[2:], fragmentOffset)
		ipv6FragmentHeader[IPv6ExtensionHeaderNextHeaderOffset] = transportProtocol
		if ipv4Meta.flags&header.IPv4FlagMoreFragments != 0 {
			ipv6FragmentHeader[IPv6FragmentExtensionHeaderFlagOffset] |= 0b1
		}
		ipv6Packet.SetNextHeader(header.IPv6FragmentHeader)
		ipv6Packet.SetPayloadLength(ipv4Meta.payloadLength + header.IPv6FragmentHeaderSize)
	} else {
		ipv6Packet.SetNextHeader(transportProtocol)
		ipv6Packet.SetPayloadLength(ipv4Meta.payloadLength)
	}
	copy(ipv6Packet[IPv6SourceAddressOffset:], SIITPrefix[:SIITPrefixSize])
	copy(ipv6Packet[IPv6SourceAddressOffset+SIITPrefixSize:], ipv4Header[IPv4SourceAddressOffset:IPv4SourceAddressOffset+IPv4AddressSize])
	copy(ipv6Packet[IPv6DestinationAddressOffset:], SIITPrefix[:SIITPrefixSize])
	copy(ipv6Packet[IPv6DestinationAddressOffset+SIITPrefixSize:], ipv4Header[IPv4DestinationAddressOffset:IPv4DestinationAddressOffset+IPv4AddressSize])
	return
}

func siit46TranslateICMPTransport(buffer []byte, reservedSpaceSize *uint8, ipv6Packet header.IPv6) header.IPv6 {
	icmpv6Packet := header.ICMPv6(ipv6Packet[header.IPv6FixedHeaderSize:])
	icmpv4Packet := header.ICMPv4(icmpv6Packet)
	translateQuote := false
	switch icmpv4Packet.Type() {
	case header.ICMPv4Echo:
		icmpv6Packet.SetType(header.ICMPv6EchoRequest)
	case header.ICMPv4EchoReply:
		icmpv6Packet.SetType(header.ICMPv6EchoReply)
	case header.ICMPv4DstUnreachable:
		translateQuote = true
		switch icmpv4Packet.Code() {
		case header.ICMPv4NetUnreachable, header.ICMPv4HostUnreachable, header.ICMPv4SourceRouteFailed, header.ICMPv4DestinationNetworkUnknown, header.ICMPv4DestinationHostUnknown, header.ICMPv4SourceHostIsolated, header.ICMPv4NetUnreachableForTos, header.ICMPv4HostUnreachableForTos:
			icmpv6Packet.SetType(header.ICMPv6DstUnreachable)
			icmpv6Packet.SetCode(header.ICMPv6NetworkUnreachable)
		case header.ICMPv4NetProhibited, header.ICMPv4HostProhibited, header.ICMPv4AdminProhibited, header.ICMPv4PrecedenceCutInEffect:
			icmpv6Packet.SetType(header.ICMPv6DstUnreachable)
			icmpv6Packet.SetCode(header.ICMPv6Prohibited)
		case header.ICMPv4ProtoUnreachable:
			icmpv6Packet.SetType(header.ICMPv6ParamProblem)
			icmpv6Packet.SetCode(header.ICMPv6UnknownHeader)
			binary.BigEndian.PutUint32(icmpv6Packet[4:], header.IPv6NextHeaderOffset)
		case header.ICMPv4PortUnreachable:
			icmpv6Packet.SetType(header.ICMPv6DstUnreachable)
			icmpv6Packet.SetCode(header.ICMPv6PortUnreachable)
		case header.ICMPv4FragmentationNeeded:
			icmpv6Packet.SetType(header.ICMPv6PacketTooBig)
			icmpv6Packet.SetCode(header.ICMPv6UnusedCode)
			icmpv4MTU := icmpv4Packet.MTU()
			if icmpv4MTU < header.IPv4MinimumMTU {
				fragmentationNeededIPHeader := header.IPv4(icmpv4Packet.Payload())
				if len(fragmentationNeededIPHeader) < header.IPv4MinimumSize {
					icmpv4MTU = header.IPv4MinimumMTU
				} else {
					fragmentationNeededPacketLength := fragmentationNeededIPHeader.TotalLength()
					for _, PlateauMTU := range PlateauMTUs {
						if PlateauMTU < header.IPv4MinimumMTU {
							break
						}
						if PlateauMTU < fragmentationNeededPacketLength {
							icmpv4MTU = PlateauMTU
							break
						}
					}
					if icmpv4MTU < header.IPv4MinimumMTU {
						icmpv4MTU = header.IPv4MinimumMTU
					}
				}
			}
			icmpv6Packet.SetMTU(max(header.IPv6MinimumMTU, min(uint32(icmpv4MTU)+20, uint32(IPv6OutboundMTU), uint32(IPv4OutboundMTU)+20)))
		default:
		}
	case header.ICMPv4TimeExceeded:
		translateQuote = true
		icmpv6Packet.SetType(header.ICMPv6TimeExceeded)
	case header.ICMPv4ParamProblem:
		translateQuote = true
		icmpv6Packet.SetType(header.ICMPv6ParamProblem)
		icmpv6Packet.SetCode(header.ICMPv6ErroneousHeader)
		switch icmpv4Packet[4 /* Pointer Offset */] {
		case 0 /* Version/IHL */ :
			icmpv6Packet[4 /* Pointer Offset */ +3 /* Zeroed Bytes of the 4-byte Pointer */] = 0 /* Version/Traffic Class */
		case 1 /* Type Of Service */ :
			icmpv6Packet[4 /* Pointer Offset */ +3 /* Zeroed Bytes of the 4-byte Pointer */] = 1 /* Traffic Class/Flow Label */
		case 2, 3 /* Total Length */ :
			icmpv6Packet[4 /* Pointer Offset */ +3 /* Zeroed Bytes of the 4-byte Pointer */] = 4 /* Payload Length */
		case 8 /* Time to Live */ :
			icmpv6Packet[4 /* Pointer Offset */ +3 /* Zeroed Bytes of the 4-byte Pointer */] = 7 /* Hop Limit */
		case 9 /* Protocol */ :
			icmpv6Packet[4 /* Pointer Offset */ +3 /* Zeroed Bytes of the 4-byte Pointer */] = 6 /* Next Header */
		case 12, 13, 14, 15 /* Source Address */ :
			icmpv6Packet[4 /* Pointer Offset */ +3 /* Zeroed Bytes of the 4-byte Pointer */] = 8 /* Source Address */
		case 16, 17, 18, 19 /* Destination Address */ :
			icmpv6Packet[4 /* Pointer Offset */ +3 /* Zeroed Bytes of the 4-byte Pointer */] = 24 /* Destination Address */
		default:
		}
		icmpv4Packet[4 /* Pointer Offset */] = 0
	default:
	}
	if translateQuote {
		// RFC 7915 requires the quoted packet inside an ICMP error to be
		// translated as well. This implementation only expands classic fixed-
		// header IPv4 quotes in place. Unsupported quoted shapes fail closed by
		// keeping the original IPv4 quote rather than emitting a mixed-family
		// partially translated payload.
		if translatedPacket := siit46TranslateICMPErrorQuote(buffer, reservedSpaceSize, ipv6Packet, icmpv6Packet); translatedPacket != nil {
			return translatedPacket
		}
	}
	return ipv6Packet
}

func siit46TranslateICMPErrorQuote(buffer []byte, reservedSpaceSize *uint8, ipv6Packet header.IPv6, icmpv6Packet header.ICMPv6) header.IPv6 {
	const quoteExpansion = header.IPv6FixedHeaderSize - header.IPv4MinimumSize

	quote := icmpv6Packet.Payload()
	if len(quote) < header.IPv4MinimumSize {
		return nil
	}

	quotedIPv4 := header.IPv4(quote)
	if header.IPVersion(quotedIPv4) != header.IPv4Version {
		return nil
	}
	if quotedIPv4.HeaderLength() != header.IPv4MinimumSize {
		return nil
	}
	if quotedIPv4.Flags()&header.IPv4FlagMoreFragments != 0 || quotedIPv4.FragmentOffset() != 0 {
		return nil
	}

	quotedProtocol := quotedIPv4.Protocol()
	quotedTOS, quotedFlowLabel := quotedIPv4.TOS()
	quotedTTL := quotedIPv4.TTL()
	quotedPayloadLength := quotedIPv4.PayloadLength()
	var quotedSourceAddress [IPv4AddressSize]byte
	var quotedDestinationAddress [IPv4AddressSize]byte
	copy(quotedSourceAddress[:], quotedIPv4[IPv4SourceAddressOffset:IPv4SourceAddressOffset+IPv4AddressSize])
	copy(quotedDestinationAddress[:], quotedIPv4[IPv4DestinationAddressOffset:IPv4DestinationAddressOffset+IPv4AddressSize])
	switch quotedProtocol {
	case uint8(header.TCPProtocolNumber), uint8(header.UDPProtocolNumber):
		if len(quote) < header.IPv4MinimumSize+8 {
			return nil
		}
	case uint8(header.ICMPv4ProtocolNumber):
		if len(quote) < header.IPv4MinimumSize+header.ICMPv4MinimumSize {
			return nil
		}
		quotedICMPv4 := header.ICMPv4(quote[header.IPv4MinimumSize:])
		switch quotedICMPv4.Type() {
		case header.ICMPv4Echo, header.ICMPv4EchoReply:
		default:
			// RFC 7915 translation stops at the first embedded header. Nested
			// ICMP errors would carry another embedded packet, so keep the outer
			// error translated but leave the quote untouched instead.
			return nil
		}
	default:
		return nil
	}

	if *reservedSpaceSize < quoteExpansion {
		return nil
	}

	oldPacketStart := int(*reservedSpaceSize) + MessageTransportHeaderSize
	oldPacketLength := header.IPv6FixedHeaderSize + int(ipv6Packet.PayloadLength())
	newPacketStart := oldPacketStart - quoteExpansion
	copy(buffer[newPacketStart:newPacketStart+oldPacketLength], buffer[oldPacketStart:oldPacketStart+oldPacketLength])

	*reservedSpaceSize -= quoteExpansion
	newPacketLength := oldPacketLength + quoteExpansion
	ipv6Packet = header.IPv6(buffer[newPacketStart : newPacketStart+newPacketLength])
	icmpv6Packet = header.ICMPv6(ipv6Packet[header.IPv6FixedHeaderSize : header.IPv6FixedHeaderSize+int(ipv6Packet.PayloadLength())+quoteExpansion])
	quote = icmpv6Packet.Payload()

	oldQuoteLength := len(quote) - quoteExpansion
	copy(quote[header.IPv6FixedHeaderSize:header.IPv6FixedHeaderSize+oldQuoteLength-header.IPv4MinimumSize], quote[header.IPv4MinimumSize:oldQuoteLength])
	clear(quote[:header.IPv6FixedHeaderSize])

	quotedIPv6 := header.IPv6(quote)
	quotedIPv6.SetTOS(quotedTOS, quotedFlowLabel)
	quotedIPv6.SetHopLimit(quotedTTL)
	quotedIPv6.SetPayloadLength(quotedPayloadLength)
	if quotedProtocol == uint8(header.ICMPv4ProtocolNumber) {
		quotedIPv6.SetNextHeader(uint8(header.ICMPv6ProtocolNumber))
	} else {
		quotedIPv6.SetNextHeader(quotedProtocol)
	}
	copy(quotedIPv6[IPv6SourceAddressOffset:], SIITPrefix[:SIITPrefixSize])
	copy(quotedIPv6[IPv6SourceAddressOffset+SIITPrefixSize:], quotedSourceAddress[:])
	copy(quotedIPv6[IPv6DestinationAddressOffset:], SIITPrefix[:SIITPrefixSize])
	copy(quotedIPv6[IPv6DestinationAddressOffset+SIITPrefixSize:], quotedDestinationAddress[:])

	if quotedProtocol == uint8(header.ICMPv4ProtocolNumber) {
		quotedICMPv6 := header.ICMPv6(quote[header.IPv6FixedHeaderSize:])
		quotedICMPv4 := header.ICMPv4(quote[header.IPv6FixedHeaderSize:])
		switch quotedICMPv4.Type() {
		case header.ICMPv4Echo:
			quotedICMPv6.SetType(header.ICMPv6EchoRequest)
		case header.ICMPv4EchoReply:
			quotedICMPv6.SetType(header.ICMPv6EchoReply)
		default:
			return nil
		}
		quotedICMPv6.SetChecksum(0)
		quotedICMPv6.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
			checksum.Checksum(quotedIPv6[IPv6SourceAddressOffset:IPv6SourceAddressOffset+IPv6AddressSize*2], 0),
			uint16(len(quotedICMPv6)),
		), uint16(header.ICMPv6ProtocolNumber)), checksum.Checksum(quotedICMPv6, 0)))
	}

	ipv6Packet.SetPayloadLength(ipv6Packet.PayloadLength() + quoteExpansion)
	return ipv6Packet
}

func siit46UpdateTransportChecksum(ipv6Packet header.IPv6, ipv4Meta siit46IPv4Metadata, fragmentOffset uint16, transportProtocol uint8) bool {
	if fragmentOffset != 0 {
		return true
	}
	transportStart := header.IPv6FixedHeaderSize
	if ipv4Meta.isFragmented {
		transportStart += header.IPv6FragmentHeaderSize
	}
	transportEnd := transportStart + int(ipv4Meta.payloadLength)
	if transportProtocol == uint8(header.ICMPv6ProtocolNumber) {
		transportEnd = header.IPv6FixedHeaderSize + int(ipv6Packet.PayloadLength())
	}
	transport := ipv6Packet[transportStart:transportEnd]
	switch transportProtocol {
	case uint8(header.TCPProtocolNumber):
		if len(transport) < header.TCPMinimumSize {
			return true
		}
		siit46PartialUpdateTransportChecksum(transport, header.TCPChecksumOffset)
	case DCCPProtocolNumber:
		if len(transport) < DCCPMinimumSize {
			return true
		}
		// DCCP also carries a pseudo-header checksum, so SIIT has to repair it
		// just like TCP/UDP when the translated addresses change family.
		siit46PartialUpdateTransportChecksum(transport, DCCPChecksumOffset)
	case uint8(header.UDPProtocolNumber):
		if len(transport) < header.UDPMinimumSize {
			return true
		}
		if transport[6+1]|transport[6] != 0 {
			siit46PartialUpdateTransportChecksum(transport, 6)
		} else {
			// RFC 7915's stateless UDP rule only lets SIIT46 synthesize an IPv6 UDP
			// checksum when the whole IPv4 UDP payload is present. For a fragmented
			// first fragment with checksum zero, this translator only has the UDP
			// header and an incomplete payload, so it must fail closed instead of
			// emitting an invalid IPv6 UDP packet or assuming a tunnel-specific zero-
			// checksum mode from RFC 6935/6936.
			if ipv4Meta.isFragmented {
				return false
			}
			udpPacket := header.UDP(transport)
			udpPacket.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
				checksum.Checksum(ipv6Packet[IPv6SourceAddressOffset:IPv6SourceAddressOffset+IPv6AddressSize*2], 0),
				uint16(len(transport)),
			), uint16(header.UDPProtocolNumber)), checksum.Checksum(udpPacket, 0)))
		}
	case uint8(header.ICMPv6ProtocolNumber):
		if len(transport) < header.ICMPv6MinimumSize {
			return true
		}
		icmpv6Packet := header.ICMPv6(transport)
		icmpv6Packet.SetChecksum(0)
		icmpv6Packet.SetChecksum(^checksum.Combine(checksum.Combine(checksum.Combine(
			checksum.Checksum(ipv6Packet[IPv6SourceAddressOffset:IPv6SourceAddressOffset+IPv6AddressSize*2], 0),
			uint16(len(transport)),
		), uint16(header.ICMPv6ProtocolNumber)), checksum.Checksum(icmpv6Packet, 0)))
	default:
	}
	return true
}

func siit46PartialUpdateTransportChecksum(transport []byte, checksumOffset int) {
	//currentChecksum := binary.BigEndian.Uint16(transport[checksumOffset:])
	//binary.BigEndian.PutUint16(transport[checksumOffset:], ^checksum.Combine(
	//	^currentChecksum,
	//	checksum.Combine(
	//		checksum.Combine(
	//			checksum.Checksum(ipv6Packet[IPv6SourceAddressOffset:IPv6SourceAddressOffset+header.IPv6AddressSize*2], 0),
	//			^checksum.Checksum(ipv6Packet[IPv6SourceAddressOffset+SIITPrefixSize:IPv6SourceAddressOffset+SIITPrefixSize+header.IPv4AddressSize], 0),
	//		),
	//		^checksum.Checksum(ipv6Packet[IPv6DestinationAddressOffset+SIITPrefixSize:IPv6DestinationAddressOffset+SIITPrefixSize+header.IPv4AddressSize], 0),
	//	),
	//))
	binary.BigEndian.PutUint16(transport[checksumOffset:], ^checksum.Combine(
		^binary.BigEndian.Uint16(transport[checksumOffset:]), siit46TransportChecksumDelta,
	))
}

func makeRoomForIPv6Header(buffer []byte, reservedSpaceSize *uint8, ipv4Meta siit46IPv4Metadata) (ipv4Header header.IPv4, ipv6Packet header.IPv6) {
	if reservedSpaceSize == nil {
		return
	}
	bufferLength := uint(len(buffer))
	sourceOffset := uint(*reservedSpaceSize)
	if sourceOffset > bufferLength || bufferLength-sourceOffset < MessageTransportHeaderSize+uint(ipv4Meta.headerLength) {
		return
	}
	source := buffer[sourceOffset:]
	headerRoom := uint(header.IPv6FixedHeaderSize)
	if ipv4Meta.isFragmented {
		headerRoom += header.IPv6FragmentHeaderSize
	}
	// Inconsistent reserved headroom is an internal bookkeeping failure, not a
	// packet-shape decision. Fail closed instead of underflowing and panicking.
	if sourceOffset < headerRoom || sourceOffset-headerRoom+MessageTransportHeaderSize+uint(ipv4Meta.headerLength) > bufferLength || sourceOffset-headerRoom+uint(ipv4Meta.headerLength) > uint(^uint8(0)) {
		return
	}
	newReservedSpaceSize := sourceOffset - headerRoom
	destination := buffer[newReservedSpaceSize : newReservedSpaceSize+MessageTransportHeaderSize+uint(ipv4Meta.headerLength)]
	ipv4Header = destination[MessageTransportHeaderSize:]
	*reservedSpaceSize = uint8(newReservedSpaceSize + uint(ipv4Meta.headerLength))
	packetStart := int(*reservedSpaceSize) + MessageTransportHeaderSize
	if packetStart > len(buffer) {
		ipv4Header = nil
		*reservedSpaceSize = uint8(sourceOffset)
		return
	}
	ipv6Packet = buffer[packetStart:]
	copy(destination, source)
	return
}

func isIPv4PacketTranslatable(ipv4Packet header.IPv4) bool {
	_, ok := parseSIIT46IPv4Packet(ipv4Packet)
	return ok
}

func parseSIIT46IPv4Packet(ipv4Packet header.IPv4) (meta siit46IPv4Metadata, ok bool) {
	if header.IPVersion(ipv4Packet) != header.IPv4Version {
		return meta, false
	}
	if len(ipv4Packet) < header.IPv4MinimumSize {
		return meta, false
	}
	meta.headerLength = ipv4Packet.HeaderLength()
	if meta.headerLength < header.IPv4MinimumSize || int(meta.headerLength) > len(ipv4Packet) {
		return meta, false
	}
	meta.totalLength = ipv4Packet.TotalLength()
	if int(meta.headerLength) > int(meta.totalLength) || int(meta.totalLength) > len(ipv4Packet) {
		return meta, false
	}
	meta.protocol = ipv4Packet.Protocol()
	if isTransportProtocolForbiddenForIPv4(meta.protocol) {
		return meta, false
	}
	meta.flags = ipv4Packet.Flags()
	if meta.flags&IPv4FlagReserved != 0 {
		return meta, false
	}
	meta.fragmentOffset = ipv4Packet.FragmentOffset()
	meta.payloadLength = meta.totalLength - uint16(meta.headerLength)
	if meta.flags&header.IPv4FlagMoreFragments != 0 && meta.payloadLength%8 != 0 {
		return meta, false
	}
	meta.isFragmented = meta.flags&header.IPv4FlagMoreFragments != 0 || meta.fragmentOffset != 0
	if checksum.Checksum(ipv4Packet[:meta.headerLength], 0) != 0xffff {
		return meta, false
	}
	if meta.headerLength == header.IPv4MinimumSize && meta.protocol != uint8(header.ICMPv4ProtocolNumber) {
		// Fixed 20-byte UDP/TCP packets are the common CLAT fast path. Keep them
		// on the straight-line validator and pay option or ICMP-specific checks
		// only for the rarer slow paths.
		return meta, true
	}
	if meta.headerLength != header.IPv4MinimumSize && containsAnyForbiddenIPv4Options(ipv4Packet.Options()) {
		return meta, false
	}
	if meta.protocol != uint8(header.ICMPv4ProtocolNumber) {
		return meta, true
	}
	return meta, !meta.isFragmented &&
		isICMPv4PacketTranslatable(header.ICMPv4(ipv4Packet[int(meta.headerLength):int(meta.totalLength)]))
}

func isICMPv4PacketTranslatable(icmpv4Packet header.ICMPv4) bool {
	return len(icmpv4Packet) >= header.ICMPv4MinimumSize &&
		checksum.Checksum(icmpv4Packet, 0) == 0xffff &&
		isICMPv4PacketHeaderTranslatable(icmpv4Packet.Type(), icmpv4Packet.Code(), icmpv4Packet[4:])
}

func isICMPv4PacketHeaderTranslatable(icmpv4Type header.ICMPv4Type, icmpv4Code header.ICMPv4Code, restOfHeader []byte) bool {
	switch icmpv4Type {
	case header.ICMPv4Echo, header.ICMPv4EchoReply:
		return icmpv4Code == header.ICMPv4UnusedCode
	case header.ICMPv4DstUnreachable:
		return icmpv4Code == header.ICMPv4FragmentationNeeded && restOfHeader[0]|restOfHeader[1] == 0 ||
			(icmpv4Code == header.ICMPv4NetUnreachable ||
				icmpv4Code == header.ICMPv4HostUnreachable ||
				icmpv4Code == header.ICMPv4SourceRouteFailed ||
				icmpv4Code == header.ICMPv4DestinationNetworkUnknown ||
				icmpv4Code == header.ICMPv4DestinationHostUnknown ||
				icmpv4Code == header.ICMPv4SourceHostIsolated ||
				icmpv4Code == header.ICMPv4NetUnreachableForTos ||
				icmpv4Code == header.ICMPv4HostUnreachableForTos ||
				icmpv4Code == header.ICMPv4NetProhibited ||
				icmpv4Code == header.ICMPv4HostProhibited ||
				icmpv4Code == header.ICMPv4AdminProhibited ||
				icmpv4Code == header.ICMPv4PrecedenceCutInEffect ||
				icmpv4Code == header.ICMPv4ProtoUnreachable ||
				icmpv4Code == header.ICMPv4PortUnreachable) &&
				restOfHeader[0]|restOfHeader[1]|restOfHeader[2]|restOfHeader[3] == 0
	case header.ICMPv4TimeExceeded:
		return (icmpv4Code == header.ICMPv4TTLExceeded ||
			icmpv4Code == header.ICMPv4ReassemblyTimeout) &&
			restOfHeader[0]|restOfHeader[1]|restOfHeader[2]|restOfHeader[3] == 0
	case header.ICMPv4ParamProblem:
		return (icmpv4Code == 0 /* Pointer Indicates The Error */ ||
			icmpv4Code == 2 /* Bad Length */) &&
			restOfHeader[1]|restOfHeader[2]|restOfHeader[3] == 0 &&
			(restOfHeader[0 /* Pointer Offset */] <= 3 ||
				restOfHeader[0 /* Pointer Offset */] >= 8 && restOfHeader[0 /* Pointer Offset */] <= 9 ||
				restOfHeader[0 /* Pointer Offset */] >= 12 && restOfHeader[0 /* Pointer Offset */] <= 15 ||
				restOfHeader[0 /* Pointer Offset */] >= 16 && restOfHeader[0 /* Pointer Offset */] <= 19)
		//switch icmpv4Packet.Pointer() {
		//case 0 /* Version/IHL */ :
		//	return true
		//case 1 /* Type Of Service */ :
		//	return true
		//case 2, 3 /* Total Length */ :
		//	return true
		//case 8 /* Time to Live */ :
		//	return true
		//case 9 /* Protocol */ :
		//	return true
		//case 12, 13, 14, 15 /* Source Address */ :
		//	return true
		//case 16, 17, 18, 19 /* Destination Address */ :
		//	return true
		//default:
		//	return false
		//}
	default:
		return false
	}
}

func containsAnyForbiddenIPv4Options(options header.IPv4Options) bool {
	//
	// From RFC 7915, section 4.1:
	//  If any IPv4 options are present in the IPv4 packet, they MUST be
	//  ignored and the packet translated normally; there is no attempt to
	//  translate the options.  However, if an unexpired source route option
	//  is present, then the packet MUST instead be discarded, and an ICMPv4
	//  "Destination Unreachable, Source Route Failed" (Type 3, Code 5) error
	//  message SHOULD be returned to the sender.
	//
	optionIterator := options.MakeIterator()
	for {
		option, noMore, problem := optionIterator.Next()
		if problem != nil {
			return true
		}
		if noMore {
			break
		}
		switch option.Type() {
		case IPv4OptionLooseSourceRouteType, IPv4OptionStrictSourceRouteType:
			return true
		default:
		}
	}
	return false
}

func isTransportProtocolForbiddenForIPv4(protocol uint8) bool {
	return protocol == uint8(header.IPv6HopByHopOptionsExtHdrIdentifier) ||
		protocol == uint8(header.IGMPProtocolNumber) ||
		protocol == uint8(header.IPv6RoutingExtHdrIdentifier) ||
		protocol == uint8(header.IPv6FragmentExtHdrIdentifier) ||
		protocol == IPsecAuthenticationHeaderProtocolNumber ||
		protocol == uint8(header.ICMPv6ProtocolNumber) ||
		protocol == uint8(header.IPv6DestinationOptionsExtHdrIdentifier) ||
		protocol == IPv6MobilityExtHdrIdentifier ||
		protocol == HIPProtocolNumber ||
		protocol == Shim6ProtocolNumber
}
