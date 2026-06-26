// Vendored from wireguard-go-clat@3dfa6e7 (golang.zx2c4.com/wireguard/clat). Do not edit; update by re-vendoring.
package clat

import (
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"sync/atomic"
)

//func makeRoomForNewHeader(buffer []byte, reservedSpaceSize *uint8) (messageHeaderSource []byte, messageHeaderDestination []byte, oldHeader []byte, packetWithNewHeaderSpace []byte, isFragmented bool) {
//	source := buffer[*reservedSpaceSize:]
//	packet := source[MessageTransportHeaderSize:]
//	var destination []byte
//	var oldHeaderLength uint8
//	switch header.IPVersion(packet) {
//	case header.IPv4Version:
//		ipv4Packet := header.IPv4(packet)
//		isFragmented = ipv4Packet.Flags()&header.IPv4FlagMoreFragments != 0 || ipv4Packet.FragmentOffset() != 0
//		oldHeaderLength = ipv4Packet.HeaderLength()
//		if isFragmented {
//			*reservedSpaceSize -= header.IPv6FixedHeaderSize + header.IPv6FragmentHeaderSize
//		} else {
//			*reservedSpaceSize -= header.IPv6FixedHeaderSize
//		}
//	case header.IPv6Version:
//		ipv6Packet := header.IPv6(packet)
//		isFragmented = ipv6Packet.NextHeader() == uint8(header.IPv6FragmentHeader)
//		if isFragmented {
//			oldHeaderLength = header.IPv6FixedHeaderSize + header.IPv6FragmentHeaderSize
//		} else {
//			oldHeaderLength = header.IPv6FixedHeaderSize
//		}
//		*reservedSpaceSize -= header.IPv4MinimumSize
//	default:
//		return
//	}
//	destination = buffer[*reservedSpaceSize : *reservedSpaceSize+MessageTransportHeaderSize+oldHeaderLength]
//	messageHeaderSource = destination[:MessageTransportHeaderSize]
//	oldHeader = destination[MessageTransportHeaderSize:]
//	*reservedSpaceSize += oldHeaderLength
//	messageHeaderDestination = buffer[*reservedSpaceSize:]
//	packetWithNewHeaderSpace = messageHeaderDestination[MessageTransportHeaderSize:]
//	copy(destination, source)
//	return
//}

func SIIT64InPlaceTranslate(buffer []byte, reservedSpaceSize *uint /*, verbosef func(format string, args ...any), errorf func(format string, args ...any)*/) (translated bool) {
	//verbosef("SIIT64InPlaceTranslate: original packet buffer:\n%s", hex.Dump(buffer))
	if reservedSpaceSize == nil {
		return
	}
	packetStart := *reservedSpaceSize + MessageTransportHeaderSize
	if *reservedSpaceSize > uint(len(buffer)) || packetStart > uint(len(buffer)) {
		return
	}
	isTranslatable, fragmentExtensionHeader, nextHeader, payloadOffset, payloadLength := isIPv6PacketTranslatable(buffer[packetStart:])
	//verbosef("SIIT64InPlaceTranslate: fragmentExtensionHeader: %v", fragmentExtensionHeader)
	//verbosef("SIIT64InPlaceTranslate: nextHeader: %d", nextHeader)
	//verbosef("SIIT64InPlaceTranslate: payloadOffset: %d", payloadOffset)
	//verbosef("SIIT64InPlaceTranslate: payloadLength: %d", payloadLength)
	if !isTranslatable {
		return
	}
	ipv6Header, ipv4Packet := makeRoomForIPv4Header(buffer, reservedSpaceSize, payloadOffset)
	if ipv6Header == nil || ipv4Packet == nil {
		return
	}
	//verbosef("SIIT64InPlaceTranslate: length of ipv6Header: %d", len(ipv6Header))
	//verbosef("SIIT64InPlaceTranslate: length of ipv4Packet: %d", len(ipv4Packet))
	fragmentOffset, transportProtocol := siit64TranslateHeader(ipv6Header, ipv4Packet, fragmentExtensionHeader, nextHeader, payloadLength)
	transport := ipv4Packet[header.IPv4MinimumSize : header.IPv4MinimumSize+payloadLength]
	if transportProtocol == uint8(header.ICMPv4ProtocolNumber) {
		siit64TranslateICMPTransport(header.ICMPv4(transport))
	}
	siit64UpdateTransportChecksum(ipv6Header[IPv6DestinationAddressOffset:IPv6DestinationAddressOffset+SIITPrefixSize], transport, fragmentOffset, transportProtocol)
	ipv4Packet.SetChecksum(0)
	ipv4Packet.SetChecksum(^ipv4Packet.CalculateChecksum())
	translated = true
	//verbosef("SIIT64InPlaceTranslate: actual length of translated IPv4 packet: %d", ipv4Packet.TotalLength())
	//verbosef("SIIT64InPlaceTranslate: translated packet buffer:\n%s", hex.Dump(buffer))
	//verbosef("SIIT64InPlaceTranslate: translated packet IsChecksumValid(): %v", ipv4Packet.IsChecksumValid())
	return
}

func siit64TranslateHeader(ipv6Header header.IPv6, ipv4Packet header.IPv4, fragmentExtensionHeader header.IPv6Fragment, nextHeader uint8, payloadLength uint) (fragmentOffset uint16, transportProtocol uint8) {
	ipv4Packet.SetHeaderLength(header.IPv4MinimumSize) // Set IP version to IPv4, and set IHL to 20 bytes,
	ipv4Packet.SetTOS(ipv6Header.TOS())                // Translate Traffic Class to DSCP and ECN, and discard Flow Label
	ipv4Packet.SetTotalLength(uint16(header.IPv4MinimumSize + payloadLength))
	transportProtocol = nextHeader
	if transportProtocol == uint8(header.ICMPv6ProtocolNumber) {
		transportProtocol = uint8(header.ICMPv4ProtocolNumber)
	}
	if fragmentExtensionHeader != nil && (fragmentExtensionHeader.More() || fragmentExtensionHeader.FragmentOffset() != 0) {
		fragmentOffset = fragmentExtensionHeader.FragmentOffset() << 3
		ipv4Packet.SetID(uint16(fragmentExtensionHeader.ID() & 0xffff))
		ipv4Packet.SetFlagsFragmentOffset(fragmentExtensionHeader[IPv6FragmentExtensionHeaderFlagOffset], fragmentOffset)
	} else {
		fragmentOffset = 0
		ipv4Packet.SetID(GenerateIPv4FragmentID())
		ipv4Packet.SetFlagsFragmentOffset(0, 0)
	}
	ipv4Packet.SetTTL(ipv6Header.HopLimit())
	ipv4Packet[IPv4ProtocolOffset] = transportProtocol
	copy(ipv4Packet[IPv4SourceAddressOffset:], ipv6Header[IPv6SourceAddressOffset+SIITPrefixSize:IPv6SourceAddressOffset+IPv6AddressSize])
	copy(ipv4Packet[IPv4DestinationAddressOffset:], ipv6Header[IPv6DestinationAddressOffset+SIITPrefixSize:IPv6DestinationAddressOffset+IPv6AddressSize])
	return
}

func GenerateIPv4FragmentID() uint16 {
	return uint16((atomic.AddUint32(&ipv4FragmentIDCounter, 1) - 1) & 0xffff)
}

func siit64TranslateICMPTransport(icmpv4Packet header.ICMPv4) {
	icmpv6Packet := header.ICMPv6(icmpv4Packet)
	translateQuote := false
	switch icmpv6Packet.Type() {
	case header.ICMPv6EchoRequest:
		icmpv4Packet.SetType(header.ICMPv4Echo)
	case header.ICMPv6EchoReply:
		icmpv4Packet.SetType(header.ICMPv4EchoReply)
	case header.ICMPv6DstUnreachable:
		translateQuote = true
		icmpv4Packet.SetType(header.ICMPv4DstUnreachable)
		switch icmpv6Packet.Code() {
		case header.ICMPv6NetworkUnreachable, header.ICMPv6BeyondScope, header.ICMPv6AddressUnreachable:
			icmpv4Packet.SetCode(header.ICMPv4HostUnreachable)
		case header.ICMPv6Prohibited:
			icmpv4Packet.SetCode(header.ICMPv4HostProhibited)
		case header.ICMPv6PortUnreachable:
			icmpv4Packet.SetCode(header.ICMPv4PortUnreachable)
		default:
		}
	case header.ICMPv6PacketTooBig:
		translateQuote = true
		icmpv4Packet.SetType(header.ICMPv4DstUnreachable)
		icmpv4Packet.SetCode(header.ICMPv4FragmentationNeeded)
		icmpv4Packet.SetMTU(max(header.IPv4MinimumMTU, min(max(20, uint16(icmpv6Packet.MTU()&0xffff))-20, uint16(IPv4OutboundMTU), uint16(IPv6OutboundMTU)-20)))
	case header.ICMPv6TimeExceeded:
		translateQuote = true
		icmpv4Packet.SetType(header.ICMPv4TimeExceeded)
	case header.ICMPv6ParamProblem:
		translateQuote = true
		switch icmpv6Packet.Code() {
		case header.ICMPv6ErroneousHeader:
			icmpv4Packet.SetType(header.ICMPv4ParamProblem)
			icmpv4Packet.SetCode(header.ICMPv4UnusedCode)
			switch icmpv6Packet[4 /* Pointer Offset */ +3 /* Zeroed Bytes of the 4-byte Pointer */] {
			case 0 /* Version/Traffic Class */ :
				icmpv4Packet[4 /* Pointer Offset */] = 0 /* Version/IHL */
			case 1 /* Traffic Class/Flow Label */ :
				icmpv4Packet[4 /* Pointer Offset */] = 1 /* Type Of Service */
			case 4, 5 /* Payload Length */ :
				icmpv4Packet[4 /* Pointer Offset */] = 2 /* Total Length */
			case 6 /* Next Header */ :
				icmpv4Packet[4 /* Pointer Offset */] = 9 /* Protocol */
			case 7 /* Hop Limit */ :
				icmpv4Packet[4 /* Pointer Offset */] = 8 /* Time to Live */
			case 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 /* Source Address */ :
				icmpv4Packet[4 /* Pointer Offset */] = 12 /* Source Address */
			case 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39 /* Destination Address */ :
				icmpv4Packet[4 /* Pointer Offset */] = 16 /* Destination Address */
			default:
			}
			icmpv6Packet[4 /* Pointer Offset */ +3 /* Zeroed Bytes of the 4-byte Pointer */] = 0
		case header.ICMPv6UnknownHeader:
			icmpv4Packet.SetType(header.ICMPv4DstUnreachable)
			icmpv4Packet.SetCode(header.ICMPv4ProtoUnreachable)
			clear(icmpv6Packet[4 : /* Pointer Offset */ 4 /* Pointer Offset */ +4 /* Pointer Size */])
		default:
		}
	default:
	}
	if translateQuote {
		// Tools like traceroute and mtr parse the quoted original packet inside ICMP
		// errors. Translating only the outer error leaves a mixed-family quote that
		// still exposes /96 IPv6 addresses instead of IPv4 hop semantics.
		siit64TranslateICMPErrorQuote(icmpv4Packet)
	}
}

func siit64TranslateICMPErrorQuote(icmpv4Packet header.ICMPv4) {
	quote := icmpv4Packet.Payload()
	// RFC 7915 treats the ICMP error payload as another translated IP packet,
	// but this helper only understands the classic fixed-header quote layout.
	// RFC 4884 extension-aware quote parsing remains a later audit item.
	if len(quote) < header.IPv6FixedHeaderSize {
		return
	}

	quotedIPv6 := header.IPv6(quote)
	if header.IPVersion(quotedIPv6) != header.IPv6Version {
		return
	}

	quotedNextHeader := quotedIPv6.NextHeader()
	switch quotedNextHeader {
	case uint8(header.IPv6HopByHopOptionsExtHdrIdentifier),
		uint8(header.IPv6RoutingExtHdrIdentifier),
		uint8(header.IPv6FragmentExtHdrIdentifier),
		uint8(header.IPv6DestinationOptionsExtHdrIdentifier):
		// The live packet path can size-shift whole packets, but quoted packets live
		// inside an already translated outer ICMP buffer. If the quote needs more than
		// a fixed 40->20 byte header compaction, fail closed and keep the original
		// IPv6 quote instead of emitting a partially rewritten mixed-family payload.
		return
	default:
	}

	if quotedNextHeader == uint8(header.ICMPv6ProtocolNumber) {
		if len(quote) < header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize {
			return
		}
		quotedICMPv6 := header.ICMPv6(quote[header.IPv6FixedHeaderSize:])
		// RFC 7915 says translation stops at the first embedded header. Nested
		// ICMP errors would carry another embedded packet, so keep the outer error
		// translated but leave the quote untouched instead of emitting a corrupted
		// partially translated payload.
		switch quotedICMPv6.Type() {
		case header.ICMPv6EchoRequest, header.ICMPv6EchoReply:
		default:
			return
		}
	}

	// RFC-style SIIT uses the low 32 bits when converting IPv6 addresses back to
	// IPv4. This project additionally relies on RouterOS return-path normalization
	// so quoted hop addresses seen under the configured /96 remain meaningful.
	quotedTOS, _ := quotedIPv6.TOS()
	quotedHopLimit := quotedIPv6.HopLimit()
	quotedPayloadLength := quotedIPv6.PayloadLength()
	var quotedSourceAddress [IPv4AddressSize]byte
	var quotedDestinationAddress [IPv4AddressSize]byte
	copy(quotedSourceAddress[:], quote[IPv6SourceAddressOffset+SIITPrefixSize:IPv6SourceAddressOffset+IPv6AddressSize])
	copy(quotedDestinationAddress[:], quote[IPv6DestinationAddressOffset+SIITPrefixSize:IPv6DestinationAddressOffset+IPv6AddressSize])

	quotedProtocol := quotedNextHeader
	if quotedProtocol == uint8(header.ICMPv6ProtocolNumber) {
		quotedProtocol = uint8(header.ICMPv4ProtocolNumber)
	}

	// The outer packet length cannot change at this point, so compact the quoted
	// packet in place and zero the vacated tail bytes instead of reallocating.
	copy(quote[header.IPv4MinimumSize:], quote[header.IPv6FixedHeaderSize:])
	clear(quote[len(quote)-(header.IPv6FixedHeaderSize-header.IPv4MinimumSize):])

	quotedIPv4 := header.IPv4(quote)
	quotedIPv4.Encode(&header.IPv4Fields{
		TOS:            quotedTOS,
		TotalLength:    uint16(header.IPv4MinimumSize) + quotedPayloadLength,
		ID:             0,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            quotedHopLimit,
		Protocol:       quotedProtocol,
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(quotedSourceAddress),
		DstAddr:        tcpip.AddrFrom4(quotedDestinationAddress),
	})
	quotedIPv4.SetChecksum(0)
	quotedIPv4.SetChecksum(^quotedIPv4.CalculateChecksum())

	if quotedNextHeader != uint8(header.ICMPv6ProtocolNumber) {
		// Quoted UDP/TCP bytes are diagnostic payload, not live transport traffic.
		// Their checksum fields can stay as captured bytes even though the quoted
		// IPv4 header was rebuilt around them; the outer ICMP checksum is updated
		// after this helper returns.
		return
	}

	quotedICMPv6 := header.ICMPv6(quote[header.IPv4MinimumSize:])
	quotedICMPv4 := header.ICMPv4(quote[header.IPv4MinimumSize:])
	switch quotedICMPv6.Type() {
	case header.ICMPv6EchoRequest:
		quotedICMPv4.SetType(header.ICMPv4Echo)
	case header.ICMPv6EchoReply:
		quotedICMPv4.SetType(header.ICMPv4EchoReply)
	default:
		return
	}
	quotedICMPv4.SetChecksum(0)
	quotedICMPv4.SetChecksum(^checksum.Checksum(quotedICMPv4, 0))
}

func siit64UpdateTransportChecksum(ipv6DestinationPrefix []byte, transport []byte, fragmentOffset uint16, transportProtocol uint8) {
	if fragmentOffset != 0 {
		return
	}
	switch transportProtocol {
	case uint8(header.ICMPv4ProtocolNumber):
		if len(transport) < header.ICMPv4MinimumSize {
			return
		}
		icmpv4Packet := header.ICMPv4(transport)
		icmpv4Packet.SetChecksum(0)
		icmpv4Packet.SetChecksum(^checksum.Checksum(icmpv4Packet, 0))
	case uint8(header.TCPProtocolNumber):
		if len(transport) < header.TCPMinimumSize {
			return
		}
		siit64PartialUpdateTransportChecksum(ipv6DestinationPrefix, transport, header.TCPChecksumOffset)
	case DCCPProtocolNumber:
		if len(transport) < DCCPMinimumSize {
			return
		}
		// RFC 7915 checksum-neutrality rules apply to DCCP too because its
		// checksum covers the IP pseudo-header, not just the transport bytes.
		siit64PartialUpdateTransportChecksum(ipv6DestinationPrefix, transport, DCCPChecksumOffset)
	case uint8(header.UDPProtocolNumber):
		if len(transport) < header.UDPMinimumSize {
			return
		}
		siit64PartialUpdateTransportChecksum(ipv6DestinationPrefix, transport, 6)
	default:
	}
}

func siit64PartialUpdateTransportChecksum(ipv6DestinationPrefix []byte, transport []byte, checksumOffset int) {
	//currentChecksum := binary.BigEndian.Uint16(transport[checksumOffset:])
	//binary.BigEndian.PutUint16(transport[checksumOffset:], ^checksum.Combine(
	//	^currentChecksum,
	//	checksum.Combine(
	//		checksum.Checksum(ipv4Packet[IPv4SourceAddressOffset:IPv4SourceAddressOffset+header.IPv4AddressSize*2], 0),
	//		^checksum.Checksum(ipv6Header[IPv6SourceAddressOffset:IPv6SourceAddressOffset+header.IPv6AddressSize*2], 0),
	//	),
	//))
	binary.BigEndian.PutUint16(transport[checksumOffset:], ^checksum.Combine(
		^binary.BigEndian.Uint16(transport[checksumOffset:]), checksum.Combine(
			siit64SourceChecksumDelta,
			^checksum.Checksum(ipv6DestinationPrefix, 0),
		),
	))
}

func makeRoomForIPv4Header(buffer []byte, reservedSpaceSize *uint, payloadOffset uint) (ipv6Header header.IPv6, ipv4Packet header.IPv4) {
	if reservedSpaceSize == nil {
		return
	}
	bufferLength := uint(len(buffer))
	sourceOffset := *reservedSpaceSize
	if sourceOffset > bufferLength || payloadOffset > bufferLength || sourceOffset < header.IPv4MinimumSize || bufferLength-sourceOffset < MessageTransportHeaderSize+payloadOffset {
		return
	}
	// Invalid reserved headroom is an internal buffer bookkeeping problem. Fail
	// closed instead of underflowing the reserved offset or slicing past the end.
	newReservedSpaceSize := sourceOffset - header.IPv4MinimumSize
	if newReservedSpaceSize+MessageTransportHeaderSize+payloadOffset > bufferLength {
		return
	}
	source := buffer[sourceOffset:]
	destination := buffer[newReservedSpaceSize : newReservedSpaceSize+MessageTransportHeaderSize+payloadOffset]
	ipv6Header = destination[MessageTransportHeaderSize:]
	*reservedSpaceSize = newReservedSpaceSize + payloadOffset
	packetStart := *reservedSpaceSize + MessageTransportHeaderSize
	if packetStart > bufferLength {
		ipv6Header = nil
		*reservedSpaceSize = sourceOffset
		return
	}
	ipv4Packet = buffer[packetStart:]
	copy(destination, source)
	return
}

func isIPv6PacketTranslatable(ipv6Packet header.IPv6) (isTranslatable bool, fragmentExtensionHeader header.IPv6Fragment, nextHeader uint8, payloadOffset uint, payloadLength uint) {
	isTranslatable = header.IPVersion(ipv6Packet) == header.IPv6Version
	if !isTranslatable {
		return
	}
	isTranslatable, fragmentExtensionHeader, nextHeader, payloadOffset, payloadLength = isIPv6HeaderTranslatable(ipv6Packet)
	if !isTranslatable {
		return
	}
	if fragmentExtensionHeader != nil && fragmentExtensionHeader.More() && payloadLength%8 != 0 {
		return false, fragmentExtensionHeader, nextHeader, payloadOffset, payloadLength
	}
	if nextHeader != uint8(header.ICMPv6ProtocolNumber) {
		return true, fragmentExtensionHeader, nextHeader, payloadOffset, payloadLength
	}
	isTranslatable = (fragmentExtensionHeader == nil ||
		!fragmentExtensionHeader.More() && fragmentExtensionHeader.FragmentOffset() == 0) &&
		isICMPv6PacketTranslatable(ipv6Packet, header.ICMPv6(ipv6Packet[payloadOffset:payloadOffset+payloadLength]))
	return
}

func isIPv6HeaderTranslatable(ipv6Packet header.IPv6) (isTranslatable bool, fragmentExtensionHeader header.IPv6Fragment, nextHeader uint8, payloadOffset uint, payloadLength uint) {
	isTranslatable = len(ipv6Packet) >= header.IPv6FixedHeaderSize
	if !isTranslatable {
		return
	}
	packetLength := header.IPv6FixedHeaderSize + uint(ipv6Packet.PayloadLength())
	isTranslatable = len(ipv6Packet) >= int(packetLength)
	if !isTranslatable {
		return
	}
	nextHeader = ipv6Packet.NextHeader()
	payloadOffset = header.IPv6FixedHeaderSize
	if !isIPv6ExtensionHeader(nextHeader) {
		// The common CLAT fast path is a fixed IPv6 header carrying ordinary
		// UDP/TCP traffic. Keep that path direct and only invoke the extension-
		// header walker for the slower exceptional cases.
		isTranslatable = !isTransportProtocolForbiddenForIPv6(nextHeader)
		payloadLength = packetLength - payloadOffset
		return
	}
	isTranslatable, fragmentExtensionHeader, nextHeader, payloadOffset = isEveryIPv6ExtensionHeaderTranslatable(ipv6Packet[:packetLength])
	if !isTranslatable {
		return
	}
	payloadLength = packetLength - payloadOffset
	return
}

func isICMPv6PacketTranslatable(ipv6Packet header.IPv6, icmpv6Packet header.ICMPv6) bool {
	return len(icmpv6Packet) >= header.ICMPv6MinimumSize &&
		checksum.Combine(checksum.Combine(checksum.Combine(
			checksum.Checksum(ipv6Packet[IPv6SourceAddressOffset:IPv6SourceAddressOffset+IPv6AddressSize*2], 0),
			uint16(len(icmpv6Packet)),
		), uint16(header.ICMPv6ProtocolNumber)), checksum.Checksum(icmpv6Packet, 0)) == 0xffff &&
		isICMPv6PacketHeaderTranslatable(icmpv6Packet.Type(), icmpv6Packet.Code(), icmpv6Packet[4:])
}

func isICMPv6PacketHeaderTranslatable(icmpv6Type header.ICMPv6Type, icmpv6Code header.ICMPv6Code, restOfHeader []byte) bool {
	switch icmpv6Type {
	case header.ICMPv6EchoRequest, header.ICMPv6EchoReply:
		return icmpv6Code == header.ICMPv6UnusedCode
	case header.ICMPv6DstUnreachable:
		return icmpv6Code == header.ICMPv6NetworkUnreachable ||
			icmpv6Code == header.ICMPv6Prohibited ||
			icmpv6Code == header.ICMPv6BeyondScope ||
			icmpv6Code == header.ICMPv6AddressUnreachable ||
			icmpv6Code == header.ICMPv6PortUnreachable
	case header.ICMPv6PacketTooBig:
		return icmpv6Code == header.ICMPv6UnusedCode && restOfHeader[0]|restOfHeader[1] == 0
	case header.ICMPv6TimeExceeded:
		return icmpv6Code == header.ICMPv6HopLimitExceeded ||
			icmpv6Code == header.ICMPv6ReassemblyTimeout
	case header.ICMPv6ParamProblem:
		return icmpv6Code == header.ICMPv6ErroneousHeader &&
			restOfHeader[0]|restOfHeader[1]|restOfHeader[2] == 0 &&
			(restOfHeader[3] <= 1 || restOfHeader[3] >= 4 && restOfHeader[3] <= 39) ||
			icmpv6Code == header.ICMPv6UnknownHeader &&
				restOfHeader[0]|restOfHeader[1]|restOfHeader[2]|restOfHeader[3] == 0
	default:
		return false
	}
}

func isIPv6ExtensionHeader(nextHeader uint8) bool {
	return nextHeader == uint8(header.IPv6HopByHopOptionsExtHdrIdentifier) ||
		nextHeader == uint8(header.IPv6RoutingExtHdrIdentifier) ||
		nextHeader == uint8(header.IPv6FragmentExtHdrIdentifier) ||
		nextHeader == uint8(header.IPv6DestinationOptionsExtHdrIdentifier)
}

func isEveryIPv6ExtensionHeaderTranslatable(packet header.IPv6) (isTranslatable bool, fragmentExtensionHeader header.IPv6Fragment, nextHeader uint8, payloadOffset uint) {
	nextHeader = packet.NextHeader()
	payloadOffset = header.IPv6FixedHeaderSize
	for fragmentExtensionHeader == nil && isIPv6ExtensionHeader(nextHeader) {
		if len(packet)-int(payloadOffset) < IPv6ExtensionHeaderMinimumSize {
			return
		}
		if nextHeader == uint8(header.IPv6RoutingExtHdrIdentifier) {
			if packet[payloadOffset+IPv6RoutingExtensionHeaderSegmentsLeftOffset] != 0 {
				return
			}
		} else if nextHeader == uint8(header.IPv6FragmentExtHdrIdentifier) {
			fragmentExtensionHeader = header.IPv6Fragment(packet[payloadOffset : payloadOffset+header.IPv6FragmentHeaderSize])
			if fragmentExtensionHeader[IPv6FragmentExtensionHeaderReservedOffset] != 0 || fragmentExtensionHeader[IPv6FragmentExtensionHeaderFlagOffset]&IPv6FragmentExtensionHeaderFlagReserved != 0 {
				return
			}
		}
		extensionHeaderSize := IPv6ExtensionHeaderMinimumSize + uint(packet[payloadOffset+IPv6ExtensionHeaderHeaderExtensionLengthOffset])*IPv6ExtensionHeaderSizeMultiple
		if len(packet)-int(payloadOffset) < int(extensionHeaderSize) {
			return
		}
		nextHeader = packet[payloadOffset+IPv6ExtensionHeaderNextHeaderOffset]
		payloadOffset += extensionHeaderSize
	}
	isTranslatable = !isTransportProtocolForbiddenForIPv6(nextHeader)
	return
}

func isTransportProtocolForbiddenForIPv6(protocol uint8) bool {
	return protocol == uint8(header.IPv6HopByHopOptionsExtHdrIdentifier) ||
		protocol == uint8(header.ICMPv4ProtocolNumber) ||
		protocol == uint8(header.IGMPProtocolNumber) ||
		protocol == uint8(header.IPv6RoutingExtHdrIdentifier) ||
		protocol == uint8(header.IPv6FragmentExtHdrIdentifier) ||
		protocol == IPsecAuthenticationHeaderProtocolNumber ||
		protocol == uint8(header.IPv6DestinationOptionsExtHdrIdentifier) ||
		protocol == IPv6MobilityExtHdrIdentifier ||
		protocol == HIPProtocolNumber ||
		protocol == Shim6ProtocolNumber
}
