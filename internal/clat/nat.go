// Vendored from wireguard-go-clat@3dfa6e7 (golang.zx2c4.com/wireguard/clat). Do not edit; update by re-vendoring.
package clat

import (
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func NAT66InPlaceTranslateAddress(ipv6Packet []byte, toIPv6Address []byte, addressOffset int) {
	packetLength := len(ipv6Packet)
	if packetLength < header.IPv6FixedHeaderSize {
		return
	}
	ipv6Address := ipv6Packet[addressOffset : addressOffset+IPv6AddressSize]
	switch ipv6Packet[header.IPv6NextHeaderOffset] {
	case uint8(header.TCPProtocolNumber):
		if packetLength < header.IPv6FixedHeaderSize+header.TCPMinimumSize {
			return
		}
		natPartialUpdateChecksum(ipv6Packet, header.IPv6FixedHeaderSize+header.TCPChecksumOffset, ipv6Address, toIPv6Address)
	case DCCPProtocolNumber:
		if packetLength < header.IPv6FixedHeaderSize+DCCPMinimumSize {
			return
		}
		natPartialUpdateChecksum(ipv6Packet, header.IPv6FixedHeaderSize+DCCPChecksumOffset, ipv6Address, toIPv6Address)
	case uint8(header.UDPProtocolNumber):
		if packetLength < header.IPv6FixedHeaderSize+header.UDPMinimumSize {
			return
		}
		natPartialUpdateChecksum(ipv6Packet, header.IPv6FixedHeaderSize+6, ipv6Address, toIPv6Address)
	case header.IPv6FragmentHeader:
		if packetLength < header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize {
			return
		}
		fragmentHeader := header.IPv6Fragment(ipv6Packet[header.IPv6FixedHeaderSize : header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize])
		// RFC 7915 transport checksum adjustment only applies to the fragment that
		// actually carries the checksum field. Later fragments still need the IPv6
		// address rewrite, but touching their payload bytes would corrupt data.
		if fragmentHeader.FragmentOffset() != 0 {
			break
		}
		switch fragmentHeader.NextHeader() {
		case uint8(header.TCPProtocolNumber):
			if packetLength < header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize+header.TCPMinimumSize {
				return
			}
			natPartialUpdateChecksum(ipv6Packet, header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize+header.TCPChecksumOffset, ipv6Address, toIPv6Address)
		case DCCPProtocolNumber:
			if packetLength < header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize+DCCPMinimumSize {
				return
			}
			natPartialUpdateChecksum(ipv6Packet, header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize+DCCPChecksumOffset, ipv6Address, toIPv6Address)
		case uint8(header.UDPProtocolNumber):
			if packetLength < header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize+header.UDPMinimumSize {
				return
			}
			natPartialUpdateChecksum(ipv6Packet, header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize+6, ipv6Address, toIPv6Address)
		case uint8(header.ICMPv6ProtocolNumber):
			if packetLength < header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize+header.ICMPv6MinimumSize {
				return
			}
			natPartialUpdateChecksum(ipv6Packet, header.IPv6FixedHeaderSize+header.IPv6FragmentHeaderSize+header.ICMPv6ChecksumOffset, ipv6Address, toIPv6Address)
		default:
		}
	case uint8(header.ICMPv6ProtocolNumber):
		if packetLength < header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize {
			return
		}
		natPartialUpdateChecksum(ipv6Packet, header.IPv6FixedHeaderSize+header.ICMPv6ChecksumOffset, ipv6Address, toIPv6Address)
	default:
	}
	copy(ipv6Address, toIPv6Address)
}

func NAT44InPlaceTranslateAddress(ipv4Packet []byte, toIPv4Address []byte, addressOffset int) {
	packetLength := len(ipv4Packet)
	if packetLength < header.IPv4MinimumSize {
		return
	}
	ipv4Header := header.IPv4(ipv4Packet)
	fragmentOffset := ipv4Header.FragmentOffset()
	ipv4Address := ipv4Packet[addressOffset : addressOffset+IPv4AddressSize]
	switch ipv4Packet[IPv4ProtocolOffset] {
	case uint8(header.TCPProtocolNumber):
		if fragmentOffset != 0 {
			break
		}
		if packetLength < header.IPv4MinimumSize+header.TCPMinimumSize {
			return
		}
		natPartialUpdateChecksum(ipv4Packet, header.IPv4MinimumSize+header.TCPChecksumOffset, ipv4Address, toIPv4Address)
	case DCCPProtocolNumber:
		if fragmentOffset != 0 {
			break
		}
		if packetLength < header.IPv4MinimumSize+DCCPMinimumSize {
			return
		}
		natPartialUpdateChecksum(ipv4Packet, header.IPv4MinimumSize+DCCPChecksumOffset, ipv4Address, toIPv4Address)
	case uint8(header.UDPProtocolNumber):
		if fragmentOffset != 0 {
			break
		}
		if packetLength < header.IPv4MinimumSize+header.UDPMinimumSize {
			return
		}
		natPartialUpdateChecksum(ipv4Packet, header.IPv4MinimumSize+6, ipv4Address, toIPv4Address)
	default:
	}
	natPartialUpdateChecksum(ipv4Packet, 10, ipv4Address, toIPv4Address)
	copy(ipv4Address, toIPv4Address)
}

func natPartialUpdateChecksum(packet []byte, checksumOffset int, oldAddress []byte, newAddress []byte) {
	updatedChecksum := ^(uint16(packet[checksumOffset+1]) | uint16(packet[checksumOffset])<<8)
	addressLength := len(oldAddress)
	for i := 0; i < addressLength; i += 2 {
		updatedChecksum = checksum.Combine(updatedChecksum, checksum.Combine(uint16(newAddress[i+1])|uint16(newAddress[i])<<8, ^(uint16(oldAddress[i+1])|uint16(oldAddress[i])<<8)))
	}
	updatedChecksum = ^updatedChecksum
	packet[checksumOffset+1] = byte(updatedChecksum)
	packet[checksumOffset] = byte(updatedChecksum >> 8)
	return
}
