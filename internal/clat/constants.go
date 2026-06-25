// Vendored from wireguard-go-clat@3dfa6e7 (golang.zx2c4.com/wireguard/clat). Do not edit; update by re-vendoring.
package clat

const (
	MessageTransportHeaderSize                     = 16
	IPv4FlagReserved                               = 0b100
	IPv4OptionLooseSourceRouteType                 = 131
	IPv4OptionStrictSourceRouteType                = 137
	DCCPProtocolNumber                             = 33
	DCCPMinimumSize                                = 12
	DCCPChecksumOffset                             = 6
	IPsecAuthenticationHeaderProtocolNumber        = 51
	IPv6MobilityExtHdrIdentifier                   = 135
	HIPProtocolNumber                              = 139
	Shim6ProtocolNumber                            = 140
	IPv4ProtocolOffset                             = 9
	IPv4AddressSize                                = 4
	IPv4SourceAddressOffset                        = 12
	IPv4DestinationAddressOffset                   = IPv4SourceAddressOffset + IPv4AddressSize
	IPv6AddressSize                                = 16
	IPv6SourceAddressOffset                        = 8
	IPv6DestinationAddressOffset                   = IPv6SourceAddressOffset + IPv6AddressSize
	IPv6ExtensionHeaderSizeMultiple                = 8
	IPv6ExtensionHeaderMinimumSize                 = IPv6ExtensionHeaderSizeMultiple
	IPv6ExtensionHeaderNextHeaderOffset            = 0
	IPv6ExtensionHeaderHeaderExtensionLengthOffset = 1
	IPv6RoutingExtensionHeaderSegmentsLeftOffset   = 3
	IPv6FragmentExtensionHeaderReservedOffset      = 1
	IPv6FragmentExtensionHeaderFlagOffset          = 3
	IPv6FragmentExtensionHeaderFlagReserved        = 0b110
	SIITPrefixSize                                 = 12
)
