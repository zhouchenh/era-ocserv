// Vendored from wireguard-go-clat@3dfa6e7 (golang.zx2c4.com/wireguard/clat). Do not edit; update by re-vendoring.
package clat

import "net/netip"

var (
	ipv4FragmentIDCounter = uint32(0)
	ipv6FragmentIDCounter = uint32(0)
	SIITPrefix            = netip.MustParsePrefix("64:ff9b::/96").Addr().As16()
	PlateauMTUs           = []uint16{65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68, 0}
	IPv6OutboundMTU       = 1420
	IPv4OutboundMTU       = 1400
)
