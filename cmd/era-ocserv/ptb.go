package main

import (
	"log/slog"
	"net/netip"

	"github.com/zhouchenh/era-ocserv/internal/icmp6"
	"github.com/zhouchenh/era-ocserv/internal/tun"
)

// Server-side ICMPv6 Packet-Too-Big origination for the AnyConnect data plane,
// per DEC-l3-mtu-model. The inner wire MTU advertised to the client is a fixed
// 1400 (X-CSTP-MTU = X-DTLS-MTU); the server owns the ±20 SIIT growth, so the two
// link MTUs the tun->client egress enforces are:
//
//   - native /128 dst: 1400 — the v6 client link MTU.
//   - CLAT   /128 dst: 1420 — the inbound packet here is the PRE-SIIT64 IPv6; the
//     −20 on v6->v4 translation yields the 1400 inner v4 the client expects.
//
// When a packet bound for the client exceeds its link MTU we DROP it and send a
// PTB back to the packet's IPv6 source so PMTUD shrinks the sender — instead of
// silently dropping (the prior behaviour) or shrinking the static 1400/1420 to
// compensate (forbidden by the locked spec).
//
// The caps are pinned here (NOT read from internal/clat's mutable package vars
// IPv4OutboundMTU/IPv6OutboundMTU) so the data-plane cannot drift on a re-vendor;
// they intentionally equal those constants (internal/clat/variables.go).
const (
	ptbCapNative = 1400
	ptbCapCLAT   = 1420
)

// originatePTB drops an oversize packet bound for the client and sends an ICMPv6
// Packet-Too-Big back to its IPv6 source so PMTUD shrinks the sender. q is the
// tun queue currently being drained — writing the PTB there makes the kernel
// route it out toward the Internet sender. dstKey is the inner /128 the oversize
// packet was addressed to (the PTB source). MUST be called BEFORE SIIT64 so orig
// is still IPv6.
func (b *bridge) originatePTB(q *tun.Queue, dstKey netip.Addr, linkMTU uint32, orig []byte) {
	pkt, ok := icmp6.PacketTooBigFor(dstKey, linkMTU, orig)
	if !ok {
		return
	}
	if _, err := q.Write(pkt); err != nil {
		slog.Debug("ptb write", "mtu", linkMTU, "err", err)
	}
}
