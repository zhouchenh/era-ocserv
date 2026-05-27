package bridge

import (
	"net/netip"
	"testing"
)

// TestInnerSourceAllowed covers the inner-source anti-spoof rule
// from protocol spec §6.1 / ADR 0057 §5. The helper is small but
// load-bearing: it sits on the hot path of every client-to-tun
// packet. Negative tests dominate because spoof attempts are the
// security-relevant case.
func TestInnerSourceAllowed(t *testing.T) {
	clientV6 := netip.MustParseAddr("2001:470:f9d1:9001:2a::ff")
	otherV6 := netip.MustParseAddr("2001:470:f9d1:9001:dead:beef::1")
	upstream := netip.MustParseAddr("2606:4700:4700::1111")

	// Helper: build a minimal IPv6 packet with src/dst.
	v6 := func(src, dst netip.Addr) []byte {
		pkt := make([]byte, 40)
		pkt[0] = 0x60 // version 6
		pkt[6] = 59   // next-header = no next
		pkt[7] = 64   // hop limit
		sb := src.As16()
		db := dst.As16()
		copy(pkt[8:24], sb[:])
		copy(pkt[24:40], db[:])
		return pkt
	}

	// Helper: build a minimal IPv4 packet with src/dst.
	v4 := func(src, dst netip.Addr) []byte {
		pkt := make([]byte, 20)
		pkt[0] = 0x45 // version 4, IHL 5
		pkt[8] = 64   // TTL
		sb := src.As4()
		db := dst.As4()
		copy(pkt[12:16], sb[:])
		copy(pkt[16:20], db[:])
		return pkt
	}

	tests := []struct {
		name    string
		pkt     []byte
		client  netip.Addr
		allowed bool
	}{
		{
			name:    "legit IPv6 from client /128",
			pkt:     v6(clientV6, upstream),
			client:  clientV6,
			allowed: true,
		},
		{
			name:    "spoofed IPv6 from someone else's /128",
			pkt:     v6(otherV6, upstream),
			client:  clientV6,
			allowed: false,
		},
		{
			name:    "spoofed IPv6 from upstream addr",
			pkt:     v6(upstream, clientV6),
			client:  clientV6,
			allowed: false,
		},
		{
			name:    "legit IPv4 CLAT (192.0.0.1)",
			pkt:     v4(netip.MustParseAddr("192.0.0.1"), netip.MustParseAddr("8.8.8.8")),
			client:  clientV6,
			allowed: true,
		},
		{
			name:    "spoofed IPv4 from RFC1918",
			pkt:     v4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("8.8.8.8")),
			client:  clientV6,
			allowed: false,
		},
		{
			name:    "empty packet",
			pkt:     nil,
			client:  clientV6,
			allowed: false,
		},
		{
			name:    "1-byte packet (unknown version)",
			pkt:     []byte{0x70}, // version 7 — bogus
			client:  clientV6,
			allowed: false,
		},
		{
			name:    "IPv6 packet truncated to 39 bytes",
			pkt:     v6(clientV6, upstream)[:39],
			client:  clientV6,
			allowed: false,
		},
		{
			name:    "IPv4 packet truncated to 19 bytes",
			pkt:     v4(netip.MustParseAddr("192.0.0.1"), netip.MustParseAddr("8.8.8.8"))[:19],
			client:  clientV6,
			allowed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := innerSourceAllowed(tc.pkt, tc.client)
			if got != tc.allowed {
				t.Errorf("innerSourceAllowed(...) = %v, want %v", got, tc.allowed)
			}
		})
	}
}
