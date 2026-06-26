package cstp

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

// TestConnectResponseHeaderCasing guards against Go's http.Header
// canonicalisation (X-CSTP- -> X-Cstp-, DNS -> Dns, DynDNS -> Dyndns)
// leaking onto the CONNECT response wire. Cisco Secure Client (iOS) is
// case-SENSITIVE on these names and silently rejects the tunnel config
// when they are mis-cased, which manifests as an immediate
// "secure gateway has rejected the connection" after CONNECT.
func TestConnectResponseHeaderCasing(t *testing.T) {
	cfg := Config{
		ServerName:        "eracloud.app",
		DNS:               []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")},
		DPDInterval:       30,
		KeepaliveInterval: 20,
		IdleTimeout:       0,
		DefaultMTU:        1390,
	}
	id := Identity{
		DeviceID: "dev-test",
		IPv6:     netip.MustParsePrefix("2001:470:f9d1:9001:3223:bcff:fb47:7a53/128"),
		IPv6CLAT: netip.MustParsePrefix("2001:470:f9d1:9001:c1a7::1/128"),
		MTU:      1390,
	}
	h := make(http.Header)
	emitCSTPHeaders(h, cfg, id, 1390)

	var sb strings.Builder
	if err := writeConnectResponse(&sb, h); err != nil {
		t.Fatalf("writeConnectResponse: %v", err)
	}
	wire := sb.String()
	t.Logf("\n----WIRE----\n%s----END----", wire)

	// Every X-CSTP-* header must appear with exact Cisco casing.
	for _, want := range []string{
		"X-CSTP-Server-Name:", "X-CSTP-Client-Bypass-Protocol:",
		"X-CSTP-Address-IP6: 2001:470:f9d1:9001:3223:bcff:fb47:7a53/128",
		"X-CSTP-Version:", "X-CSTP-Address:", "X-CSTP-Netmask:", "X-CSTP-Address-IP6:",
		"X-CSTP-MTU:", "X-CSTP-Base-MTU:", "X-CSTP-DPD:", "X-CSTP-Keepalive:",
		"X-CSTP-Idle-Timeout:", "X-CSTP-Session-Timeout:", "X-CSTP-Disconnected-Timeout:",
		"X-CSTP-Keep:", "X-CSTP-TCP-Keepalive:", "X-CSTP-Tunnel-All-DNS:", "X-CSTP-Rekey-Time:", "X-CSTP-Rekey-Method:",
		"X-CSTP-License:", "X-CSTP-DynDNS:", "X-CSTP-Smartcard-Removal-Disconnect:",
		"X-CSTP-DNS:", "X-CSTP-DNS-IP6:",
	} {
		if !strings.Contains(wire, want) {
			t.Errorf("missing exact-cased header: %q", want)
		}
	}

	// No Go-canonical mis-casing may leak onto the wire.
	for _, bad := range []string{
		"X-Cstp-", "Tunnel-All-Dns", "Dyndns", "X-Dtls-",
		"X-CSTP-Server-Version", // replaced by X-CSTP-Server-Name
	} {
		if strings.Contains(wire, bad) {
			t.Errorf("mis-cased token leaked onto wire: %q", bad)
		}
	}
}

func TestEmitCSTPHeadersSuppressesIPv4LeaseWithoutCLAT(t *testing.T) {
	id := Identity{
		DeviceID: "dev-test",
		IPv6:     netip.MustParsePrefix("2001:470:f9d1:9001:3223:bcff:fb47:7a53/128"),
	}
	h := make(http.Header)
	emitCSTPHeaders(h, Config{DefaultMTU: 1400}, id, 1400)

	if got := h.Get("X-CSTP-Address"); got != "" {
		t.Fatalf("X-CSTP-Address = %q, want absent without CLAT /128", got)
	}
	if got := h.Get("X-CSTP-Netmask"); got != "" {
		t.Fatalf("X-CSTP-Netmask = %q, want absent without CLAT /128", got)
	}
	if got := h.Get("X-CSTP-Address-IP6"); got == "" {
		t.Fatalf("X-CSTP-Address-IP6 missing; v6 lease should remain")
	}
}
