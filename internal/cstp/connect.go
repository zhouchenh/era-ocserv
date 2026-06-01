package cstp

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// handleConnect answers phase 3: the CONNECT /CSCOSSLC/tunnel upgrade.
// We:
//
//  1. Pull the session cookie out of the request and look it up. A
//     missing or unknown cookie returns 401, ending the connection.
//  2. Resolve the identity (per-device /128, MTU) via the injected
//     Resolver. A resolver error returns 502 so the client surfaces a
//     distinct failure mode and does not loop on a bad cookie.
//  3. Compute the inner MTU from the X-CSTP-Base-MTU / X-CSTP-MTU
//     headers per spec §1.7.
//  4. Derive the DTLS PSK from the outer TLS via the RFC 5705 keying
//     material exporter and advertise it via X-DTLS-Master-Secret etc.
//     A failure of the exporter (caller did not pass a *tls.Conn capable
//     of exporting, e.g. the raw test path) downgrades to TCP-only and
//     omits the X-DTLS-* headers.
//  5. Emit the full X-CSTP-* / X-DTLS-* header set, hijack the conn, and
//     publish the Tunnel on s.tunnels.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	cookie := extractWebVPNCookie(r)
	sess := s.sessions.lookupToken(cookie)
	if sess == nil {
		w.Header().Set("Connection", "close")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	id, err := s.cfg.Resolver.Resolve(r.Context(), sess.deviceID)
	if err != nil {
		http.Error(w, "identity resolve failed", http.StatusBadGateway)
		return
	}

	mtu := id.MTU
	if mtu <= 0 {
		mtu = s.cfg.DefaultMTU
	}
	innerMTU := negotiateInnerMTU(r, mtu)

	headers := w.Header()
	emitCSTPHeaders(headers, s.cfg, id, innerMTU)
	// iOS Cisco Secure Client requires an EXPLICIT IPv6 split-include route to
	// actually install an IPv6 route and pass v6 traffic — a tunnel-all config
	// alone is not enough. Without it the (v6-primary) tunnel comes up but
	// carries no IPv6, the post-connect connectivity check fails, and the
	// client tears down with "Reconnecting the VPN tunnel" in a loop. Stock
	// ocserv emits exactly this for is_ios + full-ipv6 + default-route clients
	// (worker-vpn.c: "Anyconnect on IOS requires this route in order to use
	// IPv6"). 2000::/3 is the entire global-unicast v6 block, so this remains
	// effectively tunnel-all for v6.
	if id.IPv6.IsValid() && iosUserAgent(r) &&
		strings.EqualFold(r.Header.Get("X-CSTP-Full-IPv6-Capability"), "true") {
		headers.Add("X-CSTP-Split-Include-IP6", "2000::/3")
		// 64:ff9b::/96 is the NAT64 well-known prefix. With a DNS64 resolver,
		// v4-only domains resolve to 64:ff9b::<v4>, which lies OUTSIDE 2000::/3,
		// so it needs its own split-include route to travel through the tunnel
		// -> host NAT64 -> v4. (CLAT still covers bare v4 literals via the inner
		// v4 lease + SIIT; this adds the DNS64 path for v4-only hostnames.)
		headers.Add("X-CSTP-Split-Include-IP6", "64:ff9b::/96")
	}
	// Honor the client's address-family request (ocserv no_ipv4): a client that
	// asked for IPv6-only gets no inner v4 lease.
	if clientSuppressedV4(r) {
		headers.Del("X-CSTP-Address")
		headers.Del("X-CSTP-Netmask")
	}
	// NOTE: we deliberately emit NO IPv4 split route. The iOS Cisco Secure Client
	// rejects ANY v4 route customization ("invalid configuration") when the inner
	// lease is a /32 — there is no on-link v4 subnet to anchor split routes on.
	// Both a 27-prefix split-include and a 4-entry split-exclude were rejected on
	// the wire. Stock ocserv's proven apple-ios config also leaves v4 as tunnel-
	// all (its `route` directives are commented out). So v4 stays plain 0.0.0.0/0
	// tunnel-all; iOS keeps loopback/link-local/multicast on the local link by
	// itself. See iosV4SplitExclude for the set to use on a /24-lease/non-iOS path.
	// DTLS advertisement. Suppressed entirely when DTLSDisabled so the client
	// runs its data plane over CSTP/TLS (TCP) only — the diagnostic/fallback
	// path for edges where the DTLS-over-UDP leg cannot round-trip.
	var tunnelDTLS *dtlsBindingState
	if !s.cfg.DTLSDisabled {
		if s.cfg.DTLSBindingInstaller != nil && s.cfg.DTLSBindingSource != nil {
			if binding, ok := s.cfg.DTLSBindingSource(r, id); ok {
				// The facade routes the absolute AnyConnect CONNECT via its control
				// handler with a SENTINEL handoff (all-zero token, stub source-v6);
				// re-derive identity from the authenticated session (the facade
				// BindingStore rejects an all-zero token; source-v6 must be the
				// device's real inner /128).
				binding.Token = sessionBindingToken(sess.token)
				if a := id.IPv6.Addr(); a.IsValid() {
					binding.SourceV6 = a
				}
				// Cisco AnyConnect / iOS DTLS uses LEGACY injected-premaster
				// RESUMPTION (NOT PSK-NEGOTIATE, which iOS never offers): the client
				// supplies a 48-byte master secret in the CONNECT request; we echo a
				// 32-byte Session-ID + a real cipher; the facade's pion dtls.Server
				// resumes the DTLS session with that master secret (via a SessionStore
				// == gnutls_session_set_premaster). Publish all three to the binding so
				// the facade can drive the abbreviated handshake.
				master, mok := parseClientMasterSecret(r)
				ocName, cok := selectDTLSCipher(r)
				if mok && cok {
					rr := s.cfg.RandRead
					if rr == nil {
						rr = rand.Read
					}
					var sid [32]byte
					if _, rerr := rr(sid[:]); rerr == nil {
						binding.DTLSMasterSecret = master
						binding.DTLSSessionID = sid
						binding.DTLSCipher = ocName
						if err := s.cfg.DTLSBindingInstaller.Upsert(r.Context(), binding); err == nil {
							emitLegacyDTLSHeaders(headers, ocName, sid[:], innerMTU)
							tunnelDTLS = &dtlsBindingState{
								installer:       s.cfg.DTLSBindingInstaller,
								binding:         binding,
								refreshInterval: s.cfg.DTLSBindingRefreshInterval,
							}
						}
					}
				}
			}
		}
	}

	// http.ResponseWriter ignores 200 on CONNECT by default; we
	// upgrade it manually to "200 CONNECTED" the way real ocserv does.
	conn, rw, err := hijack(w)
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	if err := writeConnectResponse(rw, headers); err != nil {
		_ = conn.Close()
		return
	}

	// Do NOT consume (delete) the session cookie on CONNECT. Cisco Secure
	// Client's normal lifecycle is a TWO-PHASE connect: it brings the tunnel
	// up, immediately sends AC_PKT_DISCONN "Reconnecting the VPN tunnel", then
	// re-CONNECTs with the SAME cached webvpn cookie (no re-auth). Consuming the
	// cookie on the first CONNECT made that reconnect's CONNECT return 401
	// (token gone) -> the client surfaces "secure gateway has rejected the
	// connection" and loops until it gives up. Stock ocserv keeps the cookie
	// valid and reusable for the session lifetime (it refreshes exptime /
	// increments in_use rather than deleting). We keep the row until its TTL
	// (SessionTimeout) or explicit teardown; lookupToken reaps expired rows.
	// The bridge displaces any prior tunnel for the same /128, so the reconnect
	// cleanly replaces the old tunnel without a leak.
	s.sessions.touch(sess)
	t := s.newTunnel(conn, rw, id, sess.token, tunnelDTLS)
	select {
	case s.tunnels <- t:
	case <-s.closeCh:
		_ = t.Close()
		return
	}
}

// sessionBindingToken derives a stable, non-zero 12-byte token for the
// shared-edge DTLS binding from the authenticated webvpn session cookie. The
// real 12-byte ERA apex token only rides the per-device auth handoff, not the
// facade's sentinel CONNECT handoff, but the facade's BindingStore.Upsert
// rejects an all-zero token. This value is non-zero and per-session-stable
// (so binding refreshes are idempotent); the binding's security is the
// source-IP gate plus the random PSK — the token field is identity/audit only.
func sessionBindingToken(cookie string) [12]byte {
	var t [12]byte
	sum := sha256.Sum256([]byte(cookie))
	copy(t[:], sum[:12])
	return t
}

// extractWebVPNCookie pulls the AnyConnect session cookie out of the
// CONNECT request. Cisco Secure Client sends it as a "webvpn" cookie;
// OpenConnect uses an X-CSTP-Cookie header on some paths. We accept
// either.
func extractWebVPNCookie(r *http.Request) string {
	if c, err := r.Cookie("webvpn"); err == nil && c.Value != "" {
		return c.Value
	}
	if v := r.Header.Get("X-CSTP-Cookie"); v != "" {
		return v
	}
	// Cisco Secure Client mobile sometimes uses "Cookie: webvpn=..."
	// without the standard cookie parser-friendly form; fall back to
	// manual scan.
	for _, h := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(h, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "webvpn=") {
				return strings.TrimPrefix(part, "webvpn=")
			}
		}
	}
	return ""
}

// clatInnerMTUCap is the upper bound on the advertised inner MTU. It is the
// IPv6 outbound MTU (1420) minus the 20-byte SIIT46 v4->v6 header growth, so
// a 1400-byte inner v4 packet (CLAT path) translates to a 1420-byte v6 packet
// that still fits the external 464PLAT egress without fragmentation. It is
// equally safe for the native v6 inner path (1400 <= 1420). The client's
// X-CSTP-Base-MTU stays 1500.
const clatInnerMTUCap = 1400

// negotiateInnerMTU computes the inner-frame MTU from the client's
// declared base + preferred MTUs per spec §1.7, capped at the per-
// device configured MTU and at clatInnerMTUCap (so neither the v4 CLAT nor
// the native v6 inner path fragments post-translation). Missing headers fall
// back to defaults.
func negotiateInnerMTU(r *http.Request, deviceMTU int) int {
	baseMTU := atoiDefault(r.Header.Get("X-CSTP-Base-MTU"), 1500)
	want := atoiDefault(r.Header.Get("X-CSTP-MTU"), deviceMTU)
	// inner = base - ~80 (TLS record + CSTP header + AEAD overhead +
	// safety pad). We use the spec's documented approximation.
	innerFromBase := baseMTU - 80
	if innerFromBase < 576 {
		innerFromBase = 576
	}
	// pick the smallest of (client's preferred, base-derived,
	// device-configured), bounded below by 576 (the RFC 791 minimum
	// reassembly buffer that any IPv4 host accepts).
	result := innerFromBase
	if want > 0 && want < result {
		result = want
	}
	if deviceMTU > 0 && deviceMTU < result {
		result = deviceMTU
	}
	// Cap at the SIIT-safe ceiling so a full-MTU inner v4 packet still fits
	// the v6 egress after the 20-byte header growth.
	if result > clatInnerMTUCap {
		result = clatInnerMTUCap
	}
	if result < 576 {
		result = 576
	}
	return result
}

func atoiDefault(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

// ClatPlaceholderV4 is the inner IPv4 address advertised to every AnyConnect
// client (X-CSTP-Address) and used as the SIIT/CLAT translation source in the
// data-plane bridge (cmd/era-ocserv/bridge.go references this same var so the
// wire address and the SIIT source can never drift). 192.0.0.1 is the RFC 7335
// §4 IPv4 Service-Continuity / CLAT address. (We earlier switched to a private
// 172.23.115.2 after a suspected collision with the iOS system CLAT, but that
// reassert was a FACADE-path observation — the facade looped for unrelated
// reasons — so we are re-validating the RFC-standard address on the clean path.)
var ClatPlaceholderV4 = netip.MustParseAddr("192.0.0.1")

// ClatPlaceholderV4Netmask is the subnet mask advertised with ClatPlaceholderV4.
// /32 mirrors the v6 /128 point-to-point model: no on-link subnet, all v4 via
// the default route. (The earlier "/32 loops, use /24" note was also a
// facade-path observation; re-validating /32 on the clean direct path.)
const ClatPlaceholderV4Netmask = "255.255.255.255"

// iosV4SplitExclude is the set of special-use IPv4 ranges that ideally would not
// be tunnelled — 0.0.0.0/8 (this-network), 127.0.0.0/8 (loopback),
// 169.254.0.0/16 (link-local), 224.0.0.0/3 (multicast + reserved). It is
// intentionally NOT emitted today (see handleConnect): the iOS Cisco Secure
// Client rejects any v4 split route — include OR exclude — when the inner lease
// is a /32, because there is no on-link v4 subnet to anchor split routes on. We
// advertise plain 0.0.0.0/0 tunnel-all for v4 (matching stock ocserv's apple-ios
// config) and iOS keeps loopback/link-local/multicast local on its own. Retained
// for a future /24-lease or non-iOS (desktop) emit path via X-CSTP-Split-Exclude.
var iosV4SplitExclude = []string{
	"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3",
}

// referenced to keep iosV4SplitExclude live for the documented future emit path
// without an unused-var lint; the slice itself carries the canonical set.
var _ = iosV4SplitExclude

// clientSuppressedV4 reports whether the client asked NOT to be given an inner
// IPv4 (X-CSTP-Address-Type without "IPv4"), mirroring ocserv's no_ipv4 gate
// (worker-http.c:620-624). The iPhone sends "IPv6,IPv4" so it gets v4.
func clientSuppressedV4(r *http.Request) bool {
	at := r.Header.Get("X-CSTP-Address-Type")
	return at != "" && !strings.Contains(at, "IPv4")
}

// emitCSTPHeaders sets the X-CSTP-* header bag on w for the 200
// CONNECTED response. The header set matches protocol doc §1.6.
func emitCSTPHeaders(h http.Header, cfg Config, id Identity, innerMTU int) {
	h.Set("X-CSTP-Version", "1")
	// X-CSTP-Server-Name is how Cisco Secure Client recognises the gateway
	// family; stock ocserv sends "OpenConnect VPN Server" (PACKAGE_NAME) as the
	// second header. The non-standard X-CSTP-Server-Version we used before is
	// not a header the iOS client defines, so a strict client can fail its
	// gateway-identity check. Match stock.
	h.Set("X-CSTP-Server-Name", "OpenConnect VPN Server")

	if id.IPv6.IsValid() {
		// X-CSTP-Address-IP6 is the device's inner IPv6 as a /128 host lease —
		// matching stock ocserv's default ipv6-subnet-prefix (128) and the
		// apple-ios test config the iOS client is validated against. A /64 would
		// tell iOS the whole pool /64 is ON-LINK, so it does Neighbor Discovery
		// for in-/64 destinations that this /128 point-to-point tun never
		// answers — black-holing v6 and failing iOS's post-connect reachability
		// check ("Reconnecting the VPN tunnel"). With no on-link subnet iOS
		// routes ALL global v6 via the tunnel route we advertise as
		// X-CSTP-Split-Include-IP6: 2000::/3 (handleConnect). The /128 is what
		// the reconciler routes on the server side.
		h.Set("X-CSTP-Address-IP6", id.IPv6.Addr().String()+"/128")
	}

	// CLAT inner source: every client receives the same inner IPv4. era-ocserv's
	// stateless SIIT data plane (internal/clatxlat) translates this inner v4
	// to/from 64:ff9b::<v4dst> sourced from the device's CLAT /128. We advertise
	// the RFC 7335 §4 standard CLAT address 192.0.0.1/32 (see ClatPlaceholderV4).
	// NOTE: on a 464XLAT carrier the iOS system CLAT may itself bind 192.0.0.1 —
	// historically suspected to cause a duplicate-address reassert, but that was
	// observed via the facade (which looped independently); validating here.
	h.Set("X-CSTP-Address", ClatPlaceholderV4.String())
	h.Set("X-CSTP-Netmask", ClatPlaceholderV4Netmask)

	if cfg.ServerName != "" {
		h.Set("X-CSTP-Hostname", cfg.ServerName)
	}
	if cfg.DefaultDomain != "" {
		h.Set("X-CSTP-Default-Domain", cfg.DefaultDomain)
	}
	for _, dns := range cfg.DNS {
		// Cisco Secure Client (AnyConnect) requires IPv6 DNS servers in
		// X-CSTP-DNS-IP6; an IPv6 literal placed in plain X-CSTP-DNS is parsed as
		// IPv4, fails validation, and makes the iOS client reject the WHOLE tunnel
		// config ("The VPN configuration received from the secure gateway is
		// invalid"). Stock ocserv branches exactly this way for AnyConnect agents
		// (worker-vpn.c: ip6 ? "DNS-IP6" : "DNS"). OpenConnect accepts either.
		if dns.Is4() {
			h.Add("X-CSTP-DNS", dns.String())
		} else {
			h.Add("X-CSTP-DNS-IP6", dns.String())
		}
	}
	for _, sp := range cfg.SplitInclude {
		// Same IPv4/IPv6 split as DNS: IPv6 routes go in the -IP6 variant.
		if sp.Addr().Is4() {
			h.Add("X-CSTP-Split-Include", sp.String())
		} else {
			h.Add("X-CSTP-Split-Include-IP6", sp.String())
		}
	}

	h.Set("X-CSTP-DPD", strconv.Itoa(cfg.DPDInterval))
	h.Set("X-CSTP-Keepalive", strconv.Itoa(cfg.KeepaliveInterval))
	if cfg.IdleTimeout > 0 {
		h.Set("X-CSTP-Idle-Timeout", strconv.Itoa(cfg.IdleTimeout))
	} else {
		h.Set("X-CSTP-Idle-Timeout", "none")
	}
	// Values below mirror stock ocserv's cstp config block (worker-vpn.c)
	// verbatim — "none" sentinels, not "0" — since that is what the iOS
	// client is validated against.
	h.Set("X-CSTP-Session-Timeout", "none")
	// X-CSTP-Keep: keep the tunnel established across transient drops.
	// Stock ocserv always emits this; the iOS client expects it.
	h.Set("X-CSTP-Keep", "true")
	h.Set("X-CSTP-TCP-Keepalive", "true")
	h.Set("X-CSTP-MTU", strconv.Itoa(innerMTU))
	h.Set("X-CSTP-Base-MTU", "1500")
	h.Set("X-CSTP-Tunnel-All-DNS", "true")
	// Stock ocserv always emits Client-Bypass-Protocol; it tells the client how
	// to treat the address family that is NOT tunnelled. "false" = no local
	// bypass (consistent with our tunnel-all design). Its absence leaves a
	// strict client's v4-vs-v6 disposition ambiguous on this v6-primary tunnel.
	h.Set("X-CSTP-Client-Bypass-Protocol", "false")
	h.Set("X-CSTP-Smartcard-Removal-Disconnect", "true")
	h.Set("X-CSTP-License", "accept")
	h.Set("X-CSTP-DynDNS", "true")
	h.Set("X-CSTP-Rekey-Time", "28800")
	// Rekey-Method "ssl" promises an in-place TLS rehandshake to rekey the
	// session — but era's data plane is Go crypto/tls, whose SERVER side cannot
	// renegotiate at all, so "ssl" is an un-honorable tunnel parameter. iOS
	// Cisco Secure Client records the advertised rekey method as a parameter it
	// must honor; finding the server cannot do an SSL rekey it self-terminates
	// with a config-apply reconfigure (termination reason "4h") ~150ms after
	// Connected and auto-reconnects, looping. Stock ocserv gates this on safe
	// TLS renegotiation and downgrades to "new-tunnel" when unavailable
	// (worker-vpn.c:2275-2284) — which for a Go TLS server is always. We rekey
	// by reconnecting (which we CAN do), so always advertise "new-tunnel".
	h.Set("X-CSTP-Rekey-Method", "new-tunnel")
	h.Set("X-CSTP-Disconnected-Timeout", "none")
}

// iosUserAgent reports whether the CONNECT request comes from Cisco Secure
// Client on an Apple mobile OS. Stock ocserv (worker-vpn.c) special-cases
// these clients; the User-Agent is e.g.
// "Cisco AnyConnect VPN Agent for Apple iPhone 5.1.16.264".
func iosUserAgent(r *http.Request) bool {
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	return strings.Contains(ua, "apple") || strings.Contains(ua, "iphone") ||
		strings.Contains(ua, "ipad") || strings.Contains(ua, "ios")
}

// emitLegacyDTLSHeaders advertises Cisco AnyConnect's LEGACY DTLS — the mode the
// iOS Cisco Secure Client actually speaks (it never offers PSK-NEGOTIATE). Stock
// ocserv (src/worker-vpn.c, legacy branch) echoes a Session-ID + the chosen real
// cipher; the client pre-seeded its DTLS session with the 48-byte master secret
// it sent in X-Dtls-Master-Secret, so the handshake is an abbreviated resumption
// (the facade's pion dtls.Server resumes it via a SessionStore == ocserv's
// gnutls_session_set_premaster). We consume the client's master secret (do NOT
// echo it) and never send PSK-NEGOTIATE / X-DTLS-App-ID. Header casing is fixed
// on the wire by connectWireHeaderKey (iOS is case-sensitive). X-DTLS-MTU is set
// == X-CSTP-MTU so iOS never tears down to reconfigure its tun.
func emitLegacyDTLSHeaders(h http.Header, ocName string, sessionID []byte, mtu int) {
	h.Set("X-DTLS-Session-ID", hex.EncodeToString(sessionID)) // 64 hex = 32 bytes
	h.Set("X-DTLS12-CipherSuite", ocName)
	h.Set("X-DTLS-MTU", strconv.Itoa(mtu)) // == X-CSTP-MTU so iOS never New-MTU-reconfigures
	h.Set("X-DTLS-Port", "443")
	h.Set("X-DTLS-Keepalive", "20")
	h.Set("X-DTLS-DPD", "30")
	h.Set("X-DTLS-Rekey-Time", "28810")
	// Go's TLS cannot renegotiate in place; rekey by reconnect (matches X-CSTP-Rekey-Method).
	h.Set("X-DTLS-Rekey-Method", "new-tunnel")
}

// parseClientMasterSecret extracts the AnyConnect client's 48-byte DTLS master
// secret from the X-Dtls-Master-Secret request header (96 hex chars). The client
// generates it; the server consumes it as the resumed DTLS session's keying
// material (it is NOT echoed back).
func parseClientMasterSecret(r *http.Request) ([48]byte, bool) {
	var ms [48]byte
	v := strings.TrimSpace(r.Header.Get("X-Dtls-Master-Secret"))
	if len(v) != 96 {
		return ms, false
	}
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != 48 {
		return ms, false
	}
	copy(ms[:], b)
	return ms, true
}

// dtlsCipherPrefs is the server-preference-ordered set of DTLS 1.2 ciphers the
// facade's pion dtls.Server can terminate (by ocserv oc_name). We prefer
// ECDHE-RSA-AES128-GCM-SHA256 — offered by the iOS Cisco Secure Client and
// shipped by pion (its ECDHE/cert part is vestigial on a resumed handshake).
var dtlsCipherPrefs = []string{
	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384",
}

// selectDTLSCipher picks the highest-preference cipher the client offered in its
// X-Dtls12-Ciphersuite (DTLS 1.2) request header that the facade can terminate.
func selectDTLSCipher(r *http.Request) (string, bool) {
	offered := map[string]bool{}
	for _, hv := range r.Header.Values("X-Dtls12-Ciphersuite") {
		for _, tok := range strings.Split(hv, ":") {
			offered[strings.TrimSpace(tok)] = true
		}
	}
	for _, c := range dtlsCipherPrefs {
		if offered[c] {
			return c, true
		}
	}
	return "", false
}

func dtlsAddressForRequest(r *http.Request, cfg Config) string {
	if r != nil {
		host := strings.TrimSpace(r.Host)
		if host != "" {
			if parsedHost, _, err := net.SplitHostPort(host); err == nil {
				return parsedHost
			}
			return host
		}
	}
	return strings.TrimSpace(cfg.ServerName)
}

// writeConnectResponse manually writes the 200 CONNECTED HTTP/1.1
// status line and headers onto the hijacked conn. We can't use the
// http package's response writer here because it has already returned;
// we need to drop into raw bytes to terminate the response properly.
func writeConnectResponse(rw io.Writer, h http.Header) error {
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 200 CONNECTED\r\n")
	// Emit single-valued X-CSTP-* headers through this exact-cased ordered
	// list. This is NOT just cosmetic: Cisco Secure Client (iOS) is
	// case-SENSITIVE on these header names and silently rejects the whole
	// tunnel config ("secure gateway has rejected the connection") when it
	// cannot find them under the precise Cisco casing. Go's http.Header
	// canonicalises keys (X-CSTP- -> X-Cstp-, DNS -> Dns, DynDNS -> Dyndns),
	// so any X-CSTP-* header left to the generic map-iteration path below
	// leaks onto the wire mis-cased. Keep this list aligned with the
	// h.Set(...) keys in emitCSTPHeaders and with stock ocserv's casing
	// (ocserv-src worker-vpn.c), which the iOS client accepts.
	well := []string{
		"X-CSTP-Version",
		"X-CSTP-Server-Name",
		"X-CSTP-Hostname",
		"X-CSTP-Default-Domain",
		"X-CSTP-Address",
		"X-CSTP-Netmask",
		"X-CSTP-Address-IP6",
		"X-CSTP-MTU",
		"X-CSTP-Base-MTU",
		"X-CSTP-DPD",
		"X-CSTP-Keepalive",
		"X-CSTP-Idle-Timeout",
		"X-CSTP-Session-Timeout",
		"X-CSTP-Disconnected-Timeout",
		"X-CSTP-Keep",
		"X-CSTP-TCP-Keepalive",
		"X-CSTP-Tunnel-All-DNS",
		"X-CSTP-Client-Bypass-Protocol",
		"X-CSTP-Rekey-Time",
		"X-CSTP-Rekey-Method",
		"X-CSTP-License",
		"X-CSTP-DynDNS",
		"X-CSTP-Smartcard-Removal-Disconnect",
	}
	emitted := make(map[string]bool, len(well))
	for _, k := range well {
		if vs := h.Values(k); len(vs) > 0 {
			for _, v := range vs {
				fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
			}
			// Mark as emitted under the CANONICAL key, because the range below
			// iterates the map whose keys are canonicalised (e.g. "X-Cstp-Version").
			// Without this the well-known headers are emitted a SECOND time in
			// Go's casing, producing duplicate X-CSTP-* headers in two casings —
			// which a strict client can choke on.
			emitted[http.CanonicalHeaderKey(k)] = true
		}
	}
	for k, vs := range h {
		if emitted[k] {
			continue
		}
		wireKey := connectWireHeaderKey(k)
		for _, v := range vs {
			fmt.Fprintf(&sb, "%s: %s\r\n", wireKey, v)
		}
	}
	sb.WriteString("\r\n")
	_, err := io.WriteString(rw, sb.String())
	if bw, ok := rw.(*bufio.ReadWriter); ok {
		_ = bw.Flush()
	} else if bw, ok := rw.(interface{ Flush() error }); ok {
		_ = bw.Flush()
	}
	return err
}

func connectWireHeaderKey(k string) string {
	switch k {
	case "X-Dtls-Address":
		return "X-DTLS-Address"
	case "X-Dtls-Port":
		return "X-DTLS-Port"
	case "X-Dtls-Ciphersuite":
		return "X-DTLS-CipherSuite"
	case "X-Dtls12-Ciphersuite":
		return "X-DTLS12-CipherSuite"
	case "X-Dtls-Master-Secret":
		return "X-DTLS-Master-Secret"
	case "X-Dtls-Session-Id":
		return "X-DTLS-Session-ID"
	case "X-Dtls-App-Id":
		return "X-DTLS-App-ID"
	case "X-Dtls-Rekey-Time":
		return "X-DTLS-Rekey-Time"
	case "X-Dtls-Rekey-Method":
		return "X-DTLS-Rekey-Method"
	case "X-Dtls-Keepalive":
		return "X-DTLS-Keepalive"
	case "X-Dtls-Dpd":
		return "X-DTLS-DPD"
	case "X-Dtls-Mtu":
		return "X-DTLS-MTU"
	case "X-Cstp-Server-Cert-Hash":
		return "X-CSTP-Server-Cert-Hash"
	case "X-Cstp-Dns":
		return "X-CSTP-DNS"
	case "X-Cstp-Dns-Ip6":
		return "X-CSTP-DNS-IP6"
	case "X-Cstp-Split-Include":
		return "X-CSTP-Split-Include"
	case "X-Cstp-Split-Include-Ip6":
		return "X-CSTP-Split-Include-IP6"
	case "X-Cstp-Split-Exclude":
		return "X-CSTP-Split-Exclude"
	case "X-Cstp-Split-Exclude-Ip6":
		return "X-CSTP-Split-Exclude-IP6"
	default:
		return k
	}
}

// serverCertHashBase64 is exposed for callers that want to compute the
// X-CSTP-Server-Cert-Hash advertisement out-of-band. The CSTP package
// does not own the cert; era-ocserv main wires this in if needed.
func serverCertHashBase64(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// parsePrefix is a tiny helper used by tests to construct
// netip.Prefix values without importing netip themselves.
func parsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p, nil
}
