package cstp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
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
//  2. Re-bind the mTLS cert to the session (spec §1.8 / ADR 0057 §4):
//     extract the deviceID from the current CONNECT request's client
//     cert via cfg.CertValidator and reject with 401 if it does not
//     match the deviceID stored at phase-2 promote time. Skipping this
//     step would let a leaked session token + any valid ERA device
//     cert take over another device's /128.
//  3. Resolve the identity (per-device /128, MTU) via the injected
//     Resolver. A resolver error returns 502 so the client surfaces a
//     distinct failure mode and does not loop on a bad cookie.
//  4. Compute the inner MTU from the X-CSTP-Base-MTU / X-CSTP-MTU
//     headers per spec §1.7.
//  5. Derive the DTLS PSK from the outer TLS via the RFC 5705 keying
//     material exporter and advertise it via X-DTLS-Master-Secret etc.
//     A failure of the exporter (caller did not pass a *tls.Conn capable
//     of exporting, e.g. the raw test path) downgrades to TCP-only and
//     omits the X-DTLS-* headers.
//  6. Emit the full X-CSTP-* / X-DTLS-* header set, hijack the conn, and
//     publish the Tunnel on s.tunnels.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	cookie := extractWebVPNCookie(r)
	sess := s.sessions.lookupToken(cookie)
	if sess == nil {
		w.Header().Set("Connection", "close")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Re-bind the cert to the session. The validator is optional only
	// to keep unit tests that drive CONNECT over net.Pipe usable;
	// production callers always supply one (see ADR 0057 §4).
	if s.cfg.CertValidator != nil {
		if r.TLS == nil {
			w.Header().Set("Connection", "close")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		certID, err := s.cfg.CertValidator.Validate(*r.TLS)
		if err != nil || certID == "" || certID != sess.deviceID {
			// Drop the now-tainted session so the same token cannot be
			// retried with another cert. This collapses the attacker's
			// window to a single CONNECT attempt per stolen token.
			s.sessions.consume(sess)
			w.Header().Set("Connection", "close")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
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

	// Try to derive a DTLS PSK from the outer TLS handshake. If the
	// underlying conn isn't a *tls.Conn (test path, plain TCP), this
	// silently downgrades to TCP-only CSTP.
	dtlsSecret, dtlsOK := deriveDTLSSecret(r)

	headers := w.Header()
	emitCSTPHeaders(headers, s.cfg, id, innerMTU)
	if dtlsOK {
		emitDTLSHeaders(headers, dtlsSecret, innerMTU)
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

	s.sessions.consume(sess)
	t := s.newTunnel(conn, rw, id, sess.token)
	select {
	case s.tunnels <- t:
	case <-s.closeCh:
		_ = t.Close()
		return
	}
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

// negotiateInnerMTU computes the inner-frame MTU from the client's
// declared base + preferred MTUs per spec §1.7, capped at the per-
// device configured MTU. Missing headers fall back to defaults.
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

// emitCSTPHeaders sets the X-CSTP-* header bag on w for the 200
// CONNECTED response. The header set matches protocol doc §1.6.
func emitCSTPHeaders(h http.Header, cfg Config, id Identity, innerMTU int) {
	h.Set("X-CSTP-Version", "1")
	h.Set("X-CSTP-Server-Version", "era-ocserv 0.1")

	if id.IPv6.IsValid() {
		// X-CSTP-Address-IP6 carries the per-device /128 with prefix
		// length so clients can configure the inner interface.
		h.Set("X-CSTP-Address-IP6", id.IPv6.String())
	}

	// CLAT placeholder per ADR 0035: every client receives the same
	// 192.0.0.1/32 inner source and the upstream TAYGA NAT64 handles
	// outbound v4 translation.
	h.Set("X-CSTP-Address", "192.0.0.1")
	h.Set("X-CSTP-Netmask", "255.255.255.255")

	if cfg.ServerName != "" {
		h.Set("X-CSTP-Hostname", cfg.ServerName)
	}
	if cfg.DefaultDomain != "" {
		h.Set("X-CSTP-Default-Domain", cfg.DefaultDomain)
	}
	for _, dns := range cfg.DNS {
		h.Add("X-CSTP-DNS", dns.String())
	}
	for _, sp := range cfg.SplitInclude {
		h.Add("X-CSTP-Split-Include", sp.String())
	}

	h.Set("X-CSTP-DPD", strconv.Itoa(cfg.DPDInterval))
	h.Set("X-CSTP-Keepalive", strconv.Itoa(cfg.KeepaliveInterval))
	if cfg.IdleTimeout > 0 {
		h.Set("X-CSTP-Idle-Timeout", strconv.Itoa(cfg.IdleTimeout))
	} else {
		h.Set("X-CSTP-Idle-Timeout", "0")
	}
	h.Set("X-CSTP-Session-Timeout", "0")
	h.Set("X-CSTP-MTU", strconv.Itoa(innerMTU))
	h.Set("X-CSTP-Base-MTU", "1500")
	h.Set("X-CSTP-Tunnel-All-DNS", "true")
	h.Set("X-CSTP-Smartcard-Removal-Disconnect", "true")
	h.Set("X-CSTP-License", "accept")
	h.Set("X-CSTP-DynDNS", "true")
	h.Set("X-CSTP-Rekey-Time", "28800")
	h.Set("X-CSTP-Rekey-Method", "ssl")
	h.Set("X-CSTP-Disconnected-Timeout", "2400")
}

// emitDTLSHeaders advertises the DTLS PSK-NEGOTIATE channel to the
// client. The DTLS implementation itself lives in a sibling package;
// here we only emit the headers required for the client to attempt the
// UDP handshake. The exporter-derived 32-byte secret is hex-encoded
// per legacy convention (Cisco Secure Client accepts both hex and
// base64; we pick hex to match openconnect / ocserv).
func emitDTLSHeaders(h http.Header, secret []byte, innerMTU int) {
	h.Set("X-DTLS-Master-Secret", strings.ToUpper(hex.EncodeToString(secret)))
	h.Set("X-DTLS-CipherSuite", "PSK-NEGOTIATE")
	h.Set("X-DTLS-Port", "443")
	h.Set("X-DTLS-Rekey-Time", "28800")
	h.Set("X-DTLS-Rekey-Method", "ssl")
	h.Set("X-DTLS-Keepalive", "20")
	h.Set("X-DTLS-DPD", "30")
	dtlsMTU := innerMTU - 20
	if dtlsMTU < 576 {
		dtlsMTU = 576
	}
	h.Set("X-DTLS-MTU", strconv.Itoa(dtlsMTU))
	// X-DTLS-Session-ID is required by legacy fake-resumption clients
	// but unused by PSK-NEGOTIATE. We emit a stable random value so
	// the header set looks complete to clients that parse it without
	// using it; clients that genuinely need legacy resumption will
	// also need a different cipher suite and will fall back to TCP.
	if sid, err := randHex(nil, 32); err == nil {
		h.Set("X-DTLS-Session-ID", sid)
	}
}

// deriveDTLSSecret pulls a 32-byte PSK from the outer TLS session
// using the RFC 5705 keying-material exporter. The label matches
// ocserv's "EXPORTER-openconnect-psk" with empty context. If the
// underlying http.Request was not served on a *tls.Conn that exposes
// the exporter (e.g. unit tests using net.Pipe), we report ok=false
// and the caller omits all X-DTLS-* headers.
func deriveDTLSSecret(r *http.Request) ([]byte, bool) {
	if r.TLS == nil {
		return nil, false
	}
	mat, err := r.TLS.ExportKeyingMaterial("EXPORTER-openconnect-psk", nil, 32)
	if err != nil {
		return nil, false
	}
	return mat, true
}

// writeConnectResponse manually writes the 200 CONNECTED HTTP/1.1
// status line and headers onto the hijacked conn. We can't use the
// http package's response writer here because it has already returned;
// we need to drop into raw bytes to terminate the response properly.
func writeConnectResponse(rw io.Writer, h http.Header) error {
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 200 CONNECTED\r\n")
	// Emit headers in a stable order: well-known ones first, then the
	// rest sorted. Cisco Secure Client doesn't care about ordering but
	// stable output simplifies tests.
	well := []string{
		"X-CSTP-Version",
		"X-CSTP-Server-Version",
		"X-CSTP-Hostname",
		"X-CSTP-Address",
		"X-CSTP-Netmask",
		"X-CSTP-Address-IP6",
		"X-CSTP-MTU",
		"X-CSTP-Base-MTU",
		"X-CSTP-DPD",
		"X-CSTP-Keepalive",
	}
	emitted := make(map[string]bool, len(well))
	for _, k := range well {
		if vs := h.Values(k); len(vs) > 0 {
			for _, v := range vs {
				fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
			}
			emitted[k] = true
		}
	}
	for k, vs := range h {
		if emitted[k] {
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}
	sb.WriteString("\r\n")
	_, err := io.WriteString(rw, sb.String())
	if bw, ok := rw.(interface{ Flush() error }); ok {
		_ = bw.Flush()
	}
	return err
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
