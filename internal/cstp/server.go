package cstp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// webVPNContextCookie is the session-tracking cookie name stock ocserv uses on
// the simple (non-aggregate) auth path. Cisco Secure Client's simple path
// carries the pre-auth session in this cookie rather than echoing the XML
// <opaque>, so we set it on every auth-request response and read it back when
// the auth-reply arrives without a body opaque.
const webVPNContextCookie = "webvpncontext"

// setWebVPNContext sets the pre-auth session cookie carrying the opaque id, so a
// form-posting client (Cisco Secure Client simple path) round-trips the session
// across the username and password steps. Max-Age mirrors the opaque TTL.
func setWebVPNContext(w http.ResponseWriter, opaqueID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     webVPNContextCookie,
		Value:    opaqueID,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		MaxAge:   300,
	})
}

// parseAuthReply reads a phase-2b auth-reply that may arrive either as the
// AnyConnect XML <config-auth> envelope (OpenConnect, and Cisco's aggregate
// path) OR as an application/x-www-form-urlencoded body (Cisco Secure Client's
// SIMPLE auth path, e.g. "username=alice" then "password=secret"). The body is
// classified by its first non-space byte: '<' => XML, otherwise form. Form
// bodies carry no <opaque>, so the caller falls back to the webvpncontext
// cookie for the session.
func parseAuthReply(r *http.Request) (parsedAuth, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		return parsedAuth{}, errInvalidXML
	}
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "<") {
		return parseAuthRequest(strings.NewReader(trimmed))
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return parsedAuth{}, errInvalidXML
	}
	return parsedAuth{
		Type:     authTypeAuthReply,
		Username: vals.Get("username"),
		Password: vals.Get("password"),
	}, nil
}

// ServeHTTP routes CSTP control-plane requests:
//
//   - POST  /                  -> phase 2a init or reconnect probe
//   - POST  /auth              -> phase 2b auth-reply / 2c complete
//   - CONNECT /CSCOSSLC/tunnel -> phase 3 tunnel upgrade
//
// Anything else returns 404. The TLS connection itself is owned by
// the caller; this method assumes the request is already on a
// secured connection.
//
// Cisco Secure Client User-Agent check is permissive: any UA whose
// prefix matches AnyConnect / OpenConnect is accepted, and the
// historical X-AnyConnect-Platform header is accepted whether
// present or absent (Cisco SC 4.8+ stopped sending it). Cisco SC
// Android is the one explicit rejection because v1 does not support
// it.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if ua := r.Header.Get("User-Agent"); rejectAndroidCiscoSC(ua) {
		http.Error(w, "Cisco Secure Client on Android is not supported; use OpenConnect for Android.", http.StatusForbidden)
		return
	}

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/":
		s.handleInit(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/auth":
		s.handleAuth(w, r)
	case r.Method == http.MethodConnect && r.URL.Path == "/CSCOSSLC/tunnel":
		s.handleConnect(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/profiles/"):
		s.handleProfile(w, r)
	case r.Method == http.MethodGet && isAnyConnectHousekeepingPath(r.URL.Path):
		s.handleAnyConnectHousekeeping(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleInit answers phase 2a: an init POST. We mint a fresh opaque
// session id and reply with an auth-request prompting for credentials.
//
// If the client also presents a valid existing session cookie
// (reconnect path per spec §1.8) we acknowledge it by jumping straight
// to a complete; v1 implements only the basic "fresh handshake every
// time" path and ignores the cookie. The hook is documented for the
// reconnect work item.
func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	pa, err := parseAuthRequest(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		http.Error(w, "bad init xml", http.StatusBadRequest)
		return
	}
	if pa.Type != authTypeInit {
		http.Error(w, "unexpected config-auth type", http.StatusBadRequest)
		return
	}
	sess, err := s.sessions.newOpaque(s.cfg.RandRead)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	body, err := buildUsernameRequest(sess.opaqueID, "Please enter your username.")
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	// Carry the session in both the XML <opaque> (above, for OpenConnect) and the
	// webvpncontext cookie (for Cisco Secure Client's form-posting simple path).
	setWebVPNContext(w, sess.opaqueID)
	writeAuthXML(w, http.StatusOK, body)
}

// handleAuth answers phase 2b: an auth-reply POST. We look up the
// pending session by its round-tripped opaque id, run the credentials
// through the Verifier, and on success promote the session and reply
// with a complete carrying the long-lived session token.
//
// On verification failure we reply with another auth-request bearing
// an error message. This matches ocserv semantics and lets the client
// re-prompt without tearing the TLS connection down.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	pa, err := parseAuthReply(r)
	if err != nil {
		http.Error(w, "bad auth body", http.StatusBadRequest)
		return
	}
	if pa.Type != authTypeAuthReply {
		http.Error(w, "unexpected config-auth type", http.StatusBadRequest)
		return
	}
	// The pre-auth session is round-tripped either in the XML <opaque>
	// (OpenConnect / aggregate path) or in the webvpncontext cookie (Cisco Secure
	// Client's form-posting simple path, which sends no body opaque).
	opaqueID := pa.OpaqueID
	if opaqueID == "" {
		if c, cerr := r.Cookie(webVPNContextCookie); cerr == nil {
			opaqueID = c.Value
		}
	}
	sess := s.sessions.lookupOpaque(opaqueID)

	// Until a username is stashed, this is the username step (or a fresh prompt).
	// Stock ocserv's init is stateless and the session is CREATED on the username
	// step (worker-auth.c: the SID is issued only after the username is posted, and
	// webvpncontext is set on that response, then echoed by the client on the
	// password step). So we mint a session here when the client carried no
	// opaque/cookie (Cisco Secure Client's simple form path) and reuse an existing
	// pre-auth row otherwise (OpenConnect's XML opaque). We then prompt for the
	// password as a SECOND single-input form. (A single combined username+password
	// form pushes iOS onto the aggregate-auth path, which authenticates but then
	// refuses to send the CSTP CONNECT.)
	if sess == nil || sess.username == "" {
		if pa.Username != "" {
			if sess == nil {
				fresh, err := s.sessions.newOpaque(s.cfg.RandRead)
				if err != nil {
					http.Error(w, "internal", http.StatusInternalServerError)
					return
				}
				sess = fresh
				opaqueID = fresh.opaqueID
			}
			s.sessions.stashUsername(opaqueID, pa.Username)
			setWebVPNContext(w, opaqueID)
			body, _ := buildPasswordRequest(opaqueID, "Please enter your password.")
			writeAuthXML(w, http.StatusOK, body)
			return
		}
		// No username yet: (re)prompt for it on a fresh pre-auth session.
		fresh, err := s.sessions.newOpaque(s.cfg.RandRead)
		if err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		setWebVPNContext(w, fresh.opaqueID)
		body, _ := buildUsernameRequest(fresh.opaqueID, "Please enter your username.")
		writeAuthXML(w, http.StatusOK, body)
		return
	}

	// Step 2 (password): the username is stashed; verify the credentials.
	username := sess.username
	if pa.Password == "" {
		setWebVPNContext(w, opaqueID)
		body, _ := buildPasswordRequest(opaqueID, "Please enter your password.")
		writeAuthXML(w, http.StatusOK, body)
		return
	}
	deviceID, verr := s.cfg.Verifier.Verify(r.Context(), username, pa.Password)
	if verr != nil {
		setWebVPNContext(w, opaqueID)
		body, _ := buildPasswordRequest(opaqueID, "Sign-in failed. Please try again.")
		writeAuthXML(w, http.StatusOK, body)
		return
	}
	promoted, err := s.sessions.promote(opaqueID, username, deviceID, s.cfg.RandRead)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	// webvpn carries the session credential the client re-presents on the CSTP
	// CONNECT; webvpncontext is the companion session-context cookie stock
	// ocserv also sets, which Cisco Secure Client expects to see as the pair.
	http.SetCookie(w, &http.Cookie{
		Name:     "webvpncontext",
		Value:    promoted.opaqueID,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "webvpn",
		Value:    promoted.token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	})
	// webvpnc is the AnyConnect post-auth directive cookie (see profile.go). It
	// MUST be written raw — its &/:/% are literal and http.SetCookie would
	// percent-escape them, breaking the directive. Stock ocserv clears any prior
	// directive with a 1970-expiry Set-Cookie before writing the new one; we
	// mirror that so a reconnect never carries a stale directive.
	w.Header().Add("Set-Cookie", "webvpnc=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; Secure; HttpOnly")
	w.Header().Add("Set-Cookie", "webvpnc="+s.webvpnc+"; path=/; Secure; HttpOnly")
	body, err := buildAuthComplete()
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeAuthXML(w, http.StatusOK, body)
}

// writeAuthXML emits an XML auth-envelope response with the correct
// Content-Type and status. The body is already a complete XML document.
func writeAuthXML(w http.ResponseWriter, status int, body []byte) {
	// Stock ocserv's simple (non-aggregate) auth path sends bare "text/xml"
	// (NOT application/xml, and no charset) with X-Transcend-Version: 1 and NO
	// X-Aggregate-Auth on every config-auth response — and the iOS Cisco Secure
	// Client drives that path end-to-end to a connected tunnel. We match it
	// exactly. (X-Aggregate-Auth + a combined username+password form put iOS on
	// its aggregate-auth path, which authenticated but then refused to send the
	// CSTP CONNECT; see buildAuthForm + handleAuth for the 2-step simple flow.)
	// Connection: Keep-Alive mirrors stock ocserv (worker-auth.c) and is the
	// signal Cisco Secure Client uses to run the WHOLE flow (init -> auth ->
	// complete -> CONNECT) over ONE TLS connection. Without it the iOS client
	// opens a fresh connection per phase and stalls at the hand-off to the
	// tunnel extension; with it, the client reuses one connection — the same
	// single-connection path OpenConnect uses and that works end-to-end.
	w.Header().Set("Connection", "Keep-Alive")
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("X-Transcend-Version", "1")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// handleProfile serves the canned AnyConnectProfile XML (anyConnectProfileXML,
// profile.go) on any GET /profiles/* request. This is DEFENSIVE, not part of the
// proven flow: the type="complete" envelope deliberately advertises NO
// <vpn-profile-manifest> (see buildAuthComplete in xml.go), so the proven iOS
// Cisco Secure Client never fetches a profile between auth and the CSTP CONNECT.
// It is served only because the facade routes /profiles/* to era-ocserv and some
// clients may probe it; any /profiles/* path returns the same single profile.
func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "Keep-Alive")
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("X-Transcend-Version", "1")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, anyConnectProfileXML)
}

// handleAnyConnectHousekeeping serves the AnyConnect post-auth control /
// downloader URLs (the webvpnc lu:/iu: targets + VPN-downloader update checks)
// with the same tiny canned bodies stock ocserv returns. Cisco Secure Client
// (iOS) GETs these between auth and the tunnel CONNECT; 404ing them stalls the
// pre-tunnel reconciliation. OpenConnect never requests them.
func (s *Server) handleAnyConnectHousekeeping(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "Keep-Alive")
	w.Header().Set("X-Transcend-Version", "1")
	switch p := r.URL.Path; {
	case p == "/+CSCOT+/translation-table" || p == "/VPNManifest.xml" || p == "/1/VPNManifest.xml":
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, anyConnectVPNManifestXML)
	case p == "/1/binaries/update.txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, anyConnectUpdateTxt)
	case p == "/1/binaries/vpndownloader.sh":
		w.Header().Set("Content-Type", "application/x-shellscript")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, anyConnectVPNDownloader)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, anyConnectEmptyHTML)
	}
}

// rejectAndroidCiscoSC returns true if the User-Agent indicates Cisco
// Secure Client running on Android, which is explicitly out of scope
// for v1 per ADR 0057 §7.
func rejectAndroidCiscoSC(ua string) bool {
	lower := strings.ToLower(ua)
	if !strings.Contains(lower, "anyconnect") {
		return false
	}
	return strings.Contains(lower, "android") &&
		!strings.Contains(lower, "openconnect")
}

// connectError writes a short HTTP error response on the raw hijacked
// connection. It is only used during phase 3 once the hijack has
// succeeded but before the tunnel goes live.
func connectError(c net.Conn, status int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		status, http.StatusText(status))
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, resp)
	_ = c.SetWriteDeadline(time.Time{})
	_ = c.Close()
	_ = msg // intentionally unused; we don't leak phase-3 errors to the client beyond status
}

// hijack pulls the underlying conn out of the ResponseWriter so we can
// drive the post-CONNECT binary frame stream directly. The buffered
// reader is preserved so any bytes the http server already buffered
// from the client are not lost (this matters for fast CONNECT bodies
// that arrive in the same TLS record as the headers).
func hijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("cstp: response writer does not support hijack")
	}
	return h.Hijack()
}
