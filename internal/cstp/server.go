package cstp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

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
	body, err := buildAuthRequest(sess.opaqueID, "Sign in to ERA")
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
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
	pa, err := parseAuthRequest(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		http.Error(w, "bad auth xml", http.StatusBadRequest)
		return
	}
	if pa.Type != authTypeAuthReply {
		http.Error(w, "unexpected config-auth type", http.StatusBadRequest)
		return
	}
	if pa.OpaqueID == "" || s.sessions.lookupOpaque(pa.OpaqueID) == nil {
		// Pre-auth row gone (expired) or never existed. Mint a fresh
		// one and prompt the client again.
		fresh, err := s.sessions.newOpaque(s.cfg.RandRead)
		if err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		body, _ := buildAuthError(fresh.opaqueID, "Session expired, please sign in again.")
		writeAuthXML(w, http.StatusOK, body)
		return
	}
	if pa.Username == "" || pa.Password == "" {
		body, _ := buildAuthError(pa.OpaqueID, "Username and password are required.")
		writeAuthXML(w, http.StatusOK, body)
		return
	}
	deviceID, verr := s.cfg.Verifier.Verify(r.Context(), pa.Username, pa.Password)
	if verr != nil {
		body, _ := buildAuthError(pa.OpaqueID, "Sign-in failed. Please try again.")
		writeAuthXML(w, http.StatusOK, body)
		return
	}
	promoted, err := s.sessions.promote(pa.OpaqueID, pa.Username, deviceID, s.cfg.RandRead)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "webvpn",
		Value:    promoted.token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	})
	body, err := buildAuthComplete(promoted.token, promoted.opaqueID, "")
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeAuthXML(w, http.StatusOK, body)
}

// writeAuthXML emits an XML auth-envelope response with the correct
// Content-Type and status. The body is already a complete XML document.
func writeAuthXML(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("X-Transcend-Version", "1")
	w.WriteHeader(status)
	_, _ = w.Write(body)
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
