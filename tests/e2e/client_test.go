package e2e_test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// fakeClient is a minimal AnyConnect-shaped client just rich enough
// to drive the Stage 1 handshake. It deliberately bypasses net/http's
// connection pooling because the post-CONNECT binary stream has to
// share the same TLS conn as the CONNECT request.
type fakeClient struct {
	addr      string
	tlsConfig *tls.Config

	// conn is the long-lived TLS conn the CONNECT phase rides on plus
	// the post-CONNECT binary frames.
	conn   *tls.Conn
	reader *bufio.Reader
}

// dial opens the TLS conn and stores it on the client.
func (c *fakeClient) dial() error {
	conn, err := tls.Dial("tcp", c.addr, c.tlsConfig)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return nil
}

// close terminates the TLS conn. Safe to call after a failed dial.
func (c *fakeClient) close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// httpRoundTrip writes one HTTP/1.1 request on the long-lived conn
// and reads exactly one response. It does NOT support pipelining or
// chunked transfer; the gateway only emits Content-Length for the
// XML phase responses, so a simple Read-headers-then-body path works.
//
// On 401 (used by the cert-validation tests) we still try to read the
// body so the conn is left in a consistent state for the caller's
// teardown.
func (c *fakeClient) httpRoundTrip(req string) (*httpResponse, error) {
	if _, err := io.WriteString(c.conn, req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	statusLine, err := c.reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read status: %w", err)
	}
	parts := strings.SplitN(strings.TrimRight(statusLine, "\r\n"), " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("bad status line: %q", statusLine)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad status code: %q", parts[1])
	}

	tp := textproto.NewReader(c.reader)
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, fmt.Errorf("read headers: %w", err)
	}
	resp := &httpResponse{
		StatusCode: code,
		Header:     http.Header(hdr),
	}
	if cl := hdr.Get("Content-Length"); cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil {
			return nil, fmt.Errorf("bad content-length %q: %w", cl, err)
		}
		if n > 0 {
			body := make([]byte, n)
			if _, err := io.ReadFull(c.reader, body); err != nil {
				return nil, fmt.Errorf("read body: %w", err)
			}
			resp.Body = body
		}
	}
	return resp, nil
}

// httpResponse is a minimal response shape: status code, headers, and
// (already-fully-buffered) body bytes.
type httpResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// initXML returns a phase-2a config-auth body. Matches what Cisco
// Secure Client 5.x sends.
func initXML() string {
	return `<?xml version="1.0"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
  <version who="vpn">5.1.10.233</version>
  <device-id unique-id="DEADBEEF">linux-64</device-id>
</config-auth>`
}

// authReplyXML returns a phase-2b config-auth body.
func authReplyXML(opaqueID, user, pass string) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
  <opaque is-for="sg"><session-id>%s</session-id></opaque>
  <auth>
    <username>%s</username>
    <password>%s</password>
  </auth>
</config-auth>`, opaqueID, user, pass)
}

// extractTaggedValue pulls the first <tag>...</tag> value out of body.
// Used for both <session-id> and <session-token>.
func extractTaggedValue(body, tag string) string {
	open := "<" + tag + ">"
	closeTag := "</" + tag + ">"
	i := strings.Index(body, open)
	if i < 0 {
		return ""
	}
	rest := body[i+len(open):]
	j := strings.Index(rest, closeTag)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// postXML builds the HTTP/1.1 request line + headers + body for one
// of the phase-2 POSTs. The Connection: keep-alive header is on by
// default in HTTP/1.1 but we set it explicitly so the gateway leaves
// the conn open for the follow-up request.
func postXML(path, host, body string) string {
	return fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: AnyConnect Windows 5.1.10.233\r\n"+
		"X-AnyConnect-Platform: win\r\n"+
		"Content-Type: application/xml\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: keep-alive\r\n"+
		"\r\n"+
		"%s", path, host, len(body), body)
}

// initAndAuth runs phase 2a and 2b on a freshly dialed conn and
// returns the session token. It does NOT issue CONNECT; that lives in
// connect() so tests can exercise post-auth failures (bad cookie, no
// cert) independently.
func (c *fakeClient) initAndAuth(host, user, pass string) (string, *httpResponse, *httpResponse, error) {
	initBody := initXML()
	initResp, err := c.httpRoundTrip(postXML("/", host, initBody))
	if err != nil {
		return "", nil, nil, fmt.Errorf("init POST: %w", err)
	}
	if initResp.StatusCode != 200 {
		return "", initResp, nil, fmt.Errorf("init status=%d", initResp.StatusCode)
	}
	opaqueID := extractTaggedValue(string(initResp.Body), "session-id")
	if opaqueID == "" {
		return "", initResp, nil, fmt.Errorf("init body missing session-id: %s", initResp.Body)
	}

	authResp, err := c.httpRoundTrip(postXML("/auth", host, authReplyXML(opaqueID, user, pass)))
	if err != nil {
		return "", initResp, nil, fmt.Errorf("auth POST: %w", err)
	}
	if authResp.StatusCode != 200 {
		return "", initResp, authResp, fmt.Errorf("auth status=%d", authResp.StatusCode)
	}
	token := extractTaggedValue(string(authResp.Body), "session-token")
	return token, initResp, authResp, nil
}

// connect issues CONNECT /CSCOSSLC/tunnel with the given session token
// as the webvpn cookie. On success returns the parsed response
// headers; on auth/transport failure returns a non-nil error.
//
// IMPORTANT: on a 200 CONNECTED, the conn is now in binary-frame mode.
// Future Reads must go through readFrame, not the bufio.Reader's
// HTTP machinery.
func (c *fakeClient) connect(host, token string) (http.Header, error) {
	return c.connectWithCipher(host, token, "AES128-GCM-SHA256")
}

// connectWithCipher is the underlying CONNECT helper. dtlsCipher is
// the value the client offers for X-DTLS-CipherSuite; pass empty to
// omit the header entirely (used by tests that exercise the "client
// offered nothing → server omits DTLS" path).
func (c *fakeClient) connectWithCipher(host, token, dtlsCipher string) (http.Header, error) {
	req := "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: AnyConnect Windows 5.1.10.233\r\n" +
		"Cookie: webvpn=" + token + "\r\n" +
		"X-CSTP-Version: 1\r\n" +
		"X-CSTP-Base-MTU: 1500\r\n" +
		"X-CSTP-MTU: 1400\r\n"
	if dtlsCipher != "" {
		req += "X-DTLS-CipherSuite: " + dtlsCipher + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(c.conn, req); err != nil {
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	statusLine, err := c.reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read CONNECT status: %w", err)
	}
	parts := strings.SplitN(strings.TrimRight(statusLine, "\r\n"), " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("bad CONNECT status line: %q", statusLine)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad CONNECT status code: %q", parts[1])
	}
	if code != 200 {
		// Drain headers so the conn is left clean if the caller wants
		// to reuse it (though usually it's about to close).
		tp := textproto.NewReader(c.reader)
		_, _ = tp.ReadMIMEHeader()
		return nil, fmt.Errorf("CONNECT status=%d", code)
	}
	tp := textproto.NewReader(c.reader)
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, fmt.Errorf("read CONNECT headers: %w", err)
	}
	return http.Header(hdr), nil
}

// --- CSTP frame helpers ------------------------------------------------
//
// Duplicated from internal/cstp/frame.go because that file is
// package-private. We only need encode + decode here.

const (
	cstpFrameHeaderLen = 8
	cstpPktData        byte = 0
	cstpPktDPDOut      byte = 3
	cstpPktDPDResp     byte = 4
	cstpPktKeepalive   byte = 7
)

var cstpFrameMagic = [4]byte{'S', 'T', 'F', 0x01}

// writeFrame writes a single CSTP frame onto the client's TLS conn.
func (c *fakeClient) writeFrame(typ byte, payload []byte) error {
	if len(payload) > 0xFFFF {
		return errors.New("payload too large")
	}
	buf := make([]byte, cstpFrameHeaderLen+len(payload))
	buf[0] = cstpFrameMagic[0]
	buf[1] = cstpFrameMagic[1]
	buf[2] = cstpFrameMagic[2]
	buf[3] = cstpFrameMagic[3]
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(payload)))
	buf[6] = typ
	buf[7] = 0
	copy(buf[cstpFrameHeaderLen:], payload)
	_, err := c.conn.Write(buf)
	return err
}

// readFrame reads one CSTP frame from the client's TLS conn (using
// the same bufio.Reader the HTTP phase used so leftover bytes are
// preserved). Returns the type byte and a fresh copy of the payload.
func (c *fakeClient) readFrame() (byte, []byte, error) {
	hdr := make([]byte, cstpFrameHeaderLen)
	if _, err := io.ReadFull(c.reader, hdr); err != nil {
		return 0, nil, err
	}
	if hdr[0] != cstpFrameMagic[0] || hdr[1] != cstpFrameMagic[1] ||
		hdr[2] != cstpFrameMagic[2] || hdr[3] != cstpFrameMagic[3] {
		return 0, nil, fmt.Errorf("bad frame magic: %x", hdr[:4])
	}
	plen := int(binary.BigEndian.Uint16(hdr[4:6]))
	typ := hdr[6]
	if plen == 0 {
		return typ, nil, nil
	}
	payload := make([]byte, plen)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// readFrameWithDeadline wraps readFrame in a SetReadDeadline so a
// test can give up if no frame arrives in the expected window.
func (c *fakeClient) readFrameWithDeadline(d time.Duration) (byte, []byte, error) {
	if err := c.conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		return 0, nil, err
	}
	defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	typ, payload, err := c.readFrame()
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return 0, nil, ne
	}
	return typ, payload, err
}
