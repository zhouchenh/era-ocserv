package cstp

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// stubDTLSInstaller records Upserts and always succeeds.
type stubDTLSInstaller struct{ calls int }

func (s *stubDTLSInstaller) Upsert(_ context.Context, _ DTLSBinding) error { s.calls++; return nil }

// TestConnectPerDeviceDTLSOptOut proves the per-device DTLS opt-out
// (id.DTLSDisabled, sourced from the tpm "ocserv_dtls_disabled" field). With the
// DTLS binding wired and the client offering a master secret + a supported
// cipher, the CONNECT response advertises DTLS (X-DTLS-* headers + a binding
// Upsert) ONLY when the resolved identity is not opted out; when it is, the data
// plane falls back to CSTP/TLS (TCP) with no DTLS offer.
func TestConnectPerDeviceDTLSOptOut(t *testing.T) {
	for _, tc := range []struct {
		name         string
		dtlsDisabled bool
		wantDTLS     bool
	}{
		{"opt-in: DTLS offered", false, true},
		{"opt-out: DTLS suppressed", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip := netip.MustParsePrefix("2001:470:f9d1:9001:dead:beef::1/128")
			v := &stubVerifier{user: "alice", pass: "hunter2", deviceID: "dev-001"}
			r := &stubResolver{want: Identity{DeviceID: "dev-001", IPv6: ip, MTU: 1406, DTLSDisabled: tc.dtlsDisabled}}
			inst := &stubDTLSInstaller{}
			rnd := &fixedRand{src: []byte("01234567890abcdefABCDEFxyzwQRSTuvi.PQR_")}
			s := NewServer(Config{
				Verifier:             v,
				Resolver:             r,
				ServerName:           "vpn.eracloud.app",
				DNS:                  []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")},
				DPDInterval:          30,
				KeepaliveInterval:    20,
				IdleTimeout:          1800,
				DefaultMTU:           1406,
				RandRead:             rnd.Read,
				DTLSBindingInstaller: inst,
				DTLSBindingSource: func(_ *http.Request, id Identity) (DTLSBinding, bool) {
					return DTLSBinding{DeviceID: id.DeviceID, UserID: "anyconnect", MTLSSubjectDN: "CN=" + id.DeviceID}, true
				},
			})
			ts := httptest.NewServer(s)
			defer ts.Close()

			// Auth flow → webvpn session token.
			body := postAndRead(t, ts.URL+"/", newInitBody())
			opaqueID := extractOpaqueID(body)
			uBody := postAndRead(t, ts.URL+"/auth", newAuthReplyUsername(opaqueID, "alice"))
			opaqueID = extractOpaqueID(uBody)
			authResp, err := http.Post(ts.URL+"/auth", "text/xml", strings.NewReader(newAuthReplyPassword(opaqueID, "hunter2")))
			if err != nil {
				t.Fatalf("auth POST: %v", err)
			}
			authResp.Body.Close()
			var token string
			for _, c := range authResp.Cookies() {
				if c.Name == "webvpn" && c.Value != "" {
					token = c.Value
					break
				}
			}
			if token == "" {
				t.Fatal("missing webvpn session cookie")
			}

			// CONNECT offering DTLS (a 48-byte master secret + a supported cipher).
			conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			req := "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n" +
				"Host: vpn.eracloud.app\r\n" +
				"User-Agent: AnyConnect Darwin_arm64 5.1.2\r\n" +
				"Cookie: webvpn=" + token + "\r\n" +
				"X-CSTP-Version: 1\r\n" +
				"X-CSTP-Base-MTU: 1500\r\n" +
				"X-Dtls-Master-Secret: " + strings.Repeat("ab", 48) + "\r\n" +
				"X-Dtls12-Ciphersuite: ECDHE-RSA-AES128-GCM-SHA256\r\n" +
				"\r\n"
			if _, err := io.WriteString(conn, req); err != nil {
				t.Fatalf("write CONNECT: %v", err)
			}

			br := bufio.NewReader(conn)
			statusLine, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("read status: %v", err)
			}
			if !strings.Contains(statusLine, "200") || !strings.Contains(statusLine, "CONNECTED") {
				t.Fatalf("expected 200 CONNECTED, got %q", statusLine)
			}
			hasDTLS := false
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					t.Fatalf("header read: %v", err)
				}
				if strings.TrimRight(line, "\r\n") == "" {
					break
				}
				if strings.HasPrefix(strings.ToLower(line), "x-dtls") {
					hasDTLS = true
				}
			}

			if hasDTLS != tc.wantDTLS {
				t.Fatalf("X-DTLS-* present=%v, want %v (DTLSDisabled=%v)", hasDTLS, tc.wantDTLS, tc.dtlsDisabled)
			}
			if tc.wantDTLS && inst.calls == 0 {
				t.Fatal("DTLS offered but no binding Upsert")
			}
			if !tc.wantDTLS && inst.calls != 0 {
				t.Fatalf("opted out but %d binding Upsert(s) (must publish none)", inst.calls)
			}

			// Drain the published CSTP tunnel so the handler doesn't block on close
			// (the CSTP tunnel exists regardless of the DTLS offer).
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if tun, err := s.Accept(ctx); err == nil {
				tun.Close()
			}
		})
	}
}
