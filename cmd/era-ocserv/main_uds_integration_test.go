package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/zhouchenh/era-ocserv/internal/auth"
	"github.com/zhouchenh/era-ocserv/internal/cstp"
	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
	"github.com/zhouchenh/era-ocserv/internal/udshandoff"
	"github.com/zhouchenh/era-ocserv/internal/udsserve"
)

// udsPipeListener is an in-memory net.Listener handed to udsserve via
// Options.PreboundListener, so the real UDS stack runs without AF_UNIX.
type udsPipeListener struct {
	conns  chan net.Conn
	mu     sync.Mutex
	closed bool
}

func (p *udsPipeListener) Accept() (net.Conn, error) {
	c, ok := <-p.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (p *udsPipeListener) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.conns)
	}
	return nil
}

func (p *udsPipeListener) Addr() net.Addr { return &net.UnixAddr{Name: "uds://test", Net: "unix"} }

// TestUDSHandoffEndToEndBindsSubjectDNDeviceToPortalDevice drives the real
// production UDS chain: PROXY-v2 + TLV handoff -> udsserve middleware (which
// extracts device X from the MTLS Subject DN CN into certctx) -> cstp.Server
// sign-in -> verifierForMode(modeUDS, ...) (certBoundVerifier) -> fake portal.
// A portal credential that resolves to device Y must be refused with exactly
// the response a wrong password gets; one that resolves to device X completes.
func TestUDSHandoffEndToEndBindsSubjectDNDeviceToPortalDevice(t *testing.T) {
	const deviceX = legacyTestDeviceID
	const deviceY = "dev_zyxwvutsrqponmlkjihgfedcba"

	// signIn runs init -> username -> password over one handed-off stream and
	// returns the final /auth response body.
	signIn := func(t *testing.T, portalDevice, password string) string {
		t.Helper()
		portal := &auth.MockVerifier{}
		portal.Set("user", "password", portalDevice)
		srv := cstp.NewServer(cstp.Config{
			Verifier:   verifierForMode(modeUDS, portal),
			ServerName: "localhost",
			RandRead: func(p []byte) (int, error) {
				for i := range p {
					p[i] = byte(i + 1)
				}
				return len(p), nil
			},
		})
		t.Cleanup(func() { srv.Close() })

		pl := &udsPipeListener{conns: make(chan net.Conn, 1)}
		uds, err := udsserve.Listen(context.Background(), udsserve.Options{
			SocketPath:       "uds://test",
			Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
			Metrics:          udshandoff.NewMetrics(),
			Handler:          srv,
			PreboundListener: pl,
		})
		if err != nil {
			t.Fatalf("udsserve.Listen: %v", err)
		}
		t.Cleanup(func() { uds.Close() })

		hdr := &proxyproto.HeaderV2{
			Family: 0x11,
			Src:    netip.MustParseAddrPort("203.0.113.42:51000"),
			Dst:    netip.MustParseAddrPort("198.51.100.9:443"),
			TLVs: []proxyproto.TLV{
				{Type: proxyproto.EraTLVSpecVersion, Value: []byte{proxyproto.SpecVersionStage1}},
				{Type: proxyproto.EraTLVToken, Value: make([]byte, 12)},
				{Type: proxyproto.EraTLVDeviceID, Value: []byte("123e4567-e89b-12d3-a456-426614174000")},
				{Type: proxyproto.EraTLVUserID, Value: []byte("user-1")},
				{Type: proxyproto.EraTLVSourceHintV6, Value: netip.MustParseAddr("2001:db8::1").AsSlice()},
				{Type: proxyproto.EraTLVMTLSSubjectDN, Value: []byte("CN=" + deviceX + ",O=ERA Cloud")},
				{Type: proxyproto.EraTLVTraceID, Value: []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")},
			},
		}
		hb, err := hdr.Encode()
		if err != nil {
			t.Fatalf("encode PROXY-v2 header: %v", err)
		}

		clientC, serverC := net.Pipe()
		t.Cleanup(func() { clientC.Close() })
		pl.conns <- serverC
		w := bufio.NewWriter(clientC)
		r := bufio.NewReader(clientC)
		if _, err := w.Write(hb); err != nil {
			t.Fatalf("write header: %v", err)
		}
		post := func(path, body string) string {
			t.Helper()
			fmt.Fprintf(w, "POST %s HTTP/1.1\r\nHost: localhost\r\nUser-Agent: AnyConnect-1.0\r\nContent-Type: application/xml\r\nContent-Length: %d\r\n\r\n%s", path, len(body), body)
			if err := w.Flush(); err != nil {
				t.Fatalf("flush %s: %v", path, err)
			}
			resp, err := http.ReadResponse(r, nil)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s status = %d body %q", path, resp.StatusCode, b)
			}
			return string(b)
		}

		opaque := legacyOpaqueID(post("/", `<config-auth client="vpn" type="init"/>`))
		if opaque == "" {
			t.Fatal("init response did not contain an opaque session ID")
		}
		post("/auth", legacyAuthReply(opaque, "user", ""))
		return post("/auth", legacyAuthReply(opaque, "", password))
	}

	badPassword := signIn(t, deviceX, "wrong")
	if strings.Contains(badPassword, `type="complete"`) || !strings.Contains(badPassword, "Sign-in failed") {
		t.Fatalf("bad-password baseline = %q, want generic Sign-in failed", badPassword)
	}

	t.Run("portal device Y is refused like a bad password", func(t *testing.T) {
		got := signIn(t, deviceY, "password")
		if got != badPassword {
			t.Fatalf("mismatched-device response =\n%q\nwant the bad-password response\n%q", got, badPassword)
		}
	})
	t.Run("portal device X completes", func(t *testing.T) {
		got := signIn(t, deviceX, "password")
		if !strings.Contains(got, `type="complete"`) {
			t.Fatalf("matching-device response = %q, want complete", got)
		}
	})
}
