package proxyproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestListenerThenTLSHandshakeAndHTTP mirrors the live stack: the PROXY-protocol
// listener is wrapped by tls.NewListener and served by http.Server; a client
// writes a PROXY v2 header then performs a real TLS handshake + HTTP request.
// This catches any bufio/leftover mishandling that breaks TLS after the header.
func TestListenerThenTLSHandshakeAndHTTP(t *testing.T) {
	cert := selfSignedCert(t)
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	tlsLn := tls.NewListener(NewListener(tcpLn), &tls.Config{Certificates: []tls.Certificate{cert}})

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "remote="+r.RemoteAddr)
	})}
	go func() { _ = srv.Serve(tlsLn) }()
	defer srv.Close()

	src := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51000}
	dst := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 443}
	raw, err := net.Dial("tcp", tcpLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := WriteHeaderV2(raw, src, dst); err != nil {
		t.Fatalf("write header: %v", err)
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "example.test"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
	body, _ := io.ReadAll(tc)
	s := string(body)
	if !strings.Contains(s, "200 OK") {
		t.Fatalf("no 200 OK in response: %q", s)
	}
	if !strings.Contains(s, "203.0.113.7") {
		t.Fatalf("RemoteAddr not from PROXY header: %q", s)
	}
}

// TestSpliceHeaderToTLSBackendDualStack mirrors frontdemux EXACTLY: a dual-stack
// ([::]) front accepts a connection, writes a PROXY v2 header built from the live
// conn's RemoteAddr/LocalAddr (which are v4-mapped for a 127.0.0.1 client on a
// dual-stack socket), then splices to the proxyproto+TLS backend. This catches a
// header that the live addresses make malformed.
func TestSpliceHeaderToTLSBackendDualStack(t *testing.T) {
	cert := selfSignedCert(t)
	backLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backLn.Close()
	btls := tls.NewListener(NewListener(backLn), &tls.Config{Certificates: []tls.Certificate{cert}})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "remote="+r.RemoteAddr)
	})}
	go func() { _ = srv.Serve(btls) }()
	defer srv.Close()

	frontLn, err := net.Listen("tcp", "[::]:0") // dual-stack like .47 frontdemux
	if err != nil {
		t.Fatal(err)
	}
	defer frontLn.Close()
	werr := make(chan error, 1)
	go func() {
		c, aerr := frontLn.Accept()
		if aerr != nil {
			werr <- aerr
			return
		}
		defer c.Close()
		up, derr := net.Dial("tcp", backLn.Addr().String())
		if derr != nil {
			werr <- derr
			return
		}
		defer up.Close()
		if herr := WriteHeaderV2(up, c.RemoteAddr(), c.LocalAddr()); herr != nil {
			werr <- fmt.Errorf("WriteHeaderV2(remote=%v local=%v): %w", c.RemoteAddr(), c.LocalAddr(), herr)
			return
		}
		werr <- nil
		go func() { _, _ = io.Copy(up, c) }()
		_, _ = io.Copy(c, up)
	}()

	_, port, _ := net.SplitHostPort(frontLn.Addr().String())
	raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "example.test"})
	if err := tc.Handshake(); err != nil {
		select {
		case e := <-werr:
			if e != nil {
				t.Fatalf("front splice error: %v", e)
			}
		default:
		}
		t.Fatalf("client TLS handshake: %v", err)
	}
	fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
	body, _ := io.ReadAll(tc)
	if !strings.Contains(string(body), "200 OK") {
		t.Fatalf("no 200 OK: %q", body)
	}
}
