package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/auth"
	"github.com/zhouchenh/era-ocserv/internal/certctx"
)

const testDeviceID = "dev_abcdefghijklmnopqrstuvwxyz"

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, commonName string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Unix(1700000000, 0),
		NotAfter:              time.Unix(1900000000, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key}
}

func issueTestCert(t *testing.T, ca testCA, commonName string, server bool) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := big.NewInt(int64(len(commonName) + 2))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Unix(1700000000, 0),
		NotAfter:     time.Unix(1900000000, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.DNSNames = []string{"localhost"}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}, cert
}

func writePEM(t *testing.T, path string, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
}

func handshakePair(t *testing.T, serverConfig, clientConfig *tls.Config) (serverErr, clientErr error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		serverDone <- tls.Server(conn, serverConfig).Handshake()
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	clientErr = tls.Client(conn, clientConfig).Handshake()
	serverErr = <-serverDone
	return serverErr, clientErr
}

func TestLoadTLSRequiresAndVerifiesClientCertificate(t *testing.T) {
	trusted := newTestCA(t, "test trusted ca")
	serverCert, _ := issueTestCert(t, trusted, "localhost", true)
	clientCert, _ := issueTestCert(t, trusted, testDeviceID, false)
	rogue := newTestCA(t, "test rogue ca")
	rogueClient, _ := issueTestCert(t, rogue, testDeviceID, false)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.pem")
	keyPath := filepath.Join(dir, "server-key.pem")
	caPath := filepath.Join(dir, "client-ca.pem")
	writePEM(t, certPath, "CERTIFICATE", serverCert.Certificate[0])
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)
	writePEM(t, caPath, "CERTIFICATE", trusted.cert.Raw)

	tlsCfg, err := loadTLS(config{tlsCertPath: certPath, tlsKeyPath: keyPath, clientCAPath: caPath})
	if err != nil {
		t.Fatalf("loadTLS: %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsCfg.ClientAuth)
	}
	clientBase := &tls.Config{InsecureSkipVerify: true} // test server certificate is generated locally

	serverErr, clientErr := handshakePair(t, tlsCfg, clientBase.Clone())
	if serverErr == nil {
		t.Fatalf("missing client certificate handshake succeeded: server=%v client=%v", serverErr, clientErr)
	}

	serverErr, clientErr = handshakePair(t, tlsCfg, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{rogueClient}})
	if serverErr == nil {
		t.Fatalf("untrusted client certificate handshake succeeded: server=%v client=%v", serverErr, clientErr)
	}

	serverErr, clientErr = handshakePair(t, tlsCfg, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{clientCert}})
	if serverErr != nil || clientErr != nil {
		t.Fatalf("trusted client certificate handshake failed: server=%v client=%v", serverErr, clientErr)
	}
}

func TestCertBoundVerifierMatchesPortalDevice(t *testing.T) {
	portal := &auth.MockVerifier{}
	portal.Set("user", "password", testDeviceID)
	verifier := certBoundVerifier{inner: portal}

	ctx := certctx.WithDeviceID(context.Background(), testDeviceID)
	got, err := verifier.Verify(ctx, "user", "password")
	if err != nil || got != testDeviceID {
		t.Fatalf("matching device: got %q, err %v", got, err)
	}

	ctx = certctx.WithDeviceID(context.Background(), "dev_zyxwvutsrqponmlkjihgfedcba")
	got, err = verifier.Verify(ctx, "user", "password")
	if !errors.Is(err, auth.ErrBadCredentials) || got != "" {
		t.Fatalf("mismatched device: got %q, err %v", got, err)
	}
}

func TestCertMiddlewareBindsPortalDeviceThroughHTTP(t *testing.T) {
	ca := newTestCA(t, "test middleware ca")
	_, clientLeaf := issueTestCert(t, ca, testDeviceID, false)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	validator := auth.NewCertValidator(auth.CertValidatorConfig{
		ClientCAs: roots,
		Now:       func() time.Time { return time.Unix(1800000000, 0) },
	})

	tests := []struct {
		name         string
		portalDevice string
		wantStatus   int
	}{
		{name: "matching device", portalDevice: testDeviceID, wantStatus: http.StatusNoContent},
		{name: "mismatching device", portalDevice: "dev_zyxwvutsrqponmlkjihgfedcba", wantStatus: http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			portal := &auth.MockVerifier{}
			portal.Set("test-user", "test-password", tc.portalDevice)
			verifier := certBoundVerifier{inner: portal}
			handler := certMiddleware(validator, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				deviceID, err := verifier.Verify(r.Context(), "test-user", "test-password")
				if err != nil {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				w.Header().Set("X-Test-Device-ID", deviceID)
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(http.MethodPost, "https://localhost/", nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientLeaf}}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body = %q", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus == http.StatusNoContent && rec.Header().Get("X-Test-Device-ID") != testDeviceID {
				t.Fatalf("handler device id = %q, want %q", rec.Header().Get("X-Test-Device-ID"), testDeviceID)
			}
		})
	}
}

func TestRequireFlags(t *testing.T) {
	base := config{
		tlsCertPath:   "server.pem",
		tlsKeyPath:    "server-key.pem",
		clientCAPath:  "client-ca.pem",
		portalURL:     "https://portal.test",
		portalToken:   "portal-test-token",
		tpmURL:        "https://tpm.test",
		tpmToken:      "tpm-test-token",
		udsSocketPath: "/tmp/era-ocserv-test.sock",
	}
	tests := []struct {
		name    string
		mode    listenerMode
		mutate  func(*config)
		wantErr string
	}{
		{
			name:    "legacy requires client CA",
			mode:    modeLegacy,
			mutate:  func(c *config) { c.clientCAPath = "" },
			wantErr: "-client-ca",
		},
		{
			name:   "UDS does not require TLS flags",
			mode:   modeUDS,
			mutate: func(c *config) { c.tlsCertPath, c.tlsKeyPath, c.clientCAPath = "", "", "" },
		},
		{
			name:    "UDS requires socket",
			mode:    modeUDS,
			mutate:  func(c *config) { c.udsSocketPath = "" },
			wantErr: "-uds-socket",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			err := requireFlags(cfg, tc.mode)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("requireFlags: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("requireFlags error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestResolveModeRejectsInvalidMode(t *testing.T) {
	for _, mode := range []string{"invalid", "legacy-plus-tls"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := resolveMode(config{mode: mode}); err == nil {
				t.Fatalf("resolveMode(%q) succeeded", mode)
			}
		})
	}
}
