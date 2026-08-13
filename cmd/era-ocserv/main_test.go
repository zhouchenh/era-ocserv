package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
	"github.com/zhouchenh/era-ocserv/internal/cstp"
)

const legacyTestDeviceID = "dev_abcdefghijklmnopqrstuvwxyz"

type legacyTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newLegacyTestCA(t *testing.T, commonName string) legacyTestCA {
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
	return legacyTestCA{cert: cert, key: key}
}

func (ca legacyTestCA) issue(t *testing.T, commonName string, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(len(commonName) + 2)),
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
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
}

func writeLegacyTestPEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
}

func legacyHandshake(t *testing.T, serverConfig, clientConfig *tls.Config) (serverErr, clientErr error) {
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
	return <-serverDone, clientErr
}

func TestLoadTLSRequiresAndVerifiesClientCertificate(t *testing.T) {
	trusted := newLegacyTestCA(t, "trusted")
	serverCert := trusted.issue(t, "localhost", true)
	trustedClient := trusted.issue(t, legacyTestDeviceID, false)
	rogueClient := newLegacyTestCA(t, "rogue").issue(t, legacyTestDeviceID, false)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.pem")
	keyPath := filepath.Join(dir, "server-key.pem")
	caPath := filepath.Join(dir, "client-ca.pem")
	writeLegacyTestPEM(t, certPath, "CERTIFICATE", serverCert.Certificate[0])
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyTestPEM(t, keyPath, "PRIVATE KEY", keyDER)
	writeLegacyTestPEM(t, caPath, "CERTIFICATE", trusted.cert.Raw)

	tlsCfg, err := loadTLS(config{tlsCertPath: certPath, tlsKeyPath: keyPath, clientCAPath: caPath})
	if err != nil {
		t.Fatalf("loadTLS: %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsCfg.ClientAuth)
	}

	serverErr, _ := legacyHandshake(t, tlsCfg, &tls.Config{InsecureSkipVerify: true})
	if serverErr == nil {
		t.Fatal("missing client certificate handshake succeeded")
	}
	serverErr, _ = legacyHandshake(t, tlsCfg, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{rogueClient}})
	if serverErr == nil {
		t.Fatal("untrusted client certificate handshake succeeded")
	}
	serverErr, clientErr := legacyHandshake(t, tlsCfg, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{trustedClient}})
	if serverErr != nil || clientErr != nil {
		t.Fatalf("trusted client certificate handshake failed: server=%v client=%v", serverErr, clientErr)
	}
}

func TestLegacyHandlerBindsCertificateAndPortalDevice(t *testing.T) {
	ca := newLegacyTestCA(t, "handler")
	clientCert := ca.issue(t, legacyTestDeviceID, false)
	clientLeaf, err := x509.ParseCertificate(clientCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	validator := auth.NewCertValidator(auth.CertValidatorConfig{
		ClientCAs: roots,
		Now:       func() time.Time { return time.Unix(1800000000, 0) },
	})

	for _, tc := range []struct {
		name, portalDevice, want string
	}{
		{name: "matching device", portalDevice: legacyTestDeviceID, want: `type="complete"`},
		{name: "mismatching device", portalDevice: "dev_zyxwvutsrqponmlkjihgfedcba", want: "Sign-in failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			portal := &auth.MockVerifier{}
			portal.Set("user", "password", tc.portalDevice)
			srv := cstp.NewServer(cstp.Config{
				Verifier:   certBoundVerifier{inner: portal},
				ServerName: "localhost",
				RandRead: func(p []byte) (int, error) {
					for i := range p {
						p[i] = byte(i + 1)
					}
					return len(p), nil
				},
			})
			handler := certMiddleware(validator, srv)
			serve := func(path, body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, "https://localhost"+path, strings.NewReader(body))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientLeaf}}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				return rec
			}

			init := serve("/", `<config-auth client="vpn" type="init"/>`)
			if init.Code != http.StatusOK {
				t.Fatalf("init status = %d", init.Code)
			}
			opaque := legacyOpaqueID(init.Body.String())
			if opaque == "" {
				t.Fatal("init response did not contain an opaque session ID")
			}
			username := serve("/auth", legacyAuthReply(opaque, "user", ""))
			if username.Code != http.StatusOK {
				t.Fatalf("username status = %d", username.Code)
			}
			password := serve("/auth", legacyAuthReply(opaque, "", "password"))
			if password.Code != http.StatusOK || !strings.Contains(password.Body.String(), tc.want) {
				t.Fatalf("password response = status %d body %q, want %q", password.Code, password.Body.String(), tc.want)
			}
		})
	}
}

func TestVerifierForModeScopesCertificateBindingToLegacy(t *testing.T) {
	raw := &auth.MockVerifier{}

	legacy, ok := verifierForMode(modeLegacy, raw).(certBoundVerifier)
	if !ok {
		t.Fatal("legacy verifier is not certificate-bound")
	}
	if legacy.inner != raw {
		t.Fatal("legacy verifier does not wrap the raw portal verifier")
	}

	uds := verifierForMode(modeUDS, raw)
	if uds != raw {
		t.Fatal("UDS verifier was globally wrapped; want the raw portal verifier")
	}
}

func legacyAuthReply(opaque, username, password string) string {
	return `<config-auth client="vpn" type="auth-reply"><opaque is-for="sg"><session-id>` + opaque + `</session-id></opaque><auth><username>` + username + `</username><password>` + password + `</password></auth></config-auth>`
}

func legacyOpaqueID(body string) string {
	const open = "<session-id>"
	const close = "</session-id>"
	start := strings.Index(body, open)
	if start < 0 {
		return ""
	}
	rest := body[start+len(open):]
	end := strings.Index(rest, close)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func TestRequireFlagsByMode(t *testing.T) {
	base := config{
		tlsCertPath: "server.pem", tlsKeyPath: "server-key.pem", clientCAPath: "client-ca.pem",
		portalURL: "https://portal.test", portalToken: "portal-token",
		tpmURL: "https://tpm.test", tpmToken: "tpm-token", udsSocketPath: "/tmp/era-ocserv.sock",
	}
	for _, tc := range []struct {
		name   string
		mode   listenerMode
		mutate func(*config)
		want   string
	}{
		{name: "legacy requires client CA", mode: modeLegacy, mutate: func(c *config) { c.clientCAPath = "" }, want: "-client-ca"},
		{name: "UDS skips legacy TLS inputs", mode: modeUDS, mutate: func(c *config) { c.tlsCertPath, c.tlsKeyPath, c.clientCAPath = "", "", "" }},
		{name: "UDS requires socket", mode: modeUDS, mutate: func(c *config) { c.udsSocketPath = "" }, want: "-uds-socket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			err := requireFlags(cfg, tc.mode)
			if tc.want == "" && err != nil {
				t.Fatalf("requireFlags: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("requireFlags error = %v, want %q", err, tc.want)
			}
		})
	}
}
