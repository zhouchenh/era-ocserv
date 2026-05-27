package e2e_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// pki is a minimal CA-plus-leaf factory for end-to-end TLS tests. It
// generates everything in memory so the tests have no disk dependency
// and run identically on Windows / Linux / macOS.
//
// The PKI shape:
//
//	clientRootCert / clientRootKey  -- the mTLS client CA the server
//	                                   trusts.
//	serverCert / serverKey          -- the gateway's server cert; SAN
//	                                   covers "vpn.eracloud.app" and
//	                                   the loopback IP, so a fake
//	                                   client with the right
//	                                   ServerName + RootCA can dial.
//
// issueClientLeaf mints a per-test client leaf signed by clientRoot
// with the requested CN. The auth.CertValidator (configured for "CN")
// then extracts the device id from the leaf's CommonName.
type pki struct {
	clientRootCert *x509.Certificate
	clientRootKey  *ecdsa.PrivateKey
	clientRoots    *x509.CertPool

	serverCert    *x509.Certificate
	serverKey     *ecdsa.PrivateKey
	serverRoots   *x509.CertPool
	serverTLSCert tls.Certificate
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{}

	// --- client CA ---------------------------------------------------
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "era e2e client CA",
			Organization: []string{"ERA E2E"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse client CA: %v", err)
	}
	p.clientRootCert = caCert
	p.clientRootKey = caKey
	p.clientRoots = x509.NewCertPool()
	p.clientRoots.AddCert(caCert)

	// --- server cert -------------------------------------------------
	// Self-signed so the test only needs one CA pool to trust as the
	// client root. SAN includes the loopback IP because the fake
	// AnyConnect client dials 127.0.0.1; ServerName overrides hostname
	// matching but having the IP in SAN keeps the cert valid for any
	// transport that does the verification by IP.
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "vpn.eracloud.app",
			Organization: []string{"ERA E2E"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"vpn.eracloud.app", "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		BasicConstraintsValid: true,
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, srvTmpl, &srvKey.PublicKey, srvKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	srvCert, err := x509.ParseCertificate(srvDER)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	p.serverCert = srvCert
	p.serverKey = srvKey
	p.serverRoots = x509.NewCertPool()
	p.serverRoots.AddCert(srvCert)
	p.serverTLSCert = tls.Certificate{
		Certificate: [][]byte{srvDER},
		PrivateKey:  srvKey,
		Leaf:        srvCert,
	}

	return p
}

// issueClientLeaf mints a client cert with the requested CN, signed by
// the client root CA. The returned tls.Certificate is ready to drop
// into tls.Config.Certificates for the fake client.
func (p *pki) issueClientLeaf(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.clientRootCert, &key.PublicKey, p.clientRootKey)
	if err != nil {
		t.Fatalf("create client leaf: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse client leaf: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        parsed,
	}
}

// clientTLSConfig builds a tls.Config the fake AnyConnect client can
// use to dial the gateway. If clientCert is the zero value, the
// returned config presents no client cert (used to exercise the
// "missing client cert" failure path).
func (p *pki) clientTLSConfig(clientCert tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		RootCAs:    p.serverRoots,
		ServerName: "vpn.eracloud.app",
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	if clientCert.Leaf != nil {
		cfg.Certificates = []tls.Certificate{clientCert}
	}
	return cfg
}

// serverTLSConfig builds the gateway's tls.Config: presents serverCert
// and requires + verifies client certs against clientRoots.
func (p *pki) serverTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{p.serverTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.clientRoots,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
}
