package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// testPKI is a self-contained CA + leaf factory for cert-validator
// tests. It avoids any disk I/O so tests run on Windows, Linux, and
// macOS without per-OS fixturing.
type testPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	roots  *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "era test CA",
			Organization: []string{"ERA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return &testPKI{caCert: caCert, caKey: caKey, roots: roots}
}

// leafOpts shapes the leaf certificate produced by issueLeaf.
type leafOpts struct {
	// commonName populates Subject.CommonName.
	commonName string
	// orgUnits, when non-empty, populates Subject.OrganizationalUnit.
	orgUnits []string
	// notBefore / notAfter override the validity window. Zero values
	// default to a ±1h window around now.
	notBefore time.Time
	notAfter  time.Time
	// extKeyUsage overrides the ext-key-usage set. Defaults to
	// ClientAuth alone.
	extKeyUsage []x509.ExtKeyUsage
}

func (p *testPKI) issueLeaf(t *testing.T, opts leafOpts) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	now := time.Now()
	nb := opts.notBefore
	if nb.IsZero() {
		nb = now.Add(-time.Hour)
	}
	na := opts.notAfter
	if na.IsZero() {
		na = now.Add(time.Hour)
	}
	usages := opts.extKeyUsage
	if usages == nil {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         opts.commonName,
			OrganizationalUnit: opts.orgUnits,
		},
		NotBefore:   nb,
		NotAfter:    na,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &leafKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return leaf
}

// connStateWith returns a tls.ConnectionState that the validator can
// consume. We only populate PeerCertificates because that is the only
// field Validate reads.
func connStateWith(certs ...*x509.Certificate) tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: certs}
}

// validDeviceIDSample is a real-shape device id (26 lowercase
// [a-z2-7] characters after the "dev_" prefix). Reused across tests
// so the readable token doesn't drift.
const validDeviceIDSample = "dev_abcdefghijklmnopqrstuvwxyz"
