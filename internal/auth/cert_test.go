package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestCertValidator_HappyPath_CN(t *testing.T) {
	pki := newTestPKI(t)
	leaf := pki.issueLeaf(t, leafOpts{commonName: validDeviceIDSample})

	v := NewCertValidator(CertValidatorConfig{ClientCAs: pki.roots})
	got, err := v.Validate(connStateWith(leaf))
	if err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if got != validDeviceIDSample {
		t.Fatalf("Validate: device id = %q, want %q", got, validDeviceIDSample)
	}
}

func TestCertValidator_HappyPath_OU(t *testing.T) {
	pki := newTestPKI(t)
	leaf := pki.issueLeaf(t, leafOpts{
		commonName: "noise-not-a-device-id",
		orgUnits:   []string{validDeviceIDSample},
	})

	v := NewCertValidator(CertValidatorConfig{
		ClientCAs:    pki.roots,
		SubjectField: "OU",
	})
	got, err := v.Validate(connStateWith(leaf))
	if err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if got != validDeviceIDSample {
		t.Fatalf("Validate: device id = %q, want %q", got, validDeviceIDSample)
	}
}

func TestCertValidator_NoCert(t *testing.T) {
	pki := newTestPKI(t)
	v := NewCertValidator(CertValidatorConfig{ClientCAs: pki.roots})

	_, err := v.Validate(connStateWith())
	if !errors.Is(err, ErrNoCert) {
		t.Fatalf("Validate: err = %v, want ErrNoCert", err)
	}
}

func TestCertValidator_Expired(t *testing.T) {
	pki := newTestPKI(t)
	// Issue a cert whose validity window ended an hour ago.
	leaf := pki.issueLeaf(t, leafOpts{
		commonName: validDeviceIDSample,
		notBefore:  time.Now().Add(-2 * time.Hour),
		notAfter:   time.Now().Add(-time.Hour),
	})

	v := NewCertValidator(CertValidatorConfig{ClientCAs: pki.roots})
	_, err := v.Validate(connStateWith(leaf))
	if !errors.Is(err, ErrCertExpired) {
		t.Fatalf("Validate: err = %v, want ErrCertExpired", err)
	}
}

func TestCertValidator_NotYetValid(t *testing.T) {
	pki := newTestPKI(t)
	// Issue a cert whose validity window starts in the future.
	leaf := pki.issueLeaf(t, leafOpts{
		commonName: validDeviceIDSample,
		notBefore:  time.Now().Add(time.Hour),
		notAfter:   time.Now().Add(2 * time.Hour),
	})

	v := NewCertValidator(CertValidatorConfig{ClientCAs: pki.roots})
	_, err := v.Validate(connStateWith(leaf))
	if !errors.Is(err, ErrCertExpired) {
		t.Fatalf("Validate: err = %v, want ErrCertExpired (used for not-yet-valid too)", err)
	}
}

func TestCertValidator_Untrusted(t *testing.T) {
	// Build a cert signed by a CA that the validator does not trust.
	otherPKI := newTestPKI(t)
	leaf := otherPKI.issueLeaf(t, leafOpts{commonName: validDeviceIDSample})

	// Trust pool is a different CA.
	trustedPKI := newTestPKI(t)
	v := NewCertValidator(CertValidatorConfig{ClientCAs: trustedPKI.roots})

	_, err := v.Validate(connStateWith(leaf))
	if !errors.Is(err, ErrCertUntrusted) {
		t.Fatalf("Validate: err = %v, want ErrCertUntrusted", err)
	}
}

func TestCertValidator_EmptyRootsRejects(t *testing.T) {
	// A validator with nil ClientCAs rejects every cert as untrusted
	// (x509.Verify with nil Roots uses the system pool on Linux/macOS
	// and an empty pool on Windows; in either case a self-signed leaf
	// won't verify). We pass an explicit empty pool to keep the test
	// stable across platforms.
	pki := newTestPKI(t)
	leaf := pki.issueLeaf(t, leafOpts{commonName: validDeviceIDSample})

	v := NewCertValidator(CertValidatorConfig{ClientCAs: x509.NewCertPool()})
	_, err := v.Validate(connStateWith(leaf))
	if !errors.Is(err, ErrCertUntrusted) {
		t.Fatalf("Validate: err = %v, want ErrCertUntrusted", err)
	}
}

func TestCertValidator_NoDeviceID_EmptyCN(t *testing.T) {
	pki := newTestPKI(t)
	leaf := pki.issueLeaf(t, leafOpts{commonName: ""})

	v := NewCertValidator(CertValidatorConfig{ClientCAs: pki.roots})
	_, err := v.Validate(connStateWith(leaf))
	if !errors.Is(err, ErrNoDeviceID) {
		t.Fatalf("Validate: err = %v, want ErrNoDeviceID", err)
	}
}

func TestCertValidator_NoDeviceID_MalformedCN(t *testing.T) {
	pki := newTestPKI(t)
	cases := []struct {
		name string
		cn   string
	}{
		{"wrong-prefix", "usr_abcdefghijklmnopqrstuvwxyz"},
		{"missing-prefix", "abcdefghijklmnopqrstuvwxyz"},
		{"short-body", "dev_abcdefghijklmnopq"},
		{"long-body", "dev_abcdefghijklmnopqrstuvwxyz12"},
		{"uppercase-body", "dev_ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
		{"non-base32-digit", "dev_abcdefghijklmnopqrstuvwxy1"},
		{"non-base32-digit-9", "dev_abcdefghijklmnopqrstuvwxy9"},
		{"contains-space", "dev_abcdefghijklmnopqrstuvwx z"},
	}
	v := NewCertValidator(CertValidatorConfig{ClientCAs: pki.roots})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf := pki.issueLeaf(t, leafOpts{commonName: tc.cn})
			_, err := v.Validate(connStateWith(leaf))
			if !errors.Is(err, ErrNoDeviceID) {
				t.Fatalf("Validate(%q): err = %v, want ErrNoDeviceID", tc.cn, err)
			}
		})
	}
}

func TestCertValidator_NoDeviceID_OUEmpty(t *testing.T) {
	pki := newTestPKI(t)
	// CN holds a valid id, but the validator is configured for OU
	// and OU is empty.
	leaf := pki.issueLeaf(t, leafOpts{commonName: validDeviceIDSample})

	v := NewCertValidator(CertValidatorConfig{
		ClientCAs:    pki.roots,
		SubjectField: "OU",
	})
	_, err := v.Validate(connStateWith(leaf))
	if !errors.Is(err, ErrNoDeviceID) {
		t.Fatalf("Validate: err = %v, want ErrNoDeviceID", err)
	}
}

func TestCertValidator_NoDeviceID_TrimsWhitespace(t *testing.T) {
	pki := newTestPKI(t)
	// CN with surrounding whitespace should be trimmed and then
	// match cleanly. Some CA tooling leaves a trailing newline.
	leaf := pki.issueLeaf(t, leafOpts{commonName: "  " + validDeviceIDSample + "\n"})

	v := NewCertValidator(CertValidatorConfig{ClientCAs: pki.roots})
	got, err := v.Validate(connStateWith(leaf))
	if err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if got != validDeviceIDSample {
		t.Fatalf("Validate: device id = %q, want %q", got, validDeviceIDSample)
	}
}

func TestCertValidator_WrongExtKeyUsage(t *testing.T) {
	// A cert whose EKU is ServerAuth only should fail re-verification
	// with KeyUsages: ClientAuth even though it chains to our CA.
	pki := newTestPKI(t)
	leaf := pki.issueLeaf(t, leafOpts{
		commonName:  validDeviceIDSample,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	v := NewCertValidator(CertValidatorConfig{ClientCAs: pki.roots})
	_, err := v.Validate(connStateWith(leaf))
	if !errors.Is(err, ErrCertUntrusted) {
		t.Fatalf("Validate: err = %v, want ErrCertUntrusted", err)
	}
}

func TestCertValidator_NowInjectable(t *testing.T) {
	pki := newTestPKI(t)
	// Cert ends in 30m; we pin Now to 90m from real-now so it looks
	// expired without needing real wall-clock control.
	leaf := pki.issueLeaf(t, leafOpts{
		commonName: validDeviceIDSample,
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(30 * time.Minute),
	})

	frozen := time.Now().Add(90 * time.Minute)
	v := NewCertValidator(CertValidatorConfig{
		ClientCAs: pki.roots,
		Now:       func() time.Time { return frozen },
	})
	_, err := v.Validate(connStateWith(leaf))
	if !errors.Is(err, ErrCertExpired) {
		t.Fatalf("Validate: err = %v, want ErrCertExpired", err)
	}
}

func TestCertValidator_UnknownSubjectFieldFallsBackToCN(t *testing.T) {
	pki := newTestPKI(t)
	leaf := pki.issueLeaf(t, leafOpts{commonName: validDeviceIDSample})

	v := NewCertValidator(CertValidatorConfig{
		ClientCAs:    pki.roots,
		SubjectField: "bogus",
	})
	got, err := v.Validate(connStateWith(leaf))
	if err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if got != validDeviceIDSample {
		t.Fatalf("Validate: device id = %q, want %q", got, validDeviceIDSample)
	}
}

func TestCertValidator_WithIntermediateChain(t *testing.T) {
	// Build a 3-tier chain: root -> intermediate -> leaf, and confirm
	// the validator can climb to the trusted root when the
	// intermediate is delivered alongside the leaf in PeerCertificates.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "era root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen inter key: %v", err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "era intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	interCert, _ := x509.ParseCertificate(interDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: validDeviceIDSample},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	v := NewCertValidator(CertValidatorConfig{ClientCAs: roots})

	got, err := v.Validate(connStateWith(leafCert, interCert))
	if err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if got != validDeviceIDSample {
		t.Fatalf("Validate: device id = %q, want %q", got, validDeviceIDSample)
	}
}
