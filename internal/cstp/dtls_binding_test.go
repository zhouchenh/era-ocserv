package cstp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
)

func TestHTTPDTLSBindingInstallerUpsert(t *testing.T) {
	var (
		gotAuth string
		gotBody map[string]string
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	installer, err := NewHTTPDTLSBindingInstaller(HTTPDTLSBindingInstallerConfig{
		BaseURL:      base,
		ServiceToken: "svc-token-123",
		Client:       ts.Client(),
	})
	if err != nil {
		t.Fatalf("NewHTTPDTLSBindingInstaller: %v", err)
	}

	var psk [32]byte
	for i := range psk {
		psk[i] = 1
	}
	var token [12]byte
	for i := range token {
		token[i] = 2
	}
	err = installer.Upsert(context.Background(), DTLSBinding{
		SourceIP:      netip.MustParseAddr("198.51.100.10"),
		PSK:           psk,
		DeviceID:      "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa",
		UserID:        "user-1",
		MTLSSubjectDN: "CN=dev_aaaaaaaaaaaaaaaaaaaaaaaaaa,O=ERA",
		SourceV6:      netip.MustParseAddr("2001:db8::10"),
		Token:         token,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if gotAuth != "Bearer svc-token-123" {
		t.Fatalf("Authorization = %q, want Bearer svc-token-123", gotAuth)
	}
	if gotBody["source_ip"] != "198.51.100.10" {
		t.Fatalf("source_ip = %q", gotBody["source_ip"])
	}
	if gotBody["device_id"] != "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("device_id = %q", gotBody["device_id"])
	}
}

func TestHTTPDTLSBindingInstallerRejectsBadStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	installer, err := NewHTTPDTLSBindingInstaller(HTTPDTLSBindingInstallerConfig{
		BaseURL:      base,
		ServiceToken: "svc-token-123",
		Client:       ts.Client(),
	})
	if err != nil {
		t.Fatalf("NewHTTPDTLSBindingInstaller: %v", err)
	}

	err = installer.Upsert(context.Background(), DTLSBinding{
		SourceIP:      netip.MustParseAddr("198.51.100.10"),
		DeviceID:      "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa",
		UserID:        "user-1",
		MTLSSubjectDN: "CN=dev_aaaaaaaaaaaaaaaaaaaaaaaaaa,O=ERA",
		SourceV6:      netip.MustParseAddr("2001:db8::10"),
	})
	if err == nil {
		t.Fatal("Upsert error = nil, want non-nil")
	}
}
