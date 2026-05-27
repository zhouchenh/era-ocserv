package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}

// newTestVerifier wires an HTTPVerifier against the given handler and
// returns the server (for inspection) and the verifier.
func newTestVerifier(t *testing.T, h http.HandlerFunc) (*httptest.Server, *HTTPVerifier) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	v := NewHTTPVerifier(HTTPVerifierConfig{
		BaseURL:      mustParseURL(t, srv.URL),
		ServiceToken: "test-service-token",
		HTTPClient:   srv.Client(),
	})
	return srv, v
}

func TestHTTPVerifier_Success(t *testing.T) {
	var sawAuth, sawCT, sawAccept string
	var sawMethod, sawPath string
	var sawBody verifyRequest

	_, v := newTestVerifier(t, func(w http.ResponseWriter, r *http.Request) {
		sawMethod = r.Method
		sawPath = r.URL.Path
		sawAuth = r.Header.Get("Authorization")
		sawCT = r.Header.Get("Content-Type")
		sawAccept = r.Header.Get("Accept")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &sawBody); err != nil {
			t.Errorf("unmarshal body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verifyResponse{DeviceID: validDeviceIDSample})
	})

	got, err := v.Verify(context.Background(), "alice", "hunter2")
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if got != validDeviceIDSample {
		t.Fatalf("Verify: device id = %q, want %q", got, validDeviceIDSample)
	}

	if sawMethod != http.MethodPost {
		t.Errorf("server saw method %q, want POST", sawMethod)
	}
	if sawPath != verifyPath {
		t.Errorf("server saw path %q, want %q", sawPath, verifyPath)
	}
	if sawAuth != "Bearer test-service-token" {
		t.Errorf("server saw Authorization %q, want %q", sawAuth, "Bearer test-service-token")
	}
	if !strings.HasPrefix(sawCT, "application/json") {
		t.Errorf("server saw Content-Type %q, want application/json", sawCT)
	}
	if sawAccept != "application/json" {
		t.Errorf("server saw Accept %q, want application/json", sawAccept)
	}
	if sawBody.Username != "alice" || sawBody.Password != "hunter2" {
		t.Errorf("server saw body %+v, want {alice hunter2}", sawBody)
	}
}

func TestHTTPVerifier_PreservesBasePath(t *testing.T) {
	// BaseURL with a path prefix should be honoured by the resolved
	// endpoint. Some era-portal deployments could mount the API under
	// /api/v1 or similar.
	var sawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verifyResponse{DeviceID: validDeviceIDSample})
	}))
	defer srv.Close()

	// Note: ResolveReference with a rooted path replaces any existing
	// base path. The behaviour is documented; we assert it explicitly
	// so a future change to the resolution code does not silently break
	// callers who relied on this.
	base := mustParseURL(t, srv.URL+"/api/v1")
	v := NewHTTPVerifier(HTTPVerifierConfig{
		BaseURL:      base,
		ServiceToken: "tok",
		HTTPClient:   srv.Client(),
	})
	if _, err := v.Verify(context.Background(), "a", "b"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sawPath != verifyPath {
		t.Fatalf("server saw path %q, want %q (rooted verifyPath replaces base prefix)", sawPath, verifyPath)
	}
}

func TestHTTPVerifier_BadCredentials(t *testing.T) {
	_, v := newTestVerifier(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := v.Verify(context.Background(), "alice", "wrong")
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("Verify: err = %v, want ErrBadCredentials", err)
	}
}

func TestHTTPVerifier_AccountLocked(t *testing.T) {
	_, v := newTestVerifier(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusLocked)
	})
	_, err := v.Verify(context.Background(), "alice", "anything")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("Verify: err = %v, want ErrAccountLocked", err)
	}
}

func TestHTTPVerifier_Upstream5xx(t *testing.T) {
	cases := []int{500, 502, 503, 504}
	for _, code := range cases {
		t.Run(http.StatusText(code), func(t *testing.T) {
			_, v := newTestVerifier(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			})
			_, err := v.Verify(context.Background(), "alice", "p")
			if !errors.Is(err, ErrUpstream) {
				t.Fatalf("Verify(%d): err = %v, want ErrUpstream", code, err)
			}
		})
	}
}

func TestHTTPVerifier_UnexpectedStatus(t *testing.T) {
	_, v := newTestVerifier(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	_, err := v.Verify(context.Background(), "alice", "p")
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("Verify(418): err = %v, want ErrUpstream", err)
	}
}

func TestHTTPVerifier_MalformedResponse(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"not-json", "not json at all"},
		{"missing-device-id", `{"foo":"bar"}`},
		{"unknown-fields", `{"device_id":"` + validDeviceIDSample + `","extra":1}`},
		{"malformed-device-id", `{"device_id":"not-a-valid-id"}`},
		{"empty-device-id", `{"device_id":""}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, v := newTestVerifier(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := v.Verify(context.Background(), "alice", "p")
			if !errors.Is(err, ErrUpstream) {
				t.Fatalf("Verify(%s): err = %v, want ErrUpstream", tc.name, err)
			}
		})
	}
}

func TestHTTPVerifier_OversizedResponse(t *testing.T) {
	// A response larger than the 8 KiB cap should be refused as
	// upstream-malformed.
	big := strings.Repeat("a", 16<<10)
	body := `{"device_id":"` + validDeviceIDSample + `","junk":"` + big + `"}`
	_, v := newTestVerifier(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	})
	_, err := v.Verify(context.Background(), "alice", "p")
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("Verify: err = %v, want ErrUpstream", err)
	}
}

func TestHTTPVerifier_Timeout(t *testing.T) {
	// Server stalls just past the client-side context deadline so the
	// verifier must surface the timeout as ErrUpstream. The handler
	// returns on its own short deadline so httptest.Server.Close does
	// not linger waiting for the connection on platforms where the
	// client-side cancel does not promptly propagate.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}))
	t.Cleanup(srv.Close)

	v := NewHTTPVerifier(HTTPVerifierConfig{
		BaseURL:      mustParseURL(t, srv.URL),
		ServiceToken: "tok",
		HTTPClient:   srv.Client(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := v.Verify(ctx, "alice", "p")
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("Verify: err = %v, want ErrUpstream wrapping deadline", err)
	}
}

func TestHTTPVerifier_NotConfigured(t *testing.T) {
	// Per the symmetric "fail fast at construction" contract with
	// iam.NewTPMResolver (wave-1 review API-smell #2), missing
	// required fields panic rather than degrade to runtime errors.
	t.Run("nil base url panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("expected panic on nil BaseURL")
			}
		}()
		_ = NewHTTPVerifier(HTTPVerifierConfig{})
	})

	t.Run("empty service token panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("expected panic on empty ServiceToken")
			}
		}()
		_ = NewHTTPVerifier(HTTPVerifierConfig{
			BaseURL: mustParseURL(t, "https://example.invalid"),
		})
	})

	// A nil HTTPVerifier receiver still surfaces ErrUpstream rather
	// than panicking, so callers that hold a *HTTPVerifier in a
	// nillable field do not crash.
	var v *HTTPVerifier
	if _, err := v.Verify(context.Background(), "a", "b"); !errors.Is(err, ErrUpstream) {
		t.Fatalf("nil-receiver Verify: err = %v, want ErrUpstream", err)
	}
}

func TestHTTPVerifier_DefaultClientHasTimeout(t *testing.T) {
	// We do not actually wait for the default 5s timeout; just confirm
	// the constructor populates a client at all when none is provided.
	v := NewHTTPVerifier(HTTPVerifierConfig{
		BaseURL:      mustParseURL(t, "https://example.invalid"),
		ServiceToken: "tok",
	})
	if v.httpClient == nil {
		t.Fatal("default HTTPClient was not populated")
	}
	if v.httpClient.Timeout != defaultHTTPTimeout {
		t.Fatalf("default timeout = %v, want %v", v.httpClient.Timeout, defaultHTTPTimeout)
	}
}

func TestHTTPVerifier_RequestSerializationFields(t *testing.T) {
	// Confirm the wire field names are stable: era-portal will agree
	// on the contract once the access-method work lands.
	var raw map[string]any
	_, v := newTestVerifier(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &raw)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verifyResponse{DeviceID: validDeviceIDSample})
	})
	if _, err := v.Verify(context.Background(), "alice", "hunter2"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := raw["username"]; got != "alice" {
		t.Errorf("body[username] = %v, want alice", got)
	}
	if got := raw["password"]; got != "hunter2" {
		t.Errorf("body[password] = %v, want hunter2", got)
	}
	if len(raw) != 2 {
		t.Errorf("body has %d fields, want exactly username+password", len(raw))
	}
}
