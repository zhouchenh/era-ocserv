package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PasswordVerifier verifies username + password pairs and returns the
// device UUID the credentials are bound to. Implementations:
//
//   - HTTPVerifier — calls era-portal over HTTPS.
//   - MockVerifier — in-memory, exported for downstream tests.
//
// Errors returned by Verify should be one of the sentinels declared in
// errors.go (ErrBadCredentials, ErrAccountLocked, ErrUpstream) wrapped
// with %w when context is added.
type PasswordVerifier interface {
	Verify(ctx context.Context, username, password string) (deviceID string, err error)
}

// HTTPVerifier verifies passwords by calling era-portal's auth-verify
// endpoint over HTTPS.
//
// The wire shape below is a sketch and subject to revision when the
// era-portal access-method work lands; see the package-level note and
// docs/decisions/0057-era-ocserv-architecture.md §4.
type HTTPVerifier struct {
	endpoint     *url.URL
	serviceToken string
	httpClient   *http.Client
}

// HTTPVerifierConfig configures an HTTPVerifier.
type HTTPVerifierConfig struct {
	// BaseURL is the era-portal base URL, e.g.
	// https://100.91.1.48:18090. The verifier appends the auth-verify
	// path to it. Required.
	BaseURL *url.URL

	// ServiceToken is the bearer token presented to the auth-verify
	// endpoint. Required.
	ServiceToken string

	// HTTPClient is used for outbound calls. If nil, a default client
	// with a 5s timeout is constructed. Callers wanting custom TLS
	// config, transport pooling, or longer timeouts pass their own.
	HTTPClient *http.Client
}

// verifyPath is the era-portal auth-verify path. Endpoint is a sketch
// and subject to revision when the era-portal access-method work lands.
const verifyPath = "/api/auth/ocserv/verify"

// defaultHTTPTimeout caps a single password verification round-trip.
// 5s is comfortably above the iOS Cisco Secure Client's >5s auth cliff
// (see protocol §3.3) while keeping era-portal failures from blocking
// the auth goroutine for tens of seconds.
const defaultHTTPTimeout = 5 * time.Second

// NewHTTPVerifier returns an HTTPVerifier configured against cfg.
// A nil BaseURL or empty ServiceToken still constructs the verifier;
// the failure surfaces on the first Verify call as ErrUpstream so
// caller startup wiring can choose to log or panic.
func NewHTTPVerifier(cfg HTTPVerifierConfig) *HTTPVerifier {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	var endpoint *url.URL
	if cfg.BaseURL != nil {
		// Resolve verifyPath against the configured base so a base
		// like ".../api/v1" is preserved; ResolveReference with a
		// rooted ref replaces the base path, which is the documented
		// contract anyway.
		ref := &url.URL{Path: verifyPath}
		endpoint = cfg.BaseURL.ResolveReference(ref)
	}
	return &HTTPVerifier{
		endpoint:     endpoint,
		serviceToken: cfg.ServiceToken,
		httpClient:   client,
	}
}

type verifyRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type verifyResponse struct {
	DeviceID string `json:"device_id"`
}

func normalizeServiceToken(s string) string {
	return strings.TrimSpace(strings.TrimPrefix(s, "\ufeff"))
}

// Verify posts username + password to the era-portal auth-verify
// endpoint and returns the device UUID on success.
func (h *HTTPVerifier) Verify(ctx context.Context, username, password string) (string, error) {
	if h == nil || h.endpoint == nil {
		return "", fmt.Errorf("%w: verifier not configured", ErrUpstream)
	}
	token := normalizeServiceToken(h.serviceToken)
	if token == "" {
		return "", fmt.Errorf("%w: service token not configured", ErrUpstream)
	}

	body, err := json.Marshal(verifyRequest{Username: username, Password: password})
	if err != nil {
		// json.Marshal on two strings cannot fail; treat as upstream
		// to keep the function total.
		return "", fmt.Errorf("%w: encode request: %v", ErrUpstream, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("%w: build request: %v", ErrUpstream, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		// net/http surfaces context.DeadlineExceeded as a *url.Error
		// wrapping the underlying cause; rewrap with ErrUpstream so
		// callers do not have to do their own context.Is dance.
		return "", fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusOK:
		// fall through to body parsing
	case resp.StatusCode == http.StatusUnauthorized:
		return "", ErrBadCredentials
	case resp.StatusCode == http.StatusLocked:
		return "", ErrAccountLocked
	case resp.StatusCode >= 500 && resp.StatusCode <= 599:
		return "", fmt.Errorf("%w: era-portal status %d", ErrUpstream, resp.StatusCode)
	default:
		return "", fmt.Errorf("%w: era-portal status %d", ErrUpstream, resp.StatusCode)
	}

	// Cap the response body. era-portal returns a small JSON object;
	// anything larger than 8 KiB is suspicious and we refuse it.
	const maxBody = 8 << 10
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return "", fmt.Errorf("%w: read response: %v", ErrUpstream, err)
	}
	if len(raw) > maxBody {
		return "", fmt.Errorf("%w: era-portal response exceeds %d bytes", ErrUpstream, maxBody)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", fmt.Errorf("%w: era-portal returned empty body", ErrUpstream)
	}

	var parsed verifyResponse
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		return "", fmt.Errorf("%w: decode response: %v", ErrUpstream, err)
	}
	deviceID := strings.TrimSpace(parsed.DeviceID)
	if !validDeviceID(deviceID) {
		return "", fmt.Errorf("%w: era-portal returned malformed device id", ErrUpstream)
	}
	return deviceID, nil
}

// Compile-time guarantee that HTTPVerifier implements PasswordVerifier.
var _ PasswordVerifier = (*HTTPVerifier)(nil)
