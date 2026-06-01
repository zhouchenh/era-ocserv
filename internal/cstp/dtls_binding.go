package cstp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// DTLSBinding is the CSTP-authenticated metadata era-ocserv publishes to the
// facade so the shared-edge DTLS terminator can admit the matching UDP source.
type DTLSBinding struct {
	SourceIP      netip.Addr
	PSK           [32]byte // legacy PSK-NEGOTIATE path; UNUSED for Cisco injected-premaster DTLS
	DeviceID      string
	UserID        string
	MTLSSubjectDN string
	SourceV6      netip.Addr
	Token         [12]byte

	// Cisco AnyConnect legacy DTLS (the mode iOS actually uses): the client
	// sends a 48-byte master secret in the CONNECT request, the server echoes a
	// 32-byte Session-ID + a real cipher, and the DTLS handshake is an
	// abbreviated session-resumption keyed by that master secret (the facade's
	// pion dtls.Server consumes these via a SessionStore == gnutls_session_set_premaster).
	DTLSMasterSecret [48]byte // client-chosen, from X-Dtls-Master-Secret (96 hex -> 48B)
	DTLSSessionID    [32]byte // server-chosen, echoed in X-DTLS-Session-ID
	DTLSCipher       string   // chosen oc_name, e.g. "ECDHE-RSA-AES128-GCM-SHA256"
}

// DTLSBindingInstaller pushes CSTP-authenticated DTLS bindings to the facade.
type DTLSBindingInstaller interface {
	Upsert(ctx context.Context, binding DTLSBinding) error
}

// HTTPDTLSBindingInstallerConfig configures the loopback HTTP client used to
// publish CSTP -> DTLS bindings into the facade admin API.
type HTTPDTLSBindingInstallerConfig struct {
	BaseURL      *url.URL
	ServiceToken string
	Client       *http.Client
	Timeout      time.Duration
}

// HTTPDTLSBindingInstaller POSTS bindings to facade's /api/dtls/bindings.
type HTTPDTLSBindingInstaller struct {
	url   string
	token string
	http  *http.Client
}

func NewHTTPDTLSBindingInstaller(cfg HTTPDTLSBindingInstallerConfig) (*HTTPDTLSBindingInstaller, error) {
	if cfg.BaseURL == nil {
		return nil, fmt.Errorf("dtls binding installer: base URL required")
	}
	if strings.TrimSpace(cfg.ServiceToken) == "" {
		return nil, fmt.Errorf("dtls binding installer: service token required")
	}
	endpoint := cfg.BaseURL.ResolveReference(&url.URL{Path: "/api/dtls/bindings"})
	client := cfg.Client
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	return &HTTPDTLSBindingInstaller{
		url:   endpoint.String(),
		token: strings.TrimSpace(cfg.ServiceToken),
		http:  client,
	}, nil
}

func (i *HTTPDTLSBindingInstaller) Upsert(ctx context.Context, binding DTLSBinding) error {
	reqBody := map[string]string{
		"source_ip":          binding.SourceIP.Unmap().String(),
		"dtls_psk":           base64.RawStdEncoding.EncodeToString(binding.PSK[:]),
		"device_id":          binding.DeviceID,
		"user_id":            binding.UserID,
		"mtls_subject_dn":    binding.MTLSSubjectDN,
		"source_v6":          binding.SourceV6.String(),
		"token":              base64.RawURLEncoding.EncodeToString(binding.Token[:]),
		"dtls_master_secret": hex.EncodeToString(binding.DTLSMasterSecret[:]),
		"dtls_session_id":    hex.EncodeToString(binding.DTLSSessionID[:]),
		"dtls_cipher":        binding.DTLSCipher,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("dtls binding installer: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("dtls binding installer: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+i.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := i.http.Do(req)
	if err != nil {
		return fmt.Errorf("dtls binding installer: do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dtls binding installer: unexpected status %d", resp.StatusCode)
	}
	return nil
}
