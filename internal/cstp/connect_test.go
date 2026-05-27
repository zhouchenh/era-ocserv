package cstp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClientOffersPSKNegotiate locks the policy from protocol doc §2.2:
// the server only advertises DTLS when the client opted in by listing
// `PSK-NEGOTIATE` in its X-DTLS-CipherSuite header.
//
// The check has to tolerate:
//   - header missing entirely (degraded TCP-only mode)
//   - case variation
//   - the suite list being colon-, comma-, or whitespace-separated
//   - multiple X-DTLS-CipherSuite headers being merged
//   - the token appearing alongside legacy fake-resumption cipher names
//     that we ignore
func TestClientOffersPSKNegotiate(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		// values, used when a single key is expected but multiple
		// values are needed via Header.Add.
		extraHeaders map[string][]string
		want         bool
	}{
		{
			name:    "header absent",
			headers: nil,
			want:    false,
		},
		{
			name:    "empty header value",
			headers: map[string]string{"X-DTLS-CipherSuite": ""},
			want:    false,
		},
		{
			name:    "only legacy cipher offered",
			headers: map[string]string{"X-DTLS-CipherSuite": "AES256-SHA"},
			want:    false,
		},
		{
			name:    "exact PSK-NEGOTIATE",
			headers: map[string]string{"X-DTLS-CipherSuite": "PSK-NEGOTIATE"},
			want:    true,
		},
		{
			name:    "PSK-NEGOTIATE in a colon list",
			headers: map[string]string{"X-DTLS-CipherSuite": "AES256-SHA:PSK-NEGOTIATE:AES128-SHA"},
			want:    true,
		},
		{
			name:    "PSK-NEGOTIATE in a comma list",
			headers: map[string]string{"X-DTLS-CipherSuite": "AES256-SHA, PSK-NEGOTIATE , AES128-SHA"},
			want:    true,
		},
		{
			name:    "case-insensitive match",
			headers: map[string]string{"X-DTLS-CipherSuite": "psk-negotiate"},
			want:    true,
		},
		{
			name: "multiple headers, second one carries it",
			extraHeaders: map[string][]string{
				"X-DTLS-CipherSuite": {"AES256-SHA", "PSK-NEGOTIATE"},
			},
			want: true,
		},
		{
			name:    "near-match must not trigger",
			headers: map[string]string{"X-DTLS-CipherSuite": "PSK-NEGOTIATE-LEGACY"},
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodConnect, "/CSCOSSLC/tunnel", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			for k, vs := range tc.extraHeaders {
				for _, v := range vs {
					r.Header.Add(k, v)
				}
			}
			if got := clientOffersPSKNegotiate(r); got != tc.want {
				t.Fatalf("clientOffersPSKNegotiate(%q) = %v, want %v",
					r.Header.Values("X-DTLS-CipherSuite"), got, tc.want)
			}
		})
	}
}
