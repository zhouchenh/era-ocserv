package udsserve

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMiddlewareLogRedactsGroupURLToken: the per-request handoff trace line
// runs before cstp.Server in UDS mode, so it must not log the group-URL token.
func TestMiddlewareLogRedactsGroupURLToken(t *testing.T) {
	const token = "synthetic-middleware-token"
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var seen string
	h := wrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
	}), logger)

	req := httptest.NewRequest(http.MethodPost, "/drive/access/"+token+"/auth", nil)
	req = req.WithContext(contextWithInfo(req.Context(), &HandoffInfo{SubjectDN: testSubjDN, TraceID: "trace-1"}))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen != "/drive/access/"+token+"/auth" {
		t.Fatalf("downstream path = %q; routing input must be unchanged", seen)
	}
	out := buf.String()
	if strings.Contains(out, token) {
		t.Fatalf("log line leaks group-URL token: %s", out)
	}
	if !strings.Contains(out, `"path":"/drive/access/[redacted]/auth"`) {
		t.Fatalf("log line missing redacted path: %s", out)
	}
}
