package cstp

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestLogsRedactGroupTokens(t *testing.T) {
	// No parallel subtests: ServeHTTP uses the process-wide default logger.
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })
	const token = "synthetic-log-token"
	const nestedToken = "synthetic-nested-token"
	group := "/drive/access/" + token
	cases := []struct {
		name, method, path, routed string
		status                     int
		grouped                    bool
	}{
		{"init", "POST", group, "/", http.StatusOK, true},
		{"auth", "POST", group + "/auth", "/auth", http.StatusOK, true},
		{"grouped-unrouted", "GET", group + "/unknown", "/unknown", http.StatusNotFound, true},
		{"nested-unrouted", "GET", group + "/drive/access/" + nestedToken + "/unknown", "/drive/access/[redacted]/unknown", http.StatusNotFound, true},
		{"canonical-unrouted", "HEAD", "/unknown", "/unknown", http.StatusNotFound, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
			s, _, _ := freshServer(t)
			defer s.Close()
			body := "username=alice"
			if tc.name == "init" {
				body = newInitBody()
			}
			req := httptest.NewRequest(tc.method, "http://interop.invalid"+tc.path+"?ignored="+token, strings.NewReader(body))
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			if strings.Contains(logs.String(), token) || strings.Contains(logs.String(), nestedToken) {
				t.Fatal("request log exposed a synthetic group token")
			}
			var records []map[string]any
			for _, line := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")) {
				var record map[string]any
				if err := json.Unmarshal(line, &record); err != nil {
					t.Fatal(err)
				}
				records = append(records, record)
			}
			wantPath := strings.ReplaceAll(strings.ReplaceAll(tc.path, token, "[redacted]"), nestedToken, "[redacted]")
			if len(records) == 0 || records[0]["msg"] != "cstp request" || records[0]["method"] != tc.method || records[0]["path"] != wantPath {
				t.Fatal("entry log lost method or redacted route diagnostics")
			}
			if tc.grouped && (len(records) < 2 || records[1]["msg"] != "cstp group-url prefix stripped" || records[1]["routed_path"] != tc.routed || records[1]["group_url"] != "/drive/access/[redacted]") {
				t.Fatal("group log lost redacted group or routed path")
			}
			if tc.status == http.StatusNotFound {
				last := records[len(records)-1]
				if last["level"] != "WARN" || last["method"] != tc.method || last["path"] != tc.routed {
					t.Fatal("unrouted warning lost method or redacted route diagnostics")
				}
			}
			if tc.name == "init" && !strings.Contains(w.Body.String(), `action="`+group+`/auth"`) {
				t.Fatal("log redaction changed the response auth action")
			}
		})
	}
}
