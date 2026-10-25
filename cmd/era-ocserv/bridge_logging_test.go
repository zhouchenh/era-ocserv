package main

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/zhouchenh/era-ocserv/internal/logredact"
)

// TestLogCSTPConnectedRedactsSessionToken proves the CSTP connect line never
// carries the raw session token, only its short fingerprint. Captured logger
// only; no sockets.
func TestLogCSTPConnectedRedactsSessionToken(t *testing.T) {
	const session = "synthetic-cstp-session-token-7f3a9c"
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	logCSTPConnected(logger, "dev_synthetic", netip.MustParseAddr("fd00::10"), netip.MustParseAddr("fd00::11"), session)

	out := buf.String()
	if strings.Contains(out, session) {
		t.Fatalf("log output contains raw session token: %q", out)
	}
	if strings.Contains(out, "session=") {
		t.Fatalf("log output still has a raw session attr: %q", out)
	}
	if want := "session_fp=" + logredact.Fingerprint(session); !strings.Contains(out, want) {
		t.Fatalf("log output missing %q: %q", want, out)
	}
	if !strings.Contains(out, "cstp client connected") || !strings.Contains(out, "device=dev_synthetic") {
		t.Fatalf("log output missing message/device: %q", out)
	}
}
