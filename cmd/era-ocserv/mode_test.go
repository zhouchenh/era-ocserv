package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveMode_Explicit(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want listenerMode
	}{
		{"uds", modeUDS},
		{"UDS", modeUDS},
		{"legacy", modeLegacy},
		{"Legacy", modeLegacy},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := resolveMode(config{mode: tc.in})
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveMode_Unknown(t *testing.T) {
	_, err := resolveMode(config{mode: "weird"})
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestResolveMode_AutoNoDir(t *testing.T) {
	// Point at a definitely-nonexistent path. resolveMode should fall
	// back to legacy.
	cfg := config{
		mode:          "auto",
		udsSocketPath: "/no/such/path/anyconnect-cstp.sock",
	}
	got, err := resolveMode(cfg)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != modeLegacy {
		t.Errorf("got %v, want legacy", got)
	}
}

func TestResolveMode_AutoDirExists(t *testing.T) {
	// Create a temp dir and point the socket path inside it.
	tmpDir := t.TempDir()
	cfg := config{
		mode:          "auto",
		udsSocketPath: filepath.Join(tmpDir, "anyconnect-cstp.sock"),
	}
	got, err := resolveMode(cfg)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != modeUDS {
		t.Errorf("got %v, want uds", got)
	}
}

func TestResolveMode_AutoEmptyDefaultsToLegacy(t *testing.T) {
	// The udsSocketPath default in parseFlags is
	// /var/run/era-facade/handoffs/anyconnect-cstp.sock; on a dev box
	// without that dir, auto must yield legacy mode. We check this by
	// pointing at /tmp/<random-nonexistent>/x.sock.
	cfg := config{
		mode:          "",
		udsSocketPath: filepath.Join(os.TempDir(), "definitely-not-an-era-facade-dir-xyz", "x.sock"),
	}
	got, err := resolveMode(cfg)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != modeLegacy {
		t.Errorf("got %v, want legacy (no parent dir)", got)
	}
}
