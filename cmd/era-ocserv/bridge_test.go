package main

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/zhouchenh/era-ocserv/internal/cstp"
	"github.com/zhouchenh/era-ocserv/internal/dtlsuds"
)

// activeClient.chooseTransport encodes the dual-transport priority rule
// (DTLS preferred for egress, CSTP fallback). These tests exercise the
// rule directly on activeClient — the lifecycle wiring is covered by the
// dtlsuds package tests.
func TestActiveClient_ChooseTransport_Priority(t *testing.T) {
	ac := &activeClient{}
	if tr := ac.chooseTransport(); tr != nil {
		t.Fatalf("empty client returned %v, want nil", tr)
	}

	ac.cstp = &cstp.Tunnel{}
	if tr := ac.chooseTransport(); tr == nil || tr.label() != "cstp" {
		t.Fatalf("CSTP-only client picked %v, want cstp", tr)
	}

	ac.dtls = &dtlsuds.Session{}
	if tr := ac.chooseTransport(); tr == nil || tr.label() != "dtls" {
		t.Fatalf("CSTP+DTLS client picked %v, want dtls", tr)
	}

	ac.dtls = nil
	if tr := ac.chooseTransport(); tr == nil || tr.label() != "cstp" {
		t.Fatalf("CSTP-only (after DTLS drop) picked %v, want cstp", tr)
	}

	ac.cstp = nil
	if tr := ac.chooseTransport(); tr != nil {
		t.Fatalf("empty client (after both drop) returned %v, want nil", tr)
	}
}

// TestBridge_DoubleKeyRegistry proves the keystone fix: an activeClient with
// a CLAT /128 is reachable under BOTH the native /128 and the CLAT /128 keys
// (so 64:ff9b:: replies — whose inner destination is the CLAT /128 — resolve
// via clients.Load instead of dropping), and that teardown clears both keys.
func TestBridge_DoubleKeyRegistry(t *testing.T) {
	b := newBridge(nil, nil)
	native := netip.MustParseAddr("2001:470:f9d1:9001:0c5e:7777::9")
	clat := netip.MustParseAddr("2001:470:f9d1:9001:c1a7::1")

	ac := b.loadOrCreateClient(native)
	if installed := b.installCLAT(ac, native, clat); !installed {
		t.Fatal("installCLAT did not install the CLAT key for a valid /128")
	}

	// Both keys must resolve to the SAME *activeClient.
	if v, ok := b.clients.Load(native); !ok || v.(*activeClient) != ac {
		t.Fatal("native /128 key missing or points at a different client")
	}
	if v, ok := b.clients.Load(clat); !ok || v.(*activeClient) != ac {
		t.Fatal("CLAT /128 key missing or points at a different client — 64:ff9b:: replies would drop")
	}
	// The translator must be wired so tun->client SIIT can run.
	if ac.translator() == nil {
		t.Fatal("translator not set after installCLAT")
	}
	if ac.clatV6 != clat {
		t.Fatalf("ac.clatV6 = %v, want %v", ac.clatV6, clat)
	}

	// Teardown deletes BOTH keys.
	b.deregisterKeys(ac, native)
	if _, ok := b.clients.Load(native); ok {
		t.Fatal("native /128 key still present after deregisterKeys")
	}
	if _, ok := b.clients.Load(clat); ok {
		t.Fatal("CLAT /128 key still present after deregisterKeys")
	}
}

// TestBridge_NoCLATKeyWhenDisabled confirms the lower bridge helper does not
// install a translator from a zero CLAT /128. Production TPMResolver identities
// fail closed earlier when the CLAT source is missing.
func TestBridge_NoCLATKeyWhenDisabled(t *testing.T) {
	b := newBridge(nil, nil)
	native := netip.MustParseAddr("2001:470:f9d1:9001:0c5e:7777::9")

	ac := b.loadOrCreateClient(native)
	if installed := b.installCLAT(ac, native, netip.Addr{}); installed {
		t.Fatal("installCLAT installed a key for an invalid CLAT /128")
	}
	if ac.translator() != nil {
		t.Fatal("translator set when CLAT disabled")
	}
	// Only the native key exists; deregister cleans it up.
	b.deregisterKeys(ac, native)
	if _, ok := b.clients.Load(native); ok {
		t.Fatal("native /128 key still present after deregisterKeys")
	}
}

func TestActiveClient_ChooseTransport_ConcurrentSafe(t *testing.T) {
	ac := &activeClient{}
	var wg sync.WaitGroup
	// Hammer cstp/dtls flips against chooseTransport. The mutex inside
	// activeClient should keep this race-free; without it, the race
	// detector would flag this loop.
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = ac.chooseTransport()
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		ac.mu.Lock()
		if i%2 == 0 {
			ac.cstp = &cstp.Tunnel{}
		} else {
			ac.cstp = nil
		}
		if i%3 == 0 {
			ac.dtls = &dtlsuds.Session{}
		} else {
			ac.dtls = nil
		}
		ac.mu.Unlock()
	}
	close(stop)
	wg.Wait()
}
