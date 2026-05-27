package main

import (
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
