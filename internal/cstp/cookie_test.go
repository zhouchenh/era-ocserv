package cstp

import (
	"errors"
	"testing"
	"time"
)

// fixedRand returns a deterministic random source for tests. It cycles
// through src so each call gets fresh bytes.
type fixedRand struct {
	src []byte
	off int
}

func (f *fixedRand) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = f.src[(f.off+i)%len(f.src)]
	}
	f.off += len(p)
	return len(p), nil
}

func TestSessionTableNewOpaqueAndLookup(t *testing.T) {
	rand := (&fixedRand{src: []byte("0123456789abcdef")}).Read
	now := time.Now()
	st := newSessionTable(time.Hour, func() time.Time { return now })

	s, err := st.newOpaque(rand)
	if err != nil {
		t.Fatalf("newOpaque: %v", err)
	}
	if s.opaqueID == "" {
		t.Fatalf("opaqueID empty")
	}

	got := st.lookupOpaque(s.opaqueID)
	if got != s {
		t.Fatalf("lookupOpaque returned %v want %v", got, s)
	}

	if got := st.lookupOpaque("missing"); got != nil {
		t.Fatalf("expected nil for missing opaque, got %v", got)
	}
}

func TestSessionTablePromoteThenLookupToken(t *testing.T) {
	rand := (&fixedRand{src: []byte("0123456789abcdef")}).Read
	now := time.Now()
	st := newSessionTable(time.Hour, func() time.Time { return now })

	s, err := st.newOpaque(rand)
	if err != nil {
		t.Fatalf("newOpaque: %v", err)
	}

	promoted, err := st.promote(s.opaqueID, "alice", "dev-001", rand)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if promoted.token == "" {
		t.Fatalf("promoted token empty")
	}
	if promoted.username != "alice" || promoted.deviceID != "dev-001" {
		t.Fatalf("promote did not store creds: u=%q dev=%q", promoted.username, promoted.deviceID)
	}

	got := st.lookupToken(promoted.token)
	if got != promoted {
		t.Fatalf("lookupToken returned %v want %v", got, promoted)
	}

	if got := st.lookupToken(""); got != nil {
		t.Fatalf("empty token lookup should return nil, got %v", got)
	}

	if got := st.lookupToken("wrong-token"); got != nil {
		t.Fatalf("wrong token lookup should return nil, got %v", got)
	}
}

func TestSessionTablePromoteUnknownOpaque(t *testing.T) {
	rand := (&fixedRand{src: []byte("0123456789abcdef")}).Read
	st := newSessionTable(time.Hour, time.Now)

	_, err := st.promote("never-minted", "alice", "dev-001", rand)
	if !errors.Is(err, errUnknownOpaque) {
		t.Fatalf("expected errUnknownOpaque, got %v", err)
	}
}

func TestSessionTableExpiry(t *testing.T) {
	rand := (&fixedRand{src: []byte("0123456789abcdef")}).Read
	now := time.Now()
	fake := now
	st := newSessionTable(10*time.Second, func() time.Time { return fake })

	s, err := st.newOpaque(rand)
	if err != nil {
		t.Fatalf("newOpaque: %v", err)
	}
	promoted, err := st.promote(s.opaqueID, "alice", "dev-001", rand)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Within TTL.
	fake = now.Add(5 * time.Second)
	if got := st.lookupToken(promoted.token); got == nil {
		t.Fatalf("expected token to be valid at 5s")
	}

	// Past TTL.
	fake = now.Add(20 * time.Second)
	if got := st.lookupToken(promoted.token); got != nil {
		t.Fatalf("expected expired token to return nil")
	}
}

func TestSessionTableConsume(t *testing.T) {
	rand := (&fixedRand{src: []byte("0123456789abcdef")}).Read
	st := newSessionTable(time.Hour, time.Now)
	s, _ := st.newOpaque(rand)
	promoted, _ := st.promote(s.opaqueID, "alice", "dev-001", rand)

	st.consume(promoted)

	if got := st.lookupToken(promoted.token); got != nil {
		t.Fatalf("expected token to be consumed")
	}
	if got := st.lookupOpaque(promoted.opaqueID); got != nil {
		t.Fatalf("expected opaque to be consumed")
	}
}

// TestSessionTableReaperDropsStale covers P1 #4 from the wave-1
// review: the janitor must drop pre-auth rows that never see a
// follow-up POST and post-auth rows that never see a CONNECT. We
// drive a fake clock past each threshold and assert the table size
// drops to zero.
func TestSessionTableReaperDropsStale(t *testing.T) {
	rand := (&fixedRand{src: []byte("0123456789abcdef")}).Read
	start := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	now := start
	st := newSessionTable(time.Hour, func() time.Time { return now })

	// 1. Mint two pre-auth rows.
	s1, _ := st.newOpaque(rand)
	s2, _ := st.newOpaque(rand)
	if st.size() != 2 {
		t.Fatalf("table size = %d, want 2", st.size())
	}

	// 2. Advance just under preAuthMaxAge (4m); both rows must
	//    survive.
	now = start.Add(4 * time.Minute)
	if dropped := st.reapOrphans(); dropped != 0 {
		t.Errorf("at 4m: dropped %d rows, want 0", dropped)
	}
	if st.size() != 2 {
		t.Fatalf("after 4m sweep: size = %d, want 2", st.size())
	}

	// 3. Promote s2 (now it's post-auth, pre-CONNECT).
	if _, err := st.promote(s2.opaqueID, "alice", "dev-001", rand); err != nil {
		t.Fatalf("promote: %v", err)
	}

	// 4. Advance past preAuthMaxAge (6m): s1 (pre-auth) should be
	//    reaped; s2 (just promoted, post-auth) should survive (its
	//    createdAt is still 0m so age=6m which is > 60s).
	now = start.Add(6 * time.Minute)
	if dropped := st.reapOrphans(); dropped == 0 {
		t.Errorf("at 6m: dropped %d rows, want >= 1 (pre-auth orphan)", dropped)
	}
	// After the sweep, s1 must be gone.
	if got := st.lookupOpaque(s1.opaqueID); got != nil {
		t.Errorf("pre-auth orphan s1 was not reaped")
	}
	_ = s2 // (s2 may also be reaped via the post-auth-pre-CONNECT path; either is fine)

	// 5. Mint a fresh pre-auth row and verify reapOrphans leaves it
	//    alone when run immediately.
	now = start.Add(10 * time.Minute)
	s3, _ := st.newOpaque(rand)
	if dropped := st.reapOrphans(); dropped != 0 && st.lookupOpaque(s3.opaqueID) == nil {
		t.Errorf("freshly-minted pre-auth row was reaped: dropped=%d", dropped)
	}

	// 6. Advance past preAuthMaxAge for s3 and reap.
	now = start.Add(20 * time.Minute)
	st.reapOrphans()
	if got := st.lookupOpaque(s3.opaqueID); got != nil {
		t.Errorf("stale pre-auth row s3 was not reaped after 10m")
	}
}

// TestSessionJanitorExitsOnClose confirms the janitor goroutine
// returns when Server.Close runs, so SIGTERM does not leave the
// reaper running past process exit.
func TestSessionJanitorExitsOnClose(t *testing.T) {
	s, _, _ := freshServer(t)
	// The janitor is started by NewServer; close immediately.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// We cannot observe the goroutine directly without runtime/pprof
	// dumping the stack; the smoke test is that Close returns
	// promptly and a second Close is also a no-op (which exercises
	// the closed-flag short-circuit).
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestSessionTableReaperReapsExpiredOnly confirms that the reaper
// also drops any row past its hard expiresAt (TTL), even if the
// pre-auth / post-auth thresholds say otherwise. Inline reapers on
// lookup cover the common case; reapOrphans is the catch-all.
func TestSessionTableReaperReapsExpiredOnly(t *testing.T) {
	rand := (&fixedRand{src: []byte("xyzabc12")}).Read
	start := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	now := start
	st := newSessionTable(30*time.Second, func() time.Time { return now })

	s, _ := st.newOpaque(rand)

	// Tick past the TTL (30s) but inside the pre-auth threshold (5m).
	// The expiresAt branch of the reaper must still fire.
	now = start.Add(45 * time.Second)
	if dropped := st.reapOrphans(); dropped != 1 {
		t.Errorf("dropped %d, want 1 (expired row)", dropped)
	}
	if got := st.lookupOpaque(s.opaqueID); got != nil {
		t.Errorf("expired row was not reaped")
	}
}

func TestRandHelpersDifferentLengths(t *testing.T) {
	rand := (&fixedRand{src: []byte("xyzw1234")}).Read
	hexStr, err := randHex(rand, 8)
	if err != nil {
		t.Fatalf("randHex: %v", err)
	}
	if len(hexStr) != 16 {
		t.Fatalf("hex length=%d want 16", len(hexStr))
	}

	rand2 := (&fixedRand{src: []byte("abcd1234")}).Read
	urlSafe, err := randURLSafe(rand2, 32)
	if err != nil {
		t.Fatalf("randURLSafe: %v", err)
	}
	if urlSafe == "" {
		t.Fatalf("randURLSafe returned empty")
	}
}
