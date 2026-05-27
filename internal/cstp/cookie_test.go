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
