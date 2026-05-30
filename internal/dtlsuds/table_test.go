package dtlsuds

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func makeKey(srcPort, dstPort uint16) FourTuple {
	src := netip.MustParseAddrPort("[2001:db8::7]:0").Addr()
	dst := netip.MustParseAddrPort("[2001:db8::1]:0").Addr()
	return FourTuple{
		Src: netip.AddrPortFrom(src, srcPort),
		Dst: netip.AddrPortFrom(dst, dstPort),
	}
}

func makeSession(t *testing.T, key FourTuple, now time.Time) *Session {
	t.Helper()
	inner := netip.MustParseAddr("2001:470:f9d1:9001::abcd")
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i)
	}
	return newSession(
		key, "abcdef12-3456-7890-abcd-ef0123456789",
		"user-1", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "CN=device,OU=ERA",
		inner, netip.Addr{}, psk, func(b []byte) error { return nil }, now,
	)
}

func TestTable_LoadOrCreate_Idempotent(t *testing.T) {
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	tbl := NewTable(TableOptions{Now: clk.Now})

	key := makeKey(51000, 443)
	created := 0
	makeFn := func() *Session {
		created++
		return makeSession(t, key, clk.Now())
	}
	s1, loaded := tbl.LoadOrCreate(key, makeFn)
	if loaded {
		t.Fatalf("first LoadOrCreate: expected new session, got loaded")
	}
	if created != 1 {
		t.Fatalf("created = %d, want 1", created)
	}
	s2, loaded := tbl.LoadOrCreate(key, makeFn)
	if !loaded {
		t.Fatalf("second LoadOrCreate: expected loaded, got new")
	}
	if s1 != s2 {
		t.Fatalf("second call returned different session")
	}
	if created != 1 {
		t.Fatalf("create fn ran %d times, want 1", created)
	}
}

func TestTable_LoadOrCreate_ConcurrentRace(t *testing.T) {
	tbl := NewTable(TableOptions{})
	key := makeKey(51000, 443)

	const N = 32
	var wg sync.WaitGroup
	var created atomic.Int32
	seen := make([]*Session, N)
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, _ := tbl.LoadOrCreate(key, func() *Session {
				created.Add(1)
				return makeSession(t, key, now)
			})
			seen[i] = s
		}(i)
	}
	wg.Wait()
	if created.Load() != 1 {
		t.Fatalf("create ran %d times under contention, want 1", created.Load())
	}
	first := seen[0]
	for i := 1; i < N; i++ {
		if seen[i] != first {
			t.Fatalf("concurrent LoadOrCreate returned different sessions")
		}
	}
}

func TestTable_IdleEviction(t *testing.T) {
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	var evicted []FourTuple
	tbl := NewTable(TableOptions{
		IdleTimeout: 300 * time.Second,
		Now:         clk.Now,
		OnEvict: func(s *Session) {
			evicted = append(evicted, s.key)
		},
	})

	keep := makeKey(50001, 443)
	stale := makeKey(50002, 443)
	tbl.LoadOrCreate(keep, func() *Session { return makeSession(t, keep, clk.Now()) })
	tbl.LoadOrCreate(stale, func() *Session { return makeSession(t, stale, clk.Now()) })

	// Advance time past the idle deadline for `stale`, then touch `keep`.
	clk.Advance(310 * time.Second)
	if s, ok := tbl.Get(keep); ok {
		s.touch(clk.Now())
	}
	tbl.runEvictionPass()

	if len(evicted) != 1 || evicted[0] != stale {
		t.Fatalf("eviction set = %v, want [%v]", evicted, stale)
	}
	if tbl.Len() != 1 {
		t.Fatalf("table.Len = %d, want 1", tbl.Len())
	}

	// Advance further; `keep` is also stale now.
	clk.Advance(310 * time.Second)
	tbl.runEvictionPass()
	if tbl.Len() != 0 {
		t.Fatalf("table.Len = %d, want 0 after second pass", tbl.Len())
	}
	if len(evicted) != 2 {
		t.Fatalf("eviction set = %v, want 2 entries", evicted)
	}
}

func TestTable_RemoveDetachesSession(t *testing.T) {
	tbl := NewTable(TableOptions{})
	key := makeKey(50003, 443)
	now := time.Unix(1_700_000_000, 0)
	tbl.LoadOrCreate(key, func() *Session { return makeSession(t, key, now) })
	s, _ := tbl.Get(key)
	if s == nil {
		t.Fatal("Get returned nil for newly-stored session")
	}

	removed := tbl.Remove(key)
	if removed != s {
		t.Fatalf("Remove returned different session")
	}
	if _, _, err := writePktThroughSession(s); err != ErrSessionGone {
		t.Fatalf("after Remove, WritePacket err = %v, want ErrSessionGone", err)
	}
}

func TestTable_StopEvictsAll(t *testing.T) {
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	var evicted []FourTuple
	tbl := NewTable(TableOptions{
		IdleTimeout: 300 * time.Second,
		Now:         clk.Now,
		OnEvict:     func(s *Session) { evicted = append(evicted, s.key) },
	})
	for i := 0; i < 5; i++ {
		key := makeKey(uint16(60000+i), 443)
		tbl.LoadOrCreate(key, func() *Session { return makeSession(t, key, clk.Now()) })
	}
	tbl.Start()
	tbl.Stop()
	if tbl.Len() != 0 {
		t.Fatalf("Stop did not clear table; len = %d", tbl.Len())
	}
	if len(evicted) != 5 {
		t.Fatalf("evicted %d, want 5", len(evicted))
	}
}

// writePktThroughSession is a test shim that calls Session.WritePacket so
// the test asserts on the public surface (and exercises the reply-closure
// detach path).
func writePktThroughSession(s *Session) (int, []byte, error) {
	pkt := []byte{0x60, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	n, err := s.WritePacket(pkt)
	return n, pkt, err
}

// fakeClock is a deterministic monotonic clock for table tests. Concurrent
// Advance and Now calls are safe.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
