package dtlsuds

import (
	"sync"
	"time"
)

// DefaultIdleTimeout is the spec §5.3 DTLS idle-eviction interval (300 s).
// Real Cisco SecureClient sends DTLS keepalives well inside this window;
// the timeout is the converge-by-mutual-timeout escape hatch the spec
// mandates for mobile handoff.
const DefaultIdleTimeout = 300 * time.Second

// DefaultEvictionTick is how often the table walks itself looking for
// expired sessions. 30 s is the operator-debug-friendly granularity: an
// idle session has at most 30 s of post-deadline latency before it
// disappears from `Sessions()`.
const DefaultEvictionTick = 30 * time.Second

// Table is the goroutine-safe 4-tuple → *Session map era-ocserv uses to
// demux inbound DTLS datagrams and to drive idle-eviction.
//
// The table runs a periodic eviction goroutine that removes sessions
// whose lastSeen is older than IdleTimeout. A non-nil EvictCallback is
// invoked synchronously while the table lock is held — callers MUST NOT
// re-enter the table from inside the callback. The callback typically
// deregisters the session from the TUN bridge so a stale /128 lookup
// stops finding it.
//
// The table is also used to deduplicate concurrent first-datagram races:
// if two datagrams for the same 4-tuple arrive simultaneously and both
// hit `LoadOrCreate`, only one Session is constructed; the other goroutine
// gets the loaded one back.
type Table struct {
	mu          sync.RWMutex
	sessions    map[FourTuple]*Session
	idleTimeout time.Duration
	tick        time.Duration
	now         func() time.Time
	onEvict     func(*Session)

	stopOnce sync.Once
	stopCh   chan struct{}
	stopped  chan struct{}
}

// TableOptions configures a Table at construction.
type TableOptions struct {
	// IdleTimeout is the session inactivity window. Zero ⇒ DefaultIdleTimeout.
	IdleTimeout time.Duration
	// EvictionTick is the eviction-walker cadence. Zero ⇒ DefaultEvictionTick.
	EvictionTick time.Duration
	// Now allows tests to inject a deterministic clock. Production leaves
	// it nil and the table falls back to time.Now.
	Now func() time.Time
	// OnEvict, if non-nil, is invoked for each session evicted by the
	// idle-walker OR by RemoveAll (table close). Called synchronously
	// while the table lock is held; the callback MUST NOT re-enter the
	// table. Typical use: deregister the session from the TUN bridge.
	OnEvict func(*Session)
}

// NewTable constructs a Table with the supplied options. The eviction
// goroutine is NOT started here; call Start to begin the periodic walk.
func NewTable(opts TableOptions) *Table {
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.EvictionTick <= 0 {
		opts.EvictionTick = DefaultEvictionTick
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Table{
		sessions:    make(map[FourTuple]*Session),
		idleTimeout: opts.IdleTimeout,
		tick:        opts.EvictionTick,
		now:         opts.Now,
		onEvict:     opts.OnEvict,
		stopCh:      make(chan struct{}),
		stopped:     make(chan struct{}),
	}
}

// Start launches the periodic eviction goroutine. Calling Start more than
// once is a no-op; the table runs a single walker for its lifetime.
func (t *Table) Start() {
	go t.evictLoop()
}

// Stop halts the eviction goroutine and removes every session in the
// table, invoking OnEvict for each. Stop is idempotent.
func (t *Table) Stop() {
	t.stopOnce.Do(func() {
		close(t.stopCh)
		<-t.stopped
		t.RemoveAll()
	})
}

// Get returns the Session for key, or (nil, false) if no such session
// exists.
func (t *Table) Get(key FourTuple) (*Session, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.sessions[key]
	return s, ok
}

// LoadOrCreate atomically returns the existing Session for key, OR
// constructs one via create() and inserts it under key. The boolean is
// true when the existing session was returned, false when a new one was
// constructed.
//
// The create function is invoked while the table write-lock is held, so
// it MUST be cheap and MUST NOT re-enter the table. Typical use: build
// the Session struct (the identity is already known from the inbound
// TLVs, so no I/O is required).
func (t *Table) LoadOrCreate(key FourTuple, create func() *Session) (*Session, bool) {
	t.mu.RLock()
	if s, ok := t.sessions[key]; ok {
		t.mu.RUnlock()
		return s, true
	}
	t.mu.RUnlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.sessions[key]; ok {
		return s, true
	}
	s := create()
	if s == nil {
		return nil, false
	}
	t.sessions[key] = s
	return s, false
}

// Remove deletes the session for key (if present), invokes OnEvict, and
// returns the removed Session or nil if no such key existed.
func (t *Table) Remove(key FourTuple) *Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[key]
	if !ok {
		return nil
	}
	delete(t.sessions, key)
	s.detach()
	if t.onEvict != nil {
		t.onEvict(s)
	}
	return s
}

// RemoveAll evicts every session in the table, invoking OnEvict for each.
// Used by Stop and by tests.
func (t *Table) RemoveAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, s := range t.sessions {
		delete(t.sessions, k)
		s.detach()
		if t.onEvict != nil {
			t.onEvict(s)
		}
	}
}

// Len returns the current number of sessions. Useful for tests + metrics.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// Snapshot returns a shallow copy of the session pointers in the table.
// The slice is owned by the caller; the underlying *Session values are
// shared. Concurrent eviction may render some pointers stale (their
// reply closure will have been detached and WritePacket will return
// ErrSessionGone); callers MUST tolerate that.
func (t *Table) Snapshot() []*Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*Session, 0, len(t.sessions))
	for _, s := range t.sessions {
		out = append(out, s)
	}
	return out
}

// evictLoop is the periodic walker. It runs every tick interval and
// evicts sessions whose lastSeen is older than IdleTimeout.
func (t *Table) evictLoop() {
	defer close(t.stopped)
	ticker := time.NewTicker(t.tick)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.runEvictionPass()
		}
	}
}

// runEvictionPass walks the table once and removes any session whose
// lastSeen is older than IdleTimeout from now(). Exposed for tests so
// they can drive eviction deterministically.
func (t *Table) runEvictionPass() {
	now := t.now()
	deadline := now.Add(-t.idleTimeout)
	deadlineNanos := deadline.UnixNano()
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, s := range t.sessions {
		if s.lastSeen.Load() < deadlineNanos {
			delete(t.sessions, k)
			s.detach()
			if t.onEvict != nil {
				t.onEvict(s)
			}
		}
	}
}
