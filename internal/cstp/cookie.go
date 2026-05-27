package cstp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"
)

// Pre-auth and post-auth-pre-CONNECT lifetimes are short enough that
// any session in those states past the threshold is by definition
// orphaned: a real client moves from init → auth-reply in a handful
// of seconds and from auth-complete → CONNECT in well under a second.
// We set the thresholds generously to accommodate slow networks and
// human-driven auth flows; orphan abuse still gets bounded.
const (
	// preAuthMaxAge caps the time a session can sit in the pre-auth
	// (opaque-only) state before the janitor reaps it. The user has
	// been served an auth-request HTML form but never POSTed back.
	preAuthMaxAge = 5 * time.Minute

	// postAuthPreConnectMaxAge caps the time between auth-complete
	// and the CONNECT request. Real clients open the TCP+TLS conn
	// and send CONNECT within hundreds of milliseconds.
	postAuthPreConnectMaxAge = 60 * time.Second
)

// session is one row in the in-memory session table. The token is the
// long-lived 32-byte URL-safe random the client echoes on the CONNECT
// request as the "webvpn" cookie. The opaqueID is the short scratch
// value round-tripped through phase 2a -> 2b in the <opaque> element.
//
// A session moves through three states:
//
//  1. opaque-only - the entry exists after phase 2a, before the client
//     has been authenticated. Token is empty. Used to bind the auth-reply
//     to the right pre-auth state.
//  2. authenticated - phase 2b succeeded. Token is set; Username and
//     DeviceID are populated. The client may now CONNECT.
//  3. consumed - the CONNECT handler has hijacked the conn and started
//     the tunnel. We remove the row from the table to prevent replay.
type session struct {
	token     string
	opaqueID  string
	username  string
	deviceID  string
	createdAt time.Time
	expiresAt time.Time
}

// sessionTable is the in-memory map keyed independently by opaqueID
// (phase 2 lookup) and by token (phase 3 lookup). Reads dominate
// writes once a deployment is steady-state, but we use a plain mutex
// for v1; contention is bounded by the AnyConnect connect rate
// (single-digit per second per gateway).
type sessionTable struct {
	mu       sync.Mutex
	byOpaque map[string]*session
	byToken  map[string]*session
	ttl      time.Duration
	nowFn    func() time.Time
}

func newSessionTable(ttl time.Duration, nowFn func() time.Time) *sessionTable {
	return &sessionTable{
		byOpaque: make(map[string]*session),
		byToken:  make(map[string]*session),
		ttl:      ttl,
		nowFn:    nowFn,
	}
}

func (t *sessionTable) now() time.Time {
	if t.nowFn != nil {
		return t.nowFn()
	}
	return time.Now()
}

// newOpaque creates a pre-auth session row keyed by a fresh opaque ID
// returned to the client in the auth-request response.
func (t *sessionTable) newOpaque(randRead func(p []byte) (int, error)) (*session, error) {
	id, err := randHex(randRead, 8)
	if err != nil {
		return nil, err
	}
	now := t.now()
	s := &session{
		opaqueID:  id,
		createdAt: now,
		expiresAt: now.Add(t.ttl),
	}
	t.mu.Lock()
	t.byOpaque[id] = s
	t.mu.Unlock()
	return s, nil
}

// promote moves a pre-auth row to authenticated state, attaching the
// verified username + deviceID and a freshly-minted long session
// token. The opaque -> session mapping is preserved so the same
// reconnect cookie can be looked up either way during reconnect.
func (t *sessionTable) promote(opaqueID, username, deviceID string, randRead func(p []byte) (int, error)) (*session, error) {
	t.mu.Lock()
	s, ok := t.byOpaque[opaqueID]
	t.mu.Unlock()
	if !ok {
		return nil, errUnknownOpaque
	}
	tok, err := randURLSafe(randRead, 32)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	s.token = tok
	s.username = username
	s.deviceID = deviceID
	now := t.now()
	s.expiresAt = now.Add(t.ttl)
	t.byToken[tok] = s
	t.mu.Unlock()
	return s, nil
}

// lookupOpaque returns the pre-auth session for a given opaque id, or
// nil if it has expired or never existed. Expired rows are reaped
// inline.
func (t *sessionTable) lookupOpaque(opaqueID string) *session {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.byOpaque[opaqueID]
	if !ok {
		return nil
	}
	if t.now().After(s.expiresAt) {
		t.deleteLocked(s)
		return nil
	}
	return s
}

// lookupToken returns the authenticated session for a given session
// token, comparing in constant time to avoid timing-side-channels on
// the cookie value. Expired rows are reaped inline.
func (t *sessionTable) lookupToken(token string) *session {
	if token == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.byToken {
		if subtle.ConstantTimeCompare([]byte(s.token), []byte(token)) == 1 {
			if t.now().After(s.expiresAt) {
				t.deleteLocked(s)
				return nil
			}
			return s
		}
	}
	return nil
}

// consume removes a session row from both indexes once a tunnel has
// successfully hijacked the conn. Reconnect logic (spec §1.8) will
// require re-issuing or persisting tokens; for v1 we treat tokens as
// single-use.
func (t *sessionTable) consume(s *session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deleteLocked(s)
}

// reapOrphans walks both indexes and drops any session that is past
// its lifetime threshold. Returns the number of rows deleted (for
// tests / metrics).
//
// Three classes of row get reaped:
//
//  1. Pre-auth (opaque-only, no token): age > preAuthMaxAge. The
//     init POST minted the row but the auth-reply never followed.
//     Without reaping these, an unauthenticated attacker can mint
//     unlimited orphan rows by spamming POST / (wave-1 review P1
//     #4: 100 init/s × 1h TTL = 360k stale rows / hour).
//  2. Post-auth, pre-CONNECT (token set): age > postAuthPreConnectMaxAge.
//     The auth-complete shipped a token but the CONNECT never
//     arrived. Real clients move on within hundreds of ms.
//  3. Any row past its hard expiresAt (set by the TTL). Inline
//     reaping in lookupOpaque/lookupToken covers most of these but
//     a row never looked up again is never reaped without this
//     sweep.
func (t *sessionTable) reapOrphans() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var dropped []*session
	// Collect victims under the lock; we cannot delete while
	// iterating a map. The byToken index is a subset of byOpaque
	// (every authenticated row also has an opaqueID), so iterating
	// byOpaque covers both classes.
	for _, s := range t.byOpaque {
		age := now.Sub(s.createdAt)
		switch {
		case now.After(s.expiresAt):
			dropped = append(dropped, s)
		case s.token == "" && age > preAuthMaxAge:
			dropped = append(dropped, s)
		case s.token != "" && age > postAuthPreConnectMaxAge:
			dropped = append(dropped, s)
		}
	}
	// Also catch any orphaned token-only rows in byToken that, for
	// any future schema change, may not be reachable via byOpaque.
	for _, s := range t.byToken {
		if _, stillInOpaque := t.byOpaque[s.opaqueID]; !stillInOpaque {
			// Token-only orphan (defensive — current schema does not
			// produce these).
			dropped = append(dropped, s)
		}
	}
	for _, s := range dropped {
		t.deleteLocked(s)
	}
	return len(dropped)
}

// size returns the number of pre-auth rows currently in the table.
// Used by tests; not exported.
func (t *sessionTable) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byOpaque)
}

func (t *sessionTable) deleteLocked(s *session) {
	if s.opaqueID != "" {
		delete(t.byOpaque, s.opaqueID)
	}
	if s.token != "" {
		delete(t.byToken, s.token)
	}
}

// errUnknownOpaque is returned when an auth-reply references an
// opaque id we never minted or have already aged out. The handler
// turns this into a fresh auth-request rather than a 401, matching
// real ocserv behavior.
var errUnknownOpaque = stringError("cstp: unknown opaque session id")

// stringError is a tiny package-local sentinel error type to keep
// allocations off the hot path without pulling in fmt.Errorf for
// constants.
type stringError string

func (e stringError) Error() string { return string(e) }

// randHex returns a hex-encoded random string of the given byte length.
// The returned string is 2*n characters.
func randHex(randRead func(p []byte) (int, error), n int) (string, error) {
	if randRead == nil {
		randRead = rand.Read
	}
	buf := make([]byte, n)
	if _, err := randRead(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// randURLSafe returns a base64-url-safe encoding (no padding) of n
// random bytes. The session token uses this so it survives as a cookie
// value without quoting.
func randURLSafe(randRead func(p []byte) (int, error), n int) (string, error) {
	if randRead == nil {
		randRead = rand.Read
	}
	buf := make([]byte, n)
	if _, err := randRead(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
