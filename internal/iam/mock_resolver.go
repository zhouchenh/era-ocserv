package iam

import (
	"context"
	"sync"
)

// MockResolver is an in-memory Resolver for tests. It is exported so
// downstream tests in other packages (cmd/era-ocserv wiring, internal/cstp
// integration tests) can pre-seed identities without a network round-trip.
//
// The zero value is ready to use.
type MockResolver struct {
	mu sync.RWMutex
	m  map[string]Identity
}

// Set installs id under deviceID. It overwrites any prior value.
//
// Note: Set also overwrites id.DeviceID with the deviceID argument
// before storing. This keeps a Resolve(deviceID) result internally
// consistent (returned Identity.DeviceID always equals the lookup
// key) even when the caller passed a zero-value or differing
// DeviceID. Downstream tests
// (TestMockResolver in mock_resolver_test.go,
// e2e harness wiring in tests/e2e/harness_test.go) rely on this; do
// NOT change the behaviour without auditing those call sites.
// Wave-1 review API-smell #3 (docs/review/wave-1-stage-1.md).
func (m *MockResolver) Set(deviceID string, id Identity) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]Identity{}
	}
	id.DeviceID = deviceID
	m.m[deviceID] = id
}

// Delete removes deviceID from the table. Subsequent Resolves return
// ErrDeviceNotFound for it. Safe to call for a key that was never set.
func (m *MockResolver) Delete(deviceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, deviceID)
}

// Resolve implements Resolver.
func (m *MockResolver) Resolve(_ context.Context, deviceID string) (Identity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.m[deviceID]
	if !ok {
		return Identity{}, ErrDeviceNotFound
	}
	return id, nil
}
