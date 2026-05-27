package auth

import (
	"context"
	"sync"
)

// MockVerifier is an in-memory PasswordVerifier for tests.
//
// It is exported so packages that depend on PasswordVerifier (notably
// internal/cstp, internal/iam, and any future CLI fixtures) can drive
// auth-form flows without spinning up an httptest.Server. Production
// code MUST NOT use this type.
//
// The zero value is usable but rejects every call as ErrBadCredentials.
// Pre-seed credentials with Set, or override the entire decision
// function with VerifyFunc.
//
// MockVerifier is safe for concurrent use.
type MockVerifier struct {
	// VerifyFunc, if non-nil, takes precedence over the credential
	// table and is called for every Verify. Use this to drive
	// error-path tests (timeouts, ErrAccountLocked, etc).
	VerifyFunc func(ctx context.Context, username, password string) (string, error)

	mu    sync.Mutex
	creds map[string]mockCred
	calls []MockCall
}

type mockCred struct {
	password string
	deviceID string
}

// MockCall records one Verify invocation for after-the-fact assertions.
// The password is captured verbatim; tests are responsible for not
// logging the struct.
type MockCall struct {
	Username string
	Password string
}

// Set registers a username/password/device-id triple. Repeated Set
// calls with the same username overwrite. The deviceID is returned
// verbatim on a matching Verify; tests may pass a malformed shape
// deliberately if the test is exercising downstream handling.
func (m *MockVerifier) Set(username, password, deviceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.creds == nil {
		m.creds = make(map[string]mockCred)
	}
	m.creds[username] = mockCred{password: password, deviceID: deviceID}
}

// Calls returns a copy of the call log in invocation order.
func (m *MockVerifier) Calls() []MockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MockCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// Reset clears the credential table and the call log. VerifyFunc is
// not cleared so a test fixture can keep its decision function.
func (m *MockVerifier) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creds = nil
	m.calls = nil
}

// Verify implements PasswordVerifier.
func (m *MockVerifier) Verify(ctx context.Context, username, password string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	m.mu.Lock()
	m.calls = append(m.calls, MockCall{Username: username, Password: password})
	fn := m.VerifyFunc
	cred, ok := m.creds[username]
	m.mu.Unlock()

	if fn != nil {
		return fn(ctx, username, password)
	}
	if !ok || cred.password != password {
		return "", ErrBadCredentials
	}
	return cred.deviceID, nil
}

// Compile-time guarantee that MockVerifier implements PasswordVerifier.
var _ PasswordVerifier = (*MockVerifier)(nil)
