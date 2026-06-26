package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestMockVerifier_Success(t *testing.T) {
	var m MockVerifier
	m.Set("alice", "hunter2", validDeviceIDSample)

	got, err := m.Verify(context.Background(), "alice", "hunter2")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != validDeviceIDSample {
		t.Fatalf("Verify: device id = %q, want %q", got, validDeviceIDSample)
	}
}

func TestMockVerifier_WrongPassword(t *testing.T) {
	var m MockVerifier
	m.Set("alice", "hunter2", validDeviceIDSample)

	_, err := m.Verify(context.Background(), "alice", "wrong")
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("Verify: err = %v, want ErrBadCredentials", err)
	}
}

func TestMockVerifier_UnknownUser(t *testing.T) {
	var m MockVerifier
	_, err := m.Verify(context.Background(), "ghost", "anything")
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("Verify: err = %v, want ErrBadCredentials", err)
	}
}

func TestMockVerifier_VerifyFuncOverrides(t *testing.T) {
	m := &MockVerifier{
		VerifyFunc: func(ctx context.Context, username, password string) (string, error) {
			if username == "locked" {
				return "", ErrAccountLocked
			}
			return validDeviceIDSample, nil
		},
	}
	m.Set("alice", "ignored", "dev_ignored") // not consulted when VerifyFunc set

	got, err := m.Verify(context.Background(), "alice", "ignored")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != validDeviceIDSample {
		t.Fatalf("Verify: device id = %q, want %q", got, validDeviceIDSample)
	}

	if _, err := m.Verify(context.Background(), "locked", "anything"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("Verify(locked): err = %v, want ErrAccountLocked", err)
	}
}

func TestMockVerifier_CallsCaptured(t *testing.T) {
	var m MockVerifier
	m.Set("alice", "hunter2", validDeviceIDSample)

	_, _ = m.Verify(context.Background(), "alice", "hunter2")
	_, _ = m.Verify(context.Background(), "bob", "x")

	calls := m.Calls()
	want := []MockCall{
		{Username: "alice", Password: "hunter2"},
		{Username: "bob", Password: "x"},
	}
	if len(calls) != len(want) {
		t.Fatalf("Calls() len = %d, want %d", len(calls), len(want))
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("Calls()[%d] = %+v, want %+v", i, calls[i], want[i])
		}
	}
}

func TestMockVerifier_Reset(t *testing.T) {
	var m MockVerifier
	m.Set("alice", "hunter2", validDeviceIDSample)
	_, _ = m.Verify(context.Background(), "alice", "hunter2")
	m.Reset()

	if calls := m.Calls(); len(calls) != 0 {
		t.Fatalf("Calls() after Reset = %v, want empty", calls)
	}
	if _, err := m.Verify(context.Background(), "alice", "hunter2"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("Verify after Reset: err = %v, want ErrBadCredentials", err)
	}
}

func TestMockVerifier_ContextCancellation(t *testing.T) {
	var m MockVerifier
	m.Set("alice", "hunter2", validDeviceIDSample)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Verify(ctx, "alice", "hunter2"); err == nil {
		t.Fatal("Verify: expected context error, got nil")
	}
}

func TestMockVerifier_ConcurrentSafe(t *testing.T) {
	var m MockVerifier
	m.Set("alice", "hunter2", validDeviceIDSample)

	const n = 64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = m.Verify(context.Background(), "alice", "hunter2")
		}()
	}
	wg.Wait()
	if got := len(m.Calls()); got != n {
		t.Fatalf("Calls() = %d, want %d", got, n)
	}
}

func TestMockVerifier_ImplementsInterface(t *testing.T) {
	// Compile-time assertion is in mock.go; this test exists so the
	// readable failure mode is "missing method" instead of an
	// unrelated build error.
	var pv PasswordVerifier = &MockVerifier{}
	_, _ = pv.Verify(context.Background(), "", "")
}
