package auth_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/zhouchenh/era-ocserv/internal/auth"
)

// ExampleMockVerifier shows how downstream tests wire a fake password
// verifier into the CSTP layer. Pre-seed credentials with Set; the
// matching Verify returns the device id, mismatches return
// ErrBadCredentials, and a VerifyFunc hook can drive error-path tests
// such as upstream timeouts.
func ExampleMockVerifier() {
	var v auth.MockVerifier
	v.Set("alice@example.com", "hunter2", "dev_abcdefghijklmnopqrstuvwxyz")

	deviceID, err := v.Verify(context.Background(), "alice@example.com", "hunter2")
	fmt.Println("ok:", deviceID, err)

	_, err = v.Verify(context.Background(), "alice@example.com", "wrong")
	fmt.Println("bad:", errors.Is(err, auth.ErrBadCredentials))

	v.VerifyFunc = func(context.Context, string, string) (string, error) {
		return "", auth.ErrAccountLocked
	}
	_, err = v.Verify(context.Background(), "alice@example.com", "hunter2")
	fmt.Println("locked:", errors.Is(err, auth.ErrAccountLocked))

	// Output:
	// ok: dev_abcdefghijklmnopqrstuvwxyz <nil>
	// bad: true
	// locked: true
}
