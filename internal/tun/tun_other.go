//go:build !linux

package tun

import (
	"errors"
	"runtime"
)

// ErrUnsupported is returned by Open on non-Linux platforms.
var ErrUnsupported = errors.New("tun: multi-queue TUN is only supported on Linux")

// Device is a stub on non-Linux platforms. Open always fails with
// ErrUnsupported.
type Device struct{}

// Queue is a stub on non-Linux platforms.
type Queue struct{}

// Open returns ErrUnsupported on every non-Linux platform. era-ocserv only
// targets Linux; the stub exists so packages that import "tun" still build on
// developer workstations.
func Open(_ Options) (*Device, error) {
	return nil, errUnsupported()
}

// Name returns the empty string on non-Linux platforms.
func (d *Device) Name() string { return "" }

// Queues returns nil on non-Linux platforms.
func (d *Device) Queues() []*Queue { return nil }

// Close is a no-op on non-Linux platforms.
func (d *Device) Close() error { return nil }

// Read always returns ErrUnsupported on non-Linux platforms.
func (q *Queue) Read(_ []byte) (int, error) { return 0, errUnsupported() }

// Write always returns ErrUnsupported on non-Linux platforms.
func (q *Queue) Write(_ []byte) (int, error) { return 0, errUnsupported() }

// Close is a no-op on non-Linux platforms.
func (q *Queue) Close() error { return nil }

func errUnsupported() error {
	return errors.New("tun: not supported on " + runtime.GOOS)
}
