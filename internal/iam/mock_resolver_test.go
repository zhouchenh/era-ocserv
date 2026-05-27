package iam

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestMockResolver(t *testing.T) {
	var m MockResolver
	ctx := context.Background()

	// Empty Mock: every Resolve returns ErrDeviceNotFound.
	if _, err := m.Resolve(ctx, "dev_unknown"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("empty resolve err = %v, want %v", err, ErrDeviceNotFound)
	}

	// Set, then Resolve returns the seeded value (and Set overwrites
	// DeviceID with the key to keep callers consistent).
	want := Identity{
		IPv6: netip.MustParsePrefix("2001:470:f9d1:9001::1/128"),
		MTU:  1406,
		DNS:  []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")},
	}
	m.Set("dev_aaaaaaaaaaaaaaaaaaaaaaaaaa", want)
	got, err := m.Resolve(ctx, "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("seeded resolve err = %v", err)
	}
	if got.DeviceID != "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("DeviceID = %q, want it overwritten to the key", got.DeviceID)
	}
	if got.IPv6 != want.IPv6 {
		t.Errorf("IPv6 = %v, want %v", got.IPv6, want.IPv6)
	}
	if got.MTU != 1406 {
		t.Errorf("MTU = %d, want 1406", got.MTU)
	}

	// Delete removes the entry.
	m.Delete("dev_aaaaaaaaaaaaaaaaaaaaaaaaaa")
	if _, err := m.Resolve(ctx, "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("after Delete err = %v, want %v", err, ErrDeviceNotFound)
	}

	// Overwrite a Set re-overwrites.
	m.Set("dev_bbbbbbbbbbbbbbbbbbbbbbbbbb", Identity{IPv6: netip.MustParsePrefix("2001:470:f9d1:9001::2/128")})
	m.Set("dev_bbbbbbbbbbbbbbbbbbbbbbbbbb", Identity{IPv6: netip.MustParsePrefix("2001:470:f9d1:9001::3/128")})
	got, err = m.Resolve(ctx, "dev_bbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("overwrite resolve err = %v", err)
	}
	if want := netip.MustParsePrefix("2001:470:f9d1:9001::3/128"); got.IPv6 != want {
		t.Errorf("IPv6 = %v, want %v (second Set should win)", got.IPv6, want)
	}
}

// TestMockResolverImplementsResolver is a compile-time assertion.
func TestMockResolverImplementsResolver(t *testing.T) {
	var _ Resolver = (*MockResolver)(nil)
}
