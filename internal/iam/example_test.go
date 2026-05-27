package iam_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/zhouchenh/era-ocserv/internal/iam"
)

// ExampleMockResolver shows how downstream tests pre-seed device
// identities for the CSTP CONNECT phase. Set overwrites Identity.DeviceID
// with the key so callers never have to repeat it; an unknown device
// resolves to ErrDeviceNotFound; Delete unseats the entry.
func ExampleMockResolver() {
	var r iam.MockResolver
	r.Set("dev_abcdefghijklmnopqrstuvwxyz", iam.Identity{
		IPv6: netip.MustParsePrefix("2001:470:f9d1:9001::1/128"),
		MTU:  1406,
	})

	id, err := r.Resolve(context.Background(), "dev_abcdefghijklmnopqrstuvwxyz")
	fmt.Println("ok:", id.DeviceID, id.IPv6, id.MTU, err)

	_, err = r.Resolve(context.Background(), "dev_unknownunknownunknownuu")
	fmt.Println("missing:", errors.Is(err, iam.ErrDeviceNotFound))

	// Output:
	// ok: dev_abcdefghijklmnopqrstuvwxyz 2001:470:f9d1:9001::1/128 1406 <nil>
	// missing: true
}
