package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestTPMExplicitCLATInvalidNeverFallsBack(t *testing.T) {
	for _, value := range []string{`null`, `""`, `" "`, `1`, `false`, `{}`, `[]`, `"bad"`, `"192.0.0.1/32"`, `"2001:db8::1/128"`, `"2001:470:f9d1:9001::/64"`} {
		t.Run(value, func(t *testing.T) {
			r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
				assertAuth(t, req)
				fmt.Fprintf(w, `{"device_id":%q,"source_ipv6_ocserv":"2001:470:f9d1:9001::1/128","source_ipv6_clat":"2001:470:f9d1:9001::2/128","source_ipv6_ocserv_clat":%s}`, testDeviceID, value)
			}, nil)
			if _, err := r.Resolve(context.Background(), testDeviceID); !errors.Is(err, ErrUpstream) {
				t.Fatalf("invalid explicit field accepted/fell back: %v", err)
			}
		})
	}
}

func TestTPMPinnedAllocatorCLATFixtures(t *testing.T) {
	for _, name := range []string{"dual-bound.json", "ocserv-only.json"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "tpm-clat", name))
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			field := func(key string) string {
				t.Helper()
				var s string
				if err := json.Unmarshal(fields[key], &s); err != nil {
					t.Fatal(err)
				}
				return s
			}
			device := field("device_id")
			native := netip.MustParsePrefix(field("source_ipv6_ocserv"))
			clat := netip.MustParsePrefix(field("source_ipv6_ocserv_clat"))
			if name == "dual-bound.json" && field("source_ipv6_clat") == clat.String() {
				t.Fatal("fixture lacks distinguishing shared field")
			}
			calls := 0
			r, _ := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) { calls++; assertAuth(t, req); w.Write(data) }, func(c *TPMResolverConfig) { c.PoolPrefix = netip.MustParsePrefix("2001:db8:1::/64") })
			id, err := r.Resolve(context.Background(), device)
			if err != nil || id.IPv6 != native || id.IPv6CLAT != clat || calls != 1 {
				t.Fatalf("producer/consumer mismatch: %v", err)
			}
		})
	}
}
