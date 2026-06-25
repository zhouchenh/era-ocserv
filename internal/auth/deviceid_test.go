package auth

import "testing"

func TestValidDeviceID(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"alphabet-only", "dev_abcdefghijklmnopqrstuvwxyz", true},
		{"with-digits", "dev_abcdefghijklmnopqrst234567", true},
		{"mixed", "dev_a2b3c4d5e6f7abcdefghijklmn", true},

		{"empty", "", false},
		{"prefix-only", "dev_", false},
		{"missing-prefix", "abcdefghijklmnopqrstuvwxyz", false},
		{"wrong-prefix-usr", "usr_abcdefghijklmnopqrstuvwxyz", false},
		{"uppercase-prefix", "DEV_abcdefghijklmnopqrstuvwxyz", false},
		{"uppercase-body", "dev_ABCDEFGHIJKLMNOPQRSTUVWXYZ", false},
		{"too-short", "dev_abcdefghijklmnopqrstuvwxy", false},
		{"too-long", "dev_abcdefghijklmnopqrstuvwxyz2", false},
		{"non-base32-digit-0", "dev_0bcdefghijklmnopqrstuvwxyz", false},
		{"non-base32-digit-1", "dev_1bcdefghijklmnopqrstuvwxyz", false},
		{"non-base32-digit-8", "dev_8bcdefghijklmnopqrstuvwxyz", false},
		{"non-base32-digit-9", "dev_9bcdefghijklmnopqrstuvwxyz", false},
		{"hyphen", "dev_abcdefghijklmnopqrstuvwxy-", false},
		{"underscore-in-body", "dev_abcdefghijklmnopqrstuvwx_z", false},
		{"trailing-whitespace", "dev_abcdefghijklmnopqrstuvwxyz ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validDeviceID(tc.in); got != tc.want {
				t.Fatalf("validDeviceID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
