package logredact

import "testing"

func TestGroupURLTokens(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/drive/access/synthetic-token", "/drive/access/[redacted]"},
		{"/drive/access/synthetic-token/", "/drive/access/[redacted]/"},
		{"/drive/access/synthetic-token/auth", "/drive/access/[redacted]/auth"},
		{"/drive/access/a/drive/access/b/x", "/drive/access/[redacted]/drive/access/[redacted]/x"},
		{"/drive/access//x", "/drive/access//x"},
		{"/CSCOSSLC/tunnel", "/CSCOSSLC/tunnel"},
		{"/", "/"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := GroupURLTokens(tc.in); got != tc.want {
			t.Errorf("GroupURLTokens(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
