// Package logredact removes bearer-like path segments from values that are
// written to diagnostic logs. It never changes routing or response values.
package logredact

import "strings"

// GroupURLTokens replaces the token segment after every /drive/access/ in
// path with "[redacted]", preserving the surrounding route (including nested
// group URLs on unrouted input).
func GroupURLTokens(path string) string {
	parts := strings.Split(path, "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "drive" && parts[i+1] == "access" && parts[i+2] != "" {
			parts[i+2] = "[redacted]"
		}
	}
	return strings.Join(parts, "/")
}
