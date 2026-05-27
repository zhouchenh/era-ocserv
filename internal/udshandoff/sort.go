package udshandoff

import "sort"

// sortProtocolNames sorts a slice of ProtocolName in ascending lexical order.
// Tiny helper to keep AllProtocols deterministic.
func sortProtocolNames(s []ProtocolName) {
	sort.Slice(s, func(i, j int) bool { return string(s[i]) < string(s[j]) })
}
