package cstp

import (
	"bufio"
	"net"
)

// NewTunnelForTesting constructs a *Tunnel directly around the given
// net.Conn, bypassing the CSTP control-plane handshake. It exists
// solely so sibling test suites in the era-ocserv module (notably
// internal/dtls) can exercise the Tunnel surface (AttachDTLS,
// DetachDTLS, InjectInbound, ReadPacket, WritePacket) without
// standing up a full TLS-enabled CSTP server, an mTLS-validated
// client, and a phase-2 XML conversation just to get a Tunnel
// pointer.
//
// The returned Tunnel runs the same reader and heartbeat goroutines
// the production newTunnel starts, so test callers can drive it with
// the same wire bytes a real client would emit. The Server reference
// is the parent Server whose configuration (DPDInterval / KeepaliveInterval /
// IdleTimeout / Now) the tunnel will inherit; pass a NewServer-built
// Server with the tuning the test needs.
//
// This is package-public because Go does not have a concept of
// "package-internal but test-accessible across packages"; the name
// announces its limited intent and the godoc here is the contract.
// Production code MUST NOT call this; production tunnels arise only
// from handleConnect.
func NewTunnelForTesting(s *Server, conn net.Conn, rw *bufio.ReadWriter, id Identity, sessionToken string) *Tunnel {
	return s.newTunnel(conn, rw, id, sessionToken)
}

// RegisterDTLSForTesting installs a (psk, tunnel) entry in the
// Server's DTLS lookup table directly, bypassing handleConnect's
// PSK-derivation path. Sibling tests in internal/dtls use this to
// stage a Tunnel as if it had completed a TLS CONNECT with a
// successful exporter call, so the DTLS server can resolve the
// session by PSK identity.
//
// As with NewTunnelForTesting, the name announces test-only intent;
// production code MUST NOT call this.
func RegisterDTLSForTesting(s *Server, sessionToken string, psk []byte, t *Tunnel) {
	s.registerTunnel(sessionToken, psk, t)
}
