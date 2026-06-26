// Package proxyproto implements the HAProxy PROXY protocol v2 (the binary
// variant) for carrying the ORIGINAL client address across an internal TCP hop.
//
// era-proxy's frontdemux L4-splices an accepted :443 connection to a local
// backend (e.g. the covert front). Without help, that backend sees the loopback
// peer (127.0.0.1), not the real client, so the backend cannot tell its own
// upstream who the client is. PROXY protocol v2 solves this the standard way: the
// splicing side prepends a fixed binary header announcing the real source and
// destination addresses, and the receiving side reads+strips it and treats the
// announced source as the connection's RemoteAddr. This is the same mechanism
// every load balancer (HAProxy, nginx, AWS NLB, …) uses; it changes no protocol
// semantics, only address attribution.
//
// Only the v2 STREAM (TCP over IPv4/IPv6) shape is implemented — that is all the
// internal hop needs. LOCAL connections and the UDP/DGRAM family are accepted on
// read (header skipped) but never emitted.
package proxyproto

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// v2Signature is the fixed 12-byte PROXY v2 preamble.
var v2Signature = [12]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const (
	verCmdProxy = 0x21 // version 2 (0x20) | command PROXY (0x01)
	verCmdLocal = 0x20 // version 2 | command LOCAL (0x00)

	famTCP4 = 0x11 // AF_INET  | STREAM
	famTCP6 = 0x21 // AF_INET6 | STREAM
)

// readHeaderTimeout bounds how long Accept waits for the PROXY header before
// giving up. The peer (frontdemux) writes it immediately, so this is only a
// safety net against a stalled/empty connection.
var readHeaderTimeout = 5 * time.Second

// WriteHeaderV2 writes a PROXY protocol v2 STREAM header to w announcing src as
// the original source and dst as the original destination. src and dst must be
// *net.TCPAddr (or net.Addr whose String() is host:port) of the same IP family.
// It returns an error if the addresses are unusable; callers should then abort
// the connection rather than splice without attribution.
func WriteHeaderV2(w io.Writer, src, dst net.Addr) error {
	sa, err := toAddrPort(src)
	if err != nil {
		return fmt.Errorf("proxyproto: source addr: %w", err)
	}
	da, err := toAddrPort(dst)
	if err != nil {
		return fmt.Errorf("proxyproto: dest addr: %w", err)
	}
	if sa.Addr().Is4() != da.Addr().Is4() {
		return errors.New("proxyproto: source/dest IP family mismatch")
	}

	var buf []byte
	buf = append(buf, v2Signature[:]...)
	buf = append(buf, verCmdProxy)
	if sa.Addr().Is4() {
		buf = append(buf, famTCP4)
		buf = binary.BigEndian.AppendUint16(buf, 12) // 4+4+2+2
		s4, d4 := sa.Addr().As4(), da.Addr().As4()
		buf = append(buf, s4[:]...)
		buf = append(buf, d4[:]...)
	} else {
		buf = append(buf, famTCP6)
		buf = binary.BigEndian.AppendUint16(buf, 36) // 16+16+2+2
		s16, d16 := sa.Addr().As16(), da.Addr().As16()
		buf = append(buf, s16[:]...)
		buf = append(buf, d16[:]...)
	}
	buf = binary.BigEndian.AppendUint16(buf, sa.Port())
	buf = binary.BigEndian.AppendUint16(buf, da.Port())

	_, err = w.Write(buf)
	return err
}

// toAddrPort converts a net.Addr (expected host:port) to a netip.AddrPort with
// the address unmapped to its native family.
func toAddrPort(a net.Addr) (netip.AddrPort, error) {
	if a == nil {
		return netip.AddrPort{}, errors.New("nil addr")
	}
	if ta, ok := a.(*net.TCPAddr); ok {
		ip, ok := netip.AddrFromSlice(ta.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("bad ip %v", ta.IP)
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(ta.Port)), nil
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// ReadHeaderV2 reads and consumes a PROXY protocol v2 header from r, returning
// the announced source address. For a LOCAL command (health checks) it returns a
// nil addr and nil error (the caller keeps the real peer addr). It reads exactly
// the header bytes and no more, so the remaining stream is left intact.
func ReadHeaderV2(r io.Reader) (src *net.TCPAddr, err error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("proxyproto: read header: %w", err)
	}
	if [12]byte(hdr[0:12]) != v2Signature {
		return nil, errors.New("proxyproto: bad v2 signature")
	}
	verCmd := hdr[12]
	fam := hdr[13]
	alen := int(binary.BigEndian.Uint16(hdr[14:16]))

	addr := make([]byte, alen)
	if _, err := io.ReadFull(r, addr); err != nil {
		return nil, fmt.Errorf("proxyproto: read addr block: %w", err)
	}
	if verCmd == verCmdLocal {
		return nil, nil // LOCAL: no announced address
	}
	if verCmd != verCmdProxy {
		return nil, fmt.Errorf("proxyproto: unsupported version/command 0x%02x", verCmd)
	}
	switch fam {
	case famTCP4:
		if alen < 12 {
			return nil, errors.New("proxyproto: short TCP4 addr block")
		}
		ip := net.IP(append([]byte(nil), addr[0:4]...))
		port := int(binary.BigEndian.Uint16(addr[8:10]))
		return &net.TCPAddr{IP: ip, Port: port}, nil
	case famTCP6:
		if alen < 36 {
			return nil, errors.New("proxyproto: short TCP6 addr block")
		}
		ip := net.IP(append([]byte(nil), addr[0:16]...))
		port := int(binary.BigEndian.Uint16(addr[32:34]))
		return &net.TCPAddr{IP: ip, Port: port}, nil
	default:
		// Unsupported family (e.g. AF_UNIX/DGRAM): header consumed, keep real peer.
		return nil, nil
	}
}

// Listener wraps a net.Listener so each accepted connection's PROXY v2 header is
// read and stripped, and the connection's RemoteAddr reports the announced client
// address. Connections whose header is missing/invalid are dropped (closed) and
// Accept continues — the only legitimate source is the local splicer, which
// always sends the header.
type Listener struct {
	net.Listener
	// OnError, when set, is called with the reason a connection was dropped (a
	// missing/invalid PROXY header). Optional; for diagnostics only.
	OnError func(error)
}

// NewListener wraps inner so accepted conns expose the PROXY-announced source as
// RemoteAddr. Use it ONLY when the upstream splicer is trusted to send the header
// (e.g. a loopback frontdemux backend) — never on a directly client-facing port.
func NewListener(inner net.Listener) *Listener { return &Listener{Listener: inner} }

// Accept accepts the next connection, reads its PROXY v2 header, and returns a
// conn whose RemoteAddr is the announced source. Bad/headerless conns are closed
// and skipped.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		_ = c.SetReadDeadline(time.Now().Add(readHeaderTimeout))
		br := bufio.NewReader(c)
		src, herr := ReadHeaderV2(br)
		_ = c.SetReadDeadline(time.Time{})
		if herr != nil {
			if l.OnError != nil {
				l.OnError(fmt.Errorf("drop conn from %s: %w", c.RemoteAddr(), herr))
			}
			_ = c.Close()
			continue
		}
		wrapped := &conn{Conn: c, reader: br}
		if src != nil {
			wrapped.remote = src
		}
		return wrapped, nil
	}
}

// conn is an accepted connection whose Reads come from a buffered reader (holding
// any bytes read past the PROXY header) and whose RemoteAddr is the announced
// client address.
type conn struct {
	net.Conn
	reader *bufio.Reader
	remote net.Addr
}

func (c *conn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func (c *conn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}
