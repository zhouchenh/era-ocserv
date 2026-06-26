//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// netlinkConn is a minimal NETLINK_ROUTE client used to bring the device UP,
// set its MTU, and assign optional IPv4 / IPv6 addresses.
//
// We intentionally do not pull in a third-party netlink library: the surface
// we need is tiny (three message types, no event subscription) and the
// kernel's rtnetlink protocol is stable.
type netlinkConn struct {
	fd  int
	seq atomic.Uint32
}

func newNetlinkConn() (*netlinkConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, &os.PathError{Op: "socket(AF_NETLINK)", Err: err}
	}
	// Bind to our own pid; the kernel uses pid==0 to mean "auto-assign by
	// PID", which is fine for our purposes — we never receive multicast.
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "bind(AF_NETLINK)", Err: err}
	}
	return &netlinkConn{fd: fd}, nil
}

func (c *netlinkConn) close() error { return unix.Close(c.fd) }

// nextSeq returns a fresh sequence number for an outgoing request.
func (c *netlinkConn) nextSeq() uint32 {
	return c.seq.Add(1)
}

// ifindex resolves a Linux interface name to its kernel ifindex via
// RTM_GETLINK. Returns an error if the device is not present.
func (c *netlinkConn) ifindex(name string) (int32, error) {
	seq := c.nextSeq()
	body := make([]byte, 0, 64)
	// ifinfomsg header
	body = append(body, make([]byte, unix.SizeofIfInfomsg)...)
	// IFLA_IFNAME attribute (NUL-terminated)
	body = appendAttr(body, unix.IFLA_IFNAME, append([]byte(name), 0))

	hdr := unix.NlMsghdr{
		Type:  unix.RTM_GETLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
	}
	resps, err := c.exchange(hdr, body)
	if err != nil {
		return 0, err
	}
	for _, r := range resps {
		if r.Header.Type != unix.RTM_NEWLINK {
			continue
		}
		if len(r.Data) < unix.SizeofIfInfomsg {
			return 0, fmt.Errorf("short RTM_NEWLINK payload (%d bytes)", len(r.Data))
		}
		info := (*unix.IfInfomsg)(unsafe.Pointer(&r.Data[0]))
		return info.Index, nil
	}
	return 0, fmt.Errorf("ifindex for %q: no RTM_NEWLINK in reply", name)
}

// setLink issues a single RTM_NEWLINK that both sets the MTU and toggles
// IFF_UP. We do not use NLM_F_CREATE — the link already exists, the tun
// driver created it.
func (c *netlinkConn) setLink(idx int32, mtu int) error {
	seq := c.nextSeq()

	info := unix.IfInfomsg{
		Family: unix.AF_UNSPEC,
		Index:  idx,
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
	}
	body := make([]byte, 0, unix.SizeofIfInfomsg+12)
	body = append(body, asBytes(unsafe.Pointer(&info), unix.SizeofIfInfomsg)...)

	var mtuBuf [4]byte
	binary.NativeEndian.PutUint32(mtuBuf[:], uint32(mtu))
	body = appendAttr(body, unix.IFLA_MTU, mtuBuf[:])

	hdr := unix.NlMsghdr{
		Type:  unix.RTM_NEWLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
	}
	_, err := c.exchange(hdr, body)
	return err
}

// addAddr issues RTM_NEWADDR with NLM_F_CREATE|NLM_F_EXCL to assign an inner
// address. EEXIST is treated as success — repeating Open() on a hot device
// shouldn't fail because the operator already configured an address.
func (c *netlinkConn) addAddr(idx int32, prefix netip.Prefix) error {
	seq := c.nextSeq()
	addr := prefix.Addr()
	var (
		family  uint8
		rawAddr []byte
	)
	if addr.Is4() {
		family = unix.AF_INET
		a4 := addr.As4()
		rawAddr = a4[:]
	} else {
		family = unix.AF_INET6
		a16 := addr.As16()
		rawAddr = a16[:]
	}

	msg := unix.IfAddrmsg{
		Family:    family,
		Prefixlen: uint8(prefix.Bits()),
		Scope:     unix.RT_SCOPE_UNIVERSE,
		Index:     uint32(idx),
	}
	body := make([]byte, 0, unix.SizeofIfAddrmsg+32)
	body = append(body, asBytes(unsafe.Pointer(&msg), unix.SizeofIfAddrmsg)...)
	body = appendAttr(body, unix.IFA_LOCAL, rawAddr)
	body = appendAttr(body, unix.IFA_ADDRESS, rawAddr)

	hdr := unix.NlMsghdr{
		Type:  unix.RTM_NEWADDR,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   seq,
	}
	_, err := c.exchange(hdr, body)
	if err != nil {
		if errno, ok := asSyscallErrno(err); ok && errno == unix.EEXIST {
			return nil
		}
		return err
	}
	return nil
}

// netlinkMsg is one (header, body) pair pulled out of a recv buffer.
type netlinkMsg struct {
	Header unix.NlMsghdr
	Data   []byte
}

// exchange sends one request and reads responses until the ACK / DONE / error
// terminator. The returned slice does not include the terminator message.
func (c *netlinkConn) exchange(hdr unix.NlMsghdr, body []byte) ([]netlinkMsg, error) {
	pkt := encodeNetlinkMsg(hdr, body)
	if err := unix.Sendto(c.fd, pkt, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, &os.PathError{Op: "sendto(netlink)", Err: err}
	}

	buf := make([]byte, 16*1024)
	var out []netlinkMsg
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, &os.PathError{Op: "recvfrom(netlink)", Err: err}
		}
		done, msgs, err := parseNetlinkMsgs(buf[:n], hdr.Seq)
		if err != nil {
			return nil, err
		}
		out = append(out, msgs...)
		if done {
			return out, nil
		}
	}
}

// encodeNetlinkMsg builds a single netlink datagram (header + body). Len is
// fixed up to (SizeofNlMsghdr + len(body)) and the trailing padding is
// applied so multiple messages can in principle be concatenated.
func encodeNetlinkMsg(hdr unix.NlMsghdr, body []byte) []byte {
	hdr.Len = uint32(unix.SizeofNlMsghdr + len(body))
	total := nlmAlign(int(hdr.Len))
	buf := make([]byte, total)
	*(*unix.NlMsghdr)(unsafe.Pointer(&buf[0])) = hdr
	copy(buf[unix.SizeofNlMsghdr:], body)
	return buf
}

// parseNetlinkMsgs walks a recv buffer and pulls out messages matching the
// expected seq. It returns done=true when an ACK (NLMSG_ERROR with Error==0),
// NLMSG_DONE, or a non-multi NLMSG_ERROR with Error!=0 (turned into a Go
// error) is encountered.
func parseNetlinkMsgs(buf []byte, expectSeq uint32) (done bool, out []netlinkMsg, err error) {
	for len(buf) >= unix.SizeofNlMsghdr {
		hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
		if int(hdr.Len) < unix.SizeofNlMsghdr || int(hdr.Len) > len(buf) {
			return false, nil, fmt.Errorf("netlink: malformed message len=%d, remaining=%d", hdr.Len, len(buf))
		}
		body := buf[unix.SizeofNlMsghdr:hdr.Len]
		// Skip messages for other sequences (shouldn't happen on our pid-bound socket).
		if hdr.Seq != expectSeq {
			buf = buf[nlmAlign(int(hdr.Len)):]
			continue
		}
		switch hdr.Type {
		case unix.NLMSG_DONE:
			return true, out, nil
		case unix.NLMSG_ERROR:
			if len(body) < 4 {
				return false, nil, fmt.Errorf("netlink: short NLMSG_ERROR (%d bytes)", len(body))
			}
			ec := int32(binary.NativeEndian.Uint32(body[:4]))
			if ec == 0 {
				// ACK
				return true, out, nil
			}
			return false, nil, unix.Errno(-ec)
		default:
			out = append(out, netlinkMsg{Header: hdr, Data: append([]byte(nil), body...)})
		}
		// For a non-multipart request (no NLM_F_MULTI on the response), the
		// kernel always tacks NLMSG_DONE / NLMSG_ERROR at the end. So we
		// keep walking the buffer.
		buf = buf[nlmAlign(int(hdr.Len)):]
	}
	return false, out, nil
}

// appendAttr appends a netlink TLV attribute to body. The header is 4 bytes
// (uint16 length, uint16 type) followed by value padded to NLA_ALIGNTO.
func appendAttr(body []byte, typ uint16, value []byte) []byte {
	attrLen := unix.SizeofRtAttr + len(value)
	body = append(body, 0, 0, 0, 0)
	binary.NativeEndian.PutUint16(body[len(body)-4:len(body)-2], uint16(attrLen))
	binary.NativeEndian.PutUint16(body[len(body)-2:], typ)
	body = append(body, value...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	return body
}

// nlmAlign rounds n up to the netlink message alignment (4 bytes).
func nlmAlign(n int) int { return (n + 3) &^ 3 }

// asBytes views the given memory as a byte slice WITHOUT copying. The caller
// must keep the source alive for the lifetime of the returned slice (we only
// use this transiently to encode a struct into a netlink message body).
func asBytes(p unsafe.Pointer, size int) []byte {
	return unsafe.Slice((*byte)(p), size)
}
