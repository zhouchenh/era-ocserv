// PROXY protocol v2 stream reader that surfaces both the address block AND
// the optional TLV section.
//
// proxyproto.go has the original "address-only" reader, kept for the existing
// loopback splicer use-case. This file adds the TLV-aware reader the UDS
// handoff framework consumes — Stage 1 of the era-facade↔era-proxy hop spec
// (`era-facade/docs/architecture/uds-handoff-protocol.md` §3).
//
// Differences from ReadHeaderV2:
//   - Always returns the parsed TLV records (or an empty slice when none).
//   - Surfaces the destination address (the original public dst at the facade)
//     in addition to the source — the spec uses dst as a session key for
//     DTLS demux (§5.3).
//   - Rejects LOCAL command (0x20). The facade-to-backend hop never uses
//     LOCAL; the spec mandates 0x21 (§3.1).
//   - Rejects family bytes outside {0x11, 0x21, 0x12, 0x22}.
//   - Bytes past the address-block length are NOT consumed — the post-header
//     bytestream is left on the wire for the SOCK_STREAM payload phase. For
//     SOCK_DGRAM the address-block IS the whole header — see DecodeDGramFrame
//     in udshandoff.

package proxyproto

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
)

// HeaderV2 is the full parsed view of a PROXY-v2 header — address block plus
// TLVs.
type HeaderV2 struct {
	// Family is the raw family byte from the header (0x11/0x21/0x12/0x22).
	// Stage 1 callers can use Transport() and IsIPv6() if they prefer the
	// derived shape.
	Family byte
	// Src is the announced original client address (host:port).
	Src netip.AddrPort
	// Dst is the announced original destination at the facade (host:port).
	// Load-bearing for DTLS session keying per spec §5.3.
	Dst netip.AddrPort
	// TLVs are the parsed records in source order. Standard PP2 TLVs and ERA
	// custom TLVs are intermixed; lookups go through HeaderV2.Lookup or the
	// per-protocol validator.
	TLVs []TLV
}

// Transport returns "tcp" for 0x11/0x21, "udp" for 0x12/0x22, "" otherwise.
func (h *HeaderV2) Transport() string {
	switch h.Family {
	case famTCP4, famTCP6:
		return "tcp"
	case famUDP4, famUDP6:
		return "udp"
	default:
		return ""
	}
}

// IsIPv6 reports whether the address family is IPv6.
func (h *HeaderV2) IsIPv6() bool {
	return h.Family == famTCP6 || h.Family == famUDP6
}

// Lookup returns the value of the first TLV with type t, or nil if absent.
// Since duplicates are rejected at decode time, "first" == "only".
func (h *HeaderV2) Lookup(t TLVType) []byte {
	for i := range h.TLVs {
		if h.TLVs[i].Type == t {
			return h.TLVs[i].Value
		}
	}
	return nil
}

// HeaderErr is returned by ReadHeaderV2WithTLVs when the parser definitively
// identifies a protocol violation. The kind discriminates the spec's §8.1
// error table so the listener can pick the appropriate counter to increment.
type HeaderErr struct {
	Kind   HeaderErrKind
	Detail string
	Err    error
}

// HeaderErrKind names the spec §8.1 error classes the reader can produce.
type HeaderErrKind int

const (
	// ErrSignatureInvalid — the first 12 bytes did not match the PROXY-v2
	// magic. Per spec §8.1 row 1: increment uds_proxy_v2_invalid_signature_total.
	ErrSignatureInvalid HeaderErrKind = iota + 1
	// ErrIncompleteHeader — EOF or short read before all declared bytes
	// arrived. Per spec §8.1 row "UDS read EOF before header complete":
	// increment uds_incomplete_header_total.
	ErrIncompleteHeader
	// ErrUnsupportedVersionCmd — ver_cmd byte was not 0x21 (LOCAL or other).
	ErrUnsupportedVersionCmd
	// ErrUnsupportedFamily — family byte was not in {0x11, 0x21, 0x12, 0x22}.
	ErrUnsupportedFamily
	// ErrAddressBlockShort — the declared address-block length is smaller
	// than the family-specific minimum (12 for v4, 36 for v6).
	ErrAddressBlockShort
	// ErrTLVMalformed — TLV decoding failed (truncation, duplicate, reserved
	// range, trailing garbage).
	ErrTLVMalformed
)

func (e *HeaderErr) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("proxyproto: %s: %s", e.Kind, e.Detail)
	}
	return fmt.Sprintf("proxyproto: %s: %s: %v", e.Kind, e.Detail, e.Err)
}

func (e *HeaderErr) Unwrap() error { return e.Err }

// String returns a short label matching the spec §8.1 row.
func (k HeaderErrKind) String() string {
	switch k {
	case ErrSignatureInvalid:
		return "signature_invalid"
	case ErrIncompleteHeader:
		return "incomplete_header"
	case ErrUnsupportedVersionCmd:
		return "unsupported_version_cmd"
	case ErrUnsupportedFamily:
		return "unsupported_family"
	case ErrAddressBlockShort:
		return "address_block_short"
	case ErrTLVMalformed:
		return "tlv_malformed"
	default:
		return "unknown"
	}
}

// ReadHeaderV2WithTLVs reads the complete PROXY-v2 header (fixed 16-byte
// prefix + address fields + TLVs) from r and returns the parsed view.
//
// Behaviour vs spec §3:
//   - ver_cmd MUST be 0x21 (PROXY). LOCAL (0x20) is rejected.
//   - family byte MUST be 0x11, 0x21, 0x12, or 0x22. Any other value is
//     rejected.
//   - Bytes are read exactly up to addr_block_len; nothing past the address
//     block is consumed.
//   - TLV decoding follows DecodeTLVs (which enforces no-duplicates and
//     no-reserved-range).
//
// Per-TLV value validation is NOT performed here — call ValidateTLV on each
// returned TLV (the listener does this, so it can attribute failures to the
// per-flow metrics with the right protocol tag).
func ReadHeaderV2WithTLVs(r io.Reader) (*HeaderV2, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, &HeaderErr{Kind: ErrIncompleteHeader, Detail: "fixed prefix EOF", Err: err}
		}
		return nil, &HeaderErr{Kind: ErrIncompleteHeader, Detail: "fixed prefix read", Err: err}
	}
	if [12]byte(hdr[0:12]) != v2Signature {
		return nil, &HeaderErr{
			Kind:   ErrSignatureInvalid,
			Detail: fmt.Sprintf("first 8 bytes=%x", hdr[0:8]),
		}
	}
	verCmd := hdr[12]
	if verCmd != verCmdProxy {
		return nil, &HeaderErr{
			Kind:   ErrUnsupportedVersionCmd,
			Detail: fmt.Sprintf("ver_cmd=0x%02x (want 0x21)", verCmd),
		}
	}
	fam := hdr[13]
	switch fam {
	case famTCP4, famTCP6, famUDP4, famUDP6:
		// ok
	default:
		return nil, &HeaderErr{
			Kind:   ErrUnsupportedFamily,
			Detail: fmt.Sprintf("family=0x%02x", fam),
		}
	}
	alen := int(binary.BigEndian.Uint16(hdr[14:16]))
	body := make([]byte, alen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, &HeaderErr{Kind: ErrIncompleteHeader, Detail: fmt.Sprintf("addr_block %d bytes", alen), Err: err}
	}
	var (
		addrLen int
		isV6    bool
	)
	switch fam {
	case famTCP4, famUDP4:
		addrLen = addrPairV4
	case famTCP6, famUDP6:
		addrLen = addrPairV6
		isV6 = true
	}
	if alen < addrLen {
		return nil, &HeaderErr{
			Kind:   ErrAddressBlockShort,
			Detail: fmt.Sprintf("addr_block_len=%d < required %d", alen, addrLen),
		}
	}
	var src, dst netip.AddrPort
	if isV6 {
		var s, d [16]byte
		copy(s[:], body[0:16])
		copy(d[:], body[16:32])
		src = netip.AddrPortFrom(netip.AddrFrom16(s), binary.BigEndian.Uint16(body[32:34]))
		dst = netip.AddrPortFrom(netip.AddrFrom16(d), binary.BigEndian.Uint16(body[34:36]))
	} else {
		var s, d [4]byte
		copy(s[:], body[0:4])
		copy(d[:], body[4:8])
		src = netip.AddrPortFrom(netip.AddrFrom4(s), binary.BigEndian.Uint16(body[8:10]))
		dst = netip.AddrPortFrom(netip.AddrFrom4(d), binary.BigEndian.Uint16(body[10:12]))
	}
	var tlvs []TLV
	if alen > addrLen {
		decoded, _, err := DecodeTLVs(body[addrLen:])
		if err != nil {
			return nil, &HeaderErr{Kind: ErrTLVMalformed, Detail: "TLV decode", Err: err}
		}
		tlvs = decoded
	}
	return &HeaderV2{
		Family: fam,
		Src:    src,
		Dst:    dst,
		TLVs:   tlvs,
	}, nil
}

// ReadHeaderV2WithTLVsBuffered is the bufio-friendly variant: it returns the
// parsed header AND any extra bytes already in the buffered reader after the
// header (so the caller can either continue reading the same bufio.Reader as
// the payload stream, or re-attach those leftover bytes to a raw net.Conn).
//
// The caller passes in a *bufio.Reader they intend to keep using; this
// function does not allocate one. Use this when integrating with an
// existing reader where you want to preserve buffered pre-header bytes (rare;
// in practice the UDS listener opens a fresh conn and uses a fresh bufio).
func ReadHeaderV2WithTLVsBuffered(br *bufio.Reader) (*HeaderV2, error) {
	return ReadHeaderV2WithTLVs(br)
}

// Encode re-emits this parsed header in PROXY-v2 wire form: signature + ver_cmd
// + family + addr_block_len + address fields + nested TLVs. Used by the
// datagram reply path to mirror the inbound's inner PROXY-v2 envelope. The
// emitted bytes ARE wire-compatible with ReadHeaderV2WithTLVs.
//
// Encode preserves the TLV order it was parsed in. The spec mandates writers
// emit TLVs in ascending-type order (§3.2); readers tolerate any order. Since
// the inbound came from the facade (which emits ascending), preserving order
// satisfies both rules.
func (h *HeaderV2) Encode() ([]byte, error) {
	var addrLen int
	switch h.Family {
	case famTCP4, famUDP4:
		addrLen = addrPairV4
	case famTCP6, famUDP6:
		addrLen = addrPairV6
	default:
		return nil, fmt.Errorf("proxyproto.Encode: unsupported family 0x%02x", h.Family)
	}
	// Compute TLV block size first so we can write addr_block_len.
	tlvSize := 0
	for _, t := range h.TLVs {
		if len(t.Value) > 0xFFFF {
			return nil, fmt.Errorf("proxyproto.Encode: tlv 0x%02x value too long", byte(t.Type))
		}
		tlvSize += 3 + len(t.Value)
	}
	out := make([]byte, 0, 16+addrLen+tlvSize)
	out = append(out, v2Signature[:]...)
	out = append(out, verCmdProxy)
	out = append(out, h.Family)
	out = binary.BigEndian.AppendUint16(out, uint16(addrLen+tlvSize))
	// Addresses.
	if h.IsIPv6() {
		s := h.Src.Addr().As16()
		d := h.Dst.Addr().As16()
		out = append(out, s[:]...)
		out = append(out, d[:]...)
	} else {
		s := h.Src.Addr().As4()
		d := h.Dst.Addr().As4()
		out = append(out, s[:]...)
		out = append(out, d[:]...)
	}
	out = binary.BigEndian.AppendUint16(out, h.Src.Port())
	out = binary.BigEndian.AppendUint16(out, h.Dst.Port())
	for _, t := range h.TLVs {
		out = append(out, byte(t.Type))
		out = binary.BigEndian.AppendUint16(out, uint16(len(t.Value)))
		out = append(out, t.Value...)
	}
	return out, nil
}

// AddrPortToTCP converts a netip.AddrPort to *net.TCPAddr (Stage 1 callers
// usually want *net.TCPAddr for compatibility with the existing egress dial
// path which is built on net.Addr). Returns nil for the zero AddrPort.
func AddrPortToTCP(ap netip.AddrPort) *net.TCPAddr {
	if !ap.IsValid() {
		return nil
	}
	return &net.TCPAddr{IP: ap.Addr().AsSlice(), Port: int(ap.Port())}
}

// AddrPortToUDP is the UDP equivalent of AddrPortToTCP.
func AddrPortToUDP(ap netip.AddrPort) *net.UDPAddr {
	if !ap.IsValid() {
		return nil
	}
	return &net.UDPAddr{IP: ap.Addr().AsSlice(), Port: int(ap.Port())}
}
