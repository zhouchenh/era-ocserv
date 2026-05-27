package udshandoff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
)

// Spec §5.1 fixed header constants.
const (
	// DGramHeaderLen is the size of the SOCK_DGRAM fixed header (v + fl +
	// tlvlen + pldlen).
	DGramHeaderLen = 6
	// MaxDatagramSize is the spec §2.6 cap: 64 KiB including fixed header +
	// TLV block + payload.
	MaxDatagramSize = 64 * 1024
)

// Direction encodes the `fl` bit-0 (facade→backend / backend→facade) field
// (spec §5.1).
type Direction byte

const (
	DirFacadeToBackend Direction = 0
	DirBackendToFacade Direction = 1
)

// DGramFrame is one parsed SOCK_DGRAM datagram, both the inner PROXY-v2
// envelope (per spec §5.4) AND the ERA TLVs.
type DGramFrame struct {
	// Version is the spec version byte from the fixed header. Stage 1 = 0x01.
	Version byte
	// Direction is bit 0 of the `fl` byte.
	Direction Direction
	// Inner is the parsed PROXY-v2 envelope decoded from the leading bytes of
	// the TLV block (per spec §5.4).
	Inner *proxyproto.HeaderV2
	// ERA holds the ERA TLVs that follow the PROXY-v2 envelope. Note: these
	// are the TLVs *after* the inner PROXY-v2 header's address block + that
	// header's own TLV section. (The inner PROXY-v2 header's TLVs, if any,
	// are accessible via Inner.TLVs.)
	ERA []proxyproto.TLV
	// Payload is the post-TLV-block opaque bytes (pldlen bytes).
	Payload []byte
}

// AllTLVs returns the union of Inner.TLVs and ERA — convenience for callers
// that just want "every TLV in this frame, anywhere it appeared". The result
// is a fresh slice; callers can iterate freely.
func (f *DGramFrame) AllTLVs() []proxyproto.TLV {
	out := make([]proxyproto.TLV, 0, len(f.Inner.TLVs)+len(f.ERA))
	out = append(out, f.Inner.TLVs...)
	out = append(out, f.ERA...)
	return out
}

// FrameErrKind names the spec §8.1 error rows specific to SOCK_DGRAM.
type FrameErrKind int

const (
	// ErrFrameTooShort — datagram smaller than the 6-byte fixed header.
	ErrFrameTooShort FrameErrKind = iota + 1
	// ErrFrameBadVersion — fixed header `v` byte is not 0x01. Per §6.2 row 1:
	// drop datagram.
	ErrFrameBadVersion
	// ErrFrameReservedFlags — fixed header `fl` byte has any of bits 1-7 set.
	// Per spec §5.1 "bits 1-7 reserved, MUST be zero in Stage 1".
	ErrFrameReservedFlags
	// ErrFrameOversize — total declared size > 64 KiB. Per spec §2.6.
	ErrFrameOversize
	// ErrFrameTruncated — 6 + tlvlen + pldlen exceeds the actual datagram
	// bytes available.
	ErrFrameTruncated
	// ErrFrameInnerPP2 — inner PROXY-v2 envelope decode failed.
	ErrFrameInnerPP2
	// ErrFrameERAMalformed — ERA TLV block decode failed.
	ErrFrameERAMalformed
)

// String returns a short label matching the spec §8.1 cause column.
func (k FrameErrKind) String() string {
	switch k {
	case ErrFrameTooShort:
		return "frame_too_short"
	case ErrFrameBadVersion:
		return "frame_bad_version"
	case ErrFrameReservedFlags:
		return "frame_reserved_flags_set"
	case ErrFrameOversize:
		return "frame_oversize"
	case ErrFrameTruncated:
		return "frame_truncated"
	case ErrFrameInnerPP2:
		return "frame_inner_pp2_decode"
	case ErrFrameERAMalformed:
		return "frame_era_tlv_decode"
	default:
		return "unknown"
	}
}

// FrameErr is a typed datagram-parse error.
type FrameErr struct {
	Kind   FrameErrKind
	Detail string
	Err    error
}

func (e *FrameErr) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("udshandoff: %s: %s", e.Kind, e.Detail)
	}
	return fmt.Sprintf("udshandoff: %s: %s: %v", e.Kind, e.Detail, e.Err)
}

func (e *FrameErr) Unwrap() error { return e.Err }

// DecodeDGramFrame parses one SOCK_DGRAM frame from buf and returns the
// parsed view. The function does NOT validate against a Spec — the listener
// runs Validate separately so it can attribute failures with the right
// protocol tag in the metric counter.
//
// Stage 1 wire ordering, per spec §5.1 + §5.4:
//
//	[ 6 B fixed header                                                       ]
//	[ TLV block (tlvlen bytes) =                                              ]
//	[   inner PROXY-v2 header (signature + ver_cmd + fam + addr_len + addr   ]
//	[                          + nested PP2 TLVs covered by addr_len)        ]
//	[   ERA TLVs concatenated                                                ]
//	[ Payload (pldlen bytes)                                                 ]
func DecodeDGramFrame(buf []byte) (*DGramFrame, error) {
	if len(buf) < DGramHeaderLen {
		return nil, &FrameErr{
			Kind:   ErrFrameTooShort,
			Detail: fmt.Sprintf("%d bytes < %d (fixed header)", len(buf), DGramHeaderLen),
		}
	}
	v := buf[0]
	if v != proxyproto.SpecVersionStage1 {
		return nil, &FrameErr{
			Kind:   ErrFrameBadVersion,
			Detail: fmt.Sprintf("v=0x%02x (want 0x%02x)", v, proxyproto.SpecVersionStage1),
		}
	}
	fl := buf[1]
	if fl&0xFE != 0 {
		return nil, &FrameErr{
			Kind:   ErrFrameReservedFlags,
			Detail: fmt.Sprintf("fl=0x%02x", fl),
		}
	}
	tlvLen := int(binary.BigEndian.Uint16(buf[2:4]))
	pldLen := int(binary.BigEndian.Uint16(buf[4:6]))
	totalDeclared := DGramHeaderLen + tlvLen + pldLen
	if totalDeclared > MaxDatagramSize {
		return nil, &FrameErr{
			Kind:   ErrFrameOversize,
			Detail: fmt.Sprintf("declared=%d cap=%d", totalDeclared, MaxDatagramSize),
		}
	}
	if totalDeclared > len(buf) {
		return nil, &FrameErr{
			Kind:   ErrFrameTruncated,
			Detail: fmt.Sprintf("declared=%d actual=%d", totalDeclared, len(buf)),
		}
	}
	tlvBlock := buf[DGramHeaderLen : DGramHeaderLen+tlvLen]
	payload := append([]byte(nil), buf[DGramHeaderLen+tlvLen:DGramHeaderLen+tlvLen+pldLen]...)

	// Decode the inner PROXY-v2 envelope. It self-describes its own length
	// (the fixed 16-byte prefix says addr_block_len; the envelope owns
	// exactly that many bytes after the prefix). We use a bytes.Reader so
	// the envelope decode stops cleanly at its own boundary.
	innerRdr := bytes.NewReader(tlvBlock)
	inner, err := proxyproto.ReadHeaderV2WithTLVs(innerRdr)
	if err != nil {
		return nil, &FrameErr{Kind: ErrFrameInnerPP2, Detail: "inner pp2 decode", Err: err}
	}
	// Whatever's left in innerRdr is the ERA TLV block.
	rem := tlvBlock[len(tlvBlock)-innerRdr.Len():]
	var eraTLVs []proxyproto.TLV
	if len(rem) > 0 {
		decoded, _, derr := proxyproto.DecodeTLVs(rem)
		if derr != nil {
			return nil, &FrameErr{Kind: ErrFrameERAMalformed, Detail: "era tlv decode", Err: derr}
		}
		eraTLVs = decoded
	}
	return &DGramFrame{
		Version:   v,
		Direction: Direction(fl & 0x01),
		Inner:     inner,
		ERA:       eraTLVs,
		Payload:   payload,
	}, nil
}

// ErrDGramOversize signals to the listener that the kernel handed it a
// datagram that already exceeds MaxDatagramSize — distinct from a frame
// whose declared length exceeds the cap. We export both kinds because the
// metric counter (uds_dgram_oversize_total) bumps for both, but the log
// fields differ.
var ErrDGramOversize = errors.New("udshandoff: datagram exceeds MaxDatagramSize cap")
