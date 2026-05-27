package udshandoff

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
)

// buildDgram synthesizes a full SOCK_DGRAM frame for tests.
func buildDgram(t *testing.T, v byte, dir Direction, inner *proxyproto.HeaderV2, eraTLVs []proxyproto.TLV, payload []byte) []byte {
	t.Helper()
	innerBytes, err := inner.Encode()
	if err != nil {
		t.Fatalf("encode inner: %v", err)
	}
	eraBytes, err := encodeTLVs(eraTLVs)
	if err != nil {
		t.Fatalf("encode tlvs: %v", err)
	}
	tlvBlock := append(innerBytes, eraBytes...)
	out := make([]byte, DGramHeaderLen+len(tlvBlock)+len(payload))
	out[0] = v
	out[1] = byte(dir) & 0x01
	binary.BigEndian.PutUint16(out[2:4], uint16(len(tlvBlock)))
	binary.BigEndian.PutUint16(out[4:6], uint16(len(payload)))
	copy(out[DGramHeaderLen:], tlvBlock)
	copy(out[DGramHeaderLen+len(tlvBlock):], payload)
	return out
}

func validInnerV6(t *testing.T) *proxyproto.HeaderV2 {
	t.Helper()
	src := netip.MustParseAddrPort("[2001:db8::7]:51000")
	dst := netip.MustParseAddrPort("[2001:db8::1]:443")
	return &proxyproto.HeaderV2{
		Family: 0x22, // UDP6
		Src:    src,
		Dst:    dst,
	}
}

func TestDecodeDGramFrame_Valid(t *testing.T) {
	inner := validInnerV6(t)
	era := []proxyproto.TLV{
		{Type: proxyproto.EraTLVSpecVersion, Value: []byte{proxyproto.SpecVersionStage1}},
		{Type: proxyproto.EraTLVTraceID, Value: []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")},
		{Type: proxyproto.EraTLVQUICConnID, Value: make([]byte, 16)},
	}
	payload := []byte("hello-quic-payload")
	frame := buildDgram(t, proxyproto.SpecVersionStage1, DirFacadeToBackend, inner, era, payload)
	parsed, err := DecodeDGramFrame(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if parsed.Version != proxyproto.SpecVersionStage1 {
		t.Fatalf("version mismatch")
	}
	if parsed.Direction != DirFacadeToBackend {
		t.Fatalf("direction mismatch")
	}
	if string(parsed.Payload) != string(payload) {
		t.Fatalf("payload mismatch")
	}
	if len(parsed.ERA) != 3 {
		t.Fatalf("got %d era tlvs, want 3", len(parsed.ERA))
	}
	if parsed.Inner.Src != inner.Src || parsed.Inner.Dst != inner.Dst {
		t.Fatalf("inner addrs mismatch")
	}
}

func TestDecodeDGramFrame_BadVersion(t *testing.T) {
	inner := validInnerV6(t)
	frame := buildDgram(t, 0x42, DirFacadeToBackend, inner, nil, nil)
	_, err := DecodeDGramFrame(frame)
	var fe *FrameErr
	if !errors.As(err, &fe) || fe.Kind != ErrFrameBadVersion {
		t.Fatalf("want ErrFrameBadVersion, got %v", err)
	}
}

func TestDecodeDGramFrame_ReservedFlagsSet(t *testing.T) {
	inner := validInnerV6(t)
	frame := buildDgram(t, proxyproto.SpecVersionStage1, DirFacadeToBackend, inner, nil, nil)
	frame[1] = 0x80 // bit 7 set
	_, err := DecodeDGramFrame(frame)
	var fe *FrameErr
	if !errors.As(err, &fe) || fe.Kind != ErrFrameReservedFlags {
		t.Fatalf("want ErrFrameReservedFlags, got %v", err)
	}
}

func TestDecodeDGramFrame_TooShort(t *testing.T) {
	_, err := DecodeDGramFrame([]byte{0x01, 0x00})
	var fe *FrameErr
	if !errors.As(err, &fe) || fe.Kind != ErrFrameTooShort {
		t.Fatalf("want ErrFrameTooShort, got %v", err)
	}
}

func TestDecodeDGramFrame_OversizeDeclared(t *testing.T) {
	frame := make([]byte, DGramHeaderLen)
	frame[0] = proxyproto.SpecVersionStage1
	// Declare tlvLen+pldLen = 64KB total + something.
	binary.BigEndian.PutUint16(frame[2:4], 0xFFFF)
	binary.BigEndian.PutUint16(frame[4:6], 0xFFFF)
	_, err := DecodeDGramFrame(frame)
	var fe *FrameErr
	if !errors.As(err, &fe) || fe.Kind != ErrFrameOversize {
		t.Fatalf("want ErrFrameOversize, got %v", err)
	}
}

func TestDecodeDGramFrame_Truncated(t *testing.T) {
	frame := make([]byte, DGramHeaderLen)
	frame[0] = proxyproto.SpecVersionStage1
	binary.BigEndian.PutUint16(frame[2:4], 100) // declared 100 bytes after header
	binary.BigEndian.PutUint16(frame[4:6], 0)
	// But provide nothing further → truncated.
	_, err := DecodeDGramFrame(frame)
	var fe *FrameErr
	if !errors.As(err, &fe) || fe.Kind != ErrFrameTruncated {
		t.Fatalf("want ErrFrameTruncated, got %v", err)
	}
}

func TestDecodeDGramFrame_InnerPP2Malformed(t *testing.T) {
	// Build a frame whose TLV block is junk (won't parse as PP2-inner).
	frame := make([]byte, DGramHeaderLen+8)
	frame[0] = proxyproto.SpecVersionStage1
	binary.BigEndian.PutUint16(frame[2:4], 8)
	binary.BigEndian.PutUint16(frame[4:6], 0)
	for i := DGramHeaderLen; i < len(frame); i++ {
		frame[i] = 0xAA
	}
	_, err := DecodeDGramFrame(frame)
	var fe *FrameErr
	if !errors.As(err, &fe) || fe.Kind != ErrFrameInnerPP2 {
		t.Fatalf("want ErrFrameInnerPP2, got %v", err)
	}
}
