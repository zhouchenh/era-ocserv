package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// buildHeader emits a complete PROXY-v2 header byte sequence for tests.
// fam in {0x11, 0x21, 0x12, 0x22}. tlvs are appended after the addr block.
func buildHeader(fam byte, src, dst netip.AddrPort, tlvs []byte) []byte {
	out := make([]byte, 0, 16+36+len(tlvs))
	out = append(out, v2Signature[:]...)
	out = append(out, verCmdProxy)
	out = append(out, fam)
	addrLen := 12
	if fam == famTCP6 || fam == famUDP6 {
		addrLen = 36
	}
	out = binary.BigEndian.AppendUint16(out, uint16(addrLen+len(tlvs)))
	switch fam {
	case famTCP4, famUDP4:
		s4 := src.Addr().As4()
		d4 := dst.Addr().As4()
		out = append(out, s4[:]...)
		out = append(out, d4[:]...)
	case famTCP6, famUDP6:
		s16 := src.Addr().As16()
		d16 := dst.Addr().As16()
		out = append(out, s16[:]...)
		out = append(out, d16[:]...)
	}
	out = binary.BigEndian.AppendUint16(out, src.Port())
	out = binary.BigEndian.AppendUint16(out, dst.Port())
	out = append(out, tlvs...)
	return out
}

func TestReadHeaderV2WithTLVs_TCP4_NoTLVs(t *testing.T) {
	src := netip.MustParseAddrPort("203.0.113.7:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	buf := buildHeader(famTCP4, src, dst, nil)
	hdr, err := ReadHeaderV2WithTLVs(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hdr.Src != src || hdr.Dst != dst {
		t.Fatalf("got src=%v dst=%v want %v / %v", hdr.Src, hdr.Dst, src, dst)
	}
	if len(hdr.TLVs) != 0 {
		t.Fatalf("expected empty TLVs, got %v", hdr.TLVs)
	}
	if hdr.IsIPv6() {
		t.Fatalf("expected v4")
	}
	if hdr.Transport() != "tcp" {
		t.Fatalf("transport = %q", hdr.Transport())
	}
}

func TestReadHeaderV2WithTLVs_TCP6_WithTLVs(t *testing.T) {
	src := netip.MustParseAddrPort("[2001:db8::7]:51000")
	dst := netip.MustParseAddrPort("[2001:db8::1]:443")
	traceID := []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	deviceID := []byte("123e4567-e89b-12d3-a456-426614174000")
	specVer := []byte{SpecVersionStage1}
	tlvBlock := append(emitTLV(EraTLVDeviceID, deviceID), emitTLV(EraTLVTraceID, traceID)...)
	tlvBlock = append(tlvBlock, emitTLV(EraTLVSpecVersion, specVer)...)
	buf := buildHeader(famTCP6, src, dst, tlvBlock)
	hdr, err := ReadHeaderV2WithTLVs(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hdr.Src != src || hdr.Dst != dst {
		t.Fatalf("got src=%v dst=%v want %v / %v", hdr.Src, hdr.Dst, src, dst)
	}
	if len(hdr.TLVs) != 3 {
		t.Fatalf("expected 3 TLVs, got %d", len(hdr.TLVs))
	}
	if !bytes.Equal(hdr.Lookup(EraTLVDeviceID), deviceID) {
		t.Fatalf("device_id mismatch")
	}
	if !bytes.Equal(hdr.Lookup(EraTLVTraceID), traceID) {
		t.Fatalf("trace_id mismatch")
	}
}

func TestReadHeaderV2WithTLVs_InvalidSignature(t *testing.T) {
	buf := make([]byte, 16)
	// Wrong magic.
	for i := range buf[:12] {
		buf[i] = 0xFF
	}
	_, err := ReadHeaderV2WithTLVs(bytes.NewReader(buf))
	var herr *HeaderErr
	if !errors.As(err, &herr) || herr.Kind != ErrSignatureInvalid {
		t.Fatalf("want ErrSignatureInvalid, got %v", err)
	}
}

func TestReadHeaderV2WithTLVs_LocalRejected(t *testing.T) {
	src := netip.MustParseAddrPort("203.0.113.7:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	buf := buildHeader(famTCP4, src, dst, nil)
	buf[12] = verCmdLocal // 0x20 LOCAL
	_, err := ReadHeaderV2WithTLVs(bytes.NewReader(buf))
	var herr *HeaderErr
	if !errors.As(err, &herr) || herr.Kind != ErrUnsupportedVersionCmd {
		t.Fatalf("want ErrUnsupportedVersionCmd, got %v", err)
	}
}

func TestReadHeaderV2WithTLVs_UnsupportedFamily(t *testing.T) {
	src := netip.MustParseAddrPort("203.0.113.7:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	buf := buildHeader(famTCP4, src, dst, nil)
	buf[13] = 0x99 // arbitrary not in {0x11,0x21,0x12,0x22}
	_, err := ReadHeaderV2WithTLVs(bytes.NewReader(buf))
	var herr *HeaderErr
	if !errors.As(err, &herr) || herr.Kind != ErrUnsupportedFamily {
		t.Fatalf("want ErrUnsupportedFamily, got %v", err)
	}
}

func TestReadHeaderV2WithTLVs_AddrBlockShort(t *testing.T) {
	src := netip.MustParseAddrPort("203.0.113.7:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	buf := buildHeader(famTCP4, src, dst, nil)
	// Patch addr_block_len to 8 (< 12 required for v4).
	binary.BigEndian.PutUint16(buf[14:16], 8)
	// Trim to match declared length so io.ReadFull doesn't EOF first.
	buf = buf[:16+8]
	_, err := ReadHeaderV2WithTLVs(bytes.NewReader(buf))
	var herr *HeaderErr
	if !errors.As(err, &herr) || herr.Kind != ErrAddressBlockShort {
		t.Fatalf("want ErrAddressBlockShort, got %v", err)
	}
}

func TestReadHeaderV2WithTLVs_TLVDuplicate_Rejected(t *testing.T) {
	src := netip.MustParseAddrPort("203.0.113.7:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	dup := append(emitTLV(EraTLVSpecVersion, []byte{0x01}), emitTLV(EraTLVSpecVersion, []byte{0x01})...)
	buf := buildHeader(famTCP4, src, dst, dup)
	_, err := ReadHeaderV2WithTLVs(bytes.NewReader(buf))
	var herr *HeaderErr
	if !errors.As(err, &herr) || herr.Kind != ErrTLVMalformed {
		t.Fatalf("want ErrTLVMalformed, got %v", err)
	}
	if !errors.Is(err, ErrTLVDuplicate) {
		t.Fatalf("expected ErrTLVDuplicate wrapped, got %v", err)
	}
}

func TestReadHeaderV2WithTLVs_IncompleteHeader(t *testing.T) {
	// 12 bytes — short of the 16-byte fixed prefix.
	buf := make([]byte, 12)
	copy(buf, v2Signature[:])
	_, err := ReadHeaderV2WithTLVs(bytes.NewReader(buf))
	var herr *HeaderErr
	if !errors.As(err, &herr) || herr.Kind != ErrIncompleteHeader {
		t.Fatalf("want ErrIncompleteHeader, got %v", err)
	}
}

func TestEncode_Decode_RoundTrip(t *testing.T) {
	src := netip.MustParseAddrPort("203.0.113.7:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	original := &HeaderV2{
		Family: famTCP4,
		Src:    src,
		Dst:    dst,
		TLVs: []TLV{
			{Type: EraTLVDeviceID, Value: []byte("123e4567-e89b-12d3-a456-426614174000")},
			{Type: EraTLVSpecVersion, Value: []byte{SpecVersionStage1}},
		},
	}
	wire, err := original.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	round, err := ReadHeaderV2WithTLVs(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if round.Src != original.Src || round.Dst != original.Dst {
		t.Fatalf("addrs mismatch")
	}
	if len(round.TLVs) != 2 {
		t.Fatalf("got %d TLVs", len(round.TLVs))
	}
}
