package proxyproto

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// emitTLV is a tiny helper to build a TLV record byte sequence.
func emitTLV(t TLVType, val []byte) []byte {
	out := make([]byte, 0, 3+len(val))
	out = append(out, byte(t))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(val)))
	out = append(out, lenBuf[:]...)
	out = append(out, val...)
	return out
}

func TestDecodeTLVs_Empty(t *testing.T) {
	tlvs, n, err := DecodeTLVs(nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 0 || len(tlvs) != 0 {
		t.Fatalf("expected empty, got n=%d tlvs=%v", n, tlvs)
	}
}

func TestDecodeTLVs_Single(t *testing.T) {
	val := []byte{0x01}
	block := emitTLV(EraTLVSpecVersion, val)
	tlvs, n, err := DecodeTLVs(block)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != len(block) {
		t.Fatalf("n=%d want %d", n, len(block))
	}
	if len(tlvs) != 1 {
		t.Fatalf("got %d tlvs want 1", len(tlvs))
	}
	if tlvs[0].Type != EraTLVSpecVersion || string(tlvs[0].Value) != string(val) {
		t.Fatalf("got %+v", tlvs[0])
	}
}

func TestDecodeTLVs_Multiple_InAscendingOrder(t *testing.T) {
	val1 := []byte{0x01}
	val2 := []byte("01234567890123456789012345")
	block := append(emitTLV(EraTLVTraceID, val2), emitTLV(EraTLVSpecVersion, val1)...)
	tlvs, _, err := DecodeTLVs(block)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(tlvs) != 2 {
		t.Fatalf("got %d tlvs", len(tlvs))
	}
	// We preserve source order — the reader tolerates any order per §3.2.
	if tlvs[0].Type != EraTLVTraceID || tlvs[1].Type != EraTLVSpecVersion {
		t.Fatalf("order wrong: %v", []TLVType{tlvs[0].Type, tlvs[1].Type})
	}
}

func TestDecodeTLVs_Duplicate(t *testing.T) {
	block := append(emitTLV(EraTLVSpecVersion, []byte{0x01}), emitTLV(EraTLVSpecVersion, []byte{0x01})...)
	_, _, err := DecodeTLVs(block)
	if !errors.Is(err, ErrTLVDuplicate) {
		t.Fatalf("expected ErrTLVDuplicate, got %v", err)
	}
}

func TestDecodeTLVs_Truncated(t *testing.T) {
	// Type + len header says 4 bytes but only 2 follow.
	block := []byte{byte(EraTLVTraceID), 0x00, 0x04, 'a', 'b'}
	_, _, err := DecodeTLVs(block)
	if !errors.Is(err, ErrTLVTruncated) {
		t.Fatalf("expected ErrTLVTruncated, got %v", err)
	}
}

func TestDecodeTLVs_ShortHeader(t *testing.T) {
	// Only 2 bytes — not enough for the 3-byte type+len header.
	_, _, err := DecodeTLVs([]byte{0x01, 0x02})
	if !errors.Is(err, ErrTLVTruncated) {
		t.Fatalf("expected ErrTLVTruncated, got %v", err)
	}
}

func TestDecodeTLVs_ReservedRange_Rejected(t *testing.T) {
	// Reserved range 0x80-0xDF must be rejected.
	block := emitTLV(TLVType(0x90), []byte("nope"))
	_, _, err := DecodeTLVs(block)
	if !errors.Is(err, ErrTLVReservedRange) {
		t.Fatalf("expected ErrTLVReservedRange, got %v", err)
	}
	// Reserved range 0xF0-0xFF must be rejected.
	block = emitTLV(TLVType(0xF5), []byte("nope"))
	_, _, err = DecodeTLVs(block)
	if !errors.Is(err, ErrTLVReservedRange) {
		t.Fatalf("expected ErrTLVReservedRange, got %v", err)
	}
}

func TestValidateTLV_SpecVersion(t *testing.T) {
	if err := ValidateTLV(TLV{Type: EraTLVSpecVersion, Value: []byte{0x01}}); err != nil {
		t.Errorf("v=0x01: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVSpecVersion, Value: []byte{}}); err == nil {
		t.Errorf("expected err for empty value")
	}
	if err := ValidateTLV(TLV{Type: EraTLVSpecVersion, Value: []byte{0x01, 0x02}}); err == nil {
		t.Errorf("expected err for 2-byte value")
	}
}

func TestValidateTLV_TraceID(t *testing.T) {
	// Crockford Base32, 26 chars.
	if err := ValidateTLV(TLV{Type: EraTLVTraceID, Value: []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")}); err != nil {
		t.Errorf("valid ULID: %v", err)
	}
	// Wrong length.
	if err := ValidateTLV(TLV{Type: EraTLVTraceID, Value: []byte("short")}); err == nil {
		t.Errorf("expected err for short")
	}
	// Excluded letter I.
	bad := strings.Replace("01ARZ3NDEKTSV4RRFFQ69G5FAV", "A", "I", 1)
	if err := ValidateTLV(TLV{Type: EraTLVTraceID, Value: []byte(bad)}); err == nil {
		t.Errorf("expected err for I (not Crockford)")
	}
	// Lowercase not accepted.
	if err := ValidateTLV(TLV{Type: EraTLVTraceID, Value: []byte("01arz3ndektsv4rrffq69g5fav")}); err == nil {
		t.Errorf("expected err for lowercase ULID")
	}
}

func TestValidateTLV_DeviceID(t *testing.T) {
	good := []byte("123e4567-e89b-12d3-a456-426614174000")
	if err := ValidateTLV(TLV{Type: EraTLVDeviceID, Value: good}); err != nil {
		t.Errorf("valid UUID: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVDeviceID, Value: []byte("dev-42")}); err != nil {
		t.Errorf("valid legacy device id: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVDeviceID, Value: []byte("dev_aaaaaaaaaaaaaaaaaaaaaaaaaa")}); err != nil {
		t.Errorf("valid tpm-style device id: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVDeviceID, Value: []byte("123E4567-E89B-12D3-A456-426614174000")}); err == nil {
		t.Errorf("expected err for uppercase UUID")
	}
	if err := ValidateTLV(TLV{Type: EraTLVDeviceID, Value: []byte("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")}); err == nil {
		t.Errorf("expected err for non-hex chars")
	}
	if err := ValidateTLV(TLV{Type: EraTLVDeviceID, Value: []byte("123e4567e89b12d3a456426614174000")}); err == nil {
		t.Errorf("expected err for no-hyphen form")
	}
}

func TestValidateTLV_UserID(t *testing.T) {
	if err := ValidateTLV(TLV{Type: EraTLVUserID, Value: []byte("user@example.com")}); err != nil {
		t.Errorf("valid user: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVUserID, Value: []byte("with space")}); err == nil {
		t.Errorf("expected err for whitespace")
	}
	if err := ValidateTLV(TLV{Type: EraTLVUserID, Value: []byte("")}); err == nil {
		t.Errorf("expected err for empty")
	}
}

func TestValidateTLV_OrigSNI(t *testing.T) {
	if err := ValidateTLV(TLV{Type: EraTLVOrigSNI, Value: []byte("eracloud.app")}); err != nil {
		t.Errorf("valid: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVOrigSNI, Value: []byte("ERAcloud.app")}); err == nil {
		t.Errorf("expected err for uppercase")
	}
	if err := ValidateTLV(TLV{Type: EraTLVOrigSNI, Value: []byte("xn--example-xyz.app")}); err != nil {
		t.Errorf("IDN A-label should pass: %v", err)
	}
}

func TestValidateTLV_VLESSTarget(t *testing.T) {
	if err := ValidateTLV(TLV{Type: EraTLVVLESSTarget, Value: []byte("upstream.local:443")}); err != nil {
		t.Errorf("dns:port: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVVLESSTarget, Value: []byte("10.0.0.1:8080")}); err != nil {
		t.Errorf("v4:port: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVVLESSTarget, Value: []byte("[2001:db8::1]:8443")}); err != nil {
		t.Errorf("v6:port: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVVLESSTarget, Value: []byte("nohost")}); err == nil {
		t.Errorf("expected err for missing port")
	}
	if err := ValidateTLV(TLV{Type: EraTLVVLESSTarget, Value: []byte("host:0")}); err == nil {
		t.Errorf("expected err for port 0")
	}
	if err := ValidateTLV(TLV{Type: EraTLVVLESSTarget, Value: []byte("host:99999")}); err == nil {
		t.Errorf("expected err for port > 65535")
	}
}

func TestValidateTLV_SourceHintV6(t *testing.T) {
	// 2001:db8::1 — globally unique in 2000::/3
	good := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	if err := ValidateTLV(TLV{Type: EraTLVSourceHintV6, Value: good}); err != nil {
		t.Errorf("global v6: %v", err)
	}
	// fc00::/7 — ULA
	ula := make([]byte, 16)
	ula[0] = 0xFC
	if err := ValidateTLV(TLV{Type: EraTLVSourceHintV6, Value: ula}); err != nil {
		t.Errorf("ULA v6: %v", err)
	}
	// fe80::/10 — link-local, must reject
	ll := make([]byte, 16)
	ll[0], ll[1] = 0xFE, 0x80
	if err := ValidateTLV(TLV{Type: EraTLVSourceHintV6, Value: ll}); err == nil {
		t.Errorf("expected err for link-local")
	}
	// ::1 — loopback, must reject
	lo := make([]byte, 16)
	lo[15] = 0x01
	if err := ValidateTLV(TLV{Type: EraTLVSourceHintV6, Value: lo}); err == nil {
		t.Errorf("expected err for loopback")
	}
	// 100::/64 — neither 2000::/3 nor fc00::/7
	other := make([]byte, 16)
	other[0] = 0x01
	if err := ValidateTLV(TLV{Type: EraTLVSourceHintV6, Value: other}); err == nil {
		t.Errorf("expected err for 100::/64")
	}
	// Wrong length
	if err := ValidateTLV(TLV{Type: EraTLVSourceHintV6, Value: make([]byte, 8)}); err == nil {
		t.Errorf("expected err for short")
	}
}

func TestValidateTLV_VLESSFlow(t *testing.T) {
	if err := ValidateTLV(TLV{Type: EraTLVVLESSFlow, Value: []byte("xtls-rprx-vision-seed")}); err != nil {
		t.Errorf("vision-seed: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVVLESSFlow, Value: []byte("")}); err != nil {
		t.Errorf("empty: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVVLESSFlow, Value: []byte("xtls-rprx-something")}); err == nil {
		t.Errorf("expected err for unknown flow")
	}
}

func TestValidateTLV_QUICConnID(t *testing.T) {
	for _, l := range []int{7, 21} {
		if err := ValidateTLV(TLV{Type: EraTLVQUICConnID, Value: make([]byte, l)}); err == nil {
			t.Errorf("len %d: expected err", l)
		}
	}
	for _, l := range []int{8, 14, 20} {
		if err := ValidateTLV(TLV{Type: EraTLVQUICConnID, Value: make([]byte, l)}); err != nil {
			t.Errorf("len %d: %v", l, err)
		}
	}
}

func TestValidateTLV_DTLSPSK(t *testing.T) {
	if err := ValidateTLV(TLV{Type: EraTLVDTLSPSK, Value: make([]byte, 32)}); err != nil {
		t.Errorf("32B: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVDTLSPSK, Value: make([]byte, 16)}); err == nil {
		t.Errorf("expected err for 16B")
	}
}

func TestValidateTLV_Token(t *testing.T) {
	if err := ValidateTLV(TLV{Type: EraTLVToken, Value: make([]byte, 12)}); err != nil {
		t.Errorf("12B: %v", err)
	}
	if err := ValidateTLV(TLV{Type: EraTLVToken, Value: make([]byte, 16)}); err == nil {
		t.Errorf("expected err for 16B")
	}
}
