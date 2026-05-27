package proxyproto

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// FuzzDecodeTLVs explores the TLV decoder with arbitrary byte sequences.
// The contract is: any input returns either (parsed-records, nil) or a
// typed error — never a panic, never a hang, never an allocation that
// exceeds the input size by orders of magnitude.
func FuzzDecodeTLVs(f *testing.F) {
	// Seed with a few hand-crafted inputs covering interesting shapes.
	f.Add([]byte{})
	f.Add([]byte{byte(EraTLVSpecVersion), 0x00, 0x01, 0x01})
	f.Add([]byte{byte(EraTLVTraceID), 0x00, 0x1A,
		'0', '1', 'A', 'R', 'Z', '3', 'N', 'D', 'E', 'K', 'T', 'S', 'V', '4', 'R', 'R', 'F', 'F', 'Q', '6', '9', 'G', '5', 'F', 'A', 'V'})
	// Truncated TLV.
	f.Add([]byte{byte(EraTLVTraceID), 0x00, 0xFF, 'a', 'b'})
	// Duplicate TLV.
	f.Add([]byte{
		byte(EraTLVSpecVersion), 0x00, 0x01, 0x01,
		byte(EraTLVSpecVersion), 0x00, 0x01, 0x01,
	})
	// Reserved-range TLV.
	f.Add([]byte{0x90, 0x00, 0x04, 'a', 'b', 'c', 'd'})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic; that's the entire fuzz invariant for a
		// well-behaved parser on adversarial input.
		_, _, _ = DecodeTLVs(data)
	})
}

// FuzzReadHeaderV2WithTLVs feeds arbitrary bytes into the PROXY-v2 reader
// (including bytes that happen to start with the magic signature).
func FuzzReadHeaderV2WithTLVs(f *testing.F) {
	// Seed corpus: build a few canonical headers, then truncations.
	src := netip.MustParseAddrPort("203.0.113.7:51000")
	dst := netip.MustParseAddrPort("198.51.100.9:443")
	hdr := &HeaderV2{
		Family: famTCP4, Src: src, Dst: dst,
		TLVs: []TLV{
			{Type: EraTLVSpecVersion, Value: []byte{SpecVersionStage1}},
			{Type: EraTLVTraceID, Value: []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")},
		},
	}
	wire, _ := hdr.Encode()
	f.Add(wire)
	f.Add(wire[:8])  // truncated
	f.Add(wire[:16]) // truncated mid addr-block
	// Bytes starting with the magic but wrong fam.
	bad := append([]byte(nil), wire...)
	bad[13] = 0x99
	f.Add(bad)
	// Reserved-range TLV embedded.
	rr := &HeaderV2{
		Family: famTCP4, Src: src, Dst: dst,
		TLVs: []TLV{{Type: TLVType(0x90), Value: []byte{1, 2, 3}}},
	}
	rrWire, _ := rr.Encode()
	f.Add(rrWire)
	// Bizarrely large declared len.
	huge := make([]byte, 16)
	copy(huge, v2Signature[:])
	huge[12] = verCmdProxy
	huge[13] = famTCP4
	binary.BigEndian.PutUint16(huge[14:16], 0xFFFF)
	f.Add(huge)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic and must not allocate egregiously past input size.
		// io.ReadFull on a bytes.Reader bounds memory naturally.
		_, _ = ReadHeaderV2WithTLVs(bytes.NewReader(data))
	})
}
