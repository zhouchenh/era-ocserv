package udshandoff

import (
	"net/netip"
	"testing"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
)

// FuzzDecodeDGramFrame explores the SOCK_DGRAM frame decoder.
func FuzzDecodeDGramFrame(f *testing.F) {
	src := netip.MustParseAddrPort("[2001:db8::7]:51000")
	dst := netip.MustParseAddrPort("[2001:db8::1]:443")
	inner := &proxyproto.HeaderV2{Family: 0x22, Src: src, Dst: dst}
	era := []proxyproto.TLV{
		{Type: proxyproto.EraTLVSpecVersion, Value: []byte{proxyproto.SpecVersionStage1}},
		{Type: proxyproto.EraTLVTraceID, Value: []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")},
	}
	canonical := buildDgramHelper(inner, era, []byte("hello"))
	f.Add(canonical)
	f.Add(canonical[:5])
	f.Add(canonical[:DGramHeaderLen+8])
	// Bytes with bad version.
	bad := append([]byte(nil), canonical...)
	bad[0] = 0x42
	f.Add(bad)
	// Bytes with reserved flag set.
	bad2 := append([]byte(nil), canonical...)
	bad2[1] = 0x80
	f.Add(bad2)
	// Bytes claiming larger payload than buffer.
	bad3 := append([]byte(nil), canonical...)
	bad3[5] = 0xFF
	f.Add(bad3)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeDGramFrame(data)
	})
}

// buildDgramHelper is a non-test-helper version of buildDgram for use inside
// f.Add(...) seeds (which can't take a *testing.T).
func buildDgramHelper(inner *proxyproto.HeaderV2, era []proxyproto.TLV, payload []byte) []byte {
	innerBytes, _ := inner.Encode()
	eraBytes, _ := encodeTLVs(era)
	tlvBlock := append(innerBytes, eraBytes...)
	out := make([]byte, DGramHeaderLen+len(tlvBlock)+len(payload))
	out[0] = proxyproto.SpecVersionStage1
	out[1] = byte(DirFacadeToBackend) & 0x01
	out[2] = byte(len(tlvBlock) >> 8)
	out[3] = byte(len(tlvBlock))
	out[4] = byte(len(payload) >> 8)
	out[5] = byte(len(payload))
	copy(out[DGramHeaderLen:], tlvBlock)
	copy(out[DGramHeaderLen+len(tlvBlock):], payload)
	return out
}
