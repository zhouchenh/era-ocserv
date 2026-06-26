package cstp

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestEncodeFrameDataRoundTrip(t *testing.T) {
	payload := []byte("hello world")
	buf := make([]byte, frameHeaderLen+len(payload))
	n, err := encodeFrame(buf, pktData, payload)
	if err != nil {
		t.Fatalf("encodeFrame: %v", err)
	}
	if n != frameHeaderLen+len(payload) {
		t.Fatalf("encodeFrame n=%d, want %d", n, frameHeaderLen+len(payload))
	}

	// Wire shape: 'S','T','F',0x01, length BE16, type, 0x00.
	if buf[0] != 'S' || buf[1] != 'T' || buf[2] != 'F' || buf[3] != 0x01 {
		t.Fatalf("magic mismatch: %v", buf[:4])
	}
	if buf[4] != 0x00 || buf[5] != byte(len(payload)) {
		t.Fatalf("length encode wrong: %v", buf[4:6])
	}
	if buf[6] != pktData {
		t.Fatalf("type wrong: %d", buf[6])
	}
	if buf[7] != 0x00 {
		t.Fatalf("trailing byte wrong: %d", buf[7])
	}
	if !bytes.Equal(buf[frameHeaderLen:], payload) {
		t.Fatalf("payload mismatch: got %q want %q", buf[frameHeaderLen:], payload)
	}

	// Round-trip via readFrame.
	typ, n, err := readFrame(bytes.NewReader(buf), make([]byte, frameHeaderLen), make([]byte, 4096))
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if typ != pktData {
		t.Fatalf("readFrame typ=%d want %d", typ, pktData)
	}
	if n != len(payload) {
		t.Fatalf("readFrame n=%d want %d", n, len(payload))
	}
}

func TestReadFrameAllTypes(t *testing.T) {
	cases := []struct {
		name    string
		typ     byte
		payload []byte
	}{
		{"data", pktData, []byte{0x45, 0x00, 0x00, 0x14}},
		{"dpd-out", pktDPDOut, []byte("PING-token-1")},
		{"dpd-resp", pktDPDResp, []byte("PING-token-1")},
		{"keepalive", pktKeepalive, nil},
		{"disconnect", pktDisconnect, []byte{0x01}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, frameHeaderLen+len(tc.payload))
			if _, err := encodeFrame(buf, tc.typ, tc.payload); err != nil {
				t.Fatalf("encodeFrame: %v", err)
			}
			typ, n, err := readFrame(bytes.NewReader(buf), make([]byte, frameHeaderLen), make([]byte, 4096))
			if err != nil {
				t.Fatalf("readFrame: %v", err)
			}
			if typ != tc.typ {
				t.Fatalf("typ=%d want %d", typ, tc.typ)
			}
			if n != len(tc.payload) {
				t.Fatalf("n=%d want %d", n, len(tc.payload))
			}
		})
	}
}

func TestReadFrameBadMagic(t *testing.T) {
	bad := []byte{'X', 'T', 'F', 0x01, 0, 0, pktData, 0}
	_, _, err := readFrame(bytes.NewReader(bad), make([]byte, frameHeaderLen), make([]byte, 16))
	if !errors.Is(err, errBadMagic) {
		t.Fatalf("expected errBadMagic, got %v", err)
	}
}

func TestReadFrameShortBuffer(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 100)
	buf := make([]byte, frameHeaderLen+len(payload))
	if _, err := encodeFrame(buf, pktData, payload); err != nil {
		t.Fatalf("encodeFrame: %v", err)
	}
	_, _, err := readFrame(bytes.NewReader(buf), make([]byte, frameHeaderLen), make([]byte, 10))
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("expected io.ErrShortBuffer, got %v", err)
	}
}

func TestReadFrameFragmentedAcrossReads(t *testing.T) {
	payload := []byte("abcdefghij")
	buf := make([]byte, frameHeaderLen+len(payload))
	if _, err := encodeFrame(buf, pktData, payload); err != nil {
		t.Fatalf("encodeFrame: %v", err)
	}

	// Trickle the bytes in two reads to exercise io.ReadFull behavior.
	r := io.MultiReader(bytes.NewReader(buf[:6]), bytes.NewReader(buf[6:]))
	typ, n, err := readFrame(r, make([]byte, frameHeaderLen), make([]byte, 1024))
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if typ != pktData {
		t.Fatalf("typ=%d", typ)
	}
	if n != len(payload) {
		t.Fatalf("n=%d", n)
	}
}

func TestEncodeFrameOversize(t *testing.T) {
	payload := make([]byte, maxFramePayload+1)
	buf := make([]byte, frameHeaderLen+len(payload))
	_, err := encodeFrame(buf, pktData, payload)
	if !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("expected errFrameTooLarge, got %v", err)
	}
}
