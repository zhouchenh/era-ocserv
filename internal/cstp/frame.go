package cstp

import (
	"encoding/binary"
	"errors"
	"io"
)

// Packet-type codes carried in byte 6 of the CSTP binary frame header.
// Values match openconnect-internal.h. See protocol doc §1.5.
const (
	pktData       byte = 0
	pktDPDOut     byte = 3
	pktDPDResp    byte = 4
	pktDisconnect byte = 5
	pktKeepalive  byte = 7
	pktCompressed byte = 8
	pktTermServer byte = 9
)

// frameHeader is the 8-byte CSTP binary frame header.
//
//	Bytes 0..3: magic 'S','T','F',0x01
//	Bytes 4..5: big-endian uint16 payload length (header NOT counted)
//	Byte  6  : packet type
//	Byte  7  : trailing zero (required by the wire format)
const frameHeaderLen = 8

// maxFramePayload caps the payload portion of a single CSTP frame.
// 64 KiB is the theoretical maximum representable in the uint16
// length field; in practice client MTUs are well below 1500 so the
// limit is mostly defensive.
const maxFramePayload = 0xFFFF

// frame magic bytes 0..3.
var frameMagic = [4]byte{'S', 'T', 'F', 0x01}

// errBadMagic is returned when the first four bytes of a frame do not
// match the constant magic. The session must be torn down per spec
// §1.5.
var errBadMagic = errors.New("cstp: bad frame magic")

// errFrameTooLarge is returned when a frame announces a payload
// larger than maxFramePayload. This protects the reader against
// runaway allocations from malformed wire data.
var errFrameTooLarge = errors.New("cstp: frame payload too large")

// encodeFrame writes a single CSTP frame into dst[:frameHeaderLen+len(payload)].
// dst must have room. The caller is responsible for not nesting calls
// on a shared buffer.
func encodeFrame(dst []byte, typ byte, payload []byte) (int, error) {
	if len(payload) > maxFramePayload {
		return 0, errFrameTooLarge
	}
	if len(dst) < frameHeaderLen+len(payload) {
		return 0, io.ErrShortBuffer
	}
	dst[0] = frameMagic[0]
	dst[1] = frameMagic[1]
	dst[2] = frameMagic[2]
	dst[3] = frameMagic[3]
	binary.BigEndian.PutUint16(dst[4:6], uint16(len(payload)))
	dst[6] = typ
	dst[7] = 0
	copy(dst[frameHeaderLen:], payload)
	return frameHeaderLen + len(payload), nil
}

// readFrame reads one CSTP frame from r into the supplied scratch
// header and returns the packet type plus payload-bearing slice from
// the buf the caller provides. The returned payload is buf[:n]; if
// buf is too small for the announced payload, io.ErrShortBuffer is
// returned and the partial read is discarded (the connection is in
// an unrecoverable state and must be closed).
func readFrame(r io.Reader, hdr []byte, buf []byte) (typ byte, n int, err error) {
	if len(hdr) < frameHeaderLen {
		return 0, 0, io.ErrShortBuffer
	}
	if _, err = io.ReadFull(r, hdr[:frameHeaderLen]); err != nil {
		return 0, 0, err
	}
	if hdr[0] != frameMagic[0] || hdr[1] != frameMagic[1] ||
		hdr[2] != frameMagic[2] || hdr[3] != frameMagic[3] {
		return 0, 0, errBadMagic
	}
	plen := int(binary.BigEndian.Uint16(hdr[4:6]))
	typ = hdr[6]
	if plen == 0 {
		return typ, 0, nil
	}
	if plen > len(buf) {
		// Draining to keep the stream aligned would still leak data of
		// unknown trust; caller must close.
		return typ, 0, io.ErrShortBuffer
	}
	if _, err = io.ReadFull(r, buf[:plen]); err != nil {
		return 0, 0, err
	}
	return typ, plen, nil
}
