package dtlsuds

// AnyConnect DTLS data-plane frame format (verified against openconnect
// `dtls.c` and documented in `tpm/docs/architecture/era-ocserv-protocol.md`
// §2.3):
//
//	+-------+--------------+
//	| type  | payload      |
//	+-------+--------------+
//
// A single byte type code, immediately followed by the payload bytes
// (no magic, no length, no trailing byte — the DTLS record carries length
// and integrity). era-facade's DTLS terminator decrypts the application_data
// record and forwards the plaintext bytes as the SOCK_DGRAM payload; this
// file is era-ocserv's parser + emitter for that single-byte framing.
//
// The type codes are the same enum CSTP uses (see `internal/cstp/frame.go`)
// so AnyConnect clients can interleave DPD / keepalive on whichever channel
// happens to be silent. Stage 1 era-facade is plumbing-only; the AnyConnect
// liveness mechanics live here.
const (
	// pktData (0x00 / AC_PKT_DATA): payload is a raw inner IP packet.
	pktData byte = 0
	// pktDPDOut (0x03 / AC_PKT_DPD_OUT): liveness probe; receiver MUST
	// echo as pktDPDResp with the same payload.
	pktDPDOut byte = 3
	// pktDPDResp (0x04 / AC_PKT_DPD_RESP): liveness response.
	pktDPDResp byte = 4
	// pktDisconnect (0x05 / AC_PKT_DISCONN): peer wants to tear down.
	pktDisconnect byte = 5
	// pktKeepalive (0x07 / AC_PKT_KEEPALIVE): zero-payload silence-breaker.
	pktKeepalive byte = 7
)

// parseDTLSPlaintext splits the post-DTLS-decryption bytes into the
// 1-byte AnyConnect type code and the remaining payload.
//
// A zero-length input returns (0, nil, false) — the caller should treat
// it as a no-op (degenerate datagram).
func parseDTLSPlaintext(b []byte) (typ byte, payload []byte, ok bool) {
	if len(b) == 0 {
		return 0, nil, false
	}
	return b[0], b[1:], true
}

// encodeDTLSPlaintext prepends the 1-byte AnyConnect type code to payload
// so the resulting slice is ready to be written back to the facade as
// the §5.1 datagram payload.
//
// The returned slice is freshly allocated so the caller MAY hold the
// reference past their own buffer's lifetime; in the hot path the caller
// should pre-allocate with a one-byte headroom and avoid this helper.
func encodeDTLSPlaintext(typ byte, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = typ
	copy(out[1:], payload)
	return out
}
