package cstp

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestWriteConnectResponseFlushesRemainingHeaders(t *testing.T) {
	var buf bytes.Buffer
	rw := bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(&buf))
	h := http.Header{}
	h.Set("X-CSTP-Version", "1")
	h.Set("X-DTLS-Address", "eracloud.app")
	h.Set("X-DTLS-Port", "443")
	h.Set("X-DTLS-CipherSuite", "PSK-NEGOTIATE")
	if err := writeConnectResponse(rw, h); err != nil {
		t.Fatalf("writeConnectResponse: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"X-DTLS-Address: eracloud.app\r\n", "X-DTLS-Port: 443\r\n", "X-DTLS-CipherSuite: PSK-NEGOTIATE\r\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("response missing %q in %q", want, got)
		}
	}
}
