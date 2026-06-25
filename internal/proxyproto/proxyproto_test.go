package proxyproto

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestWriteReadV2RoundTripTCP4(t *testing.T) {
	src := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51000}
	dst := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 443}
	var buf bytes.Buffer
	if err := WriteHeaderV2(&buf, src, dst); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadHeaderV2(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got == nil || got.String() != src.String() {
		t.Fatalf("src = %v, want %v", got, src)
	}
}

func TestWriteReadV2RoundTripTCP6(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 51000}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}
	var buf bytes.Buffer
	if err := WriteHeaderV2(&buf, src, dst); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadHeaderV2(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got == nil || got.String() != src.String() {
		t.Fatalf("src = %v, want %v", got, src)
	}
}

// TestReadHeaderLeavesPayload proves ReadHeaderV2 consumes exactly the header and
// leaves the subsequent stream (e.g. a TLS ClientHello) intact.
func TestReadHeaderLeavesPayload(t *testing.T) {
	src := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51000}
	dst := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 443}
	var buf bytes.Buffer
	if err := WriteHeaderV2(&buf, src, dst); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf.WriteString("CLIENTHELLO-BYTES")
	if _, err := ReadHeaderV2(&buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	rest, _ := io.ReadAll(&buf)
	if string(rest) != "CLIENTHELLO-BYTES" {
		t.Fatalf("remaining payload = %q", rest)
	}
}

// TestListenerRemoteAddrAndPayload proves the wrapping Listener surfaces the
// announced client as RemoteAddr and still delivers the post-header payload.
func TestListenerRemoteAddrAndPayload(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	pl := NewListener(ln)

	src := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51000}
	dst := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 443}
	go func() {
		c, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			return
		}
		defer c.Close()
		_ = WriteHeaderV2(c, src, dst)
		_, _ = c.Write([]byte("HELLO"))
	}()

	c, err := pl.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer c.Close()
	if c.RemoteAddr().String() != src.String() {
		t.Fatalf("RemoteAddr = %v, want %v", c.RemoteAddr(), src)
	}
	got, _ := io.ReadAll(c)
	if string(got) != "HELLO" {
		t.Fatalf("payload = %q, want HELLO", got)
	}
}

// TestListenerDropsHeaderlessConn proves a connection that does not begin with a
// valid PROXY header is rejected (closed + skipped), not surfaced.
func TestListenerDropsHeaderlessConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	pl := NewListener(ln)

	src := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51000}
	dst := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 443}
	go func() {
		// First conn: garbage (no header) -> dropped.
		if c, derr := net.Dial("tcp", ln.Addr().String()); derr == nil {
			_, _ = c.Write([]byte("not-a-proxy-header-just-junk-bytes\n"))
			_ = c.Close()
		}
		// Second conn: valid -> surfaced.
		if c, derr := net.Dial("tcp", ln.Addr().String()); derr == nil {
			defer c.Close()
			_ = WriteHeaderV2(c, src, dst)
			_, _ = c.Write([]byte("OK"))
		}
	}()

	c, err := pl.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer c.Close()
	if c.RemoteAddr().String() != src.String() {
		t.Fatalf("expected the valid second conn, got RemoteAddr %v", c.RemoteAddr())
	}
}
