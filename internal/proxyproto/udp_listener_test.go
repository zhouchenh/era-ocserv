package proxyproto

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubPacketConn is an in-memory net.PacketConn that delivers a fixed sequence of
// (datagram, src-addr) pairs to ReadFrom. WriteTo is a no-op recorder. This
// avoids spinning a real UDP socket per test and gives the test full control
// over what "kernel source" a datagram appears to come from.
type stubPacketConn struct {
	mu       sync.Mutex
	queue    []stubDatagram
	cond     *sync.Cond
	closed   bool
	writes   []stubDatagram
	deadline time.Time
}

type stubDatagram struct {
	payload []byte
	from    net.Addr
}

func newStubPacketConn() *stubPacketConn {
	s := &stubPacketConn{}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *stubPacketConn) enqueue(d stubDatagram) {
	s.mu.Lock()
	s.queue = append(s.queue, d)
	s.cond.Signal()
	s.mu.Unlock()
}

func (s *stubPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	s.mu.Lock()
	for len(s.queue) == 0 && !s.closed {
		s.cond.Wait()
	}
	if s.closed && len(s.queue) == 0 {
		s.mu.Unlock()
		return 0, nil, net.ErrClosed
	}
	d := s.queue[0]
	s.queue = s.queue[1:]
	s.mu.Unlock()
	n := copy(p, d.payload)
	return n, d.from, nil
}

func (s *stubPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, stubDatagram{payload: append([]byte(nil), p...), from: addr})
	return len(p), nil
}

func (s *stubPacketConn) Close() error {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
	return nil
}

func (s *stubPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (s *stubPacketConn) SetDeadline(t time.Time) error      { s.deadline = t; return nil }
func (s *stubPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *stubPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// mustWriteV4 returns a v4 PROXY v2 UDP header. Test helper; fails the test on
// any encoding error so the parser is the only thing under test.
func mustWriteV4(t *testing.T, srcIP string, srcPort int, dstIP string, dstPort int) []byte {
	t.Helper()
	hdr, err := WriteHeaderV2UDP(
		&net.UDPAddr{IP: net.ParseIP(srcIP), Port: srcPort},
		&net.UDPAddr{IP: net.ParseIP(dstIP), Port: dstPort},
	)
	if err != nil {
		t.Fatalf("WriteHeaderV2UDP v4: %v", err)
	}
	return hdr
}

func mustWriteV6(t *testing.T, srcIP string, srcPort int, dstIP string, dstPort int) []byte {
	t.Helper()
	hdr, err := WriteHeaderV2UDP(
		&net.UDPAddr{IP: net.ParseIP(srcIP), Port: srcPort},
		&net.UDPAddr{IP: net.ParseIP(dstIP), Port: dstPort},
	)
	if err != nil {
		t.Fatalf("WriteHeaderV2UDP v6: %v", err)
	}
	return hdr
}

// TestUDPListenerParsesV4HeaderFirstDatagram is requirement 1: a leading PROXY
// v2 UDP4 header is parsed, stripped, and the announced src becomes RemoteAddr;
// the remainder of the datagram is delivered as payload.
func TestUDPListenerParsesV4HeaderFirstDatagram(t *testing.T) {
	stub := newStubPacketConn()
	l := NewUDPListener(stub, UDPListenerOptions{})

	hdr := mustWriteV4(t, "203.0.113.7", 54321, "198.51.100.1", 443)
	payload := []byte{0x01, 0x02, 0x03}
	dgram := append(append([]byte{}, hdr...), payload...)
	stub.enqueue(stubDatagram{payload: dgram, from: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 11111}})

	buf := make([]byte, 1500)
	n, addr, err := l.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload = % x, want % x", buf[:n], payload)
	}
	want := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 54321}
	if addr.(*net.UDPAddr).String() != want.String() {
		t.Fatalf("RemoteAddr = %v, want %v", addr, want)
	}
}

// TestUDPListenerCachesFlowAcrossDatagrams is requirement 2: a second datagram
// from the SAME kernel source (no header) returns the CACHED real addr, not the
// kernel source.
func TestUDPListenerCachesFlowAcrossDatagrams(t *testing.T) {
	stub := newStubPacketConn()
	l := NewUDPListener(stub, UDPListenerOptions{})

	hdr := mustWriteV4(t, "203.0.113.7", 54321, "198.51.100.1", 443)
	payload1 := []byte("first")
	dgram1 := append(append([]byte{}, hdr...), payload1...)
	kernelSrc := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 11111}
	stub.enqueue(stubDatagram{payload: dgram1, from: kernelSrc})

	payload2 := []byte("second")
	stub.enqueue(stubDatagram{payload: payload2, from: kernelSrc})

	// First read: header parsed, returns announced src.
	buf := make([]byte, 1500)
	n, addr, err := l.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first ReadFrom: %v", err)
	}
	if string(buf[:n]) != "first" {
		t.Fatalf("first payload = %q, want %q", buf[:n], "first")
	}
	want := "203.0.113.7:54321"
	if addr.String() != want {
		t.Fatalf("first RemoteAddr = %v, want %v", addr, want)
	}

	// Second read from same kernel source: no header to parse, must return cached
	// announced src.
	n, addr, err = l.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second ReadFrom: %v", err)
	}
	if string(buf[:n]) != "second" {
		t.Fatalf("second payload = %q, want %q", buf[:n], "second")
	}
	if addr.String() != want {
		t.Fatalf("second RemoteAddr = %v, want %v (cached)", addr, want)
	}
}

// TestUDPListenerMagicMatchButMalformed is requirement 3: a datagram whose
// leading bytes match the v2 magic but whose length is wrong (truncated addr
// block) is returned as-is with the raw kernel source — no crash, no swallow.
func TestUDPListenerMagicMatchButMalformed(t *testing.T) {
	stub := newStubPacketConn()
	var sawErr atomic.Bool
	l := NewUDPListener(stub, UDPListenerOptions{OnError: func(error) { sawErr.Store(true) }})

	// Magic OK, verCmd PROXY, family UDP4, declares 12-byte addr-pair, but the
	// datagram only carries 5 bytes after the fixed header.
	hdr := append([]byte{}, v2Signature[:]...)
	hdr = append(hdr, verCmdProxy, famUDP4, 0x00, 0x0c)
	dgram := append(hdr, 0x01, 0x02, 0x03, 0x04, 0x05)
	kernelSrc := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22222}
	stub.enqueue(stubDatagram{payload: dgram, from: kernelSrc})

	buf := make([]byte, 1500)
	n, addr, err := l.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], dgram) {
		t.Fatalf("payload mutated; want as-is")
	}
	if addr.String() != kernelSrc.String() {
		t.Fatalf("RemoteAddr = %v, want raw kernel src %v", addr, kernelSrc)
	}
	if !sawErr.Load() {
		t.Fatalf("OnError was not invoked for the malformed header")
	}
}

// TestUDPListenerNonProxyDatagram is requirement 4: a datagram that does NOT
// begin with the v2 magic is returned as-is with the raw kernel source. This is
// the backward-compat path for a client connecting directly (no splicer).
func TestUDPListenerNonProxyDatagram(t *testing.T) {
	stub := newStubPacketConn()
	l := NewUDPListener(stub, UDPListenerOptions{})

	payload := []byte("plain-quic-initial-fake")
	kernelSrc := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 33333}
	stub.enqueue(stubDatagram{payload: payload, from: kernelSrc})

	buf := make([]byte, 1500)
	n, addr, err := l.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload mutated; want as-is")
	}
	if addr.String() != kernelSrc.String() {
		t.Fatalf("RemoteAddr = %v, want raw kernel src %v", addr, kernelSrc)
	}
}

// TestUDPListenerParsesV6Header is requirement 5: a UDP6 header (family 0x22)
// with v6 src/dst addresses parses correctly.
func TestUDPListenerParsesV6Header(t *testing.T) {
	stub := newStubPacketConn()
	l := NewUDPListener(stub, UDPListenerOptions{})

	hdr := mustWriteV6(t, "2001:db8::7", 54321, "2001:db8::1", 443)
	payload := []byte{0x10, 0x20, 0x30}
	dgram := append(append([]byte{}, hdr...), payload...)
	stub.enqueue(stubDatagram{payload: dgram, from: &net.UDPAddr{IP: net.IPv6loopback, Port: 44444}})

	buf := make([]byte, 1500)
	n, addr, err := l.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload = % x, want % x", buf[:n], payload)
	}
	ua := addr.(*net.UDPAddr)
	want := netip.MustParseAddrPort("[2001:db8::7]:54321")
	gotIP, _ := netip.AddrFromSlice(ua.IP)
	if gotIP.Unmap() != want.Addr() || uint16(ua.Port) != want.Port() {
		t.Fatalf("RemoteAddr = %v, want %v", ua, want)
	}
}

// TestUDPListenerHeaderOnlyDatagramSkipped covers the rare init-only datagram
// shape: a PROXY header with NO piggybacked payload. The wrapper should NOT
// surface an empty datagram (which would confuse QUIC); it should skip and
// read the next.
func TestUDPListenerHeaderOnlyDatagramSkipped(t *testing.T) {
	stub := newStubPacketConn()
	l := NewUDPListener(stub, UDPListenerOptions{})

	hdr := mustWriteV4(t, "203.0.113.7", 54321, "198.51.100.1", 443)
	kernelSrc := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 11111}
	// Datagram 1: header only, no payload.
	stub.enqueue(stubDatagram{payload: append([]byte{}, hdr...), from: kernelSrc})
	// Datagram 2: real payload from the same kernel source (now cached).
	stub.enqueue(stubDatagram{payload: []byte("payload"), from: kernelSrc})

	buf := make([]byte, 1500)
	n, addr, err := l.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "payload" {
		t.Fatalf("payload = %q, want %q (header-only datagram should be skipped)", buf[:n], "payload")
	}
	if addr.String() != "203.0.113.7:54321" {
		t.Fatalf("RemoteAddr = %v, want cached announced src", addr)
	}
}

// TestUDPListenerIdleEviction is requirement 6: a cached flow is evicted after
// the idle timeout (verified with a fake clock).
func TestUDPListenerIdleEviction(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	stub := newStubPacketConn()
	l := NewUDPListener(stub, UDPListenerOptions{
		IdleTimeout: 60 * time.Second,
		now:         clock.now,
	})

	// Insert a flow by reading one header datagram.
	hdr := mustWriteV4(t, "203.0.113.7", 54321, "198.51.100.1", 443)
	dgram := append(append([]byte{}, hdr...), []byte("x")...)
	kernelSrc := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 11111}
	stub.enqueue(stubDatagram{payload: dgram, from: kernelSrc})
	buf := make([]byte, 1500)
	if _, _, err := l.ReadFrom(buf); err != nil {
		t.Fatalf("seed ReadFrom: %v", err)
	}
	if got := l.flowCount(); got != 1 {
		t.Fatalf("flowCount after insert = %d, want 1", got)
	}

	// Advance the fake clock past the timeout and trigger eviction.
	clock.advance(61 * time.Second)
	l.evictIdle()
	if got := l.flowCount(); got != 0 {
		t.Fatalf("flowCount after idle eviction = %d, want 0", got)
	}

	// And: a fresh datagram from the same kernel source (no header) should now
	// be returned as-is — the cached mapping is gone.
	stub.enqueue(stubDatagram{payload: []byte("after-evict"), from: kernelSrc})
	n, addr, err := l.ReadFrom(buf)
	if err != nil {
		t.Fatalf("post-evict ReadFrom: %v", err)
	}
	if string(buf[:n]) != "after-evict" {
		t.Fatalf("post-evict payload = %q", buf[:n])
	}
	if addr.String() != kernelSrc.String() {
		t.Fatalf("post-evict RemoteAddr = %v, want raw kernel src %v", addr, kernelSrc)
	}
}

// TestUDPListenerLRUEvictOnOverflow proves MaxFlows is enforced: a 3-slot map
// receiving 4 distinct flows evicts the LRU and admits the newest.
func TestUDPListenerLRUEvictOnOverflow(t *testing.T) {
	stub := newStubPacketConn()
	l := NewUDPListener(stub, UDPListenerOptions{MaxFlows: 3})

	enqueue := func(srcIP string, srcPort int, kernelPort int) {
		hdr := mustWriteV4(t, srcIP, srcPort, "198.51.100.1", 443)
		dgram := append(append([]byte{}, hdr...), []byte("x")...)
		stub.enqueue(stubDatagram{payload: dgram, from: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: kernelPort}})
	}
	enqueue("203.0.113.1", 100, 1001) // flow A (eldest)
	enqueue("203.0.113.2", 200, 1002) // flow B
	enqueue("203.0.113.3", 300, 1003) // flow C
	enqueue("203.0.113.4", 400, 1004) // flow D -> evicts A

	buf := make([]byte, 1500)
	for i := 0; i < 4; i++ {
		if _, _, err := l.ReadFrom(buf); err != nil {
			t.Fatalf("ReadFrom #%d: %v", i, err)
		}
	}
	if got := l.flowCount(); got != 3 {
		t.Fatalf("flowCount = %d, want 3 (LRU bound)", got)
	}
	// Flow A's kernel source (1001) should now be a miss: a fresh non-header
	// datagram from it should return the raw kernel src, not the cached one.
	stub.enqueue(stubDatagram{payload: []byte("orphan"), from: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1001}})
	_, addr, err := l.ReadFrom(buf)
	if err != nil {
		t.Fatalf("orphan ReadFrom: %v", err)
	}
	if !bytes.Equal([]byte(addr.String()), []byte("127.0.0.1:1001")) {
		t.Fatalf("orphan RemoteAddr = %v, want raw kernel src 127.0.0.1:1001 (flow A was evicted)", addr)
	}
}

// TestUDPListenerConcurrentReads is requirement 7: many concurrent flows + many
// concurrent ReadFroms must not race the state map. Run with -race; this test
// will fail under the race detector if the map is unprotected.
func TestUDPListenerConcurrentReads(t *testing.T) {
	stub := newStubPacketConn()
	l := NewUDPListener(stub, UDPListenerOptions{})

	const nFlows = 50
	const datagramsPerFlow = 20

	go func() {
		// Producer: round-robin a header datagram + follow-ups for each flow.
		for i := 0; i < nFlows; i++ {
			srcIP := net.IPv4(203, 0, 113, byte(i+1))
			kernelPort := 30000 + i
			hdr, err := WriteHeaderV2UDP(
				&net.UDPAddr{IP: srcIP, Port: 10000 + i},
				&net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443},
			)
			if err != nil {
				t.Errorf("WriteHeaderV2UDP: %v", err)
				return
			}
			for j := 0; j < datagramsPerFlow; j++ {
				payload := []byte(fmt.Sprintf("f%dd%d", i, j))
				var dgram []byte
				if j == 0 {
					dgram = append(hdr, payload...)
				} else {
					dgram = payload
				}
				stub.enqueue(stubDatagram{
					payload: dgram,
					from:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: kernelPort},
				})
			}
		}
	}()

	var wg sync.WaitGroup
	const readers = 8
	got := make(chan int, nFlows*datagramsPerFlow)
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1500)
			for {
				n, _, err := l.ReadFrom(buf)
				if err != nil {
					return
				}
				if n > 0 {
					got <- n
				}
				if len(got) == nFlows*datagramsPerFlow {
					return
				}
			}
		}()
	}

	deadline := time.After(5 * time.Second)
	count := 0
	for count < nFlows*datagramsPerFlow {
		select {
		case <-got:
			count++
		case <-deadline:
			t.Fatalf("only received %d datagrams of %d (timeout)", count, nFlows*datagramsPerFlow)
		}
	}
	stub.Close()
	wg.Wait()
	if fc := l.flowCount(); fc != nFlows {
		t.Fatalf("flowCount = %d, want %d", fc, nFlows)
	}
}

// TestUDPListenerLocalCommandHeaderStripped proves a LOCAL-command PROXY v2
// header (health-check shape) is stripped, the payload is delivered, and the
// kernel source is reported as RemoteAddr (LOCAL announces no address so the
// real peer is the splicer itself).
func TestUDPListenerLocalCommandHeaderStripped(t *testing.T) {
	stub := newStubPacketConn()
	l := NewUDPListener(stub, UDPListenerOptions{})

	// LOCAL: verCmd 0x20, fam UDP4, addrLen 12 (still allowed to carry an addr
	// pair per spec; receivers ignore it).
	hdr := append([]byte{}, v2Signature[:]...)
	hdr = append(hdr, verCmdLocal, famUDP4, 0x00, 0x0c)
	hdr = append(hdr, make([]byte, addrPairV4)...)
	payload := []byte("ping")
	dgram := append(hdr, payload...)
	kernelSrc := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55555}
	stub.enqueue(stubDatagram{payload: dgram, from: kernelSrc})

	buf := make([]byte, 1500)
	n, addr, err := l.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload = %q, want %q (header should be stripped)", buf[:n], payload)
	}
	if addr.String() != kernelSrc.String() {
		t.Fatalf("RemoteAddr = %v, want raw kernel src %v (LOCAL announces no addr)", addr, kernelSrc)
	}
}

// fakeClock is a monotonic clock that advances only when advance() is called.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestParseHeaderRejectsShort covers the boundary of parseProxyV2UDPHeader: a
// datagram shorter than the fixed prefix returns errNotProxyV2 (so the wrapper
// passes it through as-is).
func TestParseHeaderRejectsShort(t *testing.T) {
	if _, _, err := parseProxyV2UDPHeader([]byte{0x0d, 0x0a}); !errors.Is(err, errNotProxyV2) {
		t.Fatalf("short datagram err = %v, want errNotProxyV2", err)
	}
}

// TestUDPListenerReturnPathTranslation proves WriteTo rewrites a known announced
// addr back to the kernel addr (so server responses reach the splicer rather
// than the unreachable external client addr). Unknown addrs pass through.
func TestUDPListenerReturnPathTranslation(t *testing.T) {
	stub := newStubPacketConn()
	l := NewUDPListener(stub, UDPListenerOptions{})

	// Seed a flow: kernel 127.0.0.1:11111 -> announced 203.0.113.7:54321.
	hdr := mustWriteV4(t, "203.0.113.7", 54321, "198.51.100.1", 443)
	kernelSrc := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 11111}
	stub.enqueue(stubDatagram{
		payload: append(append([]byte{}, hdr...), []byte("x")...),
		from:    kernelSrc,
	})
	if _, _, err := l.ReadFrom(make([]byte, 1500)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// WriteTo the announced addr should be translated to the kernel addr on the
	// underlying socket.
	if _, err := l.WriteTo([]byte("reply"), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 54321}); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	stub.mu.Lock()
	last := stub.writes[len(stub.writes)-1]
	stub.mu.Unlock()
	if last.from.String() != kernelSrc.String() {
		t.Fatalf("write went to %v, want translated kernel addr %v", last.from, kernelSrc)
	}
	if string(last.payload) != "reply" {
		t.Fatalf("write payload = %q", last.payload)
	}

	// An unknown destination (no cached flow) passes through unchanged. Backward
	// compat for un-spliced clients + any cross-talk WriteTo a non-PROXY peer.
	other := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9999}
	if _, err := l.WriteTo([]byte("direct"), other); err != nil {
		t.Fatalf("direct WriteTo: %v", err)
	}
	stub.mu.Lock()
	last = stub.writes[len(stub.writes)-1]
	stub.mu.Unlock()
	if last.from.String() != other.String() {
		t.Fatalf("direct write went to %v, want %v (pass-through)", last.from, other)
	}
}

// TestUDPListenerLRUEvictAlsoDropsReverse proves the reverse map is kept in
// sync with the forward map on LRU eviction — no orphan entries that would
// misroute a later WriteTo.
func TestUDPListenerLRUEvictAlsoDropsReverse(t *testing.T) {
	stub := newStubPacketConn()
	l := NewUDPListener(stub, UDPListenerOptions{MaxFlows: 1})

	hdrA := mustWriteV4(t, "203.0.113.1", 100, "198.51.100.1", 443)
	hdrB := mustWriteV4(t, "203.0.113.2", 200, "198.51.100.1", 443)
	stub.enqueue(stubDatagram{
		payload: append(append([]byte{}, hdrA...), []byte("a")...),
		from:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1001},
	})
	stub.enqueue(stubDatagram{
		payload: append(append([]byte{}, hdrB...), []byte("b")...),
		from:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1002},
	})
	buf := make([]byte, 1500)
	for i := 0; i < 2; i++ {
		if _, _, err := l.ReadFrom(buf); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	// A's reverse must be gone — WriteTo(203.0.113.1:100) should pass through
	// to that addr unchanged, not be rewritten to A's stale kernel src.
	if _, err := l.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 100}); err != nil {
		t.Fatalf("WriteTo to evicted announced: %v", err)
	}
	stub.mu.Lock()
	last := stub.writes[len(stub.writes)-1]
	stub.mu.Unlock()
	if last.from.String() != "203.0.113.1:100" {
		t.Fatalf("after evict, write went to %v, want pass-through 203.0.113.1:100", last.from)
	}
}
