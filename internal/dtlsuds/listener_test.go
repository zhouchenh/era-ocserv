package dtlsuds

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/iam"
	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
	"github.com/zhouchenh/era-ocserv/internal/udshandoff"
)

// memDgramConn is an in-memory net.PacketConn that lets a test inject
// "received from facade" datagrams and observe replies. Avoids filesystem
// access so the tests work on Windows / macOS dev hosts.
type memDgramConn struct {
	rxQ    chan dgItem
	mu     sync.Mutex
	tx     []dgItem
	closed atomic.Bool
}

type dgItem struct {
	data []byte
	peer net.Addr
}

func newMemDgramConn() *memDgramConn { return &memDgramConn{rxQ: make(chan dgItem, 64)} }

func (m *memDgramConn) ReadFrom(b []byte) (int, net.Addr, error) {
	item, ok := <-m.rxQ
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(b, item.data)
	return n, item.peer, nil
}

func (m *memDgramConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if m.closed.Load() {
		return 0, net.ErrClosed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	dup := append([]byte(nil), p...)
	m.tx = append(m.tx, dgItem{data: dup, peer: addr})
	return len(p), nil
}

func (m *memDgramConn) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	close(m.rxQ)
	return nil
}

func (m *memDgramConn) LocalAddr() net.Addr              { return memAddr("memory") }
func (m *memDgramConn) SetDeadline(time.Time) error      { return nil }
func (m *memDgramConn) SetReadDeadline(time.Time) error  { return nil }
func (m *memDgramConn) SetWriteDeadline(time.Time) error { return nil }

func (m *memDgramConn) deliver(b []byte) {
	if m.closed.Load() {
		return
	}
	m.rxQ <- dgItem{data: b, peer: memAddr("facade")}
}

// txSnapshot returns a shallow copy of all replies observed so far.
func (m *memDgramConn) txSnapshot() []dgItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]dgItem, len(m.tx))
	copy(out, m.tx)
	return out
}

type memAddr string

func (memAddr) Network() string  { return "memory" }
func (a memAddr) String() string { return string(a) }

// mockSink is the PacketSink used by listener tests. It captures every
// WritePacket call so the test can assert on payload contents.
type mockSink struct {
	mu      sync.Mutex
	packets [][]byte
	err     error
	signal  chan struct{}
}

func newMockSink() *mockSink { return &mockSink{signal: make(chan struct{}, 16)} }

func (s *mockSink) WritePacket(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	dup := append([]byte(nil), p...)
	s.packets = append(s.packets, dup)
	select {
	case s.signal <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (s *mockSink) snapshot() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.packets))
	for i, p := range s.packets {
		out[i] = append([]byte(nil), p...)
	}
	return out
}

// mockResolver returns a fixed Identity for any device ID, optionally
// failing with err.
type mockResolver struct {
	identity iam.Identity
	err      error
}

func (m *mockResolver) Resolve(_ context.Context, _ string) (iam.Identity, error) {
	if m.err != nil {
		return iam.Identity{}, m.err
	}
	return m.identity, nil
}

// captureLifecycle records OnAdmit / OnEvict calls.
type captureLifecycle struct {
	mu       sync.Mutex
	admitted []*Session
	evicted  []*Session
}

func (c *captureLifecycle) OnAdmit(s *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.admitted = append(c.admitted, s)
}

func (c *captureLifecycle) OnEvict(s *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evicted = append(c.evicted, s)
}

func (c *captureLifecycle) snapshot() (admit, evict []*Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	admit = append([]*Session(nil), c.admitted...)
	evict = append([]*Session(nil), c.evicted...)
	return
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

// dtlsTLVs builds the mandatory ERA TLV set for AnyConnect-DTLS (spec §7
// row). Optional fields are omitted; tests can override individual TLVs.
func dtlsTLVs() []proxyproto.TLV {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 0xAB
	}
	sourceV6 := []byte{0x20, 0x01, 0x04, 0x70, 0xf9, 0xd1, 0x90, 0x01, 0, 0, 0, 0, 0, 0, 0xab, 0xcd}
	// Pre-sort by type per spec §3.2.
	return []proxyproto.TLV{
		{Type: proxyproto.EraTLVToken, Value: bytes12(0x42)},
		{Type: proxyproto.EraTLVDeviceID, Value: []byte("abcdef12-3456-7890-abcd-ef0123456789")},
		{Type: proxyproto.EraTLVUserID, Value: []byte("user-1")},
		{Type: proxyproto.EraTLVDTLSPSK, Value: psk},
		{Type: proxyproto.EraTLVSourceHintV6, Value: sourceV6},
		// CN must be a valid idgen "dev_" device id: the listener resolves the
		// TPM identity from the Subject DN CN (the DeviceID TLV above is the
		// diagnostic UUID), so a non-idgen CN is rejected before admission.
		{Type: proxyproto.EraTLVMTLSSubjectDN, Value: []byte("CN=dev_aaaaaaaaaaaaaaaaaaaaaaaaaa,OU=ERA")},
		{Type: proxyproto.EraTLVTraceID, Value: []byte("01ARZ3NDEKTSV4RRFFQ69G5FAV")},
		{Type: proxyproto.EraTLVSpecVersion, Value: []byte{proxyproto.SpecVersionStage1}},
	}
}

func bytes12(b byte) []byte {
	out := make([]byte, 12)
	for i := range out {
		out[i] = b
	}
	return out
}

// buildDgramFrame mirrors udshandoff.buildDgram (which is package-private
// there). Encodes the Stage 1 SOCK_DGRAM wire layout.
func buildDgramFrame(t *testing.T, dir udshandoff.Direction, inner *proxyproto.HeaderV2, tlvs []proxyproto.TLV, payload []byte) []byte {
	t.Helper()
	innerBytes, err := inner.Encode()
	if err != nil {
		t.Fatalf("encode inner pp2: %v", err)
	}
	// Encode TLVs in the order supplied (caller sorts).
	var era []byte
	for _, tlv := range tlvs {
		era = append(era, byte(tlv.Type))
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(tlv.Value)))
		era = append(era, lenBuf[:]...)
		era = append(era, tlv.Value...)
	}
	tlvBlock := append(innerBytes, era...)
	out := make([]byte, udshandoff.DGramHeaderLen+len(tlvBlock)+len(payload))
	out[0] = proxyproto.SpecVersionStage1
	out[1] = byte(dir) & 0x01
	binary.BigEndian.PutUint16(out[2:4], uint16(len(tlvBlock)))
	binary.BigEndian.PutUint16(out[4:6], uint16(len(payload)))
	copy(out[udshandoff.DGramHeaderLen:], tlvBlock)
	copy(out[udshandoff.DGramHeaderLen+len(tlvBlock):], payload)
	return out
}

func innerUDP6(srcPort, dstPort uint16) *proxyproto.HeaderV2 {
	src := netip.AddrPortFrom(netip.MustParseAddr("2001:db8::7"), srcPort)
	dst := netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1"), dstPort)
	return &proxyproto.HeaderV2{Family: 0x22, Src: src, Dst: dst}
}

// startListener constructs a Listener around an in-memory PacketConn and
// returns the parts the tests need to drive it.
func startListener(t *testing.T, resolver iam.Resolver, sink PacketSink, lc SessionLifecycle, clk *fakeClock) (*Listener, *memDgramConn, *udshandoff.Metrics) {
	t.Helper()
	pc := newMemDgramConn()
	metrics := udshandoff.NewMetrics()
	now := time.Now
	if clk != nil {
		now = clk.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := Listen(ctx, Options{
		Resolver:           resolver,
		Sink:               sink,
		Lifecycle:          lc,
		Logger:             testLogger(),
		Metrics:            metrics,
		IdleTimeout:        300 * time.Second,
		EvictionTick:       time.Hour, // tests drive eviction via RunEvictionPass
		Now:                now,
		PreboundPacketConn: pc,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, pc, metrics
}

func defaultResolver() *mockResolver {
	return &mockResolver{
		identity: iam.Identity{
			DeviceID: "abcdef12-3456-7890-abcd-ef0123456789",
			IPv6:     netip.MustParsePrefix("2001:470:f9d1:9001::abcd/128"),
			MTU:      1406,
		},
	}
}

// capturingResolver records the device id it was asked to resolve.
type capturingResolver struct {
	mu       sync.Mutex
	gotID    string
	identity iam.Identity
}

func (c *capturingResolver) Resolve(_ context.Context, deviceID string) (iam.Identity, error) {
	c.mu.Lock()
	c.gotID = deviceID
	c.mu.Unlock()
	return c.identity, nil
}

func (c *capturingResolver) lastID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gotID
}

// TestListener_ResolvesByCNNotDeviceIDTLV guards the production regression where
// the DTLS listener resolved the TPM identity from the diagnostic DeviceID TLV
// (which the facade fills with a derived UUIDv5 for non-UUID era-portal ids)
// instead of the authoritative idgen "dev_" id in the MTLS Subject DN CN. The
// wrong key fails ("device not found in TPM") and the DTLS data plane silently
// dies ~40s in on a real client.
func TestListener_ResolvesByCNNotDeviceIDTLV(t *testing.T) {
	sink := newMockSink()
	lc := &captureLifecycle{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	res := &capturingResolver{identity: defaultResolver().identity}
	_, pc, _ := startListener(t, res, sink, lc, clk)

	frame := buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(53000, 443), dtlsTLVs(),
		append([]byte{pktData}, makeIPv6Ping()...))
	pc.deliver(frame)

	if err := waitForSink(sink, 1, 2*time.Second); err != nil {
		t.Fatalf("sink never saw the packet: %v", err)
	}
	// dtlsTLVs() sets DeviceID TLV = "abcdef12-..." (UUID) and CN = "dev_aaa…";
	// resolution MUST use the CN id, never the TLV.
	if got := res.lastID(); got != "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("resolved by %q, want the Subject-DN CN dev_ id (not the DeviceID TLV UUID)", got)
	}
}

func TestListener_AdmitsAndForwardsDataPacket(t *testing.T) {
	sink := newMockSink()
	lc := &captureLifecycle{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	l, pc, metrics := startListener(t, defaultResolver(), sink, lc, clk)

	ipPkt := makeIPv6Ping()
	payload := append([]byte{pktData}, ipPkt...)
	frame := buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(51000, 443), dtlsTLVs(), payload)
	pc.deliver(frame)

	if err := waitForSink(sink, 1, 2*time.Second); err != nil {
		t.Fatalf("sink never saw the packet: %v", err)
	}

	packets := sink.snapshot()
	if len(packets) != 1 {
		t.Fatalf("sink saw %d packets, want 1", len(packets))
	}
	if !bytesEqual(packets[0], ipPkt) {
		t.Fatalf("sink packet mismatch:\n got %x\nwant %x", packets[0], ipPkt)
	}

	admit, _ := lc.snapshot()
	if len(admit) != 1 {
		t.Fatalf("OnAdmit fired %d times, want 1", len(admit))
	}
	if admit[0].InnerIPv6() != netip.MustParseAddr("2001:470:f9d1:9001::abcd") {
		t.Errorf("admit inner = %v", admit[0].InnerIPv6())
	}
	if admit[0].DeviceID() != "abcdef12-3456-7890-abcd-ef0123456789" {
		t.Errorf("admit device id = %q", admit[0].DeviceID())
	}
	if l.Table().Len() != 1 {
		t.Errorf("table len = %d, want 1", l.Table().Len())
	}

	snap := metrics.Snapshot()
	if snap.HandoffAccept[udshandoff.ProtoAnyConnectDTLS] != 1 {
		t.Errorf("HandoffAccept[dtls] = %d", snap.HandoffAccept[udshandoff.ProtoAnyConnectDTLS])
	}
}

func TestListener_FollowupDatagramReusesSession(t *testing.T) {
	sink := newMockSink()
	lc := &captureLifecycle{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	l, pc, _ := startListener(t, defaultResolver(), sink, lc, clk)

	first := buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(52000, 443), dtlsTLVs(),
		append([]byte{pktData}, makeIPv6Ping()...))
	pc.deliver(first)
	if err := waitForSink(sink, 1, 2*time.Second); err != nil {
		t.Fatalf("first packet: %v", err)
	}

	// Second datagram on the same 4-tuple, no PSK (per spec §5.3, follow-up
	// MAY omit DTLS_PSK / DEVICE_ID etc. — backend caches by 4-tuple). We
	// still send the TLVs because the matrix declares them mandatory; in
	// production the facade keeps re-emitting them on each datagram for
	// matrix conformance. The "follow-up" property we test is that no
	// SECOND OnAdmit fires.
	second := buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(52000, 443), dtlsTLVs(),
		append([]byte{pktData}, makeIPv6Ping()...))
	pc.deliver(second)
	if err := waitForSink(sink, 2, 2*time.Second); err != nil {
		t.Fatalf("second packet: %v", err)
	}

	admit, _ := lc.snapshot()
	if len(admit) != 1 {
		t.Fatalf("OnAdmit fired %d times, want 1", len(admit))
	}
	if l.Table().Len() != 1 {
		t.Errorf("table len = %d, want 1", l.Table().Len())
	}
}

func TestListener_DistinctFourTuplesDistinctSessions(t *testing.T) {
	sink := newMockSink()
	lc := &captureLifecycle{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	l, pc, _ := startListener(t, defaultResolver(), sink, lc, clk)

	pc.deliver(buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(50001, 443), dtlsTLVs(),
		append([]byte{pktData}, makeIPv6Ping()...)))
	pc.deliver(buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(50002, 443), dtlsTLVs(),
		append([]byte{pktData}, makeIPv6Ping()...)))

	if err := waitForSink(sink, 2, 2*time.Second); err != nil {
		t.Fatalf("waited too long: %v", err)
	}
	admit, _ := lc.snapshot()
	if len(admit) != 2 {
		t.Fatalf("OnAdmit fired %d times, want 2", len(admit))
	}
	if l.Table().Len() != 2 {
		t.Fatalf("table len = %d, want 2", l.Table().Len())
	}
}

func TestListener_DPDEcho(t *testing.T) {
	sink := newMockSink()
	lc := &captureLifecycle{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	_, pc, _ := startListener(t, defaultResolver(), sink, lc, clk)

	probe := []byte{pktDPDOut, 'P', 'I', 'N', 'G'}
	frame := buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(51500, 443), dtlsTLVs(), probe)
	pc.deliver(frame)

	// Wait for the reply.
	if err := waitForTx(pc, 1, 2*time.Second); err != nil {
		t.Fatalf("listener never replied: %v", err)
	}
	txs := pc.txSnapshot()
	if len(txs) != 1 {
		t.Fatalf("got %d replies, want 1", len(txs))
	}
	// Decode the reply frame and verify type=DPD-resp, payload echoes "PING".
	parsed, err := udshandoff.DecodeDGramFrame(txs[0].data)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if parsed.Direction != udshandoff.DirBackendToFacade {
		t.Fatalf("reply direction = %v, want backend->facade", parsed.Direction)
	}
	if len(parsed.Payload) < 1 || parsed.Payload[0] != pktDPDResp {
		t.Fatalf("reply payload[0] = 0x%02x, want 0x%02x", parsed.Payload[0], pktDPDResp)
	}
	if string(parsed.Payload[1:]) != "PING" {
		t.Fatalf("reply echo = %q, want PING", parsed.Payload[1:])
	}
	if len(sink.snapshot()) != 0 {
		t.Errorf("DPD probe should not have reached the TUN sink")
	}
}

func TestListener_DisconnectEvictsSession(t *testing.T) {
	sink := newMockSink()
	lc := &captureLifecycle{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	l, pc, _ := startListener(t, defaultResolver(), sink, lc, clk)

	// Admit a session first.
	pc.deliver(buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(53000, 443), dtlsTLVs(),
		append([]byte{pktData}, makeIPv6Ping()...)))
	if err := waitForSink(sink, 1, 2*time.Second); err != nil {
		t.Fatalf("admit: %v", err)
	}

	// Now send a disconnect.
	pc.deliver(buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(53000, 443), dtlsTLVs(),
		[]byte{pktDisconnect, 0x00}))

	if err := waitFor(func() bool { return l.Table().Len() == 0 }, 2*time.Second); err != nil {
		t.Fatalf("session never evicted: len=%d", l.Table().Len())
	}
	_, evict := lc.snapshot()
	if len(evict) != 1 {
		t.Fatalf("OnEvict fired %d times, want 1", len(evict))
	}
}

func TestListener_SessionWritePacketWrapsType(t *testing.T) {
	sink := newMockSink()
	lc := &captureLifecycle{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	_, pc, _ := startListener(t, defaultResolver(), sink, lc, clk)

	pc.deliver(buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(54000, 443), dtlsTLVs(),
		append([]byte{pktData}, makeIPv6Ping()...)))
	if err := waitForSink(sink, 1, 2*time.Second); err != nil {
		t.Fatalf("admit: %v", err)
	}
	admit, _ := lc.snapshot()
	if len(admit) != 1 {
		t.Fatal("expected 1 admit")
	}
	sess := admit[0]
	ipReply := makeIPv6Ping()
	n, err := sess.WritePacket(ipReply)
	if err != nil {
		t.Fatalf("Session.WritePacket: %v", err)
	}
	if n != len(ipReply) {
		t.Fatalf("returned n=%d, want %d", n, len(ipReply))
	}
	if err := waitForTx(pc, 1, 2*time.Second); err != nil {
		t.Fatalf("never saw outbound: %v", err)
	}
	txs := pc.txSnapshot()
	if len(txs) != 1 {
		t.Fatalf("got %d outbound, want 1", len(txs))
	}
	parsed, err := udshandoff.DecodeDGramFrame(txs[0].data)
	if err != nil {
		t.Fatalf("decode outbound: %v", err)
	}
	if parsed.Direction != udshandoff.DirBackendToFacade {
		t.Fatalf("dir = %v", parsed.Direction)
	}
	if len(parsed.Payload) != 1+len(ipReply) || parsed.Payload[0] != pktData {
		t.Fatalf("outbound payload[0]=0x%02x len=%d, want 0x00 + %d bytes",
			parsed.Payload[0], len(parsed.Payload), len(ipReply))
	}
	if !bytesEqual(parsed.Payload[1:], ipReply) {
		t.Fatalf("outbound body mismatch")
	}
}

func TestListener_IdleEvictionFiresLifecycle(t *testing.T) {
	sink := newMockSink()
	lc := &captureLifecycle{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	l, pc, _ := startListener(t, defaultResolver(), sink, lc, clk)

	pc.deliver(buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(55000, 443), dtlsTLVs(),
		append([]byte{pktData}, makeIPv6Ping()...)))
	if err := waitForSink(sink, 1, 2*time.Second); err != nil {
		t.Fatalf("admit: %v", err)
	}

	// Advance past the idle timeout and run a sync eviction pass.
	clk.Advance(301 * time.Second)
	l.RunEvictionPass()

	if l.Table().Len() != 0 {
		t.Fatalf("table len = %d, want 0", l.Table().Len())
	}
	_, evict := lc.snapshot()
	if len(evict) != 1 {
		t.Fatalf("OnEvict fired %d times, want 1", len(evict))
	}
}

func TestListener_RejectsBadDirection(t *testing.T) {
	sink := newMockSink()
	lc := &captureLifecycle{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	_, pc, metrics := startListener(t, defaultResolver(), sink, lc, clk)

	frame := buildDgramFrame(t, udshandoff.DirBackendToFacade, innerUDP6(55001, 443), dtlsTLVs(),
		append([]byte{pktData}, makeIPv6Ping()...))
	pc.deliver(frame)
	// Give the framework a moment.
	time.Sleep(100 * time.Millisecond)

	if got := len(sink.snapshot()); got != 0 {
		t.Errorf("sink saw %d packets after bad-direction frame", got)
	}
	snap := metrics.Snapshot()
	if snap.FrameRejected[udshandoff.ProtoAnyConnectDTLS] != 1 {
		t.Errorf("FrameRejected[dtls] = %d", snap.FrameRejected[udshandoff.ProtoAnyConnectDTLS])
	}
}

func TestListener_RejectsMissingPSK(t *testing.T) {
	sink := newMockSink()
	lc := &captureLifecycle{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	_, pc, metrics := startListener(t, defaultResolver(), sink, lc, clk)

	tlvs := dtlsTLVs()
	// Strip the PSK TLV.
	stripped := tlvs[:0]
	for _, tlv := range tlvs {
		if tlv.Type == proxyproto.EraTLVDTLSPSK {
			continue
		}
		stripped = append(stripped, tlv)
	}
	frame := buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(55002, 443), stripped,
		append([]byte{pktData}, makeIPv6Ping()...))
	pc.deliver(frame)
	time.Sleep(100 * time.Millisecond)

	if got := len(sink.snapshot()); got != 0 {
		t.Errorf("sink saw %d packets after missing-PSK frame", got)
	}
	snap := metrics.Snapshot()
	if snap.HandoffInvalid[udshandoff.ProtoAnyConnectDTLS] != 1 {
		t.Errorf("HandoffInvalid[dtls] = %d", snap.HandoffInvalid[udshandoff.ProtoAnyConnectDTLS])
	}
}

func TestListener_RejectsBadDeviceUUID(t *testing.T) {
	sink := newMockSink()
	lc := &captureLifecycle{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	_, pc, metrics := startListener(t, defaultResolver(), sink, lc, clk)

	tlvs := dtlsTLVs()
	for i, tlv := range tlvs {
		if tlv.Type == proxyproto.EraTLVDeviceID {
			tlvs[i].Value = []byte("not-a-uuid-not-a-uuid-not-a-uuid-no!")
		}
	}
	frame := buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(55003, 443), tlvs,
		append([]byte{pktData}, makeIPv6Ping()...))
	pc.deliver(frame)
	time.Sleep(100 * time.Millisecond)

	if got := len(sink.snapshot()); got != 0 {
		t.Errorf("sink saw %d packets after bad-device-id frame", got)
	}
	snap := metrics.Snapshot()
	if snap.HandoffInvalid[udshandoff.ProtoAnyConnectDTLS] != 1 {
		t.Errorf("HandoffInvalid[dtls] = %d", snap.HandoffInvalid[udshandoff.ProtoAnyConnectDTLS])
	}
}

func TestListener_BindsRealUDS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("real UDS bind tested only on linux; current GOOS=%s", runtime.GOOS)
	}
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "anyconnect-dtls.sock")
	sink := newMockSink()
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l, err := Listen(ctx, Options{
		SocketPath:   sockPath,
		Resolver:     defaultResolver(),
		Sink:         sink,
		Logger:       testLogger(),
		IdleTimeout:  300 * time.Second,
		EvictionTick: time.Hour,
		Now:          clk.Now,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()
	if l.SocketPath() != sockPath {
		t.Fatalf("SocketPath = %q", l.SocketPath())
	}

	// Client-side path required for SOCK_DGRAM AF_UNIX.
	cliPath := filepath.Join(dir, "client.sock")
	cli, err := net.ListenPacket("unixgram", cliPath)
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer cli.Close()
	srvAddr := &net.UnixAddr{Name: sockPath, Net: "unixgram"}
	frame := buildDgramFrame(t, udshandoff.DirFacadeToBackend, innerUDP6(55050, 443), dtlsTLVs(),
		append([]byte{pktData}, makeIPv6Ping()...))
	if _, err := cli.(*net.UnixConn).WriteToUnix(frame, srvAddr); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := waitForSink(sink, 1, 2*time.Second); err != nil {
		t.Fatalf("packet never landed: %v", err)
	}
}

// makeIPv6Ping returns a minimal 40-byte IPv6 header + 8-byte ICMP echo
// request. Used as a stable, parseable test payload. The packet sets:
//
//	version=6, payload-length=8, next-header=58 (ICMPv6), hop-limit=64
//	src = 2001:db8::7
//	dst = 2001:db8::1
//	icmp: type=128 (echo request), code=0, checksum=0, identifier=0, seq=0
func makeIPv6Ping() []byte {
	hdr := []byte{
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x08, // payload length = 8
		58, 64, // next header = ICMPv6, hop limit = 64
	}
	src := netip.MustParseAddr("2001:db8::7").As16()
	dst := netip.MustParseAddr("2001:db8::1").As16()
	hdr = append(hdr, src[:]...)
	hdr = append(hdr, dst[:]...)
	icmp := []byte{128, 0, 0, 0, 0, 0, 0, 0}
	return append(hdr, icmp...)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// waitForSink blocks until sink has seen `want` packets or timeout elapses.
func waitForSink(s *mockSink, want int, timeout time.Duration) error {
	return waitFor(func() bool { return len(s.snapshot()) >= want }, timeout)
}

// waitForTx blocks until pc has seen `want` outbound datagrams.
func waitForTx(pc *memDgramConn, want int, timeout time.Duration) error {
	return waitFor(func() bool { return len(pc.txSnapshot()) >= want }, timeout)
}

// waitFor polls fn() at 10 ms intervals until it returns true or the
// deadline is hit. Returns ctx.Err()-style "timed out" message; tests use
// the returned error verbatim.
func waitFor(fn func() bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	if fn() {
		return nil
	}
	return errTimeout
}

var errTimeout = errTimedOut("dtlsuds_test: timed out")

type errTimedOut string

func (e errTimedOut) Error() string { return string(e) }
