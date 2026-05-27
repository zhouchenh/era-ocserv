package dtls

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	piondtls "github.com/pion/dtls/v3"

	"github.com/zhouchenh/era-ocserv/internal/cstp"
)

// fakeRegistry is a trivial SessionRegistry backed by an in-memory
// map. Tests that exercise the post-handshake hand-off plumb a real
// *cstp.Server via cstp.RegisterDTLSForTesting; tests that only care
// about the PSK-callback wiring use a fakeRegistry to assert the
// unknown-session path.
type fakeRegistry struct {
	mu      sync.Mutex
	entries map[string]fakeRegEntry
}

type fakeRegEntry struct {
	psk    []byte
	tunnel *cstp.Tunnel
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{entries: map[string]fakeRegEntry{}}
}

func (r *fakeRegistry) put(sessionID string, psk []byte, t *cstp.Tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[sessionID] = fakeRegEntry{psk: psk, tunnel: t}
}

func (r *fakeRegistry) LookupSession(sessionID string) ([]byte, *cstp.Tunnel, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[sessionID]
	if !ok {
		return nil, nil, false
	}
	cp := make([]byte, len(e.psk))
	copy(cp, e.psk)
	return cp, e.tunnel, true
}

// stubVerifier and stubResolver satisfy the cstp.Server config; the
// dtls tests never drive the CSTP HTTP surface so these only need to
// not panic when the Server is constructed.
type stubVerifier struct{}

func (stubVerifier) Verify(_ context.Context, _ string, _ string) (string, error) {
	return "", errors.New("not used")
}

type stubResolver struct{}

func (stubResolver) Resolve(_ context.Context, _ string) (cstp.Identity, error) {
	return cstp.Identity{}, errors.New("not used")
}

// freshCSTPServer builds a *cstp.Server suitable for constructing
// test tunnels via cstp.NewTunnelForTesting. The DPD/keepalive/idle
// intervals are set huge so the heartbeat goroutine does not fire
// during the lifetime of any of these tests.
func freshCSTPServer(t *testing.T) *cstp.Server {
	t.Helper()
	s := cstp.NewServer(cstp.Config{
		Verifier:          stubVerifier{},
		Resolver:          stubResolver{},
		ServerName:        "vpn.eracloud.app",
		DPDInterval:       1 << 20,
		KeepaliveInterval: 1 << 20,
		IdleTimeout:       1 << 20,
		DefaultMTU:        1406,
	})
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// makeTunnel builds a real *cstp.Tunnel over a net.Pipe pair so the
// test can drive CSTP-side bytes if it needs to. The clientConn is
// returned for that purpose; tests that only care about the DTLS
// path can ignore it.
func makeTunnel(t *testing.T, srv *cstp.Server, id cstp.Identity, sessionToken string) (*cstp.Tunnel, net.Conn) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	br := bufio.NewReader(serverConn)
	bw := bufio.NewWriter(serverConn)
	rw := bufio.NewReadWriter(br, bw)
	tun := cstp.NewTunnelForTesting(srv, serverConn, rw, id, sessionToken)
	t.Cleanup(func() { _ = tun.Close() })
	return tun, clientConn
}

// freeUDPAddr returns a 127.0.0.1 UDP address with a fresh ephemeral
// port. Binding-then-closing is the standard trick for picking a
// port without race; pion's listener will rebind immediately.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("freeUDPAddr: %v", err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close()
	return addr
}

// pionClient builds a pion DTLS client configured to match the
// server profile: PSK-NEGOTIATE with TLS_PSK_WITH_AES_128_GCM_SHA256.
// The identity is the AnyConnect session token; the psk is whatever
// the server side registered for that token. The handshake is driven
// explicitly before the function returns so the caller can rely on
// the conn being post-handshake.
func pionClient(t *testing.T, addr string, identity string, psk []byte) *piondtls.Conn {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	cfg := &piondtls.Config{
		PSK: func(_ []byte) ([]byte, error) {
			return psk, nil
		},
		PSKIdentityHint: []byte(identity),
		CipherSuites: []piondtls.CipherSuiteID{
			piondtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		},
		ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
	}
	c, err := piondtls.Dial("udp", udpAddr, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.HandshakeContext(ctx); err != nil {
		t.Fatalf("HandshakeContext: %v", err)
	}
	return c
}

func randSessionToken(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return fmt.Sprintf("sess-%x", buf)
}

func randPSK(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return buf
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startDTLS spins up a Server on the given address using reg as the
// registry and returns the running server. ListenAndServe is driven
// in a background goroutine; the test's cleanup tears it down.
func startDTLS(t *testing.T, addr string, reg SessionRegistry) *Server {
	t.Helper()
	return startDTLSWithConfig(t, Config{
		Listen:           addr,
		Registry:         reg,
		Logger:           discardLogger(),
		HandshakeTimeout: 5 * time.Second,
		IdleTimeout:      30 * time.Second,
	})
}

// startDTLSWithConfig is the explicit-Config variant of startDTLS, used
// by tests that need to override the rekey deadlines or other
// non-default fields. Listen and Registry are still required and the
// Logger defaults to discardLogger if the caller did not set one.
func startDTLSWithConfig(t *testing.T, cfg Config) *Server {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = discardLogger()
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	go func() {
		_ = srv.ListenAndServe(ctx)
		close(doneCh)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		cancel()
		<-doneCh
	})
	// Brief delay so the listener is ready. pion's Listen is
	// synchronous in our usage, but the goroutine scheduler may not
	// have run the loop body yet.
	time.Sleep(20 * time.Millisecond)
	return srv
}

// TestHandshakeAgainstFakeClient is the happy-path smoke test: PSK
// identity is known to the registry, handshake completes, the
// pion-side client can write a data frame, and the server pushes
// it into the Tunnel's dataCh where ReadPacket can pick it up.
func TestHandshakeAgainstFakeClient(t *testing.T) {
	cstpSrv := freshCSTPServer(t)

	id := cstp.Identity{
		DeviceID: "dev-A",
		IPv6:     netip.MustParsePrefix("2001:db8::1/128"),
		MTU:      1406,
	}
	sessionToken := randSessionToken(t)
	psk := randPSK(t)
	tun, _ := makeTunnel(t, cstpSrv, id, sessionToken)
	cstp.RegisterDTLSForTesting(cstpSrv, sessionToken, psk, tun)

	reg := &cstpServerRegistry{srv: cstpSrv}
	addr := freeUDPAddr(t)
	_ = startDTLS(t, addr, reg)

	client := pionClient(t, addr, sessionToken, psk)

	// Client sends a DTLS data frame: 1-byte type + payload.
	payload := []byte("inbound-data-frame")
	frame := append([]byte{pktData}, payload...)
	if _, err := client.Write(frame); err != nil {
		t.Fatalf("client write: %v", err)
	}

	// Server-side Tunnel.ReadPacket should observe the payload.
	readDone := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 4096)
		n, err := tun.ReadPacket(buf)
		readDone <- readResult{n: n, err: err, buf: buf[:n]}
	}()

	select {
	case r := <-readDone:
		if r.err != nil {
			t.Fatalf("ReadPacket: %v", r.err)
		}
		if string(r.buf) != string(payload) {
			t.Fatalf("payload mismatch: got %q want %q", r.buf, payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("ReadPacket did not see inbound data within 3s")
	}
}

type readResult struct {
	n   int
	buf []byte
	err error
}

// cstpServerRegistry adapts the production *cstp.Server through the
// SessionRegistry interface. In production this is exactly what
// internal/cstp.*Server.LookupSession does — and we use it to make
// sure the production type really satisfies the interface.
type cstpServerRegistry struct {
	srv *cstp.Server
}

func (r *cstpServerRegistry) LookupSession(sessionID string) ([]byte, *cstp.Tunnel, bool) {
	return r.srv.LookupSession(sessionID)
}

// TestUnknownSessionFailsHandshake confirms that the PSK callback
// returns an error when the identity is not in the registry, and
// the client's handshake therefore fails. The tunnel is never
// attached.
func TestUnknownSessionFailsHandshake(t *testing.T) {
	reg := newFakeRegistry()
	addr := freeUDPAddr(t)
	_ = startDTLS(t, addr, reg)

	// Client offers an identity the server does not know.
	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	cfg := &piondtls.Config{
		PSK: func(_ []byte) ([]byte, error) {
			return []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, nil
		},
		PSKIdentityHint: []byte("not-a-real-session"),
		CipherSuites: []piondtls.CipherSuiteID{
			piondtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		},
		ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
	}
	c, err := piondtls.Dial("udp", udpAddr, cfg)
	if err != nil {
		// Even Dial failing here is acceptable (some pion paths
		// surface the failure that early). The contract is: the
		// client can't establish a working session.
		return
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.HandshakeContext(ctx); err == nil {
		t.Fatalf("expected handshake failure for unknown session, got success")
	}
}

// TestTunnelHandoff verifies the data plane switches to DTLS after
// AttachDTLS: a server-side tunnel.WritePacket goes out over the
// DTLS conn, not over the CSTP/TLS conn, and the pion client reads
// a properly-framed (1-byte type + payload) datagram.
//
// We start a CSTP-side drain goroutine so the synchronous net.Pipe
// never blocks: if handleConn has not finished AttachDTLS by the
// time we WritePacket, the call goes out as a CSTP frame and is
// silently consumed by the drain. The successful assertion is that
// the pion-side Read sees the DTLS-framed payload.
func TestTunnelHandoff(t *testing.T) {
	cstpSrv := freshCSTPServer(t)

	id := cstp.Identity{
		DeviceID: "dev-B",
		IPv6:     netip.MustParsePrefix("2001:db8::2/128"),
		MTU:      1406,
	}
	sessionToken := randSessionToken(t)
	psk := randPSK(t)
	tun, cstpClientConn := makeTunnel(t, cstpSrv, id, sessionToken)
	cstp.RegisterDTLSForTesting(cstpSrv, sessionToken, psk, tun)

	// Drain everything that hits the CSTP-side pipe peer so a
	// CSTP-path WritePacket never blocks on Flush.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := cstpClientConn.Read(buf); err != nil {
				return
			}
		}
	}()

	reg := &cstpServerRegistry{srv: cstpSrv}
	addr := freeUDPAddr(t)
	_ = startDTLS(t, addr, reg)

	client := pionClient(t, addr, sessionToken, psk)

	// Send a probe so handleConn finishes AttachDTLS before we
	// start checking. The probe is an inbound DTLS data frame; we
	// read it back out of the tunnel to confirm the round-trip
	// reached InjectInbound, which means the server-side handleConn
	// has progressed past AttachDTLS.
	probe := []byte("probe-rx")
	if _, err := client.Write(append([]byte{pktData}, probe...)); err != nil {
		t.Fatalf("client probe write: %v", err)
	}
	rxBuf := make([]byte, 256)
	if _, err := tun.ReadPacket(rxBuf); err != nil {
		t.Fatalf("tun.ReadPacket: %v", err)
	}

	// Now exercise the outbound DTLS path.
	srvPayload := []byte("server-to-client-via-dtls")
	if _, err := tun.WritePacket(srvPayload); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	rbuf := make([]byte, 4096)
	n, err := client.Read(rbuf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if n < 2 {
		t.Fatalf("client read %d bytes, want >=2", n)
	}
	if rbuf[0] != pktData {
		t.Fatalf("client saw type=%d want pktData=%d", rbuf[0], pktData)
	}
	if string(rbuf[1:n]) != string(srvPayload) {
		t.Fatalf("payload mismatch: got %q want %q", rbuf[1:n], srvPayload)
	}
}

// TestFallbackOnDTLSClose verifies that closing the DTLS conn from
// the client side detaches the tunnel and leaves it usable for
// further CSTP-side traffic. The Tunnel is NOT closed.
//
// Observability: we can't read the DTLS attachment pointer directly
// from outside the cstp package, so we exercise the contract through
// its public side-effects:
//
//   - After client.Close + server-side detach, a Tunnel.WritePacket
//     emits an 8-byte-CSTP frame on the original (TLS-side) conn —
//     which the test's clientConn-side pipe reader observes (the
//     CSTP frame's `S T F 0x01` magic identifies it unambiguously).
//   - Tunnel.Identity() and Tunnel.SessionID() still return live
//     values, confirming the Tunnel itself was not closed.
func TestFallbackOnDTLSClose(t *testing.T) {
	cstpSrv := freshCSTPServer(t)

	id := cstp.Identity{
		DeviceID: "dev-C",
		IPv6:     netip.MustParsePrefix("2001:db8::3/128"),
		MTU:      1406,
	}
	sessionToken := randSessionToken(t)
	psk := randPSK(t)
	tun, cstpClientConn := makeTunnel(t, cstpSrv, id, sessionToken)
	cstp.RegisterDTLSForTesting(cstpSrv, sessionToken, psk, tun)

	reg := &cstpServerRegistry{srv: cstpSrv}
	addr := freeUDPAddr(t)
	_ = startDTLS(t, addr, reg)

	client := pionClient(t, addr, sessionToken, psk)

	// Drain everything that ever lands on the CSTP-side pipe peer
	// into a single bytes.Buffer, so concurrent writes by the
	// Tunnel never block. This unblocks the synchronous net.Pipe.
	type pipeDrain struct {
		mu  sync.Mutex
		buf []byte
	}
	drain := &pipeDrain{}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := cstpClientConn.Read(buf)
			if n > 0 {
				drain.mu.Lock()
				drain.buf = append(drain.buf, buf[:n]...)
				drain.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	// Send one inbound data frame so the server-side handleConn has
	// completed AttachDTLS by the time we close.
	if _, err := client.Write([]byte{pktData, 0xde, 0xad}); err != nil {
		t.Fatalf("client write probe: %v", err)
	}
	// Drain the resulting InjectInbound on the Tunnel.
	drainBuf := make([]byte, 256)
	if _, err := tun.ReadPacket(drainBuf); err != nil {
		t.Fatalf("drain probe: %v", err)
	}

	// Client cleanly closes DTLS.
	_ = client.Close()

	// Poll until WritePacket returns success (CSTP path) AND the
	// CSTP pipe peer has observed the bytes. The CSTP frame magic
	// 'S','T','F',0x01 is the unambiguous detection signal.
	deadline := time.Now().Add(3 * time.Second)
	var fallback bool
	for time.Now().Before(deadline) {
		probe := []byte("fallback-probe")
		_, werr := tun.WritePacket(probe)
		if werr == nil {
			// Allow a brief flush.
			time.Sleep(50 * time.Millisecond)
			drain.mu.Lock()
			if bytesIndex(drain.buf, []byte{'S', 'T', 'F', 0x01}) >= 0 {
				fallback = true
			}
			drain.mu.Unlock()
			if fallback {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !fallback {
		t.Fatalf("Tunnel did not fall back to CSTP within 3s after DTLS close")
	}

	// Sanity: tunnel is still alive.
	if tun.Identity().DeviceID != "dev-C" {
		t.Fatalf("tunnel identity changed after detach")
	}
	if tun.SessionID() != sessionToken {
		t.Fatalf("tunnel session id changed after detach")
	}
}

// bytesIndex is a tiny indexOf helper to avoid pulling bytes pkg
// into a test-only file. Returns -1 if needle not found.
func bytesIndex(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestDetachIsNoOpWhenNotAttached confirms DetachDTLS is safe to
// call on a tunnel that never had an attachment. This is the
// reverse direction of the AttachDTLS lifecycle and matters for
// the cleanup path in handleConn.
func TestDetachIsNoOpWhenNotAttached(t *testing.T) {
	cstpSrv := freshCSTPServer(t)
	id := cstp.Identity{
		DeviceID: "dev-D",
		IPv6:     netip.MustParsePrefix("2001:db8::4/128"),
		MTU:      1406,
	}
	sessionToken := randSessionToken(t)
	tun, _ := makeTunnel(t, cstpSrv, id, sessionToken)

	// No AttachDTLS performed; Detach should not panic.
	tun.DetachDTLS()
	tun.DetachDTLS()
	tun.DetachDTLS()
}

// TestConcurrentHandshakesNoCollision starts N concurrent pion
// clients with distinct sessions and verifies that the server side
// adopts each one without dropping any. The data round trip
// confirms each conn ended up bound to the right Tunnel.
func TestConcurrentHandshakesNoCollision(t *testing.T) {
	const N = 4
	cstpSrv := freshCSTPServer(t)

	type slot struct {
		token   string
		psk     []byte
		tun     *cstp.Tunnel
		payload []byte
	}
	slots := make([]*slot, N)
	for i := 0; i < N; i++ {
		token := randSessionToken(t)
		psk := randPSK(t)
		ip6 := netip.MustParsePrefix(fmt.Sprintf("2001:db8::%d/128", 0x100+i))
		tun, _ := makeTunnel(t, cstpSrv, cstp.Identity{
			DeviceID: fmt.Sprintf("dev-%d", i),
			IPv6:     ip6,
			MTU:      1406,
		}, token)
		cstp.RegisterDTLSForTesting(cstpSrv, token, psk, tun)
		slots[i] = &slot{
			token:   token,
			psk:     psk,
			tun:     tun,
			payload: []byte(fmt.Sprintf("payload-%d", i)),
		}
	}

	reg := &cstpServerRegistry{srv: cstpSrv}
	addr := freeUDPAddr(t)
	_ = startDTLS(t, addr, reg)

	// Run clients in parallel.
	errs := make(chan error, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		s := slots[i]
		go func() {
			defer wg.Done()
			udpAddr, _ := net.ResolveUDPAddr("udp", addr)
			cfg := &piondtls.Config{
				PSK: func(_ []byte) ([]byte, error) {
					return s.psk, nil
				},
				PSKIdentityHint: []byte(s.token),
				CipherSuites: []piondtls.CipherSuiteID{
					piondtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
				},
				ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
			}
			conn, err := piondtls.Dial("udp", udpAddr, cfg)
			if err != nil {
				errs <- fmt.Errorf("dial %s: %w", s.token, err)
				return
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := conn.HandshakeContext(ctx); err != nil {
				errs <- fmt.Errorf("handshake %s: %w", s.token, err)
				return
			}
			frame := append([]byte{pktData}, s.payload...)
			if _, err := conn.Write(frame); err != nil {
				errs <- fmt.Errorf("write %s: %w", s.token, err)
				return
			}
			errs <- nil
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatalf("client error: %v", e)
		}
	}

	// Each tunnel must observe exactly its own payload.
	deadline := time.Now().Add(5 * time.Second)
	for _, s := range slots {
		buf := make([]byte, 4096)
		// Spawn the read on a goroutine so we can timeout uniformly.
		got := make(chan readResult, 1)
		go func(tn *cstp.Tunnel, b []byte) {
			n, err := tn.ReadPacket(b)
			got <- readResult{n: n, buf: b[:n], err: err}
		}(s.tun, buf)
		select {
		case r := <-got:
			if r.err != nil {
				t.Fatalf("ReadPacket on %s: %v", s.token, r.err)
			}
			if string(r.buf) != string(s.payload) {
				t.Fatalf("payload mismatch on %s: got %q want %q",
					s.token, r.buf, s.payload)
			}
		case <-time.After(time.Until(deadline)):
			t.Fatalf("ReadPacket on %s timed out", s.token)
		}
	}
}

// TestRekeyTimeBudgetTearsDownDTLS exercises the wall-clock rekey
// deadline: a Server configured with a very short RekeyAfter will
// close the DTLS conn once the deadline fires, but it must NOT close
// the underlying Tunnel — the AnyConnect protocol assumes the CSTP
// control channel survives a DTLS rekey (protocol doc §2.4) and the
// client re-handshakes on the same UDP socket to bring DTLS back up.
//
// We assert two observable contracts:
//
//  1. The pion client side eventually observes a read error after
//     the budget fires — i.e. the conn really did get torn down.
//  2. tun.Identity / tun.SessionID still return live values and a
//     Tunnel-side WritePacket on the CSTP fallback path succeeds.
func TestRekeyTimeBudgetTearsDownDTLS(t *testing.T) {
	cstpSrv := freshCSTPServer(t)

	id := cstp.Identity{
		DeviceID: "dev-rekey-time",
		IPv6:     netip.MustParsePrefix("2001:db8::a/128"),
		MTU:      1406,
	}
	sessionToken := randSessionToken(t)
	psk := randPSK(t)
	tun, cstpClientConn := makeTunnel(t, cstpSrv, id, sessionToken)
	cstp.RegisterDTLSForTesting(cstpSrv, sessionToken, psk, tun)

	// Drain CSTP-side bytes so the fallback WritePacket does not
	// block on the synchronous net.Pipe.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := cstpClientConn.Read(buf); err != nil {
				return
			}
		}
	}()

	reg := &cstpServerRegistry{srv: cstpSrv}
	addr := freeUDPAddr(t)
	_ = startDTLSWithConfig(t, Config{
		Listen:           addr,
		Registry:         reg,
		Logger:           discardLogger(),
		HandshakeTimeout: 3 * time.Second,
		// Very short budget so the test is fast. The 1 GiB byte cap
		// keeps the byte path out of the way; only the time deadline
		// should fire here.
		RekeyAfter:      300 * time.Millisecond,
		RekeyAfterBytes: 1 << 30,
		IdleTimeout:     5 * time.Second,
	})

	client := pionClient(t, addr, sessionToken, psk)

	// Push one frame so the server-side handleConn has progressed
	// past AttachDTLS by the time the rekey deadline fires.
	if _, err := client.Write([]byte{pktData, 'x'}); err != nil {
		t.Fatalf("client write probe: %v", err)
	}
	rxBuf := make([]byte, 32)
	if _, err := tun.ReadPacket(rxBuf); err != nil {
		t.Fatalf("tun.ReadPacket probe: %v", err)
	}

	// Wait for the budget to fire, then confirm the client-side
	// conn really did get closed by the server.
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	_, err := client.Read(buf)
	if err == nil {
		t.Fatalf("client read returned no error; expected close after rekey budget")
	}

	// Sanity: the Tunnel itself is still alive, and a CSTP-fallback
	// WritePacket goes through. The DetachDTLS in handleConn defer
	// has already swapped the data plane back.
	if tun.Identity().DeviceID != "dev-rekey-time" {
		t.Fatalf("tunnel identity changed: %+v", tun.Identity())
	}
	// Wait a beat for handleConn to run its defer.
	time.Sleep(100 * time.Millisecond)
	if _, err := tun.WritePacket([]byte("after-rekey")); err != nil {
		t.Fatalf("Tunnel.WritePacket after DTLS rekey: %v", err)
	}
}

// TestRekeyByteBudgetTearsDownDTLS exercises the same contract but
// fires the byte budget instead. RekeyAfterBytes is set tiny so a
// handful of frames trip the cap. RekeyAfter is set huge so the
// wall-clock deadline cannot fire first.
//
// The byte budget counts bytesIn + bytesOut. Inbound writes from the
// pion client come in via the read loop; outbound writes (server ->
// client) go through Tunnel.writeDTLSFrame and are accounted into the
// shared counter via the AttachDTLSWithCounter wiring. We exercise
// the inbound side here because it's the simpler driver.
func TestRekeyByteBudgetTearsDownDTLS(t *testing.T) {
	cstpSrv := freshCSTPServer(t)

	id := cstp.Identity{
		DeviceID: "dev-rekey-bytes",
		IPv6:     netip.MustParsePrefix("2001:db8::b/128"),
		MTU:      1406,
	}
	sessionToken := randSessionToken(t)
	psk := randPSK(t)
	tun, cstpClientConn := makeTunnel(t, cstpSrv, id, sessionToken)
	cstp.RegisterDTLSForTesting(cstpSrv, sessionToken, psk, tun)

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := cstpClientConn.Read(buf); err != nil {
				return
			}
		}
	}()

	reg := &cstpServerRegistry{srv: cstpSrv}
	addr := freeUDPAddr(t)
	_ = startDTLSWithConfig(t, Config{
		Listen:           addr,
		Registry:         reg,
		Logger:           discardLogger(),
		HandshakeTimeout: 3 * time.Second,
		RekeyAfter:       30 * time.Second, // far away
		// Tiny byte budget: ~64 bytes will trip after the first or
		// second data frame depending on framing overhead.
		RekeyAfterBytes: 64,
		IdleTimeout:     5 * time.Second,
	})

	client := pionClient(t, addr, sessionToken, psk)

	// Send several inbound data frames; each one will push bytesIn
	// well past the 64-byte cap.
	payload := []byte("0123456789ABCDEFGHIJKLMNOPQRSTUV")
	for i := 0; i < 4; i++ {
		frame := append([]byte{pktData}, payload...)
		if _, err := client.Write(frame); err != nil {
			// Once the budget fires the write may fail; that's the
			// observable contract.
			break
		}
		// Drain whatever the Tunnel buffers so subsequent writes
		// don't stall on the data channel.
		buf := make([]byte, 256)
		rxDone := make(chan struct{})
		go func() {
			_, _ = tun.ReadPacket(buf)
			close(rxDone)
		}()
		select {
		case <-rxDone:
		case <-time.After(500 * time.Millisecond):
			// Budget may have already fired and torn the conn down
			// before the inbound frame was delivered; that is fine.
		}
	}

	// Confirm the client-side conn really did get closed by the
	// server: a read should fail within a short window.
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	rbuf := make([]byte, 64)
	if _, err := client.Read(rbuf); err == nil {
		t.Fatalf("client read returned no error after byte budget fired")
	}

	// Tunnel is still alive after the DTLS-side close.
	if tun.Identity().DeviceID != "dev-rekey-bytes" {
		t.Fatalf("tunnel identity changed: %+v", tun.Identity())
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := tun.WritePacket([]byte("after-byte-budget")); err != nil {
		t.Fatalf("Tunnel.WritePacket after DTLS byte budget: %v", err)
	}
}

// TestOutboundDataAccountsAgainstByteBudget proves the shared counter
// wiring works end-to-end: outbound writes through the Tunnel are
// counted toward the DTLS server's rekey byte budget, not just
// inbound ones. Without the AttachDTLSWithCounter plumbing this test
// would never trip the budget.
func TestOutboundDataAccountsAgainstByteBudget(t *testing.T) {
	cstpSrv := freshCSTPServer(t)

	id := cstp.Identity{
		DeviceID: "dev-rekey-outbound",
		IPv6:     netip.MustParsePrefix("2001:db8::c/128"),
		MTU:      1406,
	}
	sessionToken := randSessionToken(t)
	psk := randPSK(t)
	tun, cstpClientConn := makeTunnel(t, cstpSrv, id, sessionToken)
	cstp.RegisterDTLSForTesting(cstpSrv, sessionToken, psk, tun)

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := cstpClientConn.Read(buf); err != nil {
				return
			}
		}
	}()

	reg := &cstpServerRegistry{srv: cstpSrv}
	addr := freeUDPAddr(t)
	_ = startDTLSWithConfig(t, Config{
		Listen:           addr,
		Registry:         reg,
		Logger:           discardLogger(),
		HandshakeTimeout: 3 * time.Second,
		RekeyAfter:       30 * time.Second, // far away
		RekeyAfterBytes:  128,
		IdleTimeout:      5 * time.Second,
	})

	client := pionClient(t, addr, sessionToken, psk)

	// Probe one inbound frame so handleConn finishes AttachDTLS.
	if _, err := client.Write([]byte{pktData, 'p'}); err != nil {
		t.Fatalf("client write probe: %v", err)
	}
	probe := make([]byte, 32)
	if _, err := tun.ReadPacket(probe); err != nil {
		t.Fatalf("tun.ReadPacket probe: %v", err)
	}

	// Read on the client side in the background so the pion socket
	// doesn't fill its receive buffer. The goroutine exits once the
	// conn closes, which is how we detect the server-side teardown.
	rxBuf := make([]byte, 256)
	rxDone := make(chan struct{})
	go func() {
		defer close(rxDone)
		for {
			if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return
			}
			if _, err := client.Read(rxBuf); err != nil {
				return
			}
		}
	}()

	// Drive outbound writes through the Tunnel; interleave small
	// inbound tickles so the server-side read loop wakes up promptly
	// to check the byte budget (the check only runs immediately after
	// a successful Read returns).
	bigPayload := make([]byte, 64)
	for i := range bigPayload {
		bigPayload[i] = 'z'
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := tun.WritePacket(bigPayload); err != nil {
			break
		}
		// Tickle: a 1-byte data frame is enough to wake the read loop.
		if _, err := client.Write([]byte{pktData, '.'}); err != nil {
			break
		}
		select {
		case <-rxDone:
			return
		case <-time.After(20 * time.Millisecond):
		}
		// Drain whatever the Tunnel buffered so the dataCh does not
		// stall on the test's lack of an active ReadPacket consumer.
		drainBuf := make([]byte, 64)
		drainCh := make(chan struct{})
		go func() {
			_, _ = tun.ReadPacket(drainBuf)
			close(drainCh)
		}()
		select {
		case <-drainCh:
		case <-time.After(50 * time.Millisecond):
		}
	}
	select {
	case <-rxDone:
	case <-time.After(time.Second):
		t.Fatalf("byte budget did not trip on outbound writes")
	}
}

// TestServerCloseUnblocksAccept asserts Server.Close terminates
// ListenAndServe cleanly.
func TestServerCloseUnblocksAccept(t *testing.T) {
	reg := newFakeRegistry()
	addr := freeUDPAddr(t)
	srv, err := NewServer(Config{
		Listen:   addr,
		Registry: reg,
		Logger:   discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- srv.ListenAndServe(context.Background())
	}()
	time.Sleep(50 * time.Millisecond)
	_ = srv.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe returned %v after Close", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("ListenAndServe did not return after Close")
	}
}
