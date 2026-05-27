package e2e_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/auth"
	"github.com/zhouchenh/era-ocserv/internal/bridge"
	"github.com/zhouchenh/era-ocserv/internal/cstp"
	"github.com/zhouchenh/era-ocserv/internal/iam"
)

// canonicalDeviceID is the device id the canned client cert and the
// MockVerifier agree on. Twenty-six lowercase base32 'a's after the
// dev_ prefix satisfies internal/auth/deviceid.go's regex.
const canonicalDeviceID = "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa"

// canonicalIPv6 is the /128 the MockResolver hands back for the
// canonical device id. The brief specifies "2001:470:f9d1:9001:2a::ff/128".
const canonicalIPv6 = "2001:470:f9d1:9001:2a::ff/128"

// harness is one fully-wired era-ocserv Stage 1 gateway running in
// memory. Tests construct it with newHarness and tear it down with
// Close (registered as a t.Cleanup automatically). The exported
// fields let tests reach into the verifier / resolver / fake tun for
// assertions without going through the wire.
type harness struct {
	t  *testing.T
	pk *pki

	cfg       cstp.Config
	cstpSrv   *cstp.Server
	httpSrv   *http.Server
	tlsConfig *tls.Config

	tun    *fakeTunDevice
	br     *bridge.Bridge
	ctx    context.Context
	cancel context.CancelFunc

	verifier *auth.MockVerifier
	resolver *iam.MockResolver
	certVal  *auth.CertValidator

	// addr is the bound loopback address the fake client dials.
	addr string

	// goroutineBaseline is the count of goroutines at construction
	// time; the shutdown test compares against this.
	goroutineBaseline int

	// wg waits for httpSrv.Serve and the bridge goroutine to return.
	wg sync.WaitGroup

	closed bool
	closeM sync.Mutex
}

// harnessOpt mutates Config or wiring before the server starts.
type harnessOpt func(*harness)

// withDPDInterval overrides the X-CSTP-DPD interval. Used by the DPD
// fires-within-interval test.
func withDPDInterval(seconds int) harnessOpt {
	return func(h *harness) {
		h.cfg.DPDInterval = seconds
	}
}

// withKeepaliveInterval overrides X-CSTP-Keepalive.
func withKeepaliveInterval(seconds int) harnessOpt {
	return func(h *harness) {
		h.cfg.KeepaliveInterval = seconds
	}
}

// withDTLSAdvertise enables the X-DTLS-* header emission gate. Used
// by tests that exercise the Stage 2 DTLS-on path; Stage 1 default
// keeps it disabled so clients do not stall on a UDP handshake
// against a server that does not listen.
func withDTLSAdvertise() harnessOpt {
	return func(h *harness) {
		h.cfg.DTLSAdvertise = true
	}
}

// newHarness brings up a full Stage 1 gateway: TLS listener, CSTP
// server, MockVerifier seeded with one credential, MockResolver
// seeded with the canonical /128, fake tun, and bridge. The harness
// registers a Cleanup; tests do not need to call Close themselves.
func newHarness(t *testing.T, opts ...harnessOpt) *harness {
	t.Helper()

	pk := newPKI(t)

	verifier := &auth.MockVerifier{}
	verifier.Set("alice", "hunter2", canonicalDeviceID)

	resolver := &iam.MockResolver{}
	resolver.Set(canonicalDeviceID, iam.Identity{
		IPv6: netip.MustParsePrefix(canonicalIPv6),
		MTU:  1500,
	})

	certVal := auth.NewCertValidator(auth.CertValidatorConfig{
		ClientCAs:    pk.clientRoots,
		SubjectField: "CN",
	})

	h := &harness{
		t:         t,
		pk:        pk,
		tun:       newFakeTunDevice(1),
		verifier:  verifier,
		resolver:  resolver,
		certVal:   certVal,
		tlsConfig: pk.serverTLSConfig(),
		cfg: cstp.Config{
			ServerName:        "vpn.eracloud.app",
			DNS:               []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")},
			DefaultMTU:        1500,
			DPDInterval:       30,
			KeepaliveInterval: 20,
			IdleTimeout:       1800,
			SessionTimeout:    time.Hour,
		},
	}
	for _, o := range opts {
		o(h)
	}

	// Stitch the same cert-bound verifier adapter the production
	// main.go wraps HTTPVerifier in. Without this, the password
	// verifier and the cert validator can disagree about deviceID.
	h.cfg.Verifier = certBoundAdapter{inner: verifier}
	h.cfg.Resolver = resolverAdapter{inner: resolver}
	// Wire the cert validator so the phase-3 CONNECT handler re-binds
	// the inbound cert to the deviceID stored at promote time (spec
	// §1.8 / ADR 0057 §4). Mirrors production main.go.
	h.cfg.CertValidator = certVal

	h.cstpSrv = cstp.NewServer(h.cfg)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", h.tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	h.addr = ln.Addr().String()

	h.httpSrv = &http.Server{
		Handler:           certMiddleware(certVal, h.cstpSrv),
		ReadHeaderTimeout: 5 * time.Second,
	}

	h.ctx, h.cancel = context.WithCancel(context.Background())
	h.br = bridge.New(h.tun, h.cstpSrv)

	h.goroutineBaseline = runtime.NumGoroutine()

	h.wg.Add(2)
	go func() {
		defer h.wg.Done()
		_ = h.httpSrv.Serve(ln)
	}()
	go func() {
		defer h.wg.Done()
		h.br.Run(h.ctx)
	}()

	t.Cleanup(func() {
		h.Close()
	})
	return h
}

// Close shuts the harness down idempotently. It is registered with
// t.Cleanup so tests rarely call it explicitly.
func (h *harness) Close() {
	h.closeM.Lock()
	defer h.closeM.Unlock()
	if h.closed {
		return
	}
	h.closed = true

	// Cancel the bridge first so it stops Accept'ing.
	h.cancel()

	// Stop accepting new TLS conns and abort in-flight ones.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = h.httpSrv.Shutdown(shutdownCtx)

	// Close the CSTP server. This wakes any goroutine blocked on
	// Accept with ErrServerClosed and closes pending tunnels.
	_ = h.cstpSrv.Close()

	// Tear down the fake tun so any pending Read returns EOF.
	h.tun.Close()

	// Wait for the listener + bridge goroutines to actually return.
	h.wg.Wait()
}

// goroutineDelta returns NumGoroutine() - the baseline captured at
// harness construction. Used by the shutdown test to assert we don't
// leak goroutines once Close completes.
func (h *harness) goroutineDelta() int {
	return runtime.NumGoroutine() - h.goroutineBaseline
}

// certBoundAdapter mirrors cmd/era-ocserv/main.go's
// certBoundVerifier: it pairs the password verifier's deviceID with
// the cert validator's deviceID and rejects on mismatch. The cert
// validator stashes the deviceID in the context via certMiddleware
// below before the cstp handler runs.
type certBoundAdapter struct {
	inner auth.PasswordVerifier
}

func (a certBoundAdapter) Verify(ctx context.Context, username, password string) (string, error) {
	certID, ok := certDeviceIDFromContext(ctx)
	if !ok {
		return "", errors.New("e2e: no cert deviceID in context")
	}
	pwID, err := a.inner.Verify(ctx, username, password)
	if err != nil {
		return "", err
	}
	if pwID != certID {
		return "", auth.ErrBadCredentials
	}
	return certID, nil
}

// resolverAdapter mirrors cmd/era-ocserv/main.go's resolverAdapter:
// it bridges iam.Identity -> cstp.Identity.
type resolverAdapter struct {
	inner iam.Resolver
}

func (r resolverAdapter) Resolve(ctx context.Context, deviceID string) (cstp.Identity, error) {
	id, err := r.inner.Resolve(ctx, deviceID)
	if err != nil {
		return cstp.Identity{}, err
	}
	return cstp.Identity{
		DeviceID: id.DeviceID,
		IPv6:     id.IPv6,
		MTU:      id.MTU,
	}, nil
}

// ctxKey is the context-key type used to thread the cert-validated
// deviceID from the middleware to the certBoundAdapter. Same shape
// as cmd/era-ocserv/main.go.
type ctxKey int

const certDeviceIDKey ctxKey = iota

func certMiddleware(cv *auth.CertValidator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusBadRequest)
			return
		}
		deviceID, err := cv.Validate(*r.TLS)
		if err != nil {
			http.Error(w, "client cert required", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), certDeviceIDKey, deviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func certDeviceIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(certDeviceIDKey).(string)
	return v, ok && v != ""
}

// fmtAddr returns the harness's bound loopback address as a string
// the fake client can pass to net.Dial. Provided as a method so tests
// don't reach into h.addr directly.
func (h *harness) Address() string { return h.addr }

// waitForCondition polls fn at a tight interval until it returns
// (true, nil) or timeout elapses. Returns the last error fn produced
// (or context.DeadlineExceeded if fn never returned true).
func waitForCondition(timeout time.Duration, interval time.Duration, fn func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		ok, err := fn()
		if ok {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return lastErr
			}
			return context.DeadlineExceeded
		}
		time.Sleep(interval)
	}
}

// makeIPv6Packet constructs a minimal IPv6 packet with the given src
// and dst addresses and arbitrary payload. The bridge's tun->tunnel
// path matches on the destination address (bytes 24..40 of the header)
// to route the packet to the right client.
func makeIPv6Packet(src, dst netip.Addr, payload []byte) []byte {
	if !src.Is6() || !dst.Is6() {
		panic("makeIPv6Packet requires IPv6 addresses")
	}
	pkt := make([]byte, 40+len(payload))
	pkt[0] = 0x60 // version 6, traffic class 0
	pkt[4] = byte(len(payload) >> 8)
	pkt[5] = byte(len(payload))
	pkt[6] = 59 // next-header = no-next-header (sentinel; we never send this past the tun)
	pkt[7] = 64 // hop limit
	sb := src.As16()
	db := dst.As16()
	copy(pkt[8:24], sb[:])
	copy(pkt[24:40], db[:])
	copy(pkt[40:], payload)
	return pkt
}

