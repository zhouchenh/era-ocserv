package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/auth"
	"github.com/zhouchenh/era-ocserv/internal/certctx"
	"github.com/zhouchenh/era-ocserv/internal/cstp"
	"github.com/zhouchenh/era-ocserv/internal/iam"
	"github.com/zhouchenh/era-ocserv/internal/tun"
	"github.com/zhouchenh/era-ocserv/internal/udshandoff"
	"github.com/zhouchenh/era-ocserv/internal/udsserve"
)

type config struct {
	mode          string
	udsSocketPath string
	listenAddr    string
	tlsCertPath   string
	tlsKeyPath    string
	clientCAPath  string
	portalURL     string
	portalToken   string
	tpmURL        string
	tpmToken      string
	tunName       string
	tunMTU        int
	tunQueues     int
	tunIPv6       string
	serverName    string
	dnsServers    string
	defaultDomain string
	logLevel      string
}

func parseFlags() config {
	var c config
	flag.StringVar(&c.mode, "mode", "auto",
		"listener mode: auto|uds|legacy. auto = UDS if -uds-socket parent dir exists, else legacy. "+
			"UDS mode consumes facade plaintext handoffs per ADR-F7 Stage 2; legacy = own TLS at -listen (pre-cutover compat).")
	flag.StringVar(&c.udsSocketPath, "uds-socket", udsserve.DefaultSocketPath,
		"UDS socket path the facade connects to. Used by -mode=uds and by -mode=auto when the parent dir exists.")
	flag.StringVar(&c.listenAddr, "listen", "127.0.0.1:8444", "(legacy mode) loopback TCP listen address for CSTP")
	flag.StringVar(&c.tlsCertPath, "tls-cert", "", "(legacy mode) path to TLS cert PEM")
	flag.StringVar(&c.tlsKeyPath, "tls-key", "", "(legacy mode) path to TLS key PEM")
	flag.StringVar(&c.clientCAPath, "client-ca", "", "(legacy mode) path to ERA PKI client CA PEM for mTLS")
	flag.StringVar(&c.portalURL, "era-portal-url", "", "era-portal base URL for password verification (required)")
	flag.StringVar(&c.portalToken, "era-portal-token", "", "era-portal service token (required)")
	flag.StringVar(&c.tpmURL, "tpm-url", "", "TPM provisioning base URL (required)")
	flag.StringVar(&c.tpmToken, "tpm-token", "", "TPM service token (required)")
	flag.StringVar(&c.tunName, "tun-name", "era-ocserv-tun", "tun interface name")
	flag.IntVar(&c.tunMTU, "tun-mtu", 1500, "tun MTU")
	flag.IntVar(&c.tunQueues, "tun-queues", 0, "tun queue count (0 = default min(NumCPU, 4))")
	flag.StringVar(&c.tunIPv6, "tun-ipv6", "", "tun's own /128 IPv6 (e.g. 2001:470:f9d1:9001:ffff::1/128); empty leaves unset")
	flag.StringVar(&c.serverName, "server-name", "vpn.eracloud.app", "SNI / server name advertised in CSTP")
	flag.StringVar(&c.dnsServers, "dns", "2606:4700:4700::1111,2606:4700:4700::1001", "comma-separated DNS servers pushed via X-CSTP-DNS")
	flag.StringVar(&c.defaultDomain, "default-domain", "", "DNS default domain pushed via X-CSTP-Default-Domain")
	flag.StringVar(&c.logLevel, "log-level", "info", "log level: debug|info|warn|error")
	flag.Parse()
	return c
}

func main() {
	if err := run(); err != nil {
		slog.Error("era-ocserv exited", "err", err)
		os.Exit(1)
	}
}

// listenerMode is the resolved-after-auto choice between UDS plaintext
// (ADR-F7 Stage 2) and legacy loopback TCP+TLS (pre-cutover compat).
type listenerMode int

const (
	modeLegacy listenerMode = iota
	modeUDS
)

func (m listenerMode) String() string {
	switch m {
	case modeUDS:
		return "uds"
	case modeLegacy:
		return "legacy"
	default:
		return "unknown"
	}
}

func resolveMode(cfg config) (listenerMode, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.mode)) {
	case "uds":
		return modeUDS, nil
	case "legacy":
		return modeLegacy, nil
	case "", "auto":
		// Auto-detect: UDS if the socket parent directory exists,
		// legacy otherwise. The facade's systemd unit creates the
		// directory at boot; on hosts where the facade is not deployed
		// the dir is absent and we fall back to legacy. This is the
		// graceful-cutover knob the Wave II spec asks for.
		dir := filepath.Dir(cfg.udsSocketPath)
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			return modeUDS, nil
		}
		return modeLegacy, nil
	default:
		return modeLegacy, fmt.Errorf("unknown -mode %q (want auto|uds|legacy)", cfg.mode)
	}
}

func run() error {
	cfg := parseFlags()
	if err := setupLogger(cfg.logLevel); err != nil {
		return err
	}
	mode, err := resolveMode(cfg)
	if err != nil {
		return err
	}
	if err := requireFlags(cfg, mode); err != nil {
		return err
	}

	var (
		tlsCfg *tls.Config
		cv     *auth.CertValidator
	)
	if mode == modeLegacy {
		tlsCfg, err = loadTLS(cfg)
		if err != nil {
			return fmt.Errorf("load TLS: %w", err)
		}
		cv = auth.NewCertValidator(auth.CertValidatorConfig{
			ClientCAs:    tlsCfg.ClientCAs,
			SubjectField: "CN",
		})
	}

	dev, err := openTun(cfg)
	if err != nil {
		return fmt.Errorf("open tun: %w", err)
	}
	defer dev.Close()
	slog.Info("tun opened", "name", dev.Name(), "queues", len(dev.Queues()), "mtu", cfg.tunMTU)

	portalBase, err := url.Parse(cfg.portalURL)
	if err != nil {
		return fmt.Errorf("parse era-portal-url: %w", err)
	}
	hv := auth.NewHTTPVerifier(auth.HTTPVerifierConfig{
		BaseURL:      portalBase,
		ServiceToken: cfg.portalToken,
	})

	tpmBase, err := url.Parse(cfg.tpmURL)
	if err != nil {
		return fmt.Errorf("parse tpm-url: %w", err)
	}
	tpmResolver := iam.NewTPMResolver(iam.TPMResolverConfig{
		BaseURL:      tpmBase,
		ServiceToken: cfg.tpmToken,
	})

	dns, err := parseDNS(cfg.dnsServers)
	if err != nil {
		return fmt.Errorf("parse dns: %w", err)
	}

	srv := cstp.NewServer(cstp.Config{
		Verifier:          certBoundVerifier{inner: hv},
		Resolver:          resolverAdapter{inner: tpmResolver},
		ServerName:        cfg.serverName,
		DNS:               dns,
		DefaultDomain:     cfg.defaultDomain,
		DefaultMTU:        cfg.tunMTU,
		DPDInterval:       30,
		KeepaliveInterval: 20,
		IdleTimeout:       1800,
		SessionTimeout:    24 * time.Hour,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	br := newBridge(dev, srv)
	go br.run(ctx)

	switch mode {
	case modeUDS:
		return runUDS(ctx, cfg, srv)
	case modeLegacy:
		return runLegacy(ctx, cfg, tlsCfg, cv, srv)
	default:
		return fmt.Errorf("unreachable: mode=%v", mode)
	}
}

// runUDS is the ADR-F7 Stage 2 path: era-facade hands us plaintext UDS
// streams pre-TLS-decrypted, with the validated client-cert Subject DN
// in TLV form. No own TLS, no own loopback TCP listener.
func runUDS(ctx context.Context, cfg config, srv *cstp.Server) error {
	metrics := udshandoff.NewMetrics()
	udsLogger := slog.Default().With(slog.String("component", "udsserve"))
	uds, err := udsserve.Listen(ctx, udsserve.Options{
		SocketPath: cfg.udsSocketPath,
		Logger:     udsLogger,
		Metrics:    metrics,
		Handler:    srv,
	})
	if err != nil {
		return fmt.Errorf("udsserve listen: %w", err)
	}
	slog.Info("era-ocserv listening (uds mode)",
		"socket", uds.SocketPath(),
		"server_name", cfg.serverName,
	)
	go func() {
		<-ctx.Done()
		slog.Info("shutdown signal received")
		// Order matters: cstp.Server.Close terminates any in-flight
		// hijacked tunnels (their conns close, the per-stream
		// goroutines in udshandoff unblock). Only then does
		// udsserve.Close return promptly — otherwise its underlying
		// udshandoff wg.Wait would block on the hijacked goroutines.
		srv.Close()
		if err := uds.Close(); err != nil {
			slog.Warn("udsserve close failed", "err", err)
		}
	}()
	<-ctx.Done()
	slog.Info("era-ocserv stopped (uds mode)")
	return nil
}

// runLegacy is the pre-cutover loopback TCP+TLS path. Kept operational
// so a deploy can fall back without rebuilding. Defaults flip to UDS
// when the facade's socket directory is present.
func runLegacy(ctx context.Context, cfg config, tlsCfg *tls.Config, cv *auth.CertValidator, srv *cstp.Server) error {
	ln, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.listenAddr, err)
	}
	tlsLn := tls.NewListener(ln, tlsCfg)

	httpSrv := &http.Server{
		Handler:           certMiddleware(cv, srv),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		slog.Info("shutdown signal received")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		httpSrv.Shutdown(shutdownCtx)
		srv.Close()
	}()

	slog.Info("era-ocserv listening (legacy mode)",
		"addr", cfg.listenAddr,
		"server_name", cfg.serverName,
	)
	if err := httpSrv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http serve: %w", err)
	}
	slog.Info("era-ocserv stopped (legacy mode)")
	return nil
}

func setupLogger(level string) error {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return fmt.Errorf("unknown log level: %s", level)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
	return nil
}

// requireFlags validates that the flags this mode actually consumes are
// non-empty. UDS-mode skips the TLS+clientCA triple because era-facade
// does that work upstream.
func requireFlags(cfg config, mode listenerMode) error {
	missing := []string{}
	if mode == modeLegacy {
		if cfg.tlsCertPath == "" {
			missing = append(missing, "-tls-cert")
		}
		if cfg.tlsKeyPath == "" {
			missing = append(missing, "-tls-key")
		}
		if cfg.clientCAPath == "" {
			missing = append(missing, "-client-ca")
		}
	}
	if cfg.portalURL == "" {
		missing = append(missing, "-era-portal-url")
	}
	if cfg.portalToken == "" {
		missing = append(missing, "-era-portal-token")
	}
	if cfg.tpmURL == "" {
		missing = append(missing, "-tpm-url")
	}
	if cfg.tpmToken == "" {
		missing = append(missing, "-tpm-token")
	}
	if mode == modeUDS && cfg.udsSocketPath == "" {
		missing = append(missing, "-uds-socket")
	}
	if len(missing) > 0 {
		return fmt.Errorf("required flags missing (mode=%s): %s", mode, strings.Join(missing, ", "))
	}
	return nil
}

func loadTLS(cfg config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.tlsCertPath, cfg.tlsKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certs parsed from %s", cfg.clientCAPath)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

func openTun(cfg config) (*tun.Device, error) {
	opts := tun.Options{
		Name:   cfg.tunName,
		MTU:    cfg.tunMTU,
		Queues: cfg.tunQueues,
	}
	if cfg.tunIPv6 != "" {
		prefix, err := netip.ParsePrefix(cfg.tunIPv6)
		if err != nil {
			return nil, fmt.Errorf("parse tun-ipv6: %w", err)
		}
		opts.IPv6 = prefix
	}
	return tun.Open(opts)
}

func parseDNS(s string) ([]netip.Addr, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]netip.Addr, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		a, err := netip.ParseAddr(p)
		if err != nil {
			return nil, fmt.Errorf("bad dns addr %q: %w", p, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// certMiddleware is the legacy-mode (loopback TCP+TLS) cert handler. It
// extracts the device id from the live TLS state, then stores it on the
// request context via certctx for the certBoundVerifier downstream.
//
// UDS-mode does the equivalent extraction earlier, from
// `ERA_TLV_MTLS_SUBJECT_DN`, and uses the same certctx key — see
// internal/udsserve.
func certMiddleware(cv *auth.CertValidator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusBadRequest)
			return
		}
		deviceID, err := cv.Validate(*r.TLS)
		if err != nil {
			slog.Warn("cert validate failed", "err", err, "remote", r.RemoteAddr)
			http.Error(w, "client cert required", http.StatusUnauthorized)
			return
		}
		ctx := certctx.WithDeviceID(r.Context(), deviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type certBoundVerifier struct {
	inner auth.PasswordVerifier
}

func (v certBoundVerifier) Verify(ctx context.Context, username, password string) (string, error) {
	certID, ok := certctx.FromContext(ctx)
	if !ok {
		return "", errors.New("internal: no cert deviceID in context")
	}
	pwID, err := v.inner.Verify(ctx, username, password)
	if err != nil {
		return "", err
	}
	if pwID != certID {
		slog.Warn("cert/password deviceID mismatch", "cert_id", certID, "pw_id", pwID)
		return "", auth.ErrBadCredentials
	}
	return certID, nil
}

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
