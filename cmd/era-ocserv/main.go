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
	"strings"
	"syscall"
	"time"

	"github.com/zhouchenh/era-ocserv/internal/auth"
	"github.com/zhouchenh/era-ocserv/internal/bridge"
	"github.com/zhouchenh/era-ocserv/internal/cstp"
	"github.com/zhouchenh/era-ocserv/internal/iam"
	"github.com/zhouchenh/era-ocserv/internal/tun"
)

type config struct {
	listenAddr     string
	tlsCertPath    string
	tlsKeyPath     string
	clientCAPath   string
	portalURL      string
	portalToken    string
	tpmURL         string
	tpmToken       string
	tunName        string
	tunMTU         int
	tunQueues      int
	tunIPv6        string
	serverName     string
	dnsServers     string
	defaultDomain  string
	logLevel       string
}

func parseFlags() config {
	var c config
	flag.StringVar(&c.listenAddr, "listen", "127.0.0.1:8444", "loopback TCP listen address for CSTP")
	flag.StringVar(&c.tlsCertPath, "tls-cert", "", "path to TLS cert PEM (required)")
	flag.StringVar(&c.tlsKeyPath, "tls-key", "", "path to TLS key PEM (required)")
	flag.StringVar(&c.clientCAPath, "client-ca", "", "path to ERA PKI client CA PEM (required for mTLS)")
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

func run() error {
	cfg := parseFlags()
	if err := setupLogger(cfg.logLevel); err != nil {
		return err
	}
	if err := requireFlags(cfg); err != nil {
		return err
	}

	tlsCfg, err := loadTLS(cfg)
	if err != nil {
		return fmt.Errorf("load TLS: %w", err)
	}

	dev, err := openTun(cfg)
	if err != nil {
		return fmt.Errorf("open tun: %w", err)
	}
	defer dev.Close()
	slog.Info("tun opened", "name", dev.Name(), "queues", len(dev.Queues()), "mtu", cfg.tunMTU)

	cv := auth.NewCertValidator(auth.CertValidatorConfig{
		ClientCAs:    tlsCfg.ClientCAs,
		SubjectField: "CN",
	})

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
		CertValidator:     cv,
		ServerName:        cfg.serverName,
		DNS:               dns,
		DefaultDomain:     cfg.defaultDomain,
		DefaultMTU:        cfg.tunMTU,
		DPDInterval:       30,
		KeepaliveInterval: 20,
		IdleTimeout:       1800,
		SessionTimeout:    24 * time.Hour,
	})

	ln, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.listenAddr, err)
	}
	tlsLn := tls.NewListener(ln, tlsCfg)

	httpSrv := &http.Server{
		Handler:           certMiddleware(cv, srv),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	br := bridge.New(tunDeviceAdapter{dev: dev}, srv)
	go br.Run(ctx)

	go func() {
		<-ctx.Done()
		slog.Info("shutdown signal received")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		httpSrv.Shutdown(shutdownCtx)
		srv.Close()
	}()

	slog.Info("era-ocserv listening", "addr", cfg.listenAddr, "server_name", cfg.serverName)
	if err := httpSrv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http serve: %w", err)
	}
	slog.Info("era-ocserv stopped")
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

func requireFlags(cfg config) error {
	missing := []string{}
	if cfg.tlsCertPath == "" {
		missing = append(missing, "-tls-cert")
	}
	if cfg.tlsKeyPath == "" {
		missing = append(missing, "-tls-key")
	}
	if cfg.clientCAPath == "" {
		missing = append(missing, "-client-ca")
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
	if len(missing) > 0 {
		return fmt.Errorf("required flags missing: %s", strings.Join(missing, ", "))
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
			slog.Warn("cert validate failed", "err", err, "remote", r.RemoteAddr)
			http.Error(w, "client cert required", http.StatusUnauthorized)
			return
		}
		ctx := contextWithCertDeviceID(r.Context(), deviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func contextWithCertDeviceID(ctx context.Context, deviceID string) context.Context {
	return context.WithValue(ctx, certDeviceIDKey, deviceID)
}

func certDeviceIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(certDeviceIDKey).(string)
	return v, ok && v != ""
}

type certBoundVerifier struct {
	inner auth.PasswordVerifier
}

func (v certBoundVerifier) Verify(ctx context.Context, username, password string) (string, error) {
	certID, ok := certDeviceIDFromContext(ctx)
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

// tunDeviceAdapter satisfies bridge.Device for the production
// *tun.Device. It exists so the bridge package depends on a narrow
// interface (Read/Write per queue) rather than the Linux-only
// concrete type, which lets cross-platform tests substitute a fake.
type tunDeviceAdapter struct {
	dev *tun.Device
}

func (a tunDeviceAdapter) Queues() []bridge.QueueIO {
	src := a.dev.Queues()
	out := make([]bridge.QueueIO, len(src))
	for i, q := range src {
		out[i] = q
	}
	return out
}
