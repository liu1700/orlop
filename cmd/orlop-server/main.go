package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const shutdownTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	configPath := flag.String("config", "", "path to YAML config")
	migrateChunks := flag.Bool("migrate-to-chunks", false,
		"migrate every tenant's flat-file storage to content-addressed chunks (issue #76)")
	seed := flag.Bool("seed", false,
		"seed a single virtual path with bytes read from stdin; requires --seed-tenant and --seed-virtual-path")
	seedTenant := flag.String("seed-tenant", "", "tenant id for --seed")
	seedPath := flag.String("seed-virtual-path", "", "virtual path for --seed (e.g. /docs/profile.json)")
	flag.Parse()
	if *configPath == "" {
		logger.Error("missing -config flag")
		os.Exit(1)
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	if *migrateChunks {
		if err := runMigrateToChunks(context.Background(), logger, cfg); err != nil {
			logger.Error("migrate-to-chunks failed", "error", err)
			os.Exit(1)
		}
		return
	}

	if *seed {
		opts := seedOpts{
			tenantID:    *seedTenant,
			virtualPath: *seedPath,
			data:        os.Stdin,
		}
		if err := runSeed(context.Background(), logger, cfg, opts); err != nil {
			logger.Error("seed failed", "error", err)
			os.Exit(1)
		}
		return
	}

	if err := run(context.Background(), logger, cfg); err != nil {
		logger.Error("orlop-server stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, cfg Config) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// TLS material: either self-provisioned at boot (CSR -> orlop-control,
	// private key never leaves this process; retries a cold control plane and
	// rotates in place) or loaded from mounted files. Provisioning uses the
	// signal-cancellable ctx so a SIGTERM during initial sign-up exits cleanly.
	tlsConfig, err := buildTLSConfig(ctx, logger, cfg)
	if err != nil {
		return err
	}

	state, err := newServerState(cfg, certIdentifier{trustDomain: cfg.TrustDomain}, logger)
	if err != nil {
		return err
	}
	defer func() { _ = state.Close() }()

	listener, err := tls.Listen("tcp", cfg.OpsBind, tlsConfig)
	if err != nil {
		return fmt.Errorf("tls listen %s: %w", cfg.OpsBind, err)
	}

	// BaseContext ties every request's r.Context() to the signal-cancellable
	// ctx. http.Server.Shutdown otherwise waits indefinitely for active
	// connections to go idle, which never happens for long-lived handlers
	// (the journal SSE stream keeps a connection open as long as the
	// browser tab is open). Without this, every SIGTERM with an SSE client
	// connected hits the shutdownTimeout and main returns
	// "context deadline exceeded".
	server := &http.Server{
		Handler:           newRouter(state),
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	gc := &gcLoop{
		state:  state,
		cfg:    cfg.GC.Effective(),
		clock:  time.Now,
		logger: logger.With("subsystem", "gc"),
	}
	gcCtx, gcCancel := context.WithCancel(ctx)
	defer gcCancel()
	gcDone := make(chan struct{})
	go func() {
		defer close(gcDone)
		if err := gc.Run(gcCtx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("gc loop exited", "error", err)
		}
	}()

	leaseSweep := newLeaseSweepLoop(state, logger.With("subsystem", "lease_sweep"))
	leaseSweepDone := make(chan struct{})
	go func() {
		defer close(leaseSweepDone)
		if err := leaseSweep.Run(gcCtx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("lease sweep loop exited", "error", err)
		}
	}()

	journalRows := newJournalRowRefreshLoop(state, logger.With("subsystem", "journal_rows_refresh"))
	journalRowsDone := make(chan struct{})
	go func() {
		defer close(journalRowsDone)
		if err := journalRows.Run(gcCtx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("journal rows refresh loop exited", "error", err)
		}
	}()

	errs := make(chan error, 2)
	go func() {
		logger.Info("orlop-server listening with mTLS",
			"ops_bind", cfg.OpsBind,
			"store_root", cfg.StoreRoot,
			"routes_db", cfg.RoutesDB,
		)
		errs <- server.Serve(listener)
	}()

	if cfg.DataBind != "" {
		go func() {
			errs <- runDataPlaneListener(ctx, logger, state, cfg.DataBind, tlsConfig)
		}()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		gcCancel()
		<-gcDone
		<-leaseSweepDone
		<-journalRowsDone
		for _, tid := range state.sortedTenantIDs() {
			ts, ok := state.tenant(tid)
			if !ok || ts.leases == nil {
				continue
			}
			dbPath := filepath.Join(filepath.Dir(ts.routesDB), "leases.db")
			if err := ts.leases.Snapshot(dbPath); err != nil {
				logger.Error("lease snapshot failed", "tenant", ts.id, "error", err)
			}
		}
		logger.Info("orlop-server stopped")
		return nil
	case err := <-errs:
		gcCancel()
		<-gcDone
		<-leaseSweepDone
		<-journalRowsDone
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// buildTLSConfig returns the server's mTLS config, dispatching on whether the
// deployment self-provisions its cert at boot (tls.self_provision) or mounts it
// from files.
func buildTLSConfig(ctx context.Context, logger *slog.Logger, cfg Config) (*tls.Config, error) {
	if cfg.TLSSelfProvision {
		return selfProvisionTLSConfig(ctx, logger, cfg)
	}
	return newTLSConfig(cfg)
}

func newTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.TLSCertFile == "" {
		return nil, errors.New("tls.cert_file is required")
	}
	if cfg.TLSKeyFile == "" {
		return nil, errors.New("tls.key_file is required")
	}
	if cfg.TLSClientCA == "" {
		return nil, errors.New("tls.client_ca_file is required")
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.TLSClientCA)
	if err != nil {
		return nil, fmt.Errorf("read client CA %s: %w", cfg.TLSClientCA, err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse client CA %s: no certificates found", cfg.TLSClientCA)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func serveHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}
