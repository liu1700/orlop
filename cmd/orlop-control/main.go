package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/ca"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/identity"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/secrets"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/serverapi"
)

const shutdownTimeout = 10 * time.Second

type config struct {
	Addr        string
	DatabaseURL string
	SecretsDir  string
	// SecretsBackend selects where the CA (root key + tenant intermediates) lives:
	// "postgres" stores it in the shared DB (no block-storage PVC); anything else
	// (default) uses the filesystem backend at SecretsDir. ORLOP_SECRETS_BACKEND.
	SecretsBackend string
	// SecretsEncKey, when set, AES-256-GCM-encrypts CA values at rest (hex-encoded
	// 32-byte key). Strongly recommended with SecretsBackend=postgres so the root
	// key is not stored in plaintext. ORLOP_SECRETS_ENC_KEY.
	SecretsEncKey string
	// AllowPlaintextSecrets opts in to storing the CA root key UNENCRYPTED. With
	// SecretsBackend=postgres and no SecretsEncKey, boot fails closed unless this
	// is set — so a misconfigured deploy can't silently persist the master signing
	// key in plaintext (visible in DB backups/replicas/pg_dump).
	// ORLOP_SECRETS_ALLOW_PLAINTEXT=1.
	AllowPlaintextSecrets bool
	TrustDomain           string
	OrgName               string
	CookieDomain          string
	// ControlPlaneToken is the shared service token the orlop control-plane
	// presents on /v1/entities (and future service-to-service routes).
	// ORLOP_CONTROL_PLANE_TOKEN. RequireServiceToken fails closed when empty,
	// so the provisioning API stays unmounted/unauthenticated-rejecting until
	// this is set.
	ControlPlaneToken string
	// InitialGrantBytes is the elastic disk size a registered agent is granted at
	// provision when the caller passes no quota_bytes. ORLOP_INITIAL_GRANT_BYTES.
	InitialGrantBytes int64
	// ServerCertFQDN is the only name POST /control/sign-server-cert will issue a
	// self-provisioned orlop-server cert for (CN + DNS SAN). Defaults to the
	// in-cluster Service name `orlop-server`. ORLOP_DATAGW_SERVER_FQDN.
	ServerCertFQDN string
	// ServerCertTTL is the validity of a self-provisioned server cert; the server
	// re-signs before it expires. ORLOP_DATAGW_SERVER_CERT_TTL (e.g. "2160h").
	ServerCertTTL time.Duration
	// APITokenTTL, when > 0, sets an expiry on newly minted orlop_ API tokens.
	// 0 (default) means tokens never expire. ORLOP_API_TOKEN_TTL (e.g. "2160h").
	APITokenTTL time.Duration

	// Mode B host-identity verifier (docs/design-identity.md §3). When
	// IdentityAudience is set, orlop-control verifies a host-issued signed JWT
	// and maps an allowlisted claim onto the tenant subject. All
	// ORLOP_IDENTITY_* knobs.
	IdentityIssuer          string // ORLOP_IDENTITY_ISSUER (optional; pins iss)
	IdentityAudience        string // ORLOP_IDENTITY_AUDIENCE (enables Mode B; pins aud)
	IdentityPublicKeyFile   string // ORLOP_IDENTITY_PUBLIC_KEY_FILE (PKIX PEM)
	IdentityTenantClaim     string // ORLOP_IDENTITY_TENANT_CLAIM (default "tenant")
	IdentityTenantAllowlist string // ORLOP_IDENTITY_TENANT_ALLOWLIST (comma-separated, fail-closed)

	// CATenantAllowlist gates lazy tenant-intermediate bootstrap (issue #8):
	// comma-separated tenant ids that may be bootstrapped on first enroll, on top
	// of the server-derived dynamic per-user/per-agent tenants (see
	// CAAllowDynamicTenants). ORLOP_CA_TENANT_ALLOWLIST.
	CATenantAllowlist string
	// CAAllowDynamicTenants permits lazy bootstrap of the server-derived dynamic
	// per-user ("u_") and per-agent ("a_") tenants. Default true (the hosted-MVP
	// enroll flow relies on it); set ORLOP_CA_ALLOW_DYNAMIC_TENANTS=false to lock
	// bootstrap down to CATenantAllowlist only.
	CAAllowDynamicTenants bool
}

func loadConfig() (config, error) {
	port := getenv("PORT", "8080")
	allowDynamicTenants, err := parseBoolEnv("ORLOP_CA_ALLOW_DYNAMIC_TENANTS", true)
	if err != nil {
		return config{}, err
	}
	return config{
		Addr:                  ":" + port,
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		SecretsDir:            os.Getenv("ORLOP_SECRETS_DIR"),
		SecretsBackend:        os.Getenv("ORLOP_SECRETS_BACKEND"),
		SecretsEncKey:         os.Getenv("ORLOP_SECRETS_ENC_KEY"),
		AllowPlaintextSecrets: os.Getenv("ORLOP_SECRETS_ALLOW_PLAINTEXT") == "1",
		TrustDomain:           getenv("ORLOP_TRUST_DOMAIN", "orlop.example"),
		OrgName:               getenv("ORLOP_ORG_NAME", "ORL"),
		CookieDomain:          os.Getenv("ORLOP_COOKIE_DOMAIN"),
		ControlPlaneToken:     os.Getenv("ORLOP_CONTROL_PLANE_TOKEN"),
		InitialGrantBytes:     atoi64Or(os.Getenv("ORLOP_INITIAL_GRANT_BYTES"), agentDiskInitialGrantBytes),
		ServerCertFQDN:        getenv("ORLOP_DATAGW_SERVER_FQDN", defaultServerCertFQDN),
		ServerCertTTL:         parseDurationOr(os.Getenv("ORLOP_DATAGW_SERVER_CERT_TTL"), defaultServerCertTTL),
		APITokenTTL:           parseDurationOr(os.Getenv("ORLOP_API_TOKEN_TTL"), 0),

		IdentityIssuer:          os.Getenv("ORLOP_IDENTITY_ISSUER"),
		IdentityAudience:        os.Getenv("ORLOP_IDENTITY_AUDIENCE"),
		IdentityPublicKeyFile:   os.Getenv("ORLOP_IDENTITY_PUBLIC_KEY_FILE"),
		IdentityTenantClaim:     os.Getenv("ORLOP_IDENTITY_TENANT_CLAIM"),
		IdentityTenantAllowlist: os.Getenv("ORLOP_IDENTITY_TENANT_ALLOWLIST"),

		CATenantAllowlist:     os.Getenv("ORLOP_CA_TENANT_ALLOWLIST"),
		CAAllowDynamicTenants: allowDynamicTenants,
	}, nil
}

// parseBoolEnv parses a boolean env var. An unset/blank value yields fallback;
// "1"/"true"/"yes"/"on" and "0"/"false"/"no"/"off" (case-insensitive) parse as
// expected. A set-but-unrecognized value is an ERROR rather than a silent
// fallback — a typo on a security toggle (e.g. ORLOP_CA_ALLOW_DYNAMIC_TENANTS)
// must fail boot, not quietly leave the permissive default in force.
func parseBoolEnv(key string, fallback bool) (bool, error) {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(key))); v {
	case "":
		return fallback, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s: unrecognized boolean %q (use true/false)", key, v)
	}
}

// buildCATenantPolicy builds the predicate that gates lazy tenant-intermediate
// bootstrap (issue #8). A tenant id may be bootstrapped if it is explicitly
// listed in ORLOP_CA_TENANT_ALLOWLIST, or — when dynamic tenants are enabled —
// if it is a server-derived per-user ("u_") or per-agent ("a_") tenant. Any
// other id (e.g. an arbitrary value mapped from a future BYO-IdP claim) is
// refused, so it cannot self-onboard a tenant the operator never registered.
func buildCATenantPolicy(cfg config) func(string) bool {
	allow := map[string]struct{}{}
	for _, t := range strings.Split(cfg.CATenantAllowlist, ",") {
		if t = strings.TrimSpace(t); t != "" {
			allow[t] = struct{}{}
		}
	}
	allowDynamic := cfg.CAAllowDynamicTenants
	return func(tenantID string) bool {
		if _, ok := allow[tenantID]; ok {
			return true
		}
		if allowDynamic && (strings.HasPrefix(tenantID, tenantPrefixUser) || strings.HasPrefix(tenantID, tenantPrefixAgent)) {
			return true
		}
		return false
	}
}

// checkCASecretsAtRest fails closed when the CA root key — the master signing
// key for the whole mTLS isolation system — would be persisted UNENCRYPTED in
// shared Postgres (where it lands in backups, replicas, and pg_dump output).
// An operator must either set ORLOP_SECRETS_ENC_KEY (recommended) or explicitly
// opt in with ORLOP_SECRETS_ALLOW_PLAINTEXT=1, so a misconfigured deploy can't
// do this silently. The filesystem backend (0600 files) is the traditional
// model and is not gated.
func checkCASecretsAtRest(cfg config, logger *slog.Logger) error {
	if cfg.SecretsBackend != "postgres" || cfg.SecretsEncKey != "" {
		return nil
	}
	if !cfg.AllowPlaintextSecrets {
		return fmt.Errorf("refusing to store the CA root key unencrypted in Postgres: " +
			"set ORLOP_SECRETS_ENC_KEY (a hex-encoded 32-byte AES key, recommended), " +
			"or ORLOP_SECRETS_ALLOW_PLAINTEXT=1 to keep the previous behavior")
	}
	if logger != nil {
		logger.Warn("CA root key stored UNENCRYPTED in Postgres " +
			"(ORLOP_SECRETS_ALLOW_PLAINTEXT=1); set ORLOP_SECRETS_ENC_KEY to encrypt at rest")
	}
	return nil
}

func parseDurationOr(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

func atoi64Or(s string, fallback int64) int64 {
	if s == "" {
		return fallback
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

// parseFloatFractionOr parses a ratio in (0,1]; anything malformed or out of
// range falls back (a 0 or >1 autoscale threshold would be nonsensical).
func parseFloatFractionOr(s string, fallback float64) float64 {
	if s == "" {
		return fallback
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v <= 0 || v > 1 {
		return fallback
	}
	return v
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "ca":
			if err := runCA(context.Background(), os.Stdout, os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "orlop-control ca:", err)
				os.Exit(1)
			}
			return
		case "migrate":
			if err := runMigrate(context.Background(), os.Stdout, os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "orlop-control migrate:", err)
				os.Exit(1)
			}
			return
		case "user":
			if err := runUser(context.Background(), os.Stdout, os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "orlop-control user:", err)
				os.Exit(1)
			}
			return
		case "token":
			if err := runToken(context.Background(), os.Stdout, os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "orlop-control token:", err)
				os.Exit(1)
			}
			return
		case "server":
			if err := runServer(context.Background(), os.Stdout, os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "orlop-control server:", err)
				os.Exit(1)
			}
			return
		}
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := loadConfig()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	if err := run(context.Background(), logger, cfg); err != nil {
		logger.Error("orlop-control stopped", "error", err)
		os.Exit(1)
	}
}

// runtimeDeps bundles the live dependencies the HTTP layer needs. When
// DATABASE_URL is unset (e.g. unit tests of the bare server), devAuth
// is nil and the device-flow routes are not mounted.
type runtimeDeps struct {
	devAuth          *devauth.Service
	allocations      *allocations.Service
	queries          db.Store
	agentCA          *ca.CA
	enrollLimit      *agentEnrollLimiter
	serverAdmin      allocations.ServerAdmin
	serverUsage      tenantUsageClient
	serverResize     allocations.TenantResizer
	journalQuerier   journalQuerier
	mountLeaseFencer mountLeaseFencer
	agentPurger      allocations.AgentDataPurger
	certRevReconcile *certRevocationReconciler
	hostIdentity     identity.Verifier
	cookieDomain     string
}

func run(ctx context.Context, logger *slog.Logger, cfg config) error {
	deps := runtimeDeps{}
	// Mode B host-identity verifier. Independent of the DB: it verifies a
	// host-issued JWT and maps an allowlisted claim onto the tenant subject. A
	// misconfiguration fails startup (fail closed) rather than silently leaving
	// the seam unguarded.
	if cfg.IdentityAudience != "" {
		v, err := buildHostIdentityVerifier(cfg)
		if err != nil {
			return fmt.Errorf("host identity verifier: %w", err)
		}
		deps.hostIdentity = v
		logger.Info("host_identity_enabled", "audience", cfg.IdentityAudience, "issuer", cfg.IdentityIssuer)
	}
	var pool *pgxpool.Pool
	if cfg.DatabaseURL != "" {
		var err error
		pool, err = pgxpool.New(ctx, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("open pgxpool: %w", err)
		}
		defer pool.Close()
		deps.queries = sqlcdb.New(pool)
		deps.devAuth = devauth.NewService(pool, logger)
		deps.allocations = allocations.NewService(pool, logger)
		deps.cookieDomain = cfg.CookieDomain
		// CA storage backend: "postgres" keeps the root key + tenant intermediates
		// in this shared DB (no block-storage PVC); otherwise the filesystem backend
		// at SecretsDir. pool is non-nil here (we are inside the DatabaseURL branch).
		var caBackend secrets.Backend
		switch cfg.SecretsBackend {
		case "postgres":
			caBackend = secrets.NewPostgres(pool)
		default:
			if cfg.SecretsDir != "" {
				caBackend = secrets.NewFilesystem(cfg.SecretsDir)
			}
		}
		if err := checkCASecretsAtRest(cfg, logger); err != nil {
			return err
		}
		// Encrypt CA values at rest (AES-256-GCM) when a key is configured — keeps
		// the root key out of plaintext storage (esp. the postgres backend).
		if caBackend != nil && cfg.SecretsEncKey != "" {
			encKey, err := hex.DecodeString(cfg.SecretsEncKey)
			if err != nil {
				return fmt.Errorf("ORLOP_SECRETS_ENC_KEY: invalid hex: %w", err)
			}
			caBackend, err = secrets.NewEncrypted(caBackend, encKey)
			if err != nil {
				return fmt.Errorf("enable CA-at-rest encryption: %w", err)
			}
		}
		if caBackend != nil {
			agentCA, err := ca.LoadOrInit(ctx, caBackend, ca.Env{
				TrustDomain:    cfg.TrustDomain,
				OrgName:        cfg.OrgName,
				AllowBootstrap: buildCATenantPolicy(cfg),
			})
			if err != nil {
				return fmt.Errorf("load ca: %w", err)
			}
			deps.agentCA = agentCA

			certPEM, keyPEM, serial, err := agentCA.MintControlPlaneCert(30 * 24 * time.Hour)
			if err != nil {
				return fmt.Errorf("mint control-plane cert: %w", err)
			}
			logger.Info("orlop-control issued control-plane cert", "serial", serial)

			rootPool := x509.NewCertPool()
			rootPool.AppendCertsFromPEM(agentCA.RootPEM())
			adminClient, err := serverapi.New(serverapi.Config{
				ClientCertPEM: certPEM,
				ClientKeyPEM:  keyPEM,
				ServerCAPool:  rootPool,
				Logger:        logger,
			})
			if err != nil {
				return fmt.Errorf("build server admin client: %w", err)
			}
			deps.serverAdmin = adminClient
			deps.serverUsage = adminClient
			deps.serverResize = adminClient
			deps.journalQuerier = &serverapiJournalAdapter{
				client:  adminClient,
				queries: deps.queries,
			}
			deps.mountLeaseFencer = &serverapiMountLeaseFencer{
				client:  adminClient,
				queries: deps.queries,
			}
			deps.agentPurger = serverapiAgentPurger{client: adminClient}
			deps.certRevReconcile = newCertRevocationReconciler(deps.queries, adminClient, logger)
		}
	}

	router := newRouter(logger, deps, cfg)
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Fan the cert deny-list out to data-plane servers and keep them converged
	// (issue #5). Stops when ctx is cancelled on shutdown.
	if deps.certRevReconcile != nil {
		go deps.certRevReconcile.Run(ctx)
	}

	// (Storage auto-grow removed: an account's disk is a fixed budget — included +
	// purchased — enforced as one shared JuiceFS quota on the owner tenant dir, set at
	// placement and on the buy path. No usage-watermark growth.)

	errs := make(chan error, 1)
	go func() {
		logger.Info("starting orlop-control",
			"addr", cfg.Addr,
			"database_url_configured", cfg.DatabaseURL != "",
			"device_flow_enabled", deps.devAuth != nil,
			"dashboard_enabled", deps.devAuth != nil && deps.queries != nil && deps.allocations != nil,
			"agent_enroll_enabled", deps.devAuth != nil && deps.queries != nil && deps.agentCA != nil,
		)
		errs <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		logger.Info("orlop-control stopped")
		return nil
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func newRouter(logger *slog.Logger, deps runtimeDeps, cfg config) http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Recoverer)
	router.Use(requestLogger(logger))

	router.Get("/healthz", healthz)

	if deps.devAuth != nil {
		mountDeviceFlow(router, newDevAuthHandlers(logger, deps.devAuth, deps.allocations, deps.cookieDomain))
	}
	if deps.devAuth != nil && deps.queries != nil && deps.allocations != nil {
		mountDashboard(router, newDashboardHandlers(logger, deps.devAuth, deps.queries, deps.allocations, deps.serverUsage, deps.mountLeaseFencer))
		mountLeaseRoutes(router, newMountLeaseHandlers(logger, deps.allocations, deps.queries, deps.devAuth, deps.mountLeaseFencer))
	}
	if deps.devAuth != nil && deps.queries != nil {
		mountAPITokens(router, newAPITokenHandlers(logger, deps.devAuth, deps.queries, cfg.APITokenTTL))
	}
	// /v1/entities + /v1/agents/{id}/enroll-token are control-plane→control-plane
	// surfaces, gated by the static service token (RequireServiceToken fails
	// closed when ORLOP_CONTROL_PLANE_TOKEN is unset). Entities needs the
	// DB-backed queries; the enroll-token minter additionally needs devAuth.
	if deps.devAuth != nil && deps.queries != nil {
		mountEntities(router, RequireServiceToken(cfg.ControlPlaneToken),
			newEntityHandlers(logger, deps.queries, deps.devAuth.IssueAgentEnrollToken, deps.allocations, deps.serverResize, deps.allocations, deps.agentPurger, cfg.InitialGrantBytes))
	}
	// POST /v1/admin/purge-sweep: on-demand erase of revoked-but-unpurged
	// allocations' backend data. Same service-token gate as /v1/entities.
	if deps.queries != nil && deps.allocations != nil {
		mountPurgeSweep(router, RequireServiceToken(cfg.ControlPlaneToken),
			newPurgeSweepHandlers(logger, deps.queries, deps.allocations, deps.agentPurger))
	}
	// GET /v1/tenants/{owner}/usage: per-user disk usage for the control-plane's
	// storage meter, same static-token gate as /v1/entities. serverUsage may be
	// nil (no SecretsDir) — the handler then 503s rather than crashing.
	if deps.queries != nil {
		mountControlTenantUsage(router, RequireServiceToken(cfg.ControlPlaneToken),
			newControlTenantUsageHandlers(logger, deps.queries, deps.serverUsage))
	}
	if deps.devAuth != nil && deps.allocations != nil && deps.queries != nil && deps.journalQuerier != nil {
		mountJournal(router, newJournalHandlers(deps.devAuth, deps.allocations, deps.queries, deps.journalQuerier))
	}
	if deps.devAuth != nil && deps.queries != nil && deps.agentCA != nil {
		mountAgentEnroll(router, RequireEnrollBearer(deps.devAuth, deps.queries), newAgentEnrollHandlers(logger, deps.queries, deps.devAuth, deps.agentCA, deps.enrollLimit, deps.allocations, deps.serverAdmin))
	}
	// POST /control/sign-server-cert: orlop-server self-provisions its TLS
	// cert at boot by sending a CSR here (private key stays in its pod). Same
	// static service-token gate as /v1/entities; requires the CA's root key.
	if deps.agentCA != nil {
		mountServerCert(router, RequireServiceToken(cfg.ControlPlaneToken),
			newServerCertHandlers(logger, deps.agentCA, cfg.ServerCertFQDN, cfg.ServerCertTTL))
	}
	// Mode B: GET /v1/whoami behind the host-identity verifier (mounted only
	// when ORLOP_IDENTITY_AUDIENCE is configured).
	if deps.hostIdentity != nil {
		mountHostIdentity(router, RequireHostIdentity(deps.hostIdentity, logger))
	}

	return router
}

// buildHostIdentityVerifier constructs the Mode B JWT verifier from config.
// Reads the PKIX public key from ORLOP_IDENTITY_PUBLIC_KEY_FILE.
func buildHostIdentityVerifier(cfg config) (identity.Verifier, error) {
	if cfg.IdentityPublicKeyFile == "" {
		return nil, fmt.Errorf("ORLOP_IDENTITY_PUBLIC_KEY_FILE is required when ORLOP_IDENTITY_AUDIENCE is set")
	}
	pubPEM, err := os.ReadFile(cfg.IdentityPublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}
	var allow []string
	for _, t := range strings.Split(cfg.IdentityTenantAllowlist, ",") {
		if t = strings.TrimSpace(t); t != "" {
			allow = append(allow, t)
		}
	}
	return identity.NewJWTVerifier(identity.JWTConfig{
		Issuer:          cfg.IdentityIssuer,
		Audience:        cfg.IdentityAudience,
		PublicKeyPEM:    pubPEM,
		TenantClaim:     cfg.IdentityTenantClaim,
		TenantAllowlist: allow,
	})
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", middleware.GetReqID(r.Context()),
			)
		})
	}
}

func healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// serverapiJournalAdapter adapts *serverapi.Client to the journalQuerier
// interface declared in journal_handlers.go. It looks up the tenant's
// opsAddr at query time via the DB (same pattern as dashboard_handlers.go
// handleAllocationUsage) so the adapter carries no per-tenant state.
type serverapiJournalAdapter struct {
	client  *serverapi.Client
	queries interface {
		GetServerVMByTenant(ctx context.Context, tenantID string) (sqlcdb.ServerVm, error)
		GetServerPoolByDataAddr(ctx context.Context, dataAddr string) (sqlcdb.ServerPool, error)
	}
}

func (a *serverapiJournalAdapter) QueryJournal(
	ctx context.Context,
	tenantID, allocationID string,
	limit uint32,
	cursor string,
) ([]journalEntryJSON, string, error) {
	opsAddr, ok, err := a.opsAddrFor(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		// User has never allocated a disk — empty journal by construction.
		return []journalEntryJSON{}, "", nil
	}

	res, err := a.client.QueryJournal(ctx, opsAddr, tenantID, allocationID, limit, cursor)
	if err != nil {
		return nil, "", err
	}

	out := make([]journalEntryJSON, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, fromServerJournalEntry(e))
	}
	return out, res.NextCursor, nil
}

// QueryJournalAfterSeq is the backfill counterpart: ascending-seq rows for
// the allocation with seq > afterSeq. allocationID is required.
func (a *serverapiJournalAdapter) QueryJournalAfterSeq(
	ctx context.Context,
	tenantID, allocationID string,
	limit uint32,
	afterSeq uint64,
) ([]journalEntryJSON, error) {
	opsAddr, ok, err := a.opsAddrFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return []journalEntryJSON{}, nil
	}
	res, err := a.client.QueryJournalAfterSeq(ctx, opsAddr, tenantID, allocationID, limit, afterSeq)
	if err != nil {
		return nil, err
	}
	out := make([]journalEntryJSON, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, fromServerJournalEntry(e))
	}
	return out, nil
}

// StreamJournal opens the SSE pipe to orlop-server and translates each
// JournalEntry into the journalEntryJSON shape used by the public-facing
// handlers. The returned channel mirrors the server-side channel: it closes
// when the SSE body ends, ctx is cancelled, or a read error occurs.
//
// A small adapter goroutine forwards entries to the caller-visible channel
// so the public type doesn't leak the internal serverapi.JournalEntry shape.
func (a *serverapiJournalAdapter) StreamJournal(
	ctx context.Context,
	tenantID, allocationID string,
	afterSeq uint64,
) (<-chan journalEntryJSON, error) {
	opsAddr, ok, err := a.opsAddrFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !ok {
		// No server vm yet → empty closed channel. The caller's WS handler
		// will see ch close immediately and return cleanly.
		ch := make(chan journalEntryJSON)
		close(ch)
		return ch, nil
	}
	upstream, err := a.client.StreamJournal(ctx, opsAddr, tenantID, allocationID, afterSeq)
	if err != nil {
		return nil, err
	}
	out := make(chan journalEntryJSON, 64)
	go func() {
		defer close(out)
		for e := range upstream {
			select {
			case out <- fromServerJournalEntry(e):
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// RevertPath calls orlop-server's POST /control/tenants/{id}/journal/revert.
// agentID is recorded on the inverse journal row.
func (a *serverapiJournalAdapter) RevertPath(
	ctx context.Context,
	tenantID, allocationID, sessionID, path string,
	seq uint64,
	force bool,
	agentID string,
) (revertResult, error) {
	opsAddr, ok, err := a.opsAddrFor(ctx, tenantID)
	if err != nil {
		return revertResult{}, err
	}
	if !ok {
		// No data plane for this tenant yet. Treat the row the user clicked
		// as gone — nothing to revert against.
		return revertResult{Ok: false, Conflict: &revertConflict{Reason: reasonNoJournalRow}}, nil
	}
	res, err := a.client.RevertJournalPath(ctx, opsAddr, tenantID, allocationID, sessionID, path, seq, force, agentID)
	if err != nil {
		return revertResult{}, err
	}
	out := revertResult{Ok: res.Ok}
	if res.Conflict != nil {
		out.Conflict = &revertConflict{Reason: res.Conflict.Reason}
	}
	return out, nil
}

// opsAddrFor resolves a tenant's orlop-server ops address. Returns ok=false
// when the user has not yet provisioned an allocation (ErrNoRows on
// server_vms) — the journal is empty by construction in that case.
func (a *serverapiJournalAdapter) opsAddrFor(ctx context.Context, tenantID string) (string, bool, error) {
	vm, err := a.queries.GetServerVMByTenant(ctx, tenantID)
	if errors.Is(err, db.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("journal adapter: get server vm: %w", err)
	}
	pool, err := a.queries.GetServerPoolByDataAddr(ctx, vm.DataAddr)
	if err != nil {
		return "", false, fmt.Errorf("journal adapter: get server pool: %w", err)
	}
	return pool.OpsAddr, true, nil
}

func fromServerJournalEntry(e serverapi.JournalEntry) journalEntryJSON {
	return journalEntryJSON{
		SessionID:     e.SessionID,
		AllocationID:  e.AllocationID,
		Seq:           e.Seq,
		TsUnixMs:      e.TsUnixMs,
		Path:          e.Path,
		Op:            e.Op,
		AgentID:       e.AgentID,
		BeforeVersion: e.BeforeVersion,
		AfterVersion:  e.AfterVersion,
		RenameFrom:    e.RenameFrom,
		SizeBefore:    e.SizeBefore,
		SizeAfter:     e.SizeAfter,
	}
}

// serverapiMountLeaseFencer adapts *serverapi.Client to the mountLeaseFencer
// interface declared in dashboard_handlers.go. Looks up the tenant's opsAddr
// at call time via the DB so the adapter carries no per-tenant state.
type serverapiMountLeaseFencer struct {
	client  *serverapi.Client
	queries interface {
		GetServerVMByTenant(ctx context.Context, tenantID string) (sqlcdb.ServerVm, error)
		GetServerPoolByDataAddr(ctx context.Context, dataAddr string) (sqlcdb.ServerPool, error)
	}
}

func (a *serverapiMountLeaseFencer) FenceAllocation(ctx context.Context, tenantID, allocationID string) error {
	vm, err := a.queries.GetServerVMByTenant(ctx, tenantID)
	if errors.Is(err, db.ErrNotFound) {
		// No server-pool placement for this tenant (single-node / no populated server_pool):
		// there is no remote data-plane registry to clear, so fencing is a clean no-op rather
		// than an error. The local dg-server's stale active-lease slot is instead taken over
		// by the next mount's Install (mount_lease_registry.go), mirroring the DB-lease
		// takeover that already happens unconditionally one layer up.
		return nil
	}
	if err != nil {
		return fmt.Errorf("fence: get server vm: %w", err)
	}
	pool, err := a.queries.GetServerPoolByDataAddr(ctx, vm.DataAddr)
	if err != nil {
		return fmt.Errorf("fence: get server pool: %w", err)
	}
	return a.client.ClearActiveMountLease(ctx, pool.OpsAddr, tenantID, allocationID)
}

// serverapiAgentPurger adapts *serverapi.Client to allocations.AgentDataPurger
// (the purge path only needs error-or-not from the per-agent erase; the
// detailed counts stay in the client's own logs).
type serverapiAgentPurger struct {
	client *serverapi.Client
}

func (p serverapiAgentPurger) PurgeAgentData(ctx context.Context, opsAddr, tenantID, agentID string) error {
	_, err := p.client.PurgeAgentData(ctx, opsAddr, tenantID, agentID)
	return err
}

func (p serverapiAgentPurger) UnregisterTenant(ctx context.Context, opsAddr, tenantID string) error {
	return p.client.UnregisterTenant(ctx, opsAddr, tenantID)
}

func (p serverapiAgentPurger) ClearActiveMountLease(ctx context.Context, opsAddr, tenantID, allocationID string) error {
	return p.client.ClearActiveMountLease(ctx, opsAddr, tenantID, allocationID)
}
