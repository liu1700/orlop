package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/liu1700/orlop/cmd/orlop-server/internal/quota"
)

// serverState carries the dependencies each handler needs. Constructed once
// at startup and read concurrently — TenantDB and AuditLog handle their own
// locking.
type serverState struct {
	mu         sync.RWMutex
	tenants    map[string]*tenantState
	policy     *Policy
	audit      *AuditLog
	metrics    *serverMetrics
	identifier Identifier
	uid        uint32
	gid        uint32
	conns      *connRegistry
	logger     *slog.Logger
	quota      *quota.Manager
	// quotaApply, when non-nil, applies account quotas in the background instead
	// of inline in registerTenant/setAccountQuota (cfg.QuotaApplyAsync). Nil when
	// disabled or when there is no quota manager.
	quotaApply  *accountQuotaApplier
	adminCfg    adminConfig
	trustDomain string
	// mountLeases is the authoritative active-lease record per allocation,
	// pushed from orlop-control. Writes whose session_id does not match the
	// registered lease are rejected — see mount_lease_registry.go and #175.
	mountLeases *mountLeaseRegistry
	// certRevocations is the in-memory serial deny-list pushed from orlop-control
	// (issue #5). A revoked client leaf is refused at session start, before any
	// frame is served — the data-plane kill switch. See cert_revocation_registry.go.
	certRevocations *certRevocationRegistry

	// tenantRegLocks serializes register/unregister/resize of the SAME tenant so
	// concurrent same-id operations stay idempotent and leak-free, WITHOUT holding
	// mu across a new tenant's slow JuiceFS filesystem init. Different tenants take
	// different keys and proceed in parallel; data-plane tenant lookups (mu.RLock)
	// are never blocked for the duration of a registration (#119).
	tenantRegLocks keyedMutex
	// regFileMu serializes writes to registered_tenants.json. Now that different
	// tenants persist off mu (each under its own tenantRegLocks key), this guards
	// the shared load→mutate→atomic-rename file so one write cannot clobber another.
	regFileMu sync.Mutex

	// beforeTenantInit, when non-nil, is invoked inside registerTenant after the
	// existence check but before the (unlocked) filesystem/tenant-state init. Tests
	// set it to block a specific tenant's slow init and prove other tenants still
	// register and existing tenants still resolve. Always nil in production.
	beforeTenantInit func(tenantID string)

	// connSem bounds concurrent framed sessions; reqSem bounds concurrent
	// in-flight request handlers. Both are buffered-channel semaphores sized at
	// construction (see dos_hardening.go). Nil-safe: a serverState built without
	// newServerState (some tests) runs unbounded.
	connSem chan struct{}
	reqSem  chan struct{}
}

// adminConfig holds config for the dynamic tenant registration endpoint.
type adminConfig struct {
	TenantsRoot           string
	MetadataRoot          string
	RegisteredTenantsPath string
	LeaseCfg              leaseConfig
}

// tenant returns the tenantState for id under a read lock.
func (s *serverState) tenant(id string) (*tenantState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts, ok := s.tenants[id]
	return ts, ok
}

type tenantState struct {
	id        string
	name      string
	db        *TenantDB
	storeRoot string
	routesDB  string // full path to routes.db; leases.db sits beside it (the metadata dir)
	chunks    *ChunkStore
	manifests *ManifestStore
	journal   *SessionJournal
	leases    *leaseManager
	// changes fans metadata change-feed doorbells out to subscribed data
	// connections (issue #122). Nil-safe: test fixtures that build
	// tenantState by hand can leave it unset.
	changes *changeNotifier

	// liveMu guards closed. A data-plane store mutation (chunk Put) takes it for
	// reading across the whole write; unregisterTenant takes it for writing to set
	// closed=true immediately before os.RemoveAll. That ordering fences the
	// "dying pod recreates an orphan tenant dir after unregister" race (#103): a
	// write from a still-open connection whose pod is being torn down either
	// completes before RemoveAll (and is removed with the dir) or observes closed
	// and refuses without touching disk — it can never os.MkdirAll the tenant dir
	// back after RemoveAll has run.
	liveMu sync.RWMutex
	closed bool
}

// errTenantGone is returned by tenant store mutations attempted after the
// tenant has been unregistered (see liveMu), instead of silently recreating
// the tenant's on-disk directory.
var errTenantGone = errors.New("tenant unregistered")

// putChunk stores a chunk through the tenant's content-addressed store unless
// the tenant has been torn down. It holds liveMu for reading across the entire
// store write (see liveMu for the ordering invariant). Chunk Put is the only
// data-plane write that MkdirAll's the tenant directory — a manifest write
// instead hits the already-closed routes.db and fails — so this is the one
// mutation that must be gated.
func (t *tenantState) putChunk(hash, data []byte) (bool, error) {
	t.liveMu.RLock()
	defer t.liveMu.RUnlock()
	if t.closed {
		return false, errTenantGone
	}
	return t.chunks.Put(hash, data)
}

// markClosed flips the tenant's write gate so no later store mutation can
// recreate its on-disk state, and blocks until in-flight writes drain (the write
// lock waits out every reader). unregisterTenant calls it immediately before
// os.RemoveAll.
func (t *tenantState) markClosed() {
	t.liveMu.Lock()
	t.closed = true
	t.liveMu.Unlock()
}

func newServerState(cfg Config, identifier Identifier, logger *slog.Logger) (*serverState, error) {
	if logger == nil {
		logger = slog.Default()
	}
	policy, err := NewPolicy(cfg.Allow, cfg.Deny)
	if err != nil {
		return nil, err
	}
	audit, err := NewAuditLog(cfg.AuditLog)
	if err != nil {
		return nil, err
	}
	conns := newConnRegistry()
	metrics := newServerMetrics()
	leaseCfg := cfg.Lease.Effective()
	tenants := make(map[string]*tenantState, len(cfg.Tenants))
	for _, tenant := range cfg.Tenants {
		ts, err := openTenantState(tenant.ID, tenant.Name, tenant.StoreRoot, tenant.RoutesDB, leaseCfg, conns, audit, metrics)
		if err != nil {
			_ = audit.Close()
			_ = closeTenants(tenants)
			return nil, err
		}
		tenants[tenant.ID] = ts
	}

	// Load dynamically registered tenants from the persisted JSON file.
	if cfg.RegisteredTenantsPath != "" {
		registered, err := loadRegisteredTenants(cfg.RegisteredTenantsPath)
		if err != nil {
			_ = audit.Close()
			_ = closeTenants(tenants)
			return nil, fmt.Errorf("load registered tenants: %w", err)
		}
		for _, rt := range registered {
			if _, dup := tenants[rt.ID]; dup {
				continue // static config wins
			}
			ts, err := openTenantState(rt.ID, rt.Name, rt.StoreRoot, rt.RoutesDB, leaseCfg, conns, audit, metrics)
			if err != nil {
				logger.Warn("skipping registered tenant: open failed", "tenant_id", rt.ID, "error", err)
				continue
			}
			tenants[rt.ID] = ts
		}
	}

	if len(tenants) == 0 && cfg.TenantsRoot == "" {
		_ = audit.Close()
		return nil, fmt.Errorf("at least one tenant is required")
	}

	var qm *quota.Manager
	if cfg.TenantsRoot != "" {
		statePath := filepath.Join(filepath.Dir(cfg.RegisteredTenantsPath), "quota_state.json")
		quotaOpts := []quota.Option{quota.WithBurstMargin(cfg.QuotaBurstMarginBytes)}
		if cfg.QuotaBackend == "juicefs" {
			quotaOpts = append(quotaOpts, quota.WithJuiceFS(cfg.QuotaJuicefsMetaURL, cfg.QuotaJuicefsMountRoot))
		}
		qm, err = quota.NewManager(statePath, cfg.TenantsRoot, quota.DefaultExec(), logger.With("subsystem", "quota"), cfg.QuotaEnforce, quotaOpts...)
		if err != nil {
			_ = audit.Close()
			_ = closeTenants(tenants)
			return nil, fmt.Errorf("quota manager: %w", err)
		}
		if !cfg.QuotaEnforce {
			// With enforcement off there is NO per-tenant disk cap at any layer, so
			// one agent writing unique chunks can fill the host disk for every
			// tenant (a per-chunk size cap bounds per-write amplification, not the
			// total). Production must enable ext4 project quota or a JuiceFS
			// directory quota. Loud at boot so this isn't a silent footgun.
			logger.Warn("disk quota enforcement is OFF (quota.enforce=false): " +
				"per-tenant disk usage is NOT capped; one agent can fill the host disk for all tenants. " +
				"Enable ext4 project quota or a JuiceFS directory quota for production.")
		}
	}

	var quotaApply *accountQuotaApplier
	if qm != nil && cfg.QuotaApplyAsync {
		quotaApply = newAccountQuotaApplier(qm, logger.With("subsystem", "quota"))
	}

	return &serverState{
		tenants:         tenants,
		policy:          policy,
		audit:           audit,
		metrics:         metrics,
		identifier:      identifier,
		uid:             uint32(os.Getuid()),
		gid:             uint32(os.Getgid()),
		conns:           conns,
		logger:          logger,
		quota:           qm,
		quotaApply:      quotaApply,
		trustDomain:     cfg.TrustDomain,
		mountLeases:     newMountLeaseRegistry(),
		certRevocations: newCertRevocationRegistry(),
		connSem:         make(chan struct{}, maxDataPlaneSessions),
		reqSem:          make(chan struct{}, maxInFlightRequests),
		adminCfg: adminConfig{
			TenantsRoot:           cfg.TenantsRoot,
			MetadataRoot:          cfg.MetadataRoot,
			RegisteredTenantsPath: cfg.RegisteredTenantsPath,
			LeaseCfg:              leaseCfg,
		},
	}, nil
}

// openTenantState opens all per-tenant resources for a single tenant entry.
// dbPath is routes.db (the metadata dir); leases.db is co-located beside it, so
// both the latency-critical SQLite files follow metadata_root (e.g. an NVMe disk)
// while the chunk store stays under storeRoot (e.g. JuiceFS).
func openTenantState(id, name, storeRoot, dbPath string, leaseCfg leaseConfig, conns *connRegistry, audit *AuditLog, metrics *serverMetrics) (*tenantState, error) {
	// The metadata dir may differ from storeRoot (split disks) and may not exist
	// yet on the boot-reopen path; create it before opening the SQLite handle.
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
		return nil, fmt.Errorf("mkdir metadata dir for %s: %w", id, err)
	}
	tdb, err := OpenTenantDB(dbPath)
	if err != nil {
		return nil, err
	}
	chunks, err := NewChunkStore(storeRoot)
	if err != nil {
		_ = tdb.Close()
		return nil, err
	}
	if _, err := tdb.DB().Exec(`drop table if exists sessions`); err != nil {
		_ = tdb.Close()
		return nil, fmt.Errorf("drop sessions table: %w", err)
	}
	journal := NewSessionJournal(tdb.DB(), metrics)
	if err := journal.EnsureSchema(); err != nil {
		_ = tdb.Close()
		return nil, err
	}
	ts := &tenantState{
		id:        id,
		name:      name,
		db:        tdb,
		storeRoot: storeRoot,
		routesDB:  dbPath,
		chunks:    chunks,
		manifests: NewManifestStore(tdb.DB(), metrics),
		journal:   journal,
		leases:    newLeaseManager(leaseCfg, conns.Push, audit, metrics),
		changes:   newChangeNotifier(),
	}
	ts.manifests.SetJournal(journal)
	ts.manifests.SetChangeNotify(ts.changes.Notify)
	leasesPath := filepath.Join(filepath.Dir(dbPath), "leases.db")
	if _, err := os.Stat(leasesPath); err == nil {
		if err := ts.leases.Restore(leasesPath); err != nil {
			_ = tdb.Close()
			return nil, fmt.Errorf("restore leases for %s: %w", id, err)
		}
	}
	return ts, nil
}

// sortedTenantIDs returns tenant IDs in deterministic ascending order
// — used by the GC sweeper so test ordering is stable and one slow
// tenant cannot affect the outcome of another's sweep.
func (s *serverState) sortedTenantIDs() []string {
	s.mu.RLock()
	ids := make([]string, 0, len(s.tenants))
	for id := range s.tenants {
		ids = append(ids, id)
	}
	s.mu.RUnlock()
	sort.Strings(ids)
	return ids
}

func (s *serverState) Close() error {
	if s.quotaApply != nil {
		s.quotaApply.Stop()
	}
	s.mu.Lock()
	tenants := s.tenants
	s.mu.Unlock()
	if err := s.audit.Close(); err != nil {
		_ = closeTenants(tenants)
		return err
	}
	return closeTenants(tenants)
}

func newRouter(state *serverState) http.Handler {
	r := chi.NewRouter()
	// /healthz and /metrics are unauthenticated by design — health checks and
	// Prometheus scrapers don't carry mTLS client certs.
	r.Get("/healthz", serveHealthz)
	if state.metrics != nil {
		r.Method(http.MethodGet, "/metrics", state.metrics.handler())
	}
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware(state))
		r.Get("/audit", state.getAudit)
	})
	r.Group(func(r chi.Router) {
		r.Use(controlPlaneOnlyMiddleware(state))
		r.Put("/control/cert-revocations", state.pushCertRevocations)
		r.Post("/control/tenants", state.registerTenant)
		r.Patch("/control/tenants/{id}", state.resizeTenant)
		r.Patch("/control/accounts/{owner}/quota", state.setAccountQuota)
		r.Delete("/control/tenants/{id}", state.unregisterTenant)
		r.Delete("/control/tenants/{id}/agents/{agentID}", state.purgeAgentData)
		r.Get("/control/tenants/{id}/usage", state.tenantUsage)
		r.Get("/control/tenants/{id}/journal", state.tenantJournalQuery)
		r.Get("/control/tenants/{id}/journal/stream", state.tenantJournalStream)
		r.Post("/control/tenants/{id}/journal/revert", state.tenantJournalRevert)
		r.Delete("/control/tenants/{id}/allocations/{alloc}/mount-lease", state.clearActiveMountLease)
		r.Get("/control/tenants/{id}/allocations/{alloc}/mount-lease", state.mountSessionStatus)
	})
	return r
}

// authMiddleware resolves the caller's identity and attaches it to the
// request context. On hosted deployments the TLS handshake has already
// verified the client cert; this middleware exposes its subject to handlers
// and rejects requests that somehow reached HTTP without a peer certificate.
func authMiddleware(state *serverState) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ident, ok := IdentityFromContext(r.Context()); ok {
				if _, ok := state.tenant(ident.TenantID); !ok {
					err := fmt.Errorf("tenant %q is not configured on this server", ident.TenantID)
					state.recordAuthFailure(r, ident)
					writeJSONError(w, http.StatusForbidden, "tenant_forbidden", err.Error())
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			ident, err := state.identifier.Identify(r)
			if err != nil {
				state.recordAuthFailure(r, ident)
				writeJSONError(w, http.StatusForbidden, "forbidden", err.Error())
				return
			}
			if _, ok := state.tenant(ident.TenantID); !ok {
				err := fmt.Errorf("tenant %q is not configured on this server", ident.TenantID)
				state.recordAuthFailure(r, ident)
				writeJSONError(w, http.StatusForbidden, "tenant_forbidden", err.Error())
				return
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), ident)))
		})
	}
}

// controlPlaneOnlyMiddleware gates routes to the control-plane identity only.
// Both production and test paths converge on controlPlaneTenantID as the
// sentinel: production sets it after mTLS URI verification; tests set it via
// context injection. Real mTLS certs must carry the configured trust-domain
// control-plane SPIFFE URI SAN.
func controlPlaneOnlyMiddleware(state *serverState) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Test path: identity already injected into context.
			if ident, ok := IdentityFromContext(r.Context()); ok {
				if ident.TenantID != controlPlaneTenantID {
					writeJSONError(w, http.StatusForbidden, "forbidden", "control plane cert required")
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			// Production path: read the peer cert from mTLS.
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				writeJSONError(w, http.StatusForbidden, "forbidden", "mTLS client cert required")
				return
			}
			cert := r.TLS.PeerCertificates[0]
			if !isControlPlaneCert(cert, state.trustDomain) {
				writeJSONError(w, http.StatusForbidden, "forbidden", "control plane cert required")
				return
			}
			ident := identityFromCert(cert, controlPlaneTenantID)
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), ident)))
		})
	}
}

// controlPlaneTenantID is the unified sentinel for "this identity is the
// control plane." It is set by both paths in controlPlaneOnlyMiddleware: by
// mTLS URI verification in production, and by test injection. It is not a
// valid tenant ID (starts with '$') so it can never collide with a real tenant.
const controlPlaneTenantID = "$control"

func closeTenants(tenants map[string]*tenantState) error {
	var firstErr error
	for _, tenant := range tenants {
		if err := tenant.db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// writeJSON writes a successful JSON response.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encodeJSON(w, body)
}

// writeJSONError writes the canonical { "error": { code, message } } shape.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encodeJSON(w, map[string]any{
		"error": map[string]any{"code": code, "message": message},
	})
}
