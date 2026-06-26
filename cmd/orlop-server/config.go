package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type rawConfig struct {
	AuditLog              string         `yaml:"audit_log"`
	Tenant                rawTenant      `yaml:"tenant"`
	Tenants               []rawTenant    `yaml:"tenants"`
	Store                 *rawStore      `yaml:"store"`
	Routes                *rawRoutes     `yaml:"routes"`
	Policy                rawPolicy      `yaml:"policy"`
	Server                rawServer      `yaml:"server"`
	TLS                   rawTLS         `yaml:"tls"`
	Lease                 LeaseConfig    `yaml:"lease"`
	GC                    GCConfig       `yaml:"gc"`
	TenantsRoot           string         `yaml:"tenants_root"`
	MetadataRoot          string         `yaml:"metadata_root"`
	RegisteredTenantsPath string         `yaml:"registered_tenants_path"`
	Quota                 rawQuota       `yaml:"quota"`
	rest                  map[string]any `yaml:",inline"`
}

type rawQuota struct {
	// Enforce gates chattr+setquota during dynamic-tenant registration.
	// Defaults to true (the prod path); set to false on filesystems that
	// lack ext4 prjquota support (most container hosts and dev VMs).
	Enforce *bool `yaml:"enforce"`
	// BurstMarginBytes is added to a tenant's accounted size when setting the
	// ext4 hard limit, so a short write burst lands in the margin instead of
	// hitting ENOSPC before the control-plane autoscaler raises the grant. nil
	// -> defaultQuotaBurstMarginBytes; 0 disables.
	BurstMarginBytes *int64 `yaml:"burst_margin_bytes"`
	// Backend selects the enforcement mechanism: "ext4" (default; chattr +
	// setquota project quotas) or "juicefs" (directory quotas via `juicefs
	// quota set` when tenants_root lives on a JuiceFS mount). The juicefs
	// backend reads the metadata-engine URL from env ORLOP_JFS_META_URL.
	Backend string `yaml:"backend"`
	// JuicefsMountRoot is the local path where the JuiceFS volume is mounted
	// (e.g. /jfs). Required when backend is "juicefs": tenant dirs under
	// tenants_root map to quota paths relative to this root.
	JuicefsMountRoot string `yaml:"juicefs_mount_root"`
}

type rawStore struct {
	Type string `yaml:"type"`
	Root string `yaml:"root"`
}

type rawRoutes struct {
	Type string `yaml:"type"`
	Path string `yaml:"path"`
}

type rawTenant struct {
	ID     string     `yaml:"id"`
	Name   string     `yaml:"name"`
	Store  *rawStore  `yaml:"store"`
	Routes *rawRoutes `yaml:"routes"`
}

type rawPolicy struct {
	Readonly *bool    `yaml:"readonly"`
	Allow    []string `yaml:"allow"`
	Deny     []string `yaml:"deny"`
}

type rawServer struct {
	OpsBind  string `yaml:"ops_bind"`
	DataBind string `yaml:"data_bind"`
}

type rawTLS struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ClientCAFile string `yaml:"client_ca_file"`
	TrustDomain  string `yaml:"trust_domain"`
	// SelfProvision makes the server mint its own TLS material at boot: it
	// generates an ed25519 keypair in memory, sends a CSR to orlop-control
	// (ControlURL) authenticated by the shared service token (env
	// ORLOP_DATAGW_SERVICE_TOKEN), and serves the returned cert. The private key
	// never touches disk. When true, cert_file/key_file/client_ca_file are
	// ignored. See the agent-isolation and cert-bootstrap design.
	SelfProvision bool   `yaml:"self_provision"`
	ControlURL    string `yaml:"control_url"`
	FQDN          string `yaml:"fqdn"`
}

// LeaseConfig holds the YAML-level lease tuning knobs. Zero values fall back
// to the defaults in Effective().
type LeaseConfig struct {
	TTLMillis           int `yaml:"ttl_ms"`
	MinHoldMillis       int `yaml:"min_hold_ms"`
	RevokeTimeoutMillis int `yaml:"revoke_timeout_ms"`
}

// Effective returns a leaseConfig with defaults applied for any zero fields.
func (c LeaseConfig) Effective() leaseConfig {
	cfg := leaseConfig{
		ttl:           30 * time.Second,
		minHold:       100 * time.Millisecond,
		revokeTimeout: 2 * time.Second,
	}
	if c.TTLMillis > 0 {
		cfg.ttl = time.Duration(c.TTLMillis) * time.Millisecond
	}
	if c.MinHoldMillis > 0 {
		cfg.minHold = time.Duration(c.MinHoldMillis) * time.Millisecond
	}
	if c.RevokeTimeoutMillis > 0 {
		cfg.revokeTimeout = time.Duration(c.RevokeTimeoutMillis) * time.Millisecond
	}
	return cfg
}

// GCConfig holds the YAML-level GC tuning knobs. Zero/empty values fall back
// to the defaults in Effective(). Set Interval to "0" to disable the GC loop.
type GCConfig struct {
	Interval        string `yaml:"interval"`
	RetentionWindow string `yaml:"retention_window"`
	BatchSize       int    `yaml:"batch_size"`
	TenantBudget    string `yaml:"tenant_budget"`
	DryRun          bool   `yaml:"dry_run"`
}

type gcConfig struct {
	Interval        time.Duration
	RetentionWindow time.Duration
	BatchSize       int
	TenantBudget    time.Duration
	DryRun          bool
}

// Effective returns a gcConfig with defaults applied for any zero/empty fields.
// Interval == "0" explicitly disables the loop (Effective().Interval == 0).
func (c GCConfig) Effective() gcConfig {
	cfg := gcConfig{
		Interval:        24 * time.Hour,
		RetentionWindow: 7 * 24 * time.Hour,
		BatchSize:       500,
		TenantBudget:    2 * time.Minute,
		DryRun:          c.DryRun,
	}
	if c.Interval == "0" {
		cfg.Interval = 0
	} else if c.Interval != "" {
		if d, err := time.ParseDuration(c.Interval); err == nil {
			cfg.Interval = d
		}
	}
	if c.RetentionWindow != "" {
		if d, err := time.ParseDuration(c.RetentionWindow); err == nil && d >= time.Hour {
			cfg.RetentionWindow = d
		}
	}
	if c.BatchSize > 0 {
		cfg.BatchSize = c.BatchSize
	}
	if c.TenantBudget != "" {
		if d, err := time.ParseDuration(c.TenantBudget); err == nil && d > 0 {
			cfg.TenantBudget = d
		}
	}
	return cfg
}

// Config is the resolved server configuration.
type Config struct {
	AuditLog  string
	StoreRoot string
	RoutesDB  string
	TenantID  string
	Tenants   []TenantConfig
	Allow     []string
	Deny      []string
	Lease     LeaseConfig
	GC        GCConfig

	// OpsBind is the address the HTTPS listener binds ("" -> :7878). Serves
	// /healthz, /audit, and the control-plane RPC at /control/tenants.
	OpsBind string
	// DataBind is the data-plane mTLS listener address ("" -> disabled).
	// FUSE clients connect here.
	DataBind    string
	TLSCertFile string
	TLSKeyFile  string
	TLSClientCA string

	// TLSSelfProvision, ControlURL, ServerFQDN, ServiceToken back the boot-time
	// cert self-provisioning flow (see rawTLS.SelfProvision). ServiceToken is read
	// from ORLOP_DATAGW_SERVICE_TOKEN (a secret), not the YAML.
	TLSSelfProvision bool
	ControlURL       string
	ServerFQDN       string
	ServiceToken     string

	// TenantsRoot is the filesystem directory under which dynamic tenant
	// subdirectories are created. Empty means dynamic registration is disabled.
	TenantsRoot string
	// MetadataRoot is the filesystem directory under which a tenant's metadata
	// (routes.db + leases.db) lives, mirroring the TenantsRoot layout. It is
	// split out so the latency-critical SQLite metadata can sit on a fast local
	// disk (NVMe block) while the bulk chunk store stays on TenantsRoot (e.g.
	// JuiceFS). Empty defaults to TenantsRoot (single-disk: metadata + chunks
	// co-located, the dev/VPS behavior).
	MetadataRoot string
	// RegisteredTenantsPath is the path to the JSON file that persists
	// dynamically registered tenants across restarts. When empty and
	// TenantsRoot is set, it defaults to <audit_log_dir>/registered_tenants.json.
	RegisteredTenantsPath string
	// TrustDomain is the SPIFFE trust domain used to validate both tenant and
	// control-plane certificates. Required when TenantsRoot is set.
	TrustDomain string
	// QuotaEnforce decides whether dynamic registration runs chattr+setquota
	// against the tenant directory. Defaults true; flip to false on hosts
	// without ext4 prjquota support.
	QuotaEnforce bool
	// QuotaBurstMarginBytes is added to a tenant's accounted size when setting
	// the ext4 hard limit, giving a burst buffer above the grant. Defaults to
	// defaultQuotaBurstMarginBytes; 0 disables.
	QuotaBurstMarginBytes int64
	// QuotaBackend is "ext4" (default) or "juicefs"; see rawQuota.Backend.
	QuotaBackend string
	// QuotaJuicefsMountRoot is the JuiceFS mount root for the juicefs backend.
	QuotaJuicefsMountRoot string
	// QuotaJuicefsMetaURL is the JuiceFS metadata engine URL (from env
	// ORLOP_JFS_META_URL — secret material stays out of the config file).
	QuotaJuicefsMetaURL string
	// QuotaApplyAsync decouples account-quota application from tenant
	// registration: registerTenant returns as soon as the tenant dir exists and
	// the quota is (re)asserted in the background with retry. On networked
	// metadata engines (JuiceFS over a remote Postgres) the first `juicefs quota
	// set` for an owner can take tens of seconds — far longer than the
	// control→server request deadline — so applying it inline blocks the agent
	// disk mount. Quota is a safety cap, not a security boundary, and the apply
	// is idempotent, so eventual application is safe. Defaults true; set
	// ORLOP_QUOTA_APPLY_ASYNC=0 to apply inline (the old behavior).
	QuotaApplyAsync bool
}

// defaultQuotaBurstMarginBytes is the ext4 hard-limit burst buffer applied above
// a tenant's accounted grant when quota.burst_margin_bytes is unset.
const defaultQuotaBurstMarginBytes = 256 << 20 // 256 MiB

// envBoolDefault reads a boolean env var, returning def when unset/blank and
// parsing common truthy/falsy spellings otherwise (unparseable -> def).
func envBoolDefault(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// resolveQuotaBurstMargin maps the optional config value to a non-negative
// margin: unset -> default, explicit negative -> 0 (disabled), else the value.
func resolveQuotaBurstMargin(v *int64) int64 {
	if v == nil {
		return defaultQuotaBurstMarginBytes
	}
	if *v < 0 {
		return 0
	}
	return *v
}

type TenantConfig struct {
	ID        string
	Name      string
	StoreRoot string
	RoutesDB  string
}

// LoadConfig reads a YAML config file from disk and validates it.
func LoadConfig(path string) (Config, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var raw rawConfig
	if err := yaml.Unmarshal(bytes, &raw); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}

	tenants, err := resolveTenantConfigs(raw)
	if err != nil && !(errors.Is(err, errNoStaticTenants) && raw.TenantsRoot != "") {
		return Config{}, err
	}

	auditLog := raw.AuditLog
	if auditLog == "" {
		auditLog = "./audit.log"
	}
	auditLogAbs := absOrSelf(auditLog)

	var primary TenantConfig
	if len(tenants) > 0 {
		primary = tenants[0]
	}

	registeredTenantsPath := raw.RegisteredTenantsPath
	if registeredTenantsPath == "" && raw.TenantsRoot != "" {
		registeredTenantsPath = filepath.Join(filepath.Dir(auditLogAbs), "registered_tenants.json")
	}

	// Metadata (routes.db + leases.db) defaults to co-located with the chunk
	// store (TenantsRoot) — single-disk. Set metadata_root to a fast local disk
	// to split the latency-critical SQLite off a networked TenantsRoot.
	metadataRoot := raw.MetadataRoot
	if metadataRoot == "" {
		metadataRoot = raw.TenantsRoot
	}

	if raw.TenantsRoot != "" && raw.TLS.TrustDomain == "" {
		return Config{}, fmt.Errorf("tls.trust_domain is required when tenants_root is set")
	}

	cfg := Config{
		AuditLog:              auditLogAbs,
		StoreRoot:             primary.StoreRoot,
		RoutesDB:              primary.RoutesDB,
		TenantID:              primary.ID,
		Tenants:               tenants,
		Allow:                 raw.Policy.Allow,
		Deny:                  raw.Policy.Deny,
		Lease:                 raw.Lease,
		GC:                    raw.GC,
		OpsBind:               raw.Server.OpsBind,
		DataBind:              raw.Server.DataBind,
		TLSCertFile:           absOrSelf(raw.TLS.CertFile),
		TLSKeyFile:            absOrSelf(raw.TLS.KeyFile),
		TLSClientCA:           absOrSelf(raw.TLS.ClientCAFile),
		TLSSelfProvision:      raw.TLS.SelfProvision,
		ControlURL:            raw.TLS.ControlURL,
		ServerFQDN:            raw.TLS.FQDN,
		ServiceToken:          os.Getenv("ORLOP_DATAGW_SERVICE_TOKEN"),
		TenantsRoot:           absOrSelf(raw.TenantsRoot),
		MetadataRoot:          absOrSelf(metadataRoot),
		RegisteredTenantsPath: absOrSelf(registeredTenantsPath),
		TrustDomain:           raw.TLS.TrustDomain,
		QuotaEnforce:          raw.Quota.Enforce == nil || *raw.Quota.Enforce,
		QuotaBurstMarginBytes: resolveQuotaBurstMargin(raw.Quota.BurstMarginBytes),
		QuotaBackend:          raw.Quota.Backend,
		QuotaJuicefsMountRoot: absOrSelf(raw.Quota.JuicefsMountRoot),
		QuotaJuicefsMetaURL:   os.Getenv("ORLOP_JFS_META_URL"),
		QuotaApplyAsync:       envBoolDefault("ORLOP_QUOTA_APPLY_ASYNC", true),
	}

	if cfg.OpsBind == "" {
		cfg.OpsBind = ":7878"
	}

	switch cfg.QuotaBackend {
	case "", "ext4":
		cfg.QuotaBackend = "ext4"
	case "juicefs":
		if cfg.QuotaEnforce {
			if cfg.QuotaJuicefsMountRoot == "" {
				return Config{}, fmt.Errorf("quota.juicefs_mount_root is required for the juicefs quota backend")
			}
			if cfg.QuotaJuicefsMetaURL == "" {
				return Config{}, fmt.Errorf("ORLOP_JFS_META_URL is required for the juicefs quota backend")
			}
		}
	default:
		return Config{}, fmt.Errorf("quota.backend must be \"ext4\" or \"juicefs\", got %q", cfg.QuotaBackend)
	}

	return cfg, nil
}

// errNoStaticTenants is returned by resolveTenantConfigs when no static tenants
// are configured. LoadConfig treats it as non-fatal when TenantsRoot is set.
var errNoStaticTenants = errors.New("no static tenants configured")

func resolveTenantConfigs(raw rawConfig) ([]TenantConfig, error) {
	rawTenants := raw.Tenants
	if len(rawTenants) == 0 {
		// Prefer the nested store/routes from `tenant:` over the top-level
		// blocks so a singular-tenant config can colocate everything under
		// one key. The per-tenant fallback to raw.Store / raw.Routes still
		// happens in the loop below.
		store := raw.Tenant.Store
		if store == nil {
			store = raw.Store
		}
		routes := raw.Tenant.Routes
		if routes == nil {
			routes = raw.Routes
		}
		// If there is nothing at all (no tenant block, no store, no routes),
		// signal that this is a dynamic-only config.
		if raw.Tenant.ID == "" && store == nil && routes == nil {
			return nil, errNoStaticTenants
		}
		rawTenants = []rawTenant{{
			ID:     raw.Tenant.ID,
			Name:   raw.Tenant.Name,
			Store:  store,
			Routes: routes,
		}}
	}
	out := make([]TenantConfig, 0, len(rawTenants))
	seen := map[string]struct{}{}
	for _, tenant := range rawTenants {
		store := tenant.Store
		routes := tenant.Routes
		if store == nil {
			store = raw.Store
		}
		if routes == nil {
			routes = raw.Routes
		}
		if tenant.ID == "" {
			return nil, errors.New("tenant.id is required")
		}
		if _, ok := seen[tenant.ID]; ok {
			return nil, fmt.Errorf("duplicate tenant.id %q", tenant.ID)
		}
		seen[tenant.ID] = struct{}{}
		if store == nil || store.Root == "" {
			return nil, fmt.Errorf("tenant %q store.root is required", tenant.ID)
		}
		if store.Type != "" && store.Type != "local" {
			return nil, fmt.Errorf("tenant %q store.type must be 'local', got %q", tenant.ID, store.Type)
		}
		if routes == nil || routes.Path == "" {
			return nil, fmt.Errorf("tenant %q routes.path is required", tenant.ID)
		}
		if routes.Type != "" && routes.Type != "sqlite" {
			return nil, fmt.Errorf("tenant %q routes.type must be 'sqlite', got %q", tenant.ID, routes.Type)
		}
		name := tenant.Name
		if name == "" {
			name = tenant.ID
		}
		out = append(out, TenantConfig{
			ID:        tenant.ID,
			Name:      name,
			StoreRoot: absOrSelf(store.Root),
			RoutesDB:  absOrSelf(routes.Path),
		})
	}
	return out, nil
}

func absOrSelf(p string) string {
	if p == "" {
		return p
	}
	if filepath.IsAbs(p) {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}
