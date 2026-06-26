// Package quota manages per-tenant storage quotas. Two backends share the
// same Manager bookkeeping (state file, project ids, idempotency):
//
//   - ext4 (default): project quotas via chattr +P / setquota on a local
//     filesystem mounted with prjquota.
//   - juicefs: directory quotas via `juicefs quota set` against the JuiceFS
//     metadata engine, for deployments whose TenantsRoot lives on a JuiceFS
//     mount (the storage-backend design). JuiceFS enforces a
//     1 GiB minimum directory quota, so smaller grants are clamped up — the
//     sub-GiB cap (anon trial 128 MiB) stays an application-layer limit.
package quota

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Exec is the interface for running external commands.
type Exec interface {
	Run(ctx context.Context, name string, args ...string) error
}

// defaultExecTimeout is the hard deadline for each external command.
// Callers can override via NewDefaultExec.
const defaultExecTimeout = 30 * time.Second

// DefaultExec returns an Exec that shells out via os/exec with a 30-second
// per-command timeout.
func DefaultExec() Exec { return defaultExec{timeout: defaultExecTimeout} }

// NewDefaultExec returns an Exec with the given per-command timeout.
// Pass 0 to inherit the caller's context deadline without adding one.
func NewDefaultExec(timeout time.Duration) Exec { return defaultExec{timeout: timeout} }

type defaultExec struct {
	timeout time.Duration
}

func (d defaultExec) Run(ctx context.Context, name string, args ...string) error {
	runCtx := ctx
	if d.timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}
	var buf bytes.Buffer
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		stderr := buf.String()
		return fmt.Errorf("%w: %s", err, stderr)
	}
	return nil
}

// ErrSizeMismatch is returned when Allocate is called for an existing tenant
// with a different sizeBytes than originally allocated.
type ErrSizeMismatch struct {
	Existing int64
}

func (e ErrSizeMismatch) Error() string {
	return fmt.Sprintf("quota: size mismatch: existing %d bytes", e.Existing)
}

// ErrNotProjectQuotaFS is returned when setquota fails, indicating the
// filesystem does not support project quotas.
type ErrNotProjectQuotaFS struct {
	Stderr string
}

func (e ErrNotProjectQuotaFS) Error() string {
	return fmt.Sprintf("quota: filesystem does not support project quotas: %s", e.Stderr)
}

// ErrTenantNotFound is returned by Resize when tenantID has no quota record —
// the tenant was never Allocate'd (or its record was reclaimed).
var ErrTenantNotFound = errors.New("quota: tenant not found")

type tenantRecord struct {
	ProjectID uint32 `json:"project_id"`
	SizeBytes int64  `json:"size_bytes"`
}

// state is the full persisted JSON shape.
type state struct {
	NextProjectID uint32                  `json:"next_project_id"`
	Tenants       map[string]tenantRecord `json:"tenants"`
}

// Manager allocates and tracks ext4 project IDs per tenant.
type Manager struct {
	mu         sync.Mutex
	statePath  string
	mountPoint string
	exec       Exec
	logger     *slog.Logger
	st         state
	// enforce gates the chattr+setquota calls. When false (staging /
	// containerized deploys without prjquota mount option), Allocate still
	// reserves a project_id and persists the size, but skips the kernel
	// enforcement. Reads of project_id stay correct; over-quota writes are
	// not blocked.
	enforce bool
	// burstMargin is added to a tenant's accounted size when computing the ext4
	// hard limit, so a short burst lands in the margin (no ENOSPC) while the
	// control-plane autoscaler catches up and raises the accounted size. The
	// stored/reported size stays the accounted grant; only the kernel cap is
	// grant+margin. 0 disables (hard limit == grant).
	burstMargin int64
	// juicefs backend fields. When metaURL is non-empty the Manager applies
	// quotas via `juicefs quota set` instead of chattr/setquota. mountRoot is
	// the filesystem path where the JuiceFS volume is mounted (e.g. /jfs);
	// tenant dirs under it map to FS-relative quota paths.
	jfsMetaURL   string
	jfsMountRoot string
	jfsBin       string
}

// Option configures a Manager at construction.
type Option func(*Manager)

// WithBurstMargin sets the per-tenant ext4 hard-limit burst margin (see the
// burstMargin field). Non-positive values are ignored (margin stays 0).
func WithBurstMargin(bytes int64) Option {
	return func(m *Manager) {
		if bytes > 0 {
			m.burstMargin = bytes
		}
	}
}

// defaultJuicefsBin is where the orlop-server image installs the
// JuiceFS CE client (distroless has no PATH lookup worth relying on).
const defaultJuicefsBin = "/usr/local/bin/juicefs"

// WithJuiceFS switches quota enforcement to JuiceFS directory quotas.
// metaURL is the JuiceFS metadata engine URL (the same one the volume was
// formatted with); mountRoot is where the volume is mounted on this host —
// a tenant dir's quota path is its location relative to mountRoot.
func WithJuiceFS(metaURL, mountRoot string) Option {
	return func(m *Manager) {
		m.jfsMetaURL = metaURL
		m.jfsMountRoot = mountRoot
		m.jfsBin = defaultJuicefsBin
	}
}

// WithJuicefsBin overrides the juicefs client path (tests).
func WithJuicefsBin(path string) Option {
	return func(m *Manager) { m.jfsBin = path }
}

// juicefsQuotaGiB returns the --capacity argument (GiB, rounded up) for an
// accounted size with the burst margin folded in. JuiceFS rejects directory
// quotas below 1 GiB, so the result is clamped to at least 1 — grants smaller
// than that keep their precise cap at the application layer only.
func (m *Manager) juicefsQuotaGiB(sizeBytes int64) string {
	const gib = int64(1) << 30
	g := (sizeBytes + m.burstMargin + gib - 1) / gib
	if g < 1 {
		g = 1
	}
	return fmt.Sprintf("%d", g)
}

// juicefsQuotaPath maps a tenant dir on the local mount to its FS-relative
// quota path (e.g. /jfs/tenants/u_x -> /tenants/u_x for mountRoot /jfs).
func (m *Manager) juicefsQuotaPath(dir string) string {
	rel := strings.TrimPrefix(filepath.Clean(dir), filepath.Clean(m.jfsMountRoot))
	if rel == "" {
		rel = "/"
	}
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	return rel
}

// applyJuicefsQuota sets (or updates) the directory quota for dir.
func (m *Manager) applyJuicefsQuota(ctx context.Context, dir string, sizeBytes int64) error {
	return m.exec.Run(ctx, m.jfsBin, "quota", "set", m.jfsMetaURL,
		"--path", m.juicefsQuotaPath(dir),
		"--capacity", m.juicefsQuotaGiB(sizeBytes),
	)
}

// hardLimitKB returns the setquota -P hard-limit argument (KiB, rounded up) for
// an accounted size, folding in the burst margin so the kernel cap sits above
// the accounted grant.
func (m *Manager) hardLimitKB(sizeBytes int64) string {
	return fmt.Sprintf("%d", (sizeBytes+m.burstMargin+1023)/1024)
}

// NewManager loads or creates the state file at statePath.
// mountPoint is the filesystem mount (e.g. /var/lib/orlop) passed to setquota -a.
// logger may be nil, in which case a discard logger is used.
//
// enforce=true wires chattr + setquota so writes past the size hit ENOSPC.
// enforce=false skips those calls — useful when the underlying filesystem
// lacks the prjquota mount option (most container hosts and dev VMs).
func NewManager(statePath, mountPoint string, ex Exec, logger *slog.Logger, enforce bool, opts ...Option) (*Manager, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	m := &Manager{
		statePath:  statePath,
		mountPoint: mountPoint,
		exec:       ex,
		logger:     logger,
		enforce:    enforce,
	}
	for _, opt := range opts {
		opt(m)
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.statePath)
	if errors.Is(err, os.ErrNotExist) {
		m.st = state{
			NextProjectID: 100,
			Tenants:       map[string]tenantRecord{},
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("quota: read state: %w", err)
	}
	if err := json.Unmarshal(data, &m.st); err != nil {
		return fmt.Errorf("quota: parse state: %w", err)
	}
	if m.st.Tenants == nil {
		m.st.Tenants = map[string]tenantRecord{}
	}
	return nil
}

// persist atomically writes state to statePath via a temp file + rename.
func (m *Manager) persist() error {
	data, err := json.Marshal(&m.st)
	if err != nil {
		return fmt.Errorf("quota: marshal state: %w", err)
	}
	tmp := m.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("quota: write state tmp: %w", err)
	}
	if err := os.Rename(tmp, m.statePath); err != nil {
		return fmt.Errorf("quota: rename state: %w", err)
	}
	return nil
}

// Allocate assigns a project ID to tenantID and applies chattr + setquota.
// Idempotent: calling again with the same size returns the existing project ID.
// Returns ErrSizeMismatch if called with a different sizeBytes.
// Returns ErrNotProjectQuotaFS if the underlying setquota call fails.
func (m *Manager) Allocate(ctx context.Context, tenantID, dir string, sizeBytes int64) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if rec, ok := m.st.Tenants[tenantID]; ok {
		if rec.SizeBytes != sizeBytes {
			return 0, ErrSizeMismatch{Existing: rec.SizeBytes}
		}
		return rec.ProjectID, nil
	}

	projID := m.st.NextProjectID
	m.st.NextProjectID++
	m.st.Tenants[tenantID] = tenantRecord{ProjectID: projID, SizeBytes: sizeBytes}

	if err := m.persist(); err != nil {
		delete(m.st.Tenants, tenantID)
		m.st.NextProjectID--
		return 0, err
	}

	if !m.enforce {
		m.logger.Info("quota_allocated_unenforced", "tenant_id", tenantID, "project_id", projID, "size_bytes", sizeBytes)
		return projID, nil
	}

	if m.jfsMetaURL != "" {
		if err := m.applyJuicefsQuota(ctx, dir, sizeBytes); err != nil {
			m.logger.Error("quota_juicefs_set_failed", "error", err, "tenant_id", tenantID)
			quotaErr := ErrNotProjectQuotaFS{Stderr: err.Error()}
			if rollErr := m.rollback(tenantID); rollErr != nil {
				return 0, errors.Join(quotaErr, rollErr)
			}
			return 0, quotaErr
		}
		m.logger.Info("quota_allocated_juicefs", "tenant_id", tenantID, "project_id", projID, "size_bytes", sizeBytes, "capacity_gib", m.juicefsQuotaGiB(sizeBytes))
		return projID, nil
	}

	if err := m.exec.Run(ctx, "chattr", "+P", "-p", fmt.Sprintf("%d", projID), dir); err != nil {
		m.logger.Error("quota_chattr_failed", "error", err, "tenant_id", tenantID)
		execErr := fmt.Errorf("quota: chattr: %w", err)
		if rollErr := m.rollback(tenantID); rollErr != nil {
			return 0, errors.Join(execErr, rollErr)
		}
		return 0, execErr
	}

	// setquota -P expects the hard limit in KiB; hardLimitKB rounds up and folds
	// in the burst margin so the kernel cap sits above the accounted grant.
	hardKB := m.hardLimitKB(sizeBytes)
	projArg := fmt.Sprintf("%d", projID)
	if err := m.exec.Run(ctx, "setquota", "-P", projArg, "0", hardKB, "0", "0", "-a", m.mountPoint); err != nil {
		m.logger.Error("quota_setquota_failed", "error", err, "tenant_id", tenantID)
		quotaErr := ErrNotProjectQuotaFS{Stderr: err.Error()}
		if rollErr := m.rollback(tenantID); rollErr != nil {
			return 0, errors.Join(quotaErr, rollErr)
		}
		return 0, quotaErr
	}

	m.logger.Info("quota_allocated", "tenant_id", tenantID, "project_id", projID, "size_bytes", sizeBytes)
	return projID, nil
}

// Resize changes an existing tenant's hard size cap in place, preserving its
// project ID, by re-running setquota with the new limit. This is the data-plane
// half of elastic storage: the control plane grows a tenant toward its promised
// ceiling and calls here to widen the kernel quota.
//
// Idempotent: re-applying the current size is a no-op that returns the existing
// project ID without shelling out.
//
// setquota runs before the state file is persisted so our bookkeeping only
// advances after the kernel limit actually changed. The kernel quota — stored
// in the filesystem, not in our JSON — is the enforcement source of truth.
//
// Returns ErrTenantNotFound if tenantID was never Allocate'd, or
// ErrNotProjectQuotaFS if the setquota call fails (state is left unchanged).
func (m *Manager) Resize(ctx context.Context, tenantID string, sizeBytes int64) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.st.Tenants[tenantID]
	if !ok {
		return 0, ErrTenantNotFound
	}
	if rec.SizeBytes == sizeBytes {
		return rec.ProjectID, nil
	}

	if m.enforce {
		if m.jfsMetaURL != "" {
			// mountPoint is the tenants root; the tenant's dir under it maps to
			// the FS-relative quota path.
			if err := m.applyJuicefsQuota(ctx, filepath.Join(m.mountPoint, tenantID), sizeBytes); err != nil {
				m.logger.Error("quota_resize_juicefs_failed", "error", err, "tenant_id", tenantID)
				return 0, ErrNotProjectQuotaFS{Stderr: err.Error()}
			}
		} else {
			hardKB := m.hardLimitKB(sizeBytes)
			projArg := fmt.Sprintf("%d", rec.ProjectID)
			if err := m.exec.Run(ctx, "setquota", "-P", projArg, "0", hardKB, "0", "0", "-a", m.mountPoint); err != nil {
				m.logger.Error("quota_resize_setquota_failed", "error", err, "tenant_id", tenantID)
				return 0, ErrNotProjectQuotaFS{Stderr: err.Error()}
			}
		}
	}

	prevSize := rec.SizeBytes
	rec.SizeBytes = sizeBytes
	m.st.Tenants[tenantID] = rec
	if err := m.persist(); err != nil {
		// The kernel limit already advanced; restore the in-memory record so a
		// retry re-attempts the persist. This only affects idempotency
		// bookkeeping — the kernel quota is the real limit.
		rec.SizeBytes = prevSize
		m.st.Tenants[tenantID] = rec
		return 0, err
	}

	event := "quota_resized"
	if !m.enforce {
		event = "quota_resized_unenforced"
	}
	m.logger.Info(event, "tenant_id", tenantID, "project_id", rec.ProjectID, "size_bytes", sizeBytes, "prev_size_bytes", prevSize)
	return rec.ProjectID, nil
}

// EnsureQuota sets tenantID's hard cap to sizeBytes whether or not a record already
// exists: it Allocates (assign a project id + apply the quota) the first time, and
// Resizes in place afterward. It is the primitive for the ACCOUNT-LEVEL quota on a
// user's tenant dir, which is re-asserted every time an agent is placed under that
// account and whenever the account's disk budget changes. Race-safe: Allocate is
// idempotent at the same size, and a concurrent allocation at a different size surfaces
// as ErrSizeMismatch, which we resolve by resizing to the requested size.
func (m *Manager) EnsureQuota(ctx context.Context, tenantID, dir string, sizeBytes int64) (uint32, error) {
	projID, err := m.Allocate(ctx, tenantID, dir, sizeBytes)
	if err == nil {
		return projID, nil
	}
	var mismatch ErrSizeMismatch
	if errors.As(err, &mismatch) {
		return m.Resize(ctx, tenantID, sizeBytes)
	}
	return 0, err
}

// rollback removes tenantID from state, decrements NextProjectID, and persists.
// Returns the persist error if it fails (caller joins with the original exec error).
func (m *Manager) rollback(tenantID string) error {
	delete(m.st.Tenants, tenantID)
	m.st.NextProjectID--
	if err := m.persist(); err != nil {
		m.logger.Error("quota_rollback_persist_failed", "error", err, "tenant_id", tenantID)
		return err
	}
	return nil
}

// Lookup returns the project ID and size for tenantID, or ok=false if not found.
func (m *Manager) Lookup(tenantID string) (projID uint32, sizeBytes int64, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.st.Tenants[tenantID]
	if !ok {
		return 0, 0, false
	}
	return rec.ProjectID, rec.SizeBytes, true
}
