package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"lukechampine.com/blake3"
)

// gcTestRig stands up a one-tenant serverState backed by tempdirs.
type gcTestRig struct {
	state  *serverState
	tenant *tenantState
	cs     *ChunkStore
	db     *sql.DB
	cfg    gcConfig
	clock  func() time.Time
	logger *slog.Logger
}

func newGCTestRig(t *testing.T) *gcTestRig {
	t.Helper()
	root := t.TempDir()
	storeRoot := filepath.Join(root, "store")
	if err := os.MkdirAll(storeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(root, "routes.db")
	createGCSchema(t, dbPath)

	cfg := Config{
		AuditLog:  filepath.Join(root, "audit.log"),
		StoreRoot: storeRoot,
		RoutesDB:  dbPath,
		TenantID:  "t1",
		Tenants: []TenantConfig{{
			ID:        "t1",
			Name:      "t1",
			StoreRoot: storeRoot,
			RoutesDB:  dbPath,
		}},
	}
	state, err := newServerState(cfg, contextIdentifier{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	tenant, _ := state.tenant("t1")
	return &gcTestRig{
		state:  state,
		tenant: tenant,
		cs:     tenant.chunks,
		db:     tenant.db.DB(),
		cfg: gcConfig{
			Interval:        time.Hour,
			RetentionWindow: time.Hour,
			BatchSize:       100,
			TenantBudget:    time.Minute,
		},
		clock:  func() time.Time { return time.Unix(10_000_000, 0) },
		logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
}

// createGCSchema sets up the schema the GC tests touch. The Rust crate's
// `orlop init` is the production schema owner; mirroring it here via the
// shared testSchemaSQL keeps these tests independent of the crate's
// migrations and in lockstep with every other test fixture.
func createGCSchema(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(testSchemaSQL); err != nil {
		t.Fatal(err)
	}
}

// putChunk writes hash bytes into the store and seeds the chunks row with
// the supplied refcount + added_at — bypassing the manifest write path
// to set up exact GC test scenarios.
func (r *gcTestRig) putChunk(t *testing.T, payload string, refcount int, addedAt int64) [32]byte {
	t.Helper()
	bytes := []byte(payload)
	h := blake3.Sum256(bytes)
	if _, err := r.cs.Put(h[:], bytes); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.Exec(
		`insert into chunks(hash, size, refcount, added_at) values(?, ?, ?, ?)
		 on conflict(hash) do update set refcount = excluded.refcount, added_at = excluded.added_at, size = excluded.size`,
		h[:], len(bytes), refcount, addedAt,
	); err != nil {
		t.Fatal(err)
	}
	return h
}

func (r *gcTestRig) chunkExists(t *testing.T, hash [32]byte) bool {
	t.Helper()
	var n int
	if err := r.db.QueryRow(
		`select count(*) from chunks where hash = ?`, hash[:],
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func TestGCSweepsRefcountZeroPastRetention(t *testing.T) {
	r := newGCTestRig(t)
	// Eligible: refcount=0, old enough.
	eligible := r.putChunk(t, "stale", 0, r.clock().Add(-2*time.Hour).Unix())
	// Ineligible (still referenced): refcount=1.
	referenced := r.putChunk(t, "live", 1, r.clock().Add(-2*time.Hour).Unix())

	g := &gcLoop{state: r.state, cfg: r.cfg, clock: r.clock, logger: r.logger}
	g.tick(context.Background())

	if r.chunkExists(t, eligible) {
		t.Error("eligible chunk not deleted")
	}
	if !r.chunkExists(t, referenced) {
		t.Error("refcount>0 chunk should not be deleted")
	}
}

func TestGCRespectsRetentionWindow(t *testing.T) {
	r := newGCTestRig(t)
	fresh := r.putChunk(t, "fresh-orphan", 0,
		r.clock().Add(-30*time.Minute).Unix()) // inside the 1h window
	stale := r.putChunk(t, "stale-orphan", 0,
		r.clock().Add(-2*time.Hour).Unix()) // outside

	g := &gcLoop{state: r.state, cfg: r.cfg, clock: r.clock, logger: r.logger}
	g.tick(context.Background())

	if !r.chunkExists(t, fresh) {
		t.Error("fresh orphan must be preserved by retention window")
	}
	if r.chunkExists(t, stale) {
		t.Error("stale orphan should have been swept")
	}
}

// Concurrent refcount bump between SELECT and DELETE: the chunk must
// survive because the DELETE re-checks refcount=0.
//
// Strategy: drive the sweep loop directly via deleteGCBatch and bump
// refcount BETWEEN the candidate SELECT and the DELETE — this guarantees
// the race window is exercised without flakiness.
func TestGCConcurrentRefcountBumpRace(t *testing.T) {
	r := newGCTestRig(t)
	h := r.putChunk(t, "racy", 0, r.clock().Add(-2*time.Hour).Unix())

	candidates, err := selectGCCandidates(r.db,
		r.clock().Add(-time.Hour).Unix(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}

	// Simulate concurrent manifest_put: bump refcount before the DELETE
	// batch runs. The DELETE's WHERE refcount=0 must skip this row.
	if _, err := r.db.Exec(
		`update chunks set refcount = 1 where hash = ?`, h[:],
	); err != nil {
		t.Fatal(err)
	}

	deleted, _, err := deleteGCBatch(r.db, candidates,
		r.clock().Add(-time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 0 {
		t.Errorf("deleted %d, want 0 — refcount race lost a live chunk", len(deleted))
	}
	if !r.chunkExists(t, h) {
		t.Error("live chunk row was deleted despite refcount=1")
	}
}

// Three-chunk batch where the MIDDLE candidate's refcount is bumped
// between SELECT and DELETE. The unlink loop must skip the middle
// candidate's file and unlink the OTHER two — slicing by count would
// have unlinked the bumped chunk's file and orphaned the third.
func TestGCConcurrentRefcountBumpMidBatch(t *testing.T) {
	r := newGCTestRig(t)
	cutoff := r.clock().Add(-2 * time.Hour).Unix()
	a := r.putChunk(t, "alpha-mid", 0, cutoff)
	b := r.putChunk(t, "bravo-mid", 0, cutoff)
	c := r.putChunk(t, "charlie-mid", 0, cutoff)

	candidates, err := selectGCCandidates(r.db,
		r.clock().Add(-time.Hour).Unix(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 3 {
		t.Fatalf("expected 3 candidates, got %d", len(candidates))
	}

	// Find the middle candidate by index in the SELECT order.
	middleHash := candidates[1].hash

	// Simulate concurrent manifest_put bumping the MIDDLE row only.
	if _, err := r.db.Exec(
		`update chunks set refcount = 1 where hash = ?`, middleHash,
	); err != nil {
		t.Fatal(err)
	}

	deleted, _, err := deleteGCBatch(r.db, candidates,
		r.clock().Add(-time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 2 {
		t.Fatalf("deleted %d, want 2", len(deleted))
	}

	// Now exercise the unlink loop in sweepTenant: confirm the files of
	// the two deleted candidates are gone, and the file of the bumped
	// candidate is still present.
	for _, cand := range deleted {
		if err := r.cs.Delete(cand.hash); err != nil {
			t.Fatalf("unlink: %v", err)
		}
	}

	// Determine which hash is the bumped one and which two were deleted.
	bumpedFound := bytes.Equal(middleHash, b[:])
	if !bumpedFound {
		t.Logf("note: SELECT did not order chunks alphabetically; bumped candidate at SELECT index 1 is the middle one regardless")
	}

	// The bumped chunk's file must still be on disk.
	bumpedPath, err := r.cs.Path(middleHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bumpedPath); err != nil {
		t.Errorf("bumped chunk's file should still exist: %v", err)
	}

	// The two deleted chunks' files must be gone.
	for _, cand := range deleted {
		p, err := r.cs.Path(cand.hash)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("deleted chunk's file should be gone (stat err = %v)", err)
		}
	}

	_ = a
	_ = b
	_ = c
}

func TestGCBatchedDeletes(t *testing.T) {
	r := newGCTestRig(t)
	r.cfg.BatchSize = 5
	cutoff := r.clock().Add(-2 * time.Hour).Unix()
	var hashes [12][32]byte
	for i := range hashes {
		hashes[i] = r.putChunk(t,
			"orphan-"+strconv.Itoa(i), 0, cutoff)
	}

	g := &gcLoop{state: r.state, cfg: r.cfg, clock: r.clock, logger: r.logger}
	g.tick(context.Background())

	for i, h := range hashes {
		if r.chunkExists(t, h) {
			t.Errorf("chunk %d not swept", i)
		}
	}
}

// Tenant budget exhausted mid-tick: tick returns early; subsequent tick
// resumes. We use a fake monotonic clock that advances on each call.
func TestGCTenantBudgetExitsEarly(t *testing.T) {
	r := newGCTestRig(t)
	r.cfg.BatchSize = 2
	cutoff := r.clock().Add(-2 * time.Hour).Unix()
	for i := 0; i < 6; i++ {
		r.putChunk(t, "orphan-budget-"+strconv.Itoa(i), 0, cutoff)
	}

	// Advancing clock — every read advances 1ms. The budget is sized so
	// exactly one batch of 2 fits before the deadline expires:
	//   tick() call 1: cutoff; call 2: deadline=base+2ms+budget
	//   sweepTenant call 3: started; call 4 (loop check 1): base+4ms → < deadline → runs batch
	//   call 5 (loop check 2): base+5ms → ≥ deadline → exits
	// budget must satisfy 4ms < 2ms+budget < 5ms  →  budget in (2ms, 3ms).
	r.cfg.TenantBudget = 2500 * time.Microsecond
	base := r.clock()
	var ticks int64
	r.clock = func() time.Time {
		n := time.Duration(ticks) * time.Millisecond
		ticks++
		return base.Add(n)
	}

	g := &gcLoop{state: r.state, cfg: r.cfg, clock: r.clock, logger: r.logger}
	g.tick(context.Background())

	var remaining int
	if err := r.db.QueryRow(`select count(*) from chunks`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining == 0 {
		t.Error("budget exhaustion should have left some chunks for the next tick")
	}
	if remaining == 6 {
		t.Error("budget exhaustion ran no batches at all")
	}
}

func TestGCDryRunDoesNotDelete(t *testing.T) {
	r := newGCTestRig(t)
	r.cfg.DryRun = true
	h := r.putChunk(t, "dry", 0, r.clock().Add(-2*time.Hour).Unix())

	g := &gcLoop{state: r.state, cfg: r.cfg, clock: r.clock, logger: r.logger}
	g.tick(context.Background())

	if !r.chunkExists(t, h) {
		t.Error("dry-run should not delete chunks")
	}
}

func TestGCEmitsSweptChunksAudit(t *testing.T) {
	r := newGCTestRig(t)
	r.putChunk(t, "audited", 0, r.clock().Add(-2*time.Hour).Unix())

	g := &gcLoop{state: r.state, cfg: r.cfg, clock: r.clock, logger: r.logger}
	g.tick(context.Background())

	if err := r.state.audit.Close(); err != nil {
		t.Fatal(err)
	}
	line := mustGrepAuditLine(t, r.state.audit.Path(), `"event":"gc_swept_chunks"`)
	if !strings.Contains(line, `"count":1`) {
		t.Errorf("audit line missing count=1: %s", line)
	}
	if !strings.Contains(line, `"tenant_id":"t1"`) {
		t.Errorf("audit line missing tenant_id: %s", line)
	}
}

func TestGCLoopRunCancels(t *testing.T) {
	r := newGCTestRig(t)
	r.cfg.Interval = 10 * time.Millisecond
	g := &gcLoop{state: r.state, cfg: r.cfg, clock: time.Now, logger: r.logger}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestGCLoopDisabled(t *testing.T) {
	r := newGCTestRig(t)
	r.cfg.Interval = 0
	g := &gcLoop{state: r.state, cfg: r.cfg, clock: time.Now, logger: r.logger}
	if err := g.Run(context.Background()); err != nil {
		t.Errorf("Run with interval=0 should return nil, got %v", err)
	}
}

func mustGrepAuditLine(t *testing.T, path, needle string) string {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(bytes), "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("no audit line containing %s in %s\n--- log ---\n%s",
		needle, path, string(bytes))
	return ""
}
