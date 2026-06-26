package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

// gcLoop is the single-goroutine sweeper that walks tenants on each tick
// and deletes chunks with refcount==0 older than RetentionWindow.
type gcLoop struct {
	state *serverState
	cfg   gcConfig
	// clock is called multiple times per tick (once per budget check). Tests
	// pass an advancing fake to simulate budget pressure; production passes
	// time.Now.
	clock  func() time.Time
	logger *slog.Logger
}

type sweepResult struct {
	Count      uint64
	BytesFreed uint64
	DryRun     bool
	Duration   time.Duration
}

// Run blocks until ctx is cancelled or cfg.Interval == 0.
func (g *gcLoop) Run(ctx context.Context) error {
	if g.cfg.Interval == 0 {
		g.logger.Info("gc disabled (interval=0)")
		return nil
	}
	// Sweep once at startup so freshly-deployed servers behave consistently
	// with long-running ones.
	g.tick(ctx)
	t := time.NewTicker(g.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			g.tick(ctx)
		}
	}
}

func (g *gcLoop) tick(ctx context.Context) {
	cutoff := g.clock().Add(-g.cfg.RetentionWindow).Unix()
	for _, tid := range g.state.sortedTenantIDs() {
		if ctx.Err() != nil {
			return
		}
		tenant, _ := g.state.tenant(tid)
		deadline := g.clock().Add(g.cfg.TenantBudget)
		result, err := g.sweepTenant(ctx, tenant, cutoff, deadline)
		if err != nil {
			g.logger.Error("gc sweep failed", "tenant", tid, "error", err)
			continue
		}
		g.state.audit.Record(AuditRecord{
			Event:      "gc_swept_chunks",
			TenantID:   tid,
			Allowed:    true,
			Command:    "orlop-server",
			Count:      &result.Count,
			BytesFreed: &result.BytesFreed,
			DryRun:     &result.DryRun,
		})
		g.logger.Info("gc sweep complete",
			"tenant", tid, "count", result.Count,
			"bytes_freed", result.BytesFreed, "dry_run", result.DryRun,
			"duration_ms", result.Duration.Milliseconds(),
		)
	}
}

// sweepTenant deletes batches of refcount==0 chunks past the retention
// cutoff, until the budget runs out or no rows remain.
//
// Each batch is atomic vs concurrent manifest writes:
//   - The same predicate `refcount=0 AND added_at<?` is repeated in the
//     DELETE so a refcount bump between SELECT and DELETE prevents the row
//     from being deleted.
//   - File unlink runs OUTSIDE the SQL tx. A crash between COMMIT and
//     unlink leaves an orphan file (no row pointing at it); a future
//     vacuum-orphans admin task can sweep these.
func (g *gcLoop) sweepTenant(ctx context.Context, t *tenantState, cutoff int64, deadline time.Time) (sweepResult, error) {
	started := g.clock()
	var result sweepResult
	result.DryRun = g.cfg.DryRun
	db := t.db.DB()

	for g.clock().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		candidates, err := selectGCCandidates(db, cutoff, g.cfg.BatchSize)
		if err != nil {
			return result, fmt.Errorf("select candidates: %w", err)
		}
		if len(candidates) == 0 {
			break
		}
		if g.cfg.DryRun {
			for _, c := range candidates {
				result.Count++
				result.BytesFreed += c.size
			}
			break // single batch is enough for a dry-run report
		}
		deleted, freed, err := deleteGCBatch(db, candidates, cutoff)
		if err != nil {
			return result, fmt.Errorf("delete batch: %w", err)
		}
		// File unlinks. Errors are logged-and-continue: orphan files are
		// tolerable, missing files are no-ops.
		for _, c := range deleted {
			if err := t.chunks.Delete(c.hash); err != nil {
				g.logger.Warn("gc unlink failed", "tenant", t.id, "error", err)
			}
		}
		result.Count += uint64(len(deleted))
		result.BytesFreed += freed
	}

	result.Duration = g.clock().Sub(started)
	return result, nil
}

type gcCandidate struct {
	hash []byte
	size uint64
}

func selectGCCandidates(db *sql.DB, cutoff int64, limit int) ([]gcCandidate, error) {
	rows, err := db.Query(
		`select hash, size from chunks where refcount = 0 and added_at < ? order by added_at asc limit ?`,
		cutoff, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []gcCandidate
	for rows.Next() {
		var h []byte
		var size int64
		if err := rows.Scan(&h, &size); err != nil {
			return nil, err
		}
		out = append(out, gcCandidate{hash: h, size: uint64(size)})
	}
	return out, rows.Err()
}

// deleteGCBatch deletes all candidates whose row still satisfies the
// GC predicate at delete time. Returns the subset of candidates whose
// rows were actually deleted, plus bytes freed. A concurrent refcount
// bump silently protects its row.
//
// Important: the per-row DELETE re-asserts `refcount = 0 AND added_at < ?`
// so a refcount bump between SELECT and DELETE leaves the row intact.
// Callers must use the returned slice (not `candidates[:n]`) when
// unlinking files, because skipped rows can sit at any index, not just
// the tail.
func deleteGCBatch(db *sql.DB, candidates []gcCandidate, cutoff int64) ([]gcCandidate, uint64, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(
		`delete from chunks where hash = ? and refcount = 0 and added_at < ?`,
	)
	if err != nil {
		return nil, 0, err
	}
	defer stmt.Close()

	deleted := make([]gcCandidate, 0, len(candidates))
	var freed uint64
	for _, c := range candidates {
		res, err := stmt.Exec(c.hash, cutoff)
		if err != nil {
			return nil, 0, err
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			deleted = append(deleted, c)
			freed += c.size
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return deleted, freed, nil
}
