package main

import (
	"context"
	"log/slog"
	"time"
)

const defaultJournalRowRefreshInterval = 10 * time.Minute

// journalRowRefreshLoop publishes orlop_journal_rows_total{allocation_id}
// by querying COUNT(*) GROUP BY allocation_id from each tenant's
// session_journal table. Spec §4.9 calls for a gauge refreshed every
// ~10 min — the per-write counter handles deltas; this gauge keeps the
// absolute size visible without paying per-write CPU.
type journalRowRefreshLoop struct {
	state    *serverState
	interval time.Duration
	logger   *slog.Logger
	// seen is the union of allocation_ids the loop set the gauge for on
	// the previous tick. The gauge's only label is allocation_id, so a
	// flat set is enough; a previously-seen allocation absent from this
	// tick has its time series dropped. Owned by Run + tick.
	seen map[string]struct{}
}

func newJournalRowRefreshLoop(state *serverState, logger *slog.Logger) *journalRowRefreshLoop {
	return &journalRowRefreshLoop{
		state:    state,
		interval: defaultJournalRowRefreshInterval,
		logger:   logger,
		seen:     make(map[string]struct{}),
	}
}

func (l *journalRowRefreshLoop) Run(ctx context.Context) error {
	l.tick(ctx)
	t := time.NewTicker(l.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			l.tick(ctx)
		}
	}
}

func (l *journalRowRefreshLoop) tick(ctx context.Context) {
	if l.state == nil {
		return
	}
	fresh := make(map[string]struct{})
	for _, tid := range l.state.sortedTenantIDs() {
		ts, ok := l.state.tenant(tid)
		if !ok || ts.journal == nil {
			continue
		}
		counts, err := ts.journal.SnapshotRowCounts(ctx)
		if err != nil {
			l.logger.Warn("journal row count snapshot failed", "tenant", tid, "error", err)
			continue
		}
		for allocID, n := range counts {
			l.state.metrics.journalRowCount(allocID, n)
			fresh[allocID] = struct{}{}
		}
	}
	for allocID := range l.seen {
		if _, still := fresh[allocID]; !still {
			l.state.metrics.journalRowCountDelete(allocID)
		}
	}
	l.seen = fresh
}
