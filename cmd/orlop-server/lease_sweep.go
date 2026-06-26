package main

import (
	"context"
	"log/slog"
	"time"
)

// defaultLeaseSweepInterval is how often the expiry sweeper wakes. Half of
// the smallest plausible TTL — catches expired leases within one tick of
// their deadline without burning CPU on no-op walks.
const defaultLeaseSweepInterval = 30 * time.Second

// leaseSweepLoop reaps leases past expiresAt that the conn-close path didn't
// catch — typically clients whose TCP socket is stuck half-open so
// ReleaseAllForConn never fires.
type leaseSweepLoop struct {
	state    *serverState
	interval time.Duration
	logger   *slog.Logger
}

func newLeaseSweepLoop(state *serverState, logger *slog.Logger) *leaseSweepLoop {
	return &leaseSweepLoop{
		state:    state,
		interval: defaultLeaseSweepInterval,
		logger:   logger,
	}
}

func (l *leaseSweepLoop) Run(ctx context.Context) error {
	l.tick()
	t := time.NewTicker(l.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			l.tick()
		}
	}
}

func (l *leaseSweepLoop) tick() {
	if l.state == nil {
		return
	}
	now := time.Now()
	for _, tid := range l.state.sortedTenantIDs() {
		ts, ok := l.state.tenant(tid)
		if !ok || ts.leases == nil {
			continue
		}
		if n := ts.leases.SweepExpired(now); n > 0 {
			l.logger.Info("lease sweep removed expired", "tenant", tid, "count", n)
		}
	}
}
