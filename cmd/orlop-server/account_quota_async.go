package main

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// quotaEnsurer is the slice of *quota.Manager the applier needs. An interface so
// tests can inject a fake; *quota.Manager satisfies it.
type quotaEnsurer interface {
	EnsureQuota(ctx context.Context, tenantID, dir string, sizeBytes int64) (uint32, error)
}

// accountQuotaApplier applies JuiceFS account quotas off the request path.
//
// On a networked metadata engine the first `juicefs quota set` for an owner can
// take tens of seconds — longer than the orlop-control→server request
// deadline — so doing it inline in registerTenant blocks the agent disk mount
// and the enroll 500s before the (idempotent) quota ever lands. This applier
// lets registerTenant return as soon as the tenant dir exists; the quota is
// (re)asserted in the background and retried until it sticks.
//
// Coalescing: at most one pending entry per owner (latest desired size wins), so
// a burst of agents registering under the same account collapses to one apply,
// and a budget change supersedes an in-flight one.
type accountQuotaApplier struct {
	qm     quotaEnsurer
	logger *slog.Logger

	retryMin time.Duration
	retryMax time.Duration

	mu      sync.Mutex
	pending map[string]pendingQuota

	wake chan struct{}
	stop chan struct{}
	done chan struct{}
}

type pendingQuota struct {
	dir       string
	sizeBytes int64
}

const (
	// quotaRetryMin/Max bound the backoff between failed background apply passes.
	quotaRetryMin = 3 * time.Second
	quotaRetryMax = 30 * time.Second
	// quotaApplyTimeout caps a single background apply. Generous: the first
	// apply on a remote meta engine is the slow case this whole path exists for.
	quotaApplyTimeout = 90 * time.Second
)

// newAccountQuotaApplier starts the background worker. Stop must be called to
// release it (wired into serverState.Close).
func newAccountQuotaApplier(qm quotaEnsurer, logger *slog.Logger) *accountQuotaApplier {
	return newAccountQuotaApplierWithBackoff(qm, logger, quotaRetryMin, quotaRetryMax)
}

// newAccountQuotaApplierWithBackoff is the test seam: it lets tests shrink the
// retry backoff so a failure path doesn't sleep for seconds.
func newAccountQuotaApplierWithBackoff(qm quotaEnsurer, logger *slog.Logger, retryMin, retryMax time.Duration) *accountQuotaApplier {
	a := &accountQuotaApplier{
		qm:       qm,
		logger:   logger,
		retryMin: retryMin,
		retryMax: retryMax,
		pending:  make(map[string]pendingQuota),
		wake:     make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go a.run()
	return a
}

// Enqueue records the desired account quota for ownerTenant and signals the
// worker. Non-blocking: returns immediately whether or not an apply is in
// flight. A later Enqueue for the same owner overwrites the desired size.
func (a *accountQuotaApplier) Enqueue(ownerTenant, ownerDir string, sizeBytes int64) {
	a.mu.Lock()
	a.pending[ownerTenant] = pendingQuota{dir: ownerDir, sizeBytes: sizeBytes}
	a.mu.Unlock()
	a.signal()
}

func (a *accountQuotaApplier) signal() {
	select {
	case a.wake <- struct{}{}:
	default: // a wake is already queued; the worker will see the latest pending map
	}
}

// Stop signals the worker to exit and waits for it to drain. Idempotent-safe
// only once (close panics on double close), matching serverState.Close.
func (a *accountQuotaApplier) Stop() {
	close(a.stop)
	<-a.done
}

func (a *accountQuotaApplier) run() {
	defer close(a.done)
	backoff := a.retryMin
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()

	for {
		select {
		case <-a.stop:
			return
		case <-a.wake:
		case <-timer.C:
		}

		failed := a.drainOnce()

		if failed {
			timer.Reset(backoff)
			if backoff *= 2; backoff > a.retryMax {
				backoff = a.retryMax
			}
		} else {
			backoff = a.retryMin
		}
	}
}

// drainOnce attempts every pending owner once. Returns true if any apply failed
// (so the caller schedules a retry). Successful entries whose desired size has
// not changed underneath are removed; entries superseded mid-apply are kept so
// the new size is applied on the next pass.
func (a *accountQuotaApplier) drainOnce() (anyFailed bool) {
	a.mu.Lock()
	snapshot := make(map[string]pendingQuota, len(a.pending))
	for owner, pq := range a.pending {
		snapshot[owner] = pq
	}
	a.mu.Unlock()

	for owner, pq := range snapshot {
		select {
		case <-a.stop:
			return false
		default:
		}

		ctx, cancel := context.WithTimeout(context.Background(), quotaApplyTimeout)
		_, err := a.qm.EnsureQuota(ctx, owner, pq.dir, pq.sizeBytes)
		cancel()

		a.mu.Lock()
		cur, stillPending := a.pending[owner]
		switch {
		case err != nil:
			anyFailed = true
			a.logger.Warn("account_quota_apply_retry", "owner_tenant", owner, "size_bytes", pq.sizeBytes, "error", err)
		case stillPending && cur == pq:
			delete(a.pending, owner) // applied exactly what is still desired
			a.logger.Info("account_quota_applied", "owner_tenant", owner, "size_bytes", pq.sizeBytes)
		default:
			// Superseded by a newer Enqueue while applying; leave it for next pass.
		}
		a.mu.Unlock()
	}
	return anyFailed
}
