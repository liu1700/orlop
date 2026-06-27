package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/serverapi"
)

// certRevocationReconcileInterval bounds the cold-start / convergence window:
// a freshly restarted orlop-server has an empty in-memory deny-list until the
// next reconcile, and a newly recorded revocation reaches every server within
// this interval. Agent leaves live ~1h, so a minute keeps the exposure small.
const certRevocationReconcileInterval = 60 * time.Second

// certRevocationPusher pushes the active deny-list to one server's ops endpoint.
type certRevocationPusher interface {
	PushCertRevocations(ctx context.Context, opsAddr string, revs []serverapi.CertRevocation) error
}

// certRevocationReconciler periodically fans the active serial deny-list out to
// every data-plane server (issue #5). This is the convergence half of the kill
// switch: lease release records a revocation in Postgres (durable), and this
// loop pushes the active set to the in-memory registries on the servers,
// repopulating any that restarted. Best-effort per server — a push failure is
// logged and retried on the next tick.
type certRevocationReconciler struct {
	q        db.Store
	pusher   certRevocationPusher
	logger   *slog.Logger
	interval time.Duration
}

func newCertRevocationReconciler(q db.Store, pusher certRevocationPusher, logger *slog.Logger) *certRevocationReconciler {
	return &certRevocationReconciler{
		q:        q,
		pusher:   pusher,
		logger:   logger,
		interval: certRevocationReconcileInterval,
	}
}

// Run pushes once immediately, then on every interval tick until ctx is done.
func (rc *certRevocationReconciler) Run(ctx context.Context) {
	t := time.NewTicker(rc.interval)
	defer t.Stop()
	rc.reconcileOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rc.reconcileOnce(ctx)
		}
	}
}

func (rc *certRevocationReconciler) reconcileOnce(ctx context.Context) {
	revs, err := rc.q.ListActiveCertRevocations(ctx)
	if err != nil {
		rc.logger.Warn("cert_revocation_reconcile_list_failed", "error", err)
		return
	}
	if len(revs) == 0 {
		return // nothing to converge; server merge-semantics need no empty push
	}
	payload := make([]serverapi.CertRevocation, 0, len(revs))
	for _, r := range revs {
		payload = append(payload, serverapi.CertRevocation{
			Serial:    r.CertSerial,
			ExpiresAt: r.ExpiresAt.Time,
		})
	}
	addrs, err := rc.q.ListActiveServerOpsAddrs(ctx)
	if err != nil {
		rc.logger.Warn("cert_revocation_reconcile_servers_failed", "error", err)
		return
	}
	for _, ops := range addrs {
		if err := rc.pusher.PushCertRevocations(ctx, ops, payload); err != nil {
			rc.logger.Warn("cert_revocation_push_failed", "ops_addr", ops, "error", err)
		}
	}
}
