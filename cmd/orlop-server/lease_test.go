package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

type fakePusher struct {
	mu     sync.Mutex
	pushed []dataplane.Frame
}

func (f *fakePusher) push(connID uint64, frame dataplane.Frame) error {
	f.mu.Lock()
	f.pushed = append(f.pushed, frame)
	f.mu.Unlock()
	return nil
}

func (f *fakePusher) snapshot() []dataplane.Frame {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]dataplane.Frame, len(f.pushed))
	copy(out, f.pushed)
	return out
}

func newTestMgr(t *testing.T) (*leaseManager, *fakePusher) {
	t.Helper()
	pusher := &fakePusher{}
	cfg := leaseConfig{
		ttl:           30 * time.Second,
		minHold:       100 * time.Millisecond,
		revokeTimeout: 2 * time.Second,
	}
	mgr := newLeaseManager(cfg, pusher.push, nil /* audit */, nil /* metrics */)
	return mgr, pusher
}

func TestGrantFreePath(t *testing.T) {
	mgr, _ := newTestMgr(t)
	g, err := mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.LeaseID) != 16 {
		t.Fatalf("lease_id length %d", len(g.LeaseID))
	}
}

func TestGrantIdempotent(t *testing.T) {
	mgr, _ := newTestMgr(t)
	g1, _ := mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)
	g2, err := mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)
	if err != nil {
		t.Fatal(err)
	}
	if string(g1.LeaseID) != string(g2.LeaseID) {
		t.Fatal("idempotent grant should return same lease_id")
	}
}

func TestReleaseFreesPath(t *testing.T) {
	mgr, _ := newTestMgr(t)
	g, _ := mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)
	if err := mgr.Release(g.LeaseID); err != nil {
		t.Fatal(err)
	}
	// Different agent now grabs it.
	if _, err := mgr.Grant(context.Background(), "agentB", 2, "/x", dataplane.LeaseExclusiveWrite); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseAllForConn(t *testing.T) {
	mgr, _ := newTestMgr(t)
	mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)
	mgr.Grant(context.Background(), "agentA", 1, "/y", dataplane.LeaseExclusiveWrite)
	mgr.ReleaseAllForConn(1)
	// Both paths should now be free.
	if _, err := mgr.Grant(context.Background(), "agentB", 2, "/x", dataplane.LeaseExclusiveWrite); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Grant(context.Background(), "agentB", 2, "/y", dataplane.LeaseExclusiveWrite); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshExtends(t *testing.T) {
	mgr, _ := newTestMgr(t)
	g, _ := mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)
	first := g.ExpiresAtUnixMs
	time.Sleep(5 * time.Millisecond)
	r, err := mgr.Refresh(g.LeaseID)
	if err != nil {
		t.Fatal(err)
	}
	if r.ExpiresAtUnixMs <= first {
		t.Fatalf("refresh did not advance expiry: %d vs %d", r.ExpiresAtUnixMs, first)
	}
}

func TestRefreshUnknownReturnsError(t *testing.T) {
	mgr, _ := newTestMgr(t)
	if _, err := mgr.Refresh(make([]byte, 16)); err == nil {
		t.Fatal("expected error for unknown lease_id")
	}
}

func TestLeaseHandlerRoundTrip(t *testing.T) {
	mgr, _ := newTestMgr(t)

	// Grant via the manager (simulates handleLeaseGrant having unmarshaled).
	g, err := mgr.Grant(context.Background(), "agentA", 1, "/file", dataplane.LeaseExclusiveWrite)
	if err != nil {
		t.Fatal(err)
	}
	// Second agent on same path within min-hold → errLeaseHeld.
	_, err = mgr.Grant(context.Background(), "agentB", 2, "/file", dataplane.LeaseExclusiveWrite)
	if !errors.Is(err, errLeaseHeld) {
		t.Fatalf("want errLeaseHeld, got %v", err)
	}
	// Release; agentB succeeds.
	if err := mgr.Release(g.LeaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Grant(context.Background(), "agentB", 2, "/file", dataplane.LeaseExclusiveWrite); err != nil {
		t.Fatal(err)
	}
}

func TestGrantWithinMinHoldReturnsBusy(t *testing.T) {
	mgr, _ := newTestMgr(t)
	mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)
	// Immediately, second agent: within min-hold window → busy.
	_, err := mgr.Grant(context.Background(), "agentB", 2, "/x", dataplane.LeaseExclusiveWrite)
	if !errors.Is(err, errLeaseHeld) {
		t.Fatalf("want errLeaseHeld within min-hold, got %v", err)
	}
}

func TestGrantAfterMinHoldRevokesAndRegrants(t *testing.T) {
	mgr, pusher := newTestMgr(t)
	g, _ := mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)

	// Sleep past min-hold.
	time.Sleep(150 * time.Millisecond)

	// Concurrently: agentB requests; agentA Releases shortly after.
	done := make(chan error, 1)
	go func() {
		_, err := mgr.Grant(context.Background(), "agentB", 2, "/x", dataplane.LeaseExclusiveWrite)
		done <- err
	}()
	// Wait for the revoke push to be observable, then release as agentA would.
	deadline := time.Now().Add(time.Second)
	var pushed []dataplane.Frame
	for time.Now().Before(deadline) {
		pushed = pusher.snapshot()
		if len(pushed) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(pushed) == 0 {
		t.Fatal("expected revoke push")
	}
	if pushed[0].Op != dataplane.OpLeaseRevoke {
		t.Fatalf("push op = %v, want LEASE_REVOKE", pushed[0].Op)
	}
	if err := mgr.Release(g.LeaseID); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("agentB grant failed: %v", err)
	}
}

func TestIdempotentGrantRebindsConnID(t *testing.T) {
	mgr, _ := newTestMgr(t)
	g, _ := mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)

	// Same agent reconnects on a new connID and re-grants.
	g2, err := mgr.Grant(context.Background(), "agentA", 2, "/x", dataplane.LeaseExclusiveWrite)
	if err != nil {
		t.Fatal(err)
	}
	if string(g.LeaseID) != string(g2.LeaseID) {
		t.Fatal("expected same lease_id on idempotent re-grant")
	}

	// ReleaseAllForConn(1) must NOT free the lease — it's bound to connID 2 now.
	mgr.ReleaseAllForConn(1)
	if _, err := mgr.Grant(context.Background(), "agentB", 3, "/x", dataplane.LeaseExclusiveWrite); !errors.Is(err, errLeaseHeld) {
		t.Fatalf("lease should still be held after stale conn cleanup, got %v", err)
	}

	// ReleaseAllForConn(2) frees it.
	mgr.ReleaseAllForConn(2)
	if _, err := mgr.Grant(context.Background(), "agentB", 3, "/x", dataplane.LeaseExclusiveWrite); err != nil {
		t.Fatalf("expected free path after current conn cleanup, got %v", err)
	}
}

func TestRevokeTimeoutForceEvicts(t *testing.T) {
	pusher := &fakePusher{}
	cfg := leaseConfig{
		ttl:           30 * time.Second,
		minHold:       10 * time.Millisecond,
		revokeTimeout: 50 * time.Millisecond, // tight for test
	}
	mgr := newLeaseManager(cfg, pusher.push, nil, nil)

	mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)
	time.Sleep(20 * time.Millisecond) // past min-hold

	start := time.Now()
	_, err := mgr.Grant(context.Background(), "agentB", 2, "/x", dataplane.LeaseExclusiveWrite)
	if err != nil {
		t.Fatalf("agentB grant after revoke timeout should succeed: %v", err)
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("grant returned before revoke timeout elapsed")
	}
}

func TestYieldForFreePathReturnsNil(t *testing.T) {
	mgr, _ := newTestMgr(t)
	if err := mgr.YieldFor(context.Background(), "agentA", "/free", "test"); err != nil {
		t.Fatal(err)
	}
}

func TestYieldForOwnLeaseReturnsNil(t *testing.T) {
	mgr, _ := newTestMgr(t)
	mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)
	if err := mgr.YieldFor(context.Background(), "agentA", "/x", "test"); err != nil {
		t.Fatalf("own lease should not block: %v", err)
	}
}

func TestYieldForBusyWithinMinHold(t *testing.T) {
	mgr, _ := newTestMgr(t)
	mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)
	if err := mgr.YieldFor(context.Background(), "agentB", "/x", "test"); !errors.Is(err, errLeaseHeld) {
		t.Fatalf("want errLeaseHeld within min-hold, got %v", err)
	}
}

func TestManifestPutFromNonHolderTriggersRevoke(t *testing.T) {
	mgr, pusher := newTestMgr(t)
	g, _ := mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)

	// Past min-hold.
	time.Sleep(150 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		done <- mgr.YieldFor(context.Background(), "agentB", "/x", "manifest_put_contention")
	}()

	// Wait for revoke push.
	deadline := time.Now().Add(time.Second)
	var pushed []dataplane.Frame
	for time.Now().Before(deadline) {
		pushed = pusher.snapshot()
		if len(pushed) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(pushed) == 0 {
		t.Fatal("expected revoke push from YieldFor contention")
	}

	// agentA releases; YieldFor returns nil.
	if err := mgr.Release(g.LeaseID); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("YieldFor should return nil, got %v", err)
	}
}

func TestAuditEventsEmitted(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	audit, err := NewAuditLog(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	cfg := leaseConfig{ttl: 30 * time.Second, minHold: 10 * time.Millisecond, revokeTimeout: 50 * time.Millisecond}
	pusher := &fakePusher{}
	mgr := newLeaseManager(cfg, pusher.push, audit, nil)

	g, _ := mgr.Grant(context.Background(), "agentA", 1, "/file", dataplane.LeaseExclusiveWrite)
	mgr.Release(g.LeaseID)

	audit.Flush()
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{`"event":"lease_grant"`, `"event":"lease_release"`, `"path":"/file"`, `"lease_id":"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("audit log missing %q\nfull log:\n%s", want, got)
		}
	}
}
