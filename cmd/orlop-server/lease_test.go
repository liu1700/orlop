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
	if err := mgr.Release(g.LeaseID, 1); err != nil {
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
	r, err := mgr.Refresh(g.LeaseID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if r.ExpiresAtUnixMs <= first {
		t.Fatalf("refresh did not advance expiry: %d vs %d", r.ExpiresAtUnixMs, first)
	}
}

func TestRefreshUnknownReturnsError(t *testing.T) {
	mgr, _ := newTestMgr(t)
	if _, err := mgr.Refresh(make([]byte, 16), 1); err == nil {
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
	if err := mgr.Release(g.LeaseID, 1); err != nil {
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
	if err := mgr.Release(g.LeaseID, 1); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("agentB grant failed: %v", err)
	}
}

func TestGrantNewConnSupersedesLease(t *testing.T) {
	mgr, _ := newTestMgr(t)
	g1, _ := mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)

	// Same holder re-grants on a new connID (successor pod): FRESH id, old id dead.
	g2, err := mgr.Grant(context.Background(), "agentA", 2, "/x", dataplane.LeaseExclusiveWrite)
	if err != nil {
		t.Fatal(err)
	}
	if string(g1.LeaseID) == string(g2.LeaseID) {
		t.Fatal("supersede must issue a fresh lease_id, not rebind the old one")
	}
	if mgr.HeldByConn(idArrayFromBytes(g1.LeaseID), 1) || mgr.HeldByConn(idArrayFromBytes(g1.LeaseID), 2) {
		t.Fatal("old lease id must be dead after supersede")
	}
	if !mgr.HeldByConn(idArrayFromBytes(g2.LeaseID), 2) {
		t.Fatal("fresh lease must be held by the new connection")
	}

	// Stale-conn cleanup must NOT free the live lease.
	mgr.ReleaseAllForConn(1)
	if _, err := mgr.Grant(context.Background(), "agentB", 3, "/x", dataplane.LeaseExclusiveWrite); !errors.Is(err, errLeaseHeld) {
		t.Fatalf("lease should still be held after stale conn cleanup, got %v", err)
	}

	// Cleanup of the CURRENT conn frees it.
	mgr.ReleaseAllForConn(2)
	if _, err := mgr.Grant(context.Background(), "agentB", 3, "/x", dataplane.LeaseExclusiveWrite); err != nil {
		t.Fatalf("expected free path after current conn cleanup, got %v", err)
	}
}

// TestStalePodCannotKillSuccessor is the prod scenario behind the fix: pod N
// (conn 1) holds the mount lease; its successor pod N+1 (conn 2) takes over;
// pod N's teardown then releases the id it was granted. That release must be
// a no-op — before the fix it destroyed pod N+1's live lease and every
// subsequent write of pod N+1 failed the session fence.
func TestStalePodCannotKillSuccessor(t *testing.T) {
	mgr, _ := newTestMgr(t)
	gN, _ := mgr.Grant(context.Background(), "agentX", 1, "/", dataplane.LeaseExclusiveWrite)
	gN1, _ := mgr.Grant(context.Background(), "agentX", 2, "/", dataplane.LeaseExclusiveWrite)

	// Pod N tears down: releases the id it holds — already superseded.
	if err := mgr.Release(gN.LeaseID, 1); !errors.Is(err, errLeaseUnknown) {
		t.Fatalf("stale release should be unknown, got %v", err)
	}
	// Even a forged release of the LIVE id from the stale conn is refused.
	if err := mgr.Release(gN1.LeaseID, 1); !errors.Is(err, errLeaseUnknown) {
		t.Fatalf("wrong-conn release should be refused, got %v", err)
	}
	if !mgr.HeldByConn(idArrayFromBytes(gN1.LeaseID), 2) {
		t.Fatal("successor's lease must survive the stale pod's teardown")
	}
	// And the stale conn cannot keep the live lease alive either.
	if _, err := mgr.Refresh(gN1.LeaseID, 1); !errors.Is(err, errLeaseUnknown) {
		t.Fatalf("wrong-conn refresh should be refused, got %v", err)
	}
	// The rightful holder still releases normally.
	if err := mgr.Release(gN1.LeaseID, 2); err != nil {
		t.Fatal(err)
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
	if err := mgr.Release(g.LeaseID, 1); err != nil {
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
	mgr.Release(g.LeaseID, 1)

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

// TestSupersedeKeepsContenderClock: a same-holder conn takeover must not reset the
// YieldFor min-hold clock — a contending holder blocked on the old record's revoke
// must still win within a bounded number of revoke cycles, not be starved by the
// holder cycling connections.
func TestSupersedeKeepsContenderClock(t *testing.T) {
	pusher := &fakePusher{}
	cfg := leaseConfig{ttl: 30 * time.Second, minHold: 10 * time.Millisecond, revokeTimeout: 50 * time.Millisecond}
	mgr := newLeaseManager(cfg, pusher.push, nil, nil)

	if _, err := mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // past min-hold

	// Contender B starts waiting (pushes a revoke to conn 1, blocks).
	done := make(chan error, 1)
	go func() {
		_, err := mgr.Grant(context.Background(), "agentB", 9, "/x", dataplane.LeaseExclusiveWrite)
		done <- err
	}()
	time.Sleep(10 * time.Millisecond) // let B enter YieldFor

	// Holder A's successor takes over from a new connection mid-revoke.
	if _, err := mgr.Grant(context.Background(), "agentA", 2, "/x", dataplane.LeaseExclusiveWrite); err != nil {
		t.Fatal(err)
	}

	// B must still win: grantedAt carried over ⇒ min-hold already elapsed ⇒ B
	// re-revokes the new conn and force-evicts within another revokeTimeout.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("contender must eventually win after supersede, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("contender starved after same-holder conn takeover")
	}
}

// TestRefreshBindsRestoredLease: the first refresh of a snapshot-restored lease
// (connID 0) binds the caller's connection, so the write-path session fence
// (HeldByConn) passes again instead of leaving a refresh-succeeds/writes-EACCES
// zombie mount.
func TestRefreshBindsRestoredLease(t *testing.T) {
	mgr, _ := newTestMgr(t)
	g, _ := mgr.Grant(context.Background(), "agentA", 1, "/x", dataplane.LeaseExclusiveWrite)
	id := idArrayFromBytes(g.LeaseID)

	// Simulate a restore: record survives with no live conn.
	mgr.mu.Lock()
	rec := mgr.byID[id]
	delete(mgr.byConn, rec.connID)
	rec.connID = 0
	mgr.mu.Unlock()

	if _, err := mgr.Refresh(g.LeaseID, 7); err != nil {
		t.Fatalf("restored-lease refresh: %v", err)
	}
	if !mgr.HeldByConn(id, 7) {
		t.Fatal("refresh must bind the restored lease to the caller's conn")
	}
	// Bound now: another conn can no longer refresh or release it.
	if _, err := mgr.Refresh(g.LeaseID, 8); !errors.Is(err, errLeaseUnknown) {
		t.Fatalf("wrong-conn refresh after bind should be refused, got %v", err)
	}
	if err := mgr.Release(g.LeaseID, 8); !errors.Is(err, errLeaseUnknown) {
		t.Fatalf("wrong-conn release after bind should be refused, got %v", err)
	}
	if err := mgr.Release(g.LeaseID, 7); err != nil {
		t.Fatal(err)
	}
}
