package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type ensureCall struct {
	tenant string
	dir    string
	size   int64
}

type fakeEnsurer struct {
	mu       sync.Mutex
	calls    []ensureCall
	failNext int // fail this many upcoming calls, then succeed

	started chan ensureCall // optional: buffered, receives each call as it begins
	release chan struct{}   // optional: when non-nil, EnsureQuota blocks until a value is received
}

func (f *fakeEnsurer) EnsureQuota(ctx context.Context, tenant, dir string, size int64) (uint32, error) {
	f.mu.Lock()
	c := ensureCall{tenant, dir, size}
	f.calls = append(f.calls, c)
	fail := f.failNext > 0
	if fail {
		f.failNext--
	}
	started, release := f.started, f.release
	f.mu.Unlock()

	if started != nil {
		started <- c
	}
	if release != nil {
		<-release
	}
	if fail {
		return 0, errors.New("quota boom")
	}
	return 1, nil
}

func (f *fakeEnsurer) snapshot() []ensureCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ensureCall, len(f.calls))
	copy(out, f.calls)
	return out
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (a *accountQuotaApplier) pendingLen() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}

// waitFor polls cond until true or the deadline, failing the test otherwise.
func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", msg)
}

func TestAccountQuotaApplier_AppliesEnqueued(t *testing.T) {
	f := &fakeEnsurer{}
	a := newAccountQuotaApplierWithBackoff(f, discardLogger(), time.Millisecond, 5*time.Millisecond)
	defer a.Stop()

	a.Enqueue("u_owner", "/jfs/tenants/u_owner", 1<<30)

	waitFor(t, 2*time.Second, func() bool { return a.pendingLen() == 0 }, "pending to drain")

	calls := f.snapshot()
	if len(calls) != 1 {
		t.Fatalf("want 1 apply, got %d: %+v", len(calls), calls)
	}
	if calls[0] != (ensureCall{"u_owner", "/jfs/tenants/u_owner", 1 << 30}) {
		t.Fatalf("unexpected apply args: %+v", calls[0])
	}
}

func TestAccountQuotaApplier_RetriesUntilSuccess(t *testing.T) {
	f := &fakeEnsurer{failNext: 2}
	a := newAccountQuotaApplierWithBackoff(f, discardLogger(), time.Millisecond, 4*time.Millisecond)
	defer a.Stop()

	a.Enqueue("u_owner", "/dir", 2<<30)

	waitFor(t, 2*time.Second, func() bool { return a.pendingLen() == 0 }, "pending to drain after retries")

	calls := f.snapshot()
	if len(calls) < 3 {
		t.Fatalf("want >=3 attempts (2 fail + 1 success), got %d: %+v", len(calls), calls)
	}
	last := calls[len(calls)-1]
	if last.size != 2<<30 {
		t.Fatalf("last attempt should carry the requested size, got %+v", last)
	}
}

func TestAccountQuotaApplier_CoalescesLatestSize(t *testing.T) {
	f := &fakeEnsurer{started: make(chan ensureCall, 8), release: make(chan struct{})}
	a := newAccountQuotaApplierWithBackoff(f, discardLogger(), time.Millisecond, 4*time.Millisecond)
	defer a.Stop()

	// First apply enters and blocks on release.
	a.Enqueue("u_owner", "/dir", 100)
	first := <-f.started
	if first.size != 100 {
		t.Fatalf("first apply size = %d, want 100", first.size)
	}
	// Supersede with a new budget while the first apply is mid-flight.
	a.Enqueue("u_owner", "/dir", 200)
	f.release <- struct{}{} // let the (now-stale) size-100 apply finish

	// The worker must re-apply with the latest size, not consider it done.
	second := <-f.started
	if second.size != 200 {
		t.Fatalf("second apply size = %d, want 200 (latest)", second.size)
	}
	f.release <- struct{}{} // let the size-200 apply finish

	waitFor(t, 2*time.Second, func() bool { return a.pendingLen() == 0 }, "pending to drain after coalesced apply")

	calls := f.snapshot()
	if len(calls) != 2 {
		t.Fatalf("want exactly 2 applies (100 superseded, then 200), got %d: %+v", len(calls), calls)
	}
	if calls[0].size != 100 || calls[1].size != 200 {
		t.Fatalf("apply order wrong: %+v", calls)
	}
}

func TestAccountQuotaApplier_StopUnblocks(t *testing.T) {
	f := &fakeEnsurer{}
	a := newAccountQuotaApplierWithBackoff(f, discardLogger(), time.Millisecond, 4*time.Millisecond)
	done := make(chan struct{})
	go func() { a.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return promptly on an idle applier")
	}
}
