package main

import (
	"errors"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"lukechampine.com/blake3"
)

// fakeCapacity builds a guard whose free-space reading is *availPtr and which
// never caches (ttl 0 forces a re-sample on every check), so a test can flip
// the store from roomy to full between puts.
func fakeCapacity(availPtr *int64) *backingCapacity {
	return &backingCapacity{
		statfs: func(string) (int64, error) { return atomic.LoadInt64(availPtr), nil },
		now:    time.Now,
		ttl:    0,
	}
}

func TestBackingCapacityCheck(t *testing.T) {
	var avail int64 = 1000
	b := fakeCapacity(&avail)

	if err := b.check("/x", 500); err != nil {
		t.Fatalf("room to fit: unexpected error %v", err)
	}
	if err := b.check("/x", 1000); err != nil {
		t.Fatalf("exact fit: unexpected error %v", err)
	}
	atomic.StoreInt64(&avail, 100)
	err := b.check("/x", 500)
	if !errors.Is(err, errBackingQuota) {
		t.Fatalf("over capacity: err = %v, want errBackingQuota", err)
	}
	if !errors.Is(err, syscall.EDQUOT) {
		t.Fatalf("errBackingQuota must wrap EDQUOT, got %v", err)
	}
}

func TestBackingCapacityFailsOpenOnStatfsError(t *testing.T) {
	b := &backingCapacity{
		statfs: func(string) (int64, error) { return 0, errors.New("statfs blew up") },
		now:    time.Now,
		ttl:    0,
	}
	// A probe error must not block writes; the real write (watchdog-bounded) is
	// the backstop.
	if err := b.check("/x", 1<<20); err != nil {
		t.Fatalf("statfs error should fail open, got %v", err)
	}
}

func TestBackingCapacityCachesWithinTTL(t *testing.T) {
	var calls int32
	fixed := time.Now()
	b := &backingCapacity{
		statfs: func(string) (int64, error) { atomic.AddInt32(&calls, 1); return 1 << 30, nil },
		now:    func() time.Time { return fixed },
		ttl:    time.Minute,
	}
	for range 5 {
		if err := b.check("/x", 1); err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("statfs called %d times within TTL, want 1", got)
	}
}

// The pre-write guard rejects a genuinely new chunk when the store is full, but
// a re-put of already-stored content writes nothing and must never be rejected.
func TestChunkStoreCapacityGuardSkipsDedup(t *testing.T) {
	var avail int64 = 1 << 30
	cs, err := NewChunkStore(t.TempDir(), WithCapacityGuard(fakeCapacity(&avail)))
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("already stored before the quota filled")
	hash := blake3.Sum256(data)
	if _, err := cs.Put(hash[:], data); err != nil {
		t.Fatalf("initial put: %v", err)
	}

	atomic.StoreInt64(&avail, 0) // store now full

	// Re-put of the existing chunk: dedup hit, no write, not rejected.
	stored, err := cs.Put(hash[:], data)
	if err != nil {
		t.Fatalf("dedup re-put should not be rejected, got %v", err)
	}
	if stored {
		t.Fatal("dedup re-put should report stored=false")
	}

	// A brand-new chunk while full is rejected with EDQUOT.
	other := []byte("a new unique chunk that needs real space")
	otherHash := blake3.Sum256(other)
	_, err = cs.Put(otherHash[:], other)
	if !errors.Is(err, syscall.EDQUOT) {
		t.Fatalf("new put while full: err = %v, want EDQUOT", err)
	}
}

// A backing write that blocks past writeTimeout returns errBackingStall (an
// EDQUOT) promptly, and no chunk becomes visible.
func TestChunkStoreWriteWatchdogStall(t *testing.T) {
	release := make(chan struct{})
	cs, err := NewChunkStore(t.TempDir(), WithBackingWriteTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	cs.syncFn = func(*os.File, []byte) error {
		<-release // simulate an fsync wedged on a full JuiceFS directory quota
		return nil
	}

	data := []byte("write that stalls on a full backing store")
	hash := blake3.Sum256(data)

	start := time.Now()
	_, err = cs.Put(hash[:], data)
	elapsed := time.Since(start)

	if !errors.Is(err, errBackingStall) || !errors.Is(err, syscall.EDQUOT) {
		t.Fatalf("stalled put: err = %v, want errBackingStall wrapping EDQUOT", err)
	}
	if elapsed > time.Second {
		t.Fatalf("watchdog took %v, expected to fire near the 50ms timeout", elapsed)
	}
	if has, _ := cs.Has(hash[:]); has {
		t.Fatal("a stalled write must not publish a chunk")
	}

	close(release) // let the abandoned goroutine drain and clean up its temp file
}

// The watchdog path must pass a healthy write through unchanged.
func TestChunkStoreWriteWatchdogCompletes(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir(), WithBackingWriteTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("a normal, fast write under the watchdog")
	hash := blake3.Sum256(data)

	stored, err := cs.Put(hash[:], data)
	if err != nil {
		t.Fatalf("healthy put: %v", err)
	}
	if !stored {
		t.Fatal("healthy put should report stored=true")
	}
	got, err := cs.Get(hash[:])
	if err != nil || string(got) != string(data) {
		t.Fatalf("get after watchdog put: got %q err %v", got, err)
	}
}

// A real (non-stall) errno from the write must still surface through the
// watchdog path, preserving the #136 capacity-errno propagation.
func TestChunkStoreWriteWatchdogPropagatesErrno(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir(), WithBackingWriteTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	cs.syncFn = func(*os.File, []byte) error { return syscall.ENOSPC }

	data := []byte("write that hits a hard ENOSPC")
	hash := blake3.Sum256(data)
	if _, err := cs.Put(hash[:], data); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("put err = %v, want ENOSPC preserved through the watchdog", err)
	}
}
