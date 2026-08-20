package main

import (
	"fmt"
	"sync"
	"syscall"
	"time"
)

// Capacity errors surfaced by the chunk store when the backing filesystem is a
// full JuiceFS directory quota (issue #135). Both wrap syscall.EDQUOT so the
// existing data-plane boundary (storageErrToWire) maps them to a wire EDQUOT
// the FUSE client surfaces as an ordinary errno — the write fails cleanly and
// the mount stays usable, instead of the write hanging until the mount looks
// dead.
//
// Why EDQUOT for a stall: on this backing store a write+fsync only blocks past
// the timeout when the account's directory quota is full (the metadata path
// stays responsive throughout — see the pre-write statfs guard). A transient
// slow-store stall mislabeled EDQUOT is a rare, acceptable inaccuracy; the
// mount staying usable is the property that matters.
var (
	errBackingStall = fmt.Errorf("backing store write stalled: %w", syscall.EDQUOT)
	errBackingQuota = fmt.Errorf("backing store over capacity: %w", syscall.EDQUOT)
)

// backingCapacityTTL caches a statfs sample so the hot chunk-write path does at
// most one probe per second per store, not one FUSE round trip per chunk. Short
// enough that the pre-write guard trips within a second of the quota filling;
// the write watchdog covers the residual lag window.
const backingCapacityTTL = time.Second

// backingCapacity pre-rejects a chunk write that would not fit in the backing
// filesystem's free space. On a JuiceFS mount, statfs of a path under a
// quota'd directory reports that directory's quota as the capacity, so this
// reads the account's live quota headroom off the (responsive) metadata path
// before touching the (blocking-when-full) data path.
type backingCapacity struct {
	statfs func(path string) (availBytes int64, err error)
	now    func() time.Time
	ttl    time.Duration

	mu      sync.Mutex
	avail   int64
	at      time.Time
	sampled bool
}

// newBackingCapacity returns a guard backed by a real statfs and clock.
func newBackingCapacity() *backingCapacity {
	return &backingCapacity{statfs: statfsAvailBytes, now: time.Now, ttl: backingCapacityTTL}
}

// check returns errBackingQuota when the backing store has less free space than
// need. It fails open: a statfs error returns nil so the real write (bounded by
// the watchdog) remains the backstop rather than blocking writes on a probe
// error.
func (b *backingCapacity) check(root string, need int64) error {
	avail, err := b.available(root)
	if err != nil {
		return nil
	}
	if avail < need {
		return errBackingQuota
	}
	return nil
}

func (b *backingCapacity) available(root string) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if b.sampled && now.Sub(b.at) < b.ttl {
		return b.avail, nil
	}
	avail, err := b.statfs(root)
	if err != nil {
		return 0, err
	}
	b.avail = avail
	b.at = now
	b.sampled = true
	return avail, nil
}

// statfsAvailBytes reports the bytes available to an unprivileged writer at
// path. On JuiceFS this reflects the enclosing directory quota.
func statfsAvailBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
