package main

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lukechampine.com/blake3"
)

func TestChunkStorePutGetRoundTrip(t *testing.T) {
	dir, err := os.MkdirTemp("", "chunkstore-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	cs, err := NewChunkStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello content-addressed world")
	hash := blake3.Sum256(data)

	stored, err := cs.Put(hash[:], data)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !stored {
		t.Fatal("first put should report stored=true")
	}

	got, err := cs.Get(hash[:])
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch")
	}
}

func TestChunkStorePutIsIdempotent(t *testing.T) {
	dir, _ := os.MkdirTemp("", "chunkstore-")
	defer os.RemoveAll(dir)
	cs, _ := NewChunkStore(dir)

	data := []byte("idempotent")
	hash := blake3.Sum256(data)

	if _, err := cs.Put(hash[:], data); err != nil {
		t.Fatal(err)
	}
	stored, err := cs.Put(hash[:], data)
	if err != nil {
		t.Fatalf("re-put: %v", err)
	}
	if stored {
		t.Fatal("second put should report stored=false")
	}
}

func TestChunkStoreRejectsHashMismatch(t *testing.T) {
	dir, _ := os.MkdirTemp("", "chunkstore-")
	defer os.RemoveAll(dir)
	cs, _ := NewChunkStore(dir)

	data := []byte("xxxxxxxx")
	wrong := blake3.Sum256([]byte("not the data"))
	if _, err := cs.Put(wrong[:], data); err == nil {
		t.Fatal("expected hash mismatch error")
	}
}

func TestChunkStoreHas(t *testing.T) {
	dir, _ := os.MkdirTemp("", "chunkstore-")
	defer os.RemoveAll(dir)
	cs, _ := NewChunkStore(dir)

	a := blake3.Sum256([]byte("a"))
	b := blake3.Sum256([]byte("b"))
	missing := blake3.Sum256([]byte("c"))

	cs.Put(a[:], []byte("a"))
	cs.Put(b[:], []byte("b"))

	out, err := cs.HasMany([][]byte{a[:], missing[:], b[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !out[0] || out[1] || !out[2] {
		t.Fatalf("HasMany result = %v, want [true, false, true]", out)
	}
}

func TestChunkStoreRejectsWrongHashLen(t *testing.T) {
	dir, _ := os.MkdirTemp("", "chunkstore-")
	defer os.RemoveAll(dir)
	cs, _ := NewChunkStore(dir)

	if _, err := cs.Put([]byte("short"), []byte("data")); err == nil {
		t.Fatal("expected length error")
	}
}

// Issue #125: chunks must be readable by every process inside the storeRoot,
// not just by the writer. When `orlop-server -migrate-to-chunks` is invoked
// as a different user (e.g. root) than the live server runs as (`orlop`),
// `os.CreateTemp`'s default 0600 left the resulting files unreadable to the
// server, and handleChunkGet returned EIO with no audit row. Pin the mode
// so future regressions land here instead of staging.
func TestChunkStorePutFilesAreModeReadable(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("readable everywhere inside the store")
	h := blake3.Sum256(data)
	if _, err := cs.Put(h[:], data); err != nil {
		t.Fatalf("Put: %v", err)
	}
	p, err := cs.Path(h[:])
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	const want = 0o644
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("chunk file mode = %#o, want %#o (issue #125: cross-user reads must succeed)", got, want)
	}
}

func TestChunkStoreDeleteRemovesFile(t *testing.T) {
	root := t.TempDir()
	cs, err := NewChunkStore(root)
	if err != nil {
		t.Fatal(err)
	}
	b := []byte("hello chunk")
	h := blake3.Sum256(b)
	if _, err := cs.Put(h[:], b); err != nil {
		t.Fatal(err)
	}

	if err := cs.Delete(h[:]); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Verify the file was actually removed.
	p, err := cs.Path(h[:])
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("chunk file still present after Delete: stat err = %v", err)
	}
	// Second delete is a no-op (idempotent).
	if err := cs.Delete(h[:]); err != nil {
		t.Errorf("Delete on missing should be nil, got %v", err)
	}
}

func TestChunkStoreHasManyValidatesWholeBatch(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := blake3.Sum256([]byte("valid"))
	if got, err := cs.HasMany([][]byte{h[:], []byte("short")}); err == nil || got != nil {
		t.Fatalf("HasMany malformed batch = (%v, %v), want (nil, error)", got, err)
	}
}

func TestChunkStoreHasManyPreservesDuplicateResults(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("deduplicated presence probe")
	presentHash := blake3.Sum256(data)
	missingHash := blake3.Sum256([]byte("deduplicated missing probe"))
	if _, err := cs.Put(presentHash[:], data); err != nil {
		t.Fatal(err)
	}

	got, err := cs.HasMany([][]byte{presentHash[:], missingHash[:], presentHash[:], missingHash[:]})
	if err != nil {
		t.Fatal(err)
	}
	want := []bool{true, false, true, false}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("HasMany duplicate result = %v, want %v", got, want)
		}
	}
}

func TestChunkStoreDeleteManyIsOrderedAndIdempotent(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := []byte("delete-many-a")
	b := []byte("delete-many-b")
	ha := blake3.Sum256(a)
	hb := blake3.Sum256(b)
	missing := blake3.Sum256([]byte("delete-many-missing"))
	for h, data := range map[[32]byte][]byte{ha: a, hb: b} {
		if _, err := cs.Put(h[:], data); err != nil {
			t.Fatal(err)
		}
	}

	results, err := cs.DeleteMany([][]byte{ha[:], missing[:], hb[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !results[0].Deleted || results[0].Err != nil || results[1].Deleted || results[1].Err != nil || !results[2].Deleted || results[2].Err != nil {
		t.Fatalf("DeleteMany results = %+v", results)
	}

	results, err = cs.DeleteMany([][]byte{ha[:], missing[:], hb[:]})
	if err != nil {
		t.Fatal(err)
	}
	for i, result := range results {
		if result.Deleted || result.Err != nil {
			t.Errorf("idempotent DeleteMany result[%d] = %+v, want missing success", i, result)
		}
	}
}

func TestChunkStoreDeleteManyRejectsMalformedBatchBeforeUnlink(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("must survive malformed batch")
	h := blake3.Sum256(data)
	if _, err := cs.Put(h[:], data); err != nil {
		t.Fatal(err)
	}
	if got, err := cs.DeleteMany([][]byte{h[:], []byte("short")}); err == nil || got != nil {
		t.Fatalf("DeleteMany malformed batch = (%v, %v), want (nil, error)", got, err)
	}
	present, err := cs.Has(h[:])
	if err != nil || !present {
		t.Fatalf("valid chunk was unlinked before validation completed: present=%v err=%v", present, err)
	}
}

func TestChunkStoreDeleteManyContinuesAfterItemError(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := []byte("delete-many-continues-a")
	b := []byte("delete-many-continues-b")
	ha := blake3.Sum256(a)
	hb := blake3.Sum256(b)
	bad := blake3.Sum256([]byte("directory cannot be unlinked as a chunk"))
	for h, data := range map[[32]byte][]byte{ha: a, hb: b} {
		if _, err := cs.Put(h[:], data); err != nil {
			t.Fatal(err)
		}
	}
	badPath, err := cs.Path(bad[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}

	results, err := cs.DeleteMany([][]byte{ha[:], bad[:], hb[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !results[0].Deleted || results[0].Err != nil || results[1].Err == nil || !results[2].Deleted || results[2].Err != nil {
		t.Fatalf("DeleteMany partial failure results = %+v", results)
	}
}

func TestChunkStoreHasManyRejectsNonRegularEntry(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := blake3.Sum256([]byte("directory masquerading as chunk"))
	p, err := cs.Path(h[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	cs.knownShard[h[0]].Store(true)
	if got, err := cs.HasMany([][]byte{h[:]}); err == nil || got != nil {
		t.Fatalf("HasMany non-regular entry = (%v, %v), want (nil, error)", got, err)
	}
}

func TestChunkStoreHasManyRejectsSymlinkChunkEntry(t *testing.T) {
	root := t.TempDir()
	cs, err := NewChunkStore(root)
	if err != nil {
		t.Fatal(err)
	}
	h := blake3.Sum256([]byte("outside chunk"))
	name := fmt.Sprintf("%x", h)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, name), []byte("not the addressed content"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := cs.Path(h[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, name), p); err != nil {
		t.Fatal(err)
	}
	cs.knownShard[h[0]].Store(true)
	if got, err := cs.HasMany([][]byte{h[:]}); err == nil || got != nil {
		t.Fatalf("HasMany symlink chunk = (%v, %v), want (nil, error)", got, err)
	}
}

func TestChunkStoreConcurrentPutAndHasManyNeverExposePartialChunk(t *testing.T) {
	root := t.TempDir()
	cs, err := NewChunkStore(root)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("atomic-content-"), 64*1024)
	h := blake3.Sum256(data)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := cs.Put(h[:], data); err != nil {
				t.Errorf("concurrent Put: %v", err)
			}
		}()
	}
	close(start)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	for {
		present, err := cs.HasMany([][]byte{h[:]})
		if err != nil {
			t.Fatal(err)
		}
		if present[0] {
			got, err := cs.Get(h[:])
			if err != nil {
				t.Fatalf("Get after present: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("HasMany reported present while a partial chunk was visible")
			}
		}
		select {
		case <-done:
			present, err := cs.HasMany([][]byte{h[:]})
			if err != nil || !present[0] {
				t.Fatalf("chunk missing after concurrent puts: present=%v err=%v", present, err)
			}
			return
		default:
		}
	}
}

func TestChunkStoreHasManyAfterReopen(t *testing.T) {
	root := t.TempDir()
	cs, err := NewChunkStore(root)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("durable across chunk-store reopen")
	h := blake3.Sum256(data)
	if _, err := cs.Put(h[:], data); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewChunkStore(root)
	if err != nil {
		t.Fatal(err)
	}
	present, err := reopened.HasMany([][]byte{h[:]})
	if err != nil || !present[0] {
		t.Fatalf("reopened HasMany = %v, err=%v; committed chunk must remain discoverable", present, err)
	}
}

func TestChunkStoreUnknownShardReconcilesOnPut(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("created outside the live chunk store")
	h := blake3.Sum256(data)
	p, err := cs.Path(h[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}

	present, err := cs.HasMany([][]byte{h[:]})
	if err != nil || present[0] {
		t.Fatalf("unindexed external shard = %v, err=%v; want safe redundant-upload miss", present, err)
	}
	stored, err := cs.Put(h[:], data)
	if err != nil || stored {
		t.Fatalf("reconcile Put = stored %v, err=%v; want existing chunk", stored, err)
	}
	present, err = cs.HasMany([][]byte{h[:]})
	if err != nil || !present[0] {
		t.Fatalf("HasMany after reconcile Put = %v, err=%v", present, err)
	}
}

func TestChunkStoreBatchWorkerLimit(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hashes := make([][]byte, maxChunkDeleteWorkers*2)
	for i := range hashes {
		h := make([]byte, HashLen)
		h[0] = byte(i)
		hashes[i] = h
		cs.knownShard[h[0]].Store(true)
		if err := os.MkdirAll(filepath.Join(cs.root, fmt.Sprintf("%02x", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	var active atomic.Int64
	var peak atomic.Int64
	_, itemErrs, err := runChunkBatch(cs, hashes, false, chunkBatchDelete, func(_ *chunkShard, _ string) (bool, error) {
		n := active.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, err := range itemErrs {
		if err != nil {
			t.Fatalf("itemErrs[%d]: %v", i, err)
		}
	}
	if got := peak.Load(); got <= 1 || got > maxChunkDeleteWorkers {
		t.Fatalf("peak workers = %d, want 2..%d", got, maxChunkDeleteWorkers)
	}
}

// BenchmarkChunkStoreHasManyFastCDC models the average eight-chunk window in
// the deterministic 512 MiB FastCDC corpus. high_dedup repeatedly probes two
// existing hashes; zero_dedup probes eight new hashes spread across shards.
func BenchmarkChunkStoreHasManyFastCDC(b *testing.B) {
	storeRoot := b.TempDir()
	var err error
	if mountedRoot := os.Getenv("ORLOP_BENCH_STORE_ROOT"); mountedRoot != "" {
		storeRoot, err = os.MkdirTemp(mountedRoot, "orlop-chunk-bench-")
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = os.RemoveAll(storeRoot) })
	}
	cs, err := NewChunkStore(storeRoot)
	if err != nil {
		b.Fatal(err)
	}
	present := make([][32]byte, 2)
	for i := range present {
		data := []byte(fmt.Sprintf("fastcdc-present-%d", i))
		present[i] = blake3.Sum256(data)
		if _, err := cs.Put(present[i][:], data); err != nil {
			b.Fatal(err)
		}
	}
	highDedup := make([][]byte, 8)
	for i := range highDedup {
		highDedup[i] = present[i%len(present)][:]
	}
	zeroDedup := make([][]byte, 8)
	for i := range zeroDedup {
		h := blake3.Sum256([]byte(fmt.Sprintf("fastcdc-missing-%d", i)))
		zeroDedup[i] = h[:]
	}
	zeroDedupPopulated := make([][]byte, 8)
	for i := range zeroDedupPopulated {
		h := blake3.Sum256([]byte(fmt.Sprintf("fastcdc-populated-missing-%d", i)))
		zeroDedupPopulated[i] = h[:]
		cs.knownShard[h[0]].Store(true)
		if err := os.MkdirAll(filepath.Join(cs.root, fmt.Sprintf("%02x", h[0])), 0o755); err != nil {
			b.Fatal(err)
		}
	}

	workloads := map[string][][]byte{
		"high_dedup":                  highDedup,
		"zero_dedup_sparse_shards":    zeroDedup,
		"zero_dedup_populated_shards": zeroDedupPopulated,
	}
	for name, hashes := range workloads {
		b.Run(name+"/serial", func(b *testing.B) {
			b.ReportMetric(float64(len(hashes)), "hashes/op")
			samples := make([]time.Duration, 0, b.N)
			for range b.N {
				started := time.Now()
				for _, h := range hashes {
					p, err := cs.Path(h)
					if err != nil {
						b.Fatal(err)
					}
					_, _ = os.Stat(p)
				}
				samples = append(samples, time.Since(started))
			}
			b.StopTimer()
			reportLatencyQuantiles(b, samples)
		})
		b.Run(name+"/shard_batch", func(b *testing.B) {
			b.ReportMetric(float64(len(hashes)), "hashes/op")
			samples := make([]time.Duration, 0, b.N)
			for range b.N {
				started := time.Now()
				if _, err := cs.HasMany(hashes); err != nil {
					b.Fatal(err)
				}
				samples = append(samples, time.Since(started))
			}
			b.StopTimer()
			reportLatencyQuantiles(b, samples)
		})
	}
}

// BenchmarkChunkStoreDeleteManyFastCDC measures the 200-object GC batch from
// the JuiceFS issue-7 reproduction. Setup is excluded so only unlink latency is
// compared. Set ORLOP_BENCH_STORE_ROOT to a mounted JuiceFS directory for the
// production-representative result.
func BenchmarkChunkStoreDeleteManyFastCDC(b *testing.B) {
	storeRoot := b.TempDir()
	var err error
	if mountedRoot := os.Getenv("ORLOP_BENCH_STORE_ROOT"); mountedRoot != "" {
		storeRoot, err = os.MkdirTemp(mountedRoot, "orlop-gc-bench-")
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = os.RemoveAll(storeRoot) })
	}
	cs, err := NewChunkStore(storeRoot)
	if err != nil {
		b.Fatal(err)
	}

	const batchSize = 200
	hashes := make([][]byte, batchSize)
	paths := make([]string, batchSize)
	for i := range hashes {
		h := blake3.Sum256([]byte(fmt.Sprintf("fastcdc-gc-%d", i)))
		hashes[i] = h[:]
		paths[i], err = cs.Path(h[:])
		if err != nil {
			b.Fatal(err)
		}
	}
	seed := func(b *testing.B) {
		b.Helper()
		for _, p := range paths {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				b.Fatal(err)
			}
			if err := os.WriteFile(p, nil, 0o644); err != nil {
				b.Fatal(err)
			}
		}
	}

	b.Run("serial", func(b *testing.B) {
		b.ReportMetric(batchSize, "hashes/op")
		samples := make([]time.Duration, 0, b.N)
		for range b.N {
			b.StopTimer()
			seed(b)
			b.StartTimer()
			started := time.Now()
			for _, p := range paths {
				if err := os.Remove(p); err != nil {
					b.Fatal(err)
				}
			}
			samples = append(samples, time.Since(started))
		}
		b.StopTimer()
		reportLatencyQuantiles(b, samples)
	})
	b.Run("shard_batch", func(b *testing.B) {
		b.ReportMetric(batchSize, "hashes/op")
		samples := make([]time.Duration, 0, b.N)
		for range b.N {
			b.StopTimer()
			seed(b)
			b.StartTimer()
			started := time.Now()
			results, err := cs.DeleteMany(hashes)
			if err != nil {
				b.Fatal(err)
			}
			for i, result := range results {
				if !result.Deleted || result.Err != nil {
					b.Fatalf("DeleteMany result[%d] = %+v", i, result)
				}
			}
			samples = append(samples, time.Since(started))
		}
		b.StopTimer()
		reportLatencyQuantiles(b, samples)
	})
}

func reportLatencyQuantiles(b *testing.B, samples []time.Duration) {
	b.Helper()
	if len(samples) == 0 {
		return
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	quantile := func(p float64) time.Duration {
		index := int(math.Ceil(float64(len(samples))*p)) - 1
		return samples[index]
	}
	b.ReportMetric(float64(quantile(0.95).Nanoseconds()), "p95-ns/op")
	b.ReportMetric(float64(quantile(0.99).Nanoseconds()), "p99-ns/op")
}
