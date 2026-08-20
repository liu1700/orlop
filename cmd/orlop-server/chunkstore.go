package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"lukechampine.com/blake3"
)

// HashLen is the wire length of a chunk hash. BLAKE3-32.
const HashLen = 32

// The process-wide delete pool keeps GC from creating an unbounded number of
// goroutines or FUSE metadata operations.
const maxChunkDeleteWorkers = 16

type chunkWorkerPool struct {
	once  sync.Once
	size  int
	tasks chan func()
}

func (p *chunkWorkerPool) submit(task func()) {
	p.once.Do(func() {
		p.tasks = make(chan func(), p.size*16)
		for range p.size {
			go func() {
				for task := range p.tasks {
					task()
				}
			}()
		}
	})
	p.tasks <- task
}

var chunkDeletePool = chunkWorkerPool{size: maxChunkDeleteWorkers}

// ChunkStore writes content-addressed blobs into <root>/<first-2-hex>/<hash-hex>.
// Same instance is safe for concurrent use — every write goes through a temp
// file that's rename()'d into place, so partial writes never become visible
// and racing writers of the same hash see deterministic content (BLAKE3 of
// the bytes is the filename).
type ChunkStore struct {
	root       string
	hashLocks  [256]sync.Mutex
	knownShard [256]atomic.Bool

	// writeTimeout bounds a single chunk write+fsync. 0 disables the watchdog
	// (the write is done inline). Set on the juicefs backend, where a full
	// directory quota stalls fsync instead of returning EDQUOT (issue #135).
	writeTimeout time.Duration
	// capacity, when non-nil, pre-rejects a write that would not fit in the
	// backing store's free space (issue #135). Nil disables the guard.
	capacity *backingCapacity
	// syncFn is a test seam for the write+fsync step; nil in production uses the
	// real os.File.Write + Sync. Tests inject a blocking or erroring fn to
	// exercise the write watchdog without a real stalled filesystem.
	syncFn func(f *os.File, data []byte) error
}

// ChunkStoreOption configures a ChunkStore at construction.
type ChunkStoreOption func(*ChunkStore)

// WithBackingWriteTimeout bounds a single chunk write+fsync; past it the write
// is abandoned and putUnlocked returns errBackingStall (issue #135). Zero or
// negative leaves the watchdog off.
func WithBackingWriteTimeout(d time.Duration) ChunkStoreOption {
	return func(cs *ChunkStore) {
		if d > 0 {
			cs.writeTimeout = d
		}
	}
}

// WithCapacityGuard enables the pre-write statfs capacity guard (issue #135).
func WithCapacityGuard(c *backingCapacity) ChunkStoreOption {
	return func(cs *ChunkStore) { cs.capacity = c }
}

// NewChunkStore returns a store rooted at <storeRoot>/objects.
func NewChunkStore(storeRoot string, opts ...ChunkStoreOption) (*ChunkStore, error) {
	root := filepath.Join(storeRoot, "objects")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", root, err)
	}
	cs := &ChunkStore{root: root}
	for _, opt := range opts {
		opt(cs)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read chunk root %s: %w", root, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		decoded, err := hex.DecodeString(name)
		if err == nil && len(decoded) == 1 && entry.IsDir() {
			cs.knownShard[decoded[0]].Store(true)
		}
	}
	return cs, nil
}

// Path is the canonical filesystem location for a hash.
func (cs *ChunkStore) Path(hash []byte) (string, error) {
	if len(hash) != HashLen {
		return "", fmt.Errorf("hash must be %d bytes, got %d", HashLen, len(hash))
	}
	hexs := hex.EncodeToString(hash)
	return filepath.Join(cs.root, hexs[:2], hexs), nil
}

// Has returns whether the chunk is present on disk. Stat-based, cheap.
func (cs *ChunkStore) Has(hash []byte) (bool, error) {
	present, err := cs.HasMany([][]byte{hash})
	if err != nil {
		return false, err
	}
	return present[0], nil
}

// Get returns the chunk bytes. Hash verification is left to the caller —
// stored content is content-addressed by definition; verification is wasted
// work on every hot-path read. Migration tools and tests verify explicitly.
func (cs *ChunkStore) Get(hash []byte) ([]byte, error) {
	p, err := cs.Path(hash)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Put stores `data` under `hash`. Verifies BLAKE3(data) == hash before
// touching disk. Idempotent: if the chunk already exists, returns false
// (not stored, already there); otherwise true.
func (cs *ChunkStore) Put(hash, data []byte) (bool, error) {
	unlock, err := cs.lockHashes([][]byte{hash})
	if err != nil {
		return false, err
	}
	defer unlock()
	return cs.putUnlocked(hash, data)
}

func (cs *ChunkStore) putUnlocked(hash, data []byte) (bool, error) {
	if len(hash) != HashLen {
		return false, fmt.Errorf("hash must be %d bytes, got %d", HashLen, len(hash))
	}
	computed := blake3.Sum256(data)
	if !bytes.Equal(computed[:], hash) {
		return false, fmt.Errorf(
			"hash mismatch: provided %s, computed %s",
			hex.EncodeToString(hash),
			hex.EncodeToString(computed[:]),
		)
	}
	// From this point, a false shard-presence hint would only cause a redundant
	// upload. Publish the hint before stat/mkdir so concurrent HasMany calls
	// verify the exact file instead of assuming the whole shard is absent.
	cs.knownShard[hash[0]].Store(true)
	p, err := cs.Path(hash)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(p); err == nil {
		return false, nil
	}
	// Pre-write capacity guard (issue #135): reject a write that would not fit
	// in the backing store's free space with EDQUOT, before touching the data
	// path that stalls when a JuiceFS directory quota is full. Placed after the
	// dedup stat so a re-put of already-stored content (which writes nothing) is
	// never rejected.
	if cs.capacity != nil {
		if err := cs.capacity.check(cs.root, int64(len(data))); err != nil {
			return false, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(p), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".chunk-*")
	if err != nil {
		return false, fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanupTmp := func() { _ = os.Remove(tmpName) }
	// os.CreateTemp defaults to 0o600 — locked to the writing uid. When
	// `orlop-server -migrate-to-chunks` is invoked as a different user
	// (e.g. root) than the live server runs as (`orlop`), the resulting
	// chunks are unreadable to the server and handleChunkGet returns
	// silent EIO on every read (issue #125). Force 0o644 so any process
	// that already has dir-traversal access to <storeRoot>/objects can
	// open the file. Tenant isolation is enforced by the parent dirs
	// (<tenant>/store is mode 0o750 orlop:orlop).
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		cleanupTmp()
		return false, fmt.Errorf("chmod chunk: %w", err)
	}
	// syncWriteClose owns tmp on every non-nil return (it closes and removes it,
	// abandoning a stalled write in the background), so no cleanupTmp() here.
	if err := cs.syncWriteClose(tmp, tmpName, data); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, p); err != nil {
		cleanupTmp()
		return false, fmt.Errorf("rename %s -> %s: %w", tmpName, p, err)
	}
	return true, nil
}

// syncWriteClose writes data to tmp, fsyncs, and closes it, leaving tmpName
// ready to rename on a nil return. On any error it closes and removes tmp.
//
// When writeTimeout is set and the write+fsync blocks past it — a full JuiceFS
// directory quota stalls fsync instead of returning EDQUOT (issue #135) — it
// abandons the operation and returns errBackingStall so the caller fails the
// request promptly. The stalled syscall cannot be interrupted, so its fd and
// temp file are reclaimed in the background once the backing store finally
// returns; the rename never runs, so no partial chunk becomes visible.
func (cs *ChunkStore) syncWriteClose(tmp *os.File, tmpName string, data []byte) error {
	if cs.writeTimeout <= 0 {
		if err := cs.writeSync(tmp, data); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return fmt.Errorf("write chunk: %w", err)
		}
		if err := tmp.Close(); err != nil {
			_ = os.Remove(tmpName)
			return fmt.Errorf("close chunk: %w", err)
		}
		return nil
	}

	done := make(chan error, 1)
	go func() { done <- cs.writeSync(tmp, data) }()

	timer := time.NewTimer(cs.writeTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		closeErr := tmp.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(tmpName)
			return fmt.Errorf("write chunk: %w", err)
		}
		return nil
	case <-timer.C:
		go func() {
			<-done // wait out the stalled syscall so cleanup cannot race it
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}()
		return errBackingStall
	}
}

// writeSync writes data to f and fsyncs it, honoring the syncFn test seam.
func (cs *ChunkStore) writeSync(f *os.File, data []byte) error {
	if cs.syncFn != nil {
		return cs.syncFn(f, data)
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// Delete removes the on-disk file for hash. Idempotent: missing files
// return nil. Does not touch any DB row — refcount management is the
// caller's responsibility.
func (cs *ChunkStore) Delete(hash []byte) error {
	results, err := cs.DeleteMany([][]byte{hash})
	if err != nil {
		return err
	}
	return results[0].Err
}

// HasMany returns a parallel boolean slice for the requested hashes.
// Each `hashes[i]` should be HashLen bytes; the i-th boolean reflects
// whether that chunk is present.
func (cs *ChunkStore) HasMany(hashes [][]byte) ([]bool, error) {
	// A mature store commonly has all 256 shard directories. When every hash is
	// unique and every shard is known, preserve the old stable serial lookup
	// path: batching cannot reduce operation count and concurrent lookup tails
	// were worse on JuiceFS. Duplicate or definitely-absent batches take the
	// optimized path below.
	allKnownUnique := true
	seen := make(map[[HashLen]byte]struct{}, len(hashes))
	for i, hash := range hashes {
		if len(hash) != HashLen {
			return nil, fmt.Errorf("hash[%d] must be %d bytes, got %d", i, HashLen, len(hash))
		}
		var key [HashLen]byte
		copy(key[:], hash)
		if _, duplicate := seen[key]; duplicate || !cs.knownShard[hash[0]].Load() {
			allKnownUnique = false
		}
		seen[key] = struct{}{}
	}
	if allKnownUnique {
		out := make([]bool, len(hashes))
		for i, hash := range hashes {
			p, _ := cs.Path(hash)
			info, err := os.Lstat(p)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("has[%d]: %w", i, err)
			}
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("has[%d]: not a regular file", i)
			}
			out[i] = true
		}
		return out, nil
	}

	out, itemErrs, err := runChunkBatch(cs, hashes, true, chunkBatchHas, func(shard *chunkShard, name string) (bool, error) {
		return visitChunkShard(shard, name, chunkBatchHas)
	})
	if err != nil {
		return nil, err
	}
	for i, err := range itemErrs {
		if err != nil {
			return nil, fmt.Errorf("has[%d]: %w", i, err)
		}
	}
	return out, nil
}

// ChunkDeleteResult reports whether an item was removed. A missing item is a
// successful idempotent delete with Deleted=false and Err=nil.
type ChunkDeleteResult struct {
	Deleted bool
	Err     error
}

// DeleteMany removes chunks in a bounded, shard-aware batch. Hashes are all
// validated before the first unlink, so malformed input cannot cause a
// partially applied batch.
func (cs *ChunkStore) DeleteMany(hashes [][]byte) ([]ChunkDeleteResult, error) {
	unlock, err := cs.lockHashes(hashes)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return cs.deleteManyUnlocked(hashes)
}

func (cs *ChunkStore) deleteManyUnlocked(hashes [][]byte) ([]ChunkDeleteResult, error) {
	deleted, itemErrs, err := runChunkBatch(cs, hashes, false, chunkBatchDelete, func(shard *chunkShard, name string) (bool, error) {
		return visitChunkShard(shard, name, chunkBatchDelete)
	})
	if err != nil {
		return nil, err
	}
	results := make([]ChunkDeleteResult, len(hashes))
	for i := range results {
		results[i] = ChunkDeleteResult{Deleted: deleted[i], Err: itemErrs[i]}
	}
	return results, nil
}

// lockHashes serializes chunk publication, manifest validation/commit, and GC
// deletion by the first hash byte. Locks are always acquired in byte order, so
// overlapping manifest and GC batches cannot deadlock. All hashes are
// validated before the first lock is taken.
func (cs *ChunkStore) lockHashes(hashes [][]byte) (func(), error) {
	var needed [256]bool
	for i, hash := range hashes {
		if len(hash) != HashLen {
			return nil, fmt.Errorf("hash[%d] must be %d bytes, got %d", i, HashLen, len(hash))
		}
		needed[hash[0]] = true
	}
	locked := make([]int, 0, len(hashes))
	for i := range needed {
		if needed[i] {
			cs.hashLocks[i].Lock()
			locked = append(locked, i)
		}
	}
	return func() {
		for i := len(locked) - 1; i >= 0; i-- {
			cs.hashLocks[locked[i]].Unlock()
		}
	}, nil
}

func (cs *ChunkStore) lockAllHashes() func() {
	for i := range cs.hashLocks {
		cs.hashLocks[i].Lock()
	}
	return func() {
		for i := len(cs.hashLocks) - 1; i >= 0; i-- {
			cs.hashLocks[i].Unlock()
		}
	}
}

type chunkBatchItem struct {
	indices []int
	name    string
}

type chunkBatchShard struct {
	name  string
	items []chunkBatchItem
}

// runChunkBatch groups hashes by their first byte, optionally collapses exact
// duplicates, opens each shard directory once, and processes at most
// a bounded number of shards concurrently. Platform helpers use exact
// generated hash paths for presence and descriptor-relative deletes where the
// OS supports them.
func runChunkBatch(cs *ChunkStore, hashes [][]byte, deduplicate bool, operation chunkBatchOperation, visit func(*chunkShard, string) (bool, error)) ([]bool, []error, error) {
	results := make([]bool, len(hashes))
	itemErrs := make([]error, len(hashes))
	if len(hashes) == 0 {
		return results, itemErrs, nil
	}

	grouped := make(map[string][]chunkBatchItem)
	seen := make(map[string]int)
	for i, hash := range hashes {
		if len(hash) != HashLen {
			return nil, nil, fmt.Errorf("hash[%d] must be %d bytes, got %d", i, HashLen, len(hash))
		}
		name := hex.EncodeToString(hash)
		shard := name[:2]
		if operation == chunkBatchHas && !cs.knownShard[hash[0]].Load() {
			continue
		}
		if deduplicate {
			if offset, ok := seen[name]; ok {
				items := grouped[shard]
				items[offset].indices = append(items[offset].indices, i)
				grouped[shard] = items
				continue
			}
			seen[name] = len(grouped[shard])
		}
		grouped[shard] = append(grouped[shard], chunkBatchItem{indices: []int{i}, name: name})
	}

	process := func(group chunkBatchShard) {
		shard, err := openChunkShard(filepath.Join(cs.root, group.name), operation)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			for _, item := range group.items {
				for _, index := range item.indices {
					itemErrs[index] = fmt.Errorf("open shard %s: %w", group.name, err)
				}
			}
			return
		}
		for _, item := range group.items {
			result, err := visit(shard, item.name)
			for _, index := range item.indices {
				results[index], itemErrs[index] = result, err
			}
		}
		_ = closeChunkShard(shard)
	}

	uniqueCount := 0
	for _, items := range grouped {
		uniqueCount += len(items)
	}
	// JuiceFS benchmarks showed that concurrent positive/negative lookups can
	// add 10ms-class FUSE outliers. Presence gets its win from exact duplicate
	// collapse and definitely-absent shard hints; keep the remaining lstats
	// serial so a populated long-lived store never regresses p99.
	if operation == chunkBatchHas || uniqueCount <= 2 {
		for name, items := range grouped {
			process(chunkBatchShard{name: name, items: items})
		}
		return results, itemErrs, nil
	}

	var wg sync.WaitGroup
	wg.Add(len(grouped))
	for name, items := range grouped {
		group := chunkBatchShard{name: name, items: items}
		chunkDeletePool.submit(func() {
			defer wg.Done()
			process(group)
		})
	}
	wg.Wait()
	return results, itemErrs, nil
}
