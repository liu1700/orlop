//! Concurrent writers on the same path through the WriteHandle CAS retry path.
//!
//! Uses a thread-safe in-memory Store. Validates that:
//! 1. Two writers flushing simultaneously: one wins, the other gets ESTALE,
//!    refetches the version, retries, and succeeds.
//! 2. Final manifest version == 2 (base 0 → v1 → v2).
//! 3. Combined cas_retries across both threads >= 1.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use orlop::backend::dataplane::messages::{RecoveryHint, RecoveryKind};
use orlop::backend::{BackendError, Entry};
use orlop::write_handle::{FlushStats, WriteHandle, CHUNK_MIN};
use orlop::store::{ChunkHash, Manifest, Store};

// ---------------------------------------------------------------------------
// Thread-safe in-memory Store with real CAS semantics.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ConcurrentMockStore {
    manifests: Mutex<HashMap<String, Manifest>>,
    chunks: Mutex<HashMap<[u8; 32], Vec<u8>>>,
}

impl Store for ConcurrentMockStore {
    fn entry_for(&self, _: &str) -> anyhow::Result<Option<Entry>> {
        Ok(None)
    }

    fn chunk_has(&self, h: &ChunkHash) -> anyhow::Result<bool> {
        Ok(self.chunks.lock().unwrap().contains_key(h))
    }

    fn chunk_put(&self, h: &ChunkHash, b: &[u8]) -> anyhow::Result<()> {
        self.chunks.lock().unwrap().insert(*h, b.to_vec());
        Ok(())
    }

    fn chunk_get(&self, h: &ChunkHash) -> anyhow::Result<Vec<u8>> {
        self.chunks
            .lock()
            .unwrap()
            .get(h)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing chunk"))
    }

    fn manifest_get(&self, p: &str) -> anyhow::Result<Manifest> {
        Ok(self
            .manifests
            .lock()
            .unwrap()
            .get(p)
            .cloned()
            .unwrap_or_default())
    }

    fn manifest_put(&self, p: &str, ev: u64, mf: &Manifest) -> anyhow::Result<u64> {
        let mut m = self.manifests.lock().unwrap();
        let cur = m.get(p).map(|x| x.version).unwrap_or(0);
        if cur != ev {
            return Err(BackendError::new(libc::ESTALE, "stale version").into());
        }
        let v = cur + 1;
        let mut clone = mf.clone();
        clone.version = v;
        m.insert(p.to_string(), clone);
        Ok(v)
    }

    fn manifest_delete(&self, _: &str, _: u64) -> anyhow::Result<()> {
        Ok(())
    }

    fn manifest_rename(&self, _: &str, _: &str, _: u64, _: u64) -> anyhow::Result<u64> {
        Ok(0)
    }

    fn dir_list(&self, _: &str) -> anyhow::Result<Vec<Entry>> {
        Ok(Vec::new())
    }

    fn dir_create(&self, _: &str, _: u32) -> anyhow::Result<()> {
        Ok(())
    }

    fn dir_remove(&self, _: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
fn concurrent_writers_cas_retry() {
    let store: Arc<ConcurrentMockStore> = Arc::new(ConcurrentMockStore::default());

    // Both writers start with base_version = 0.  One wins the first
    // manifest_put(v0→v1); the other gets ESTALE, refetches to see v1,
    // then retries manifest_put(v1→v2).  Final version must be 2.
    let s1 = Arc::clone(&store);
    let s2 = Arc::clone(&store);

    // Use a barrier so both threads reach flush() at roughly the same time.
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let b1 = Arc::clone(&barrier);
    let b2 = Arc::clone(&barrier);

    let t1 = thread::spawn(move || -> FlushStats {
        let mut wh = WriteHandle::new("/race.txt".into(), 0o644, 0, 1, 4 * 1024 * 1024, None);
        wh.mark_loaded();
        wh.mark_cached_for_test(); // simulate cached mode so write() doesn't auto-flush
        wh.write(s1.as_ref(), 0, &vec![b'A'; CHUNK_MIN as usize + 1])
            .unwrap();
        b1.wait();
        wh.flush(s1.as_ref()).unwrap()
    });

    let t2 = thread::spawn(move || -> FlushStats {
        let mut wh = WriteHandle::new("/race.txt".into(), 0o644, 0, 1, 4 * 1024 * 1024, None);
        wh.mark_loaded();
        wh.mark_cached_for_test(); // simulate cached mode so write() doesn't auto-flush
        wh.write(s2.as_ref(), 0, &vec![b'B'; CHUNK_MIN as usize + 1])
            .unwrap();
        b2.wait();
        wh.flush(s2.as_ref()).unwrap()
    });

    let stats1 = t1.join().expect("writer 1 panicked");
    let stats2 = t2.join().expect("writer 2 panicked");

    // Combined retries: at least one thread must have hit ESTALE and retried.
    assert!(
        stats1.cas_retries + stats2.cas_retries >= 1,
        "no CAS retries observed — writer1: retries={} ver={}, writer2: retries={} ver={}",
        stats1.cas_retries,
        stats1.version_new,
        stats2.cas_retries,
        stats2.version_new,
    );

    // Both flushes committed, so the manifest advanced from 0 → 1 → 2.
    let final_v = stats1.version_new.max(stats2.version_new);
    assert_eq!(
        final_v, 2,
        "expected final manifest version 2, got {}",
        final_v
    );
}

// ---------------------------------------------------------------------------
// Issue #103: concurrent writers, but the server now emits a populated
// `RecoveryHint` on each ESTALE. Asserts the loser:
//   1. Receives the hint via FlushStats.recovery (so audit can surface it).
//   2. Skips the manifest_get round-trip (uses hint.current_version directly).
//
// Wraps `ConcurrentMockStore` so the only delta is the hint construction on
// `manifest_put` and a `manifest_get` counter — same composition pattern as
// `StaleOnceStore` wrapping `MockStore` in `src/write_handle.rs`.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct HintingMockStore {
    inner: ConcurrentMockStore,
    manifest_get_calls: AtomicU64,
}

impl Store for HintingMockStore {
    fn entry_for(&self, p: &str) -> anyhow::Result<Option<Entry>> {
        self.inner.entry_for(p)
    }
    fn chunk_has(&self, h: &ChunkHash) -> anyhow::Result<bool> {
        self.inner.chunk_has(h)
    }
    fn chunk_put(&self, h: &ChunkHash, b: &[u8]) -> anyhow::Result<()> {
        self.inner.chunk_put(h, b)
    }
    fn chunk_get(&self, h: &ChunkHash) -> anyhow::Result<Vec<u8>> {
        self.inner.chunk_get(h)
    }
    fn manifest_get(&self, p: &str) -> anyhow::Result<Manifest> {
        self.manifest_get_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.manifest_get(p)
    }
    fn manifest_put(&self, p: &str, ev: u64, mf: &Manifest) -> anyhow::Result<u64> {
        // Look up current version *before* delegating so we can attach
        // current_version to the hint when CAS would fail. (We don't hold
        // the inner lock — this can race with concurrent puts. That's fine:
        // the inner CAS is still authoritative and the hint is best-effort.)
        let cur = self.inner.manifest_get(p)?.version;
        if cur != ev {
            let hint = RecoveryHint {
                kind: RecoveryKind::CasConflict,
                your_version: Some(ev),
                current_version: Some(cur),
                last_writer: None,
                suggested_action: format!("re-put with expected={cur}"),
            };
            return Err(BackendError::new(libc::ESTALE, "stale version")
                .with_recovery(hint)
                .into());
        }
        self.inner.manifest_put(p, ev, mf)
    }
    fn manifest_delete(&self, p: &str, ev: u64) -> anyhow::Result<()> {
        self.inner.manifest_delete(p, ev)
    }
    fn manifest_rename(&self, f: &str, t: &str, e1: u64, e2: u64) -> anyhow::Result<u64> {
        self.inner.manifest_rename(f, t, e1, e2)
    }
    fn dir_list(&self, p: &str) -> anyhow::Result<Vec<Entry>> {
        self.inner.dir_list(p)
    }
    fn dir_create(&self, p: &str, m: u32) -> anyhow::Result<()> {
        self.inner.dir_create(p, m)
    }
    fn dir_remove(&self, p: &str) -> anyhow::Result<()> {
        self.inner.dir_remove(p)
    }
}

#[test]
fn concurrent_writers_propagate_recovery_hint_and_skip_manifest_get() {
    let store: Arc<HintingMockStore> = Arc::new(HintingMockStore::default());

    let s1 = Arc::clone(&store);
    let s2 = Arc::clone(&store);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let b1 = Arc::clone(&barrier);
    let b2 = Arc::clone(&barrier);

    let t1 = thread::spawn(move || -> FlushStats {
        let mut wh = WriteHandle::new("/race.txt".into(), 0o644, 0, 1, 4 * 1024 * 1024, None);
        wh.mark_loaded();
        wh.mark_cached_for_test();
        wh.write(s1.as_ref(), 0, &vec![b'A'; CHUNK_MIN as usize + 1])
            .unwrap();
        b1.wait();
        wh.flush(s1.as_ref()).unwrap()
    });
    let t2 = thread::spawn(move || -> FlushStats {
        let mut wh = WriteHandle::new("/race.txt".into(), 0o644, 0, 1, 4 * 1024 * 1024, None);
        wh.mark_loaded();
        wh.mark_cached_for_test();
        wh.write(s2.as_ref(), 0, &vec![b'B'; CHUNK_MIN as usize + 1])
            .unwrap();
        b2.wait();
        wh.flush(s2.as_ref()).unwrap()
    });

    let stats1 = t1.join().expect("writer 1 panicked");
    let stats2 = t2.join().expect("writer 2 panicked");

    // The loser of the race must have observed the hint at least once.
    let loser_recovery = match (stats1.cas_retries, stats2.cas_retries) {
        (0, _) => stats2.recovery.as_ref(),
        (_, 0) => stats1.recovery.as_ref(),
        _ => stats1.recovery.as_ref().or(stats2.recovery.as_ref()),
    };
    let hint = loser_recovery.expect("the losing writer's FlushStats must carry the recovery hint");
    assert_eq!(hint.kind, RecoveryKind::CasConflict);
    assert!(
        hint.current_version.is_some(),
        "hint must carry current_version"
    );

    // Both writers committed, so the final stored version must be 2.
    let final_v = stats1.version_new.max(stats2.version_new);
    assert_eq!(final_v, 2);

    // The retry path read current_version from the hint, so the client
    // must have made zero manifest_get calls. Without the optimisation
    // this would be 1 (the loser's re-read RTT).
    assert_eq!(
        store.manifest_get_calls.load(Ordering::SeqCst),
        0,
        "client must not call manifest_get when the server attaches current_version"
    );
}
