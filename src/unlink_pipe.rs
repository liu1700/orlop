//! Pipelined unlink queue (issue #122, docs/design-metadata-mirror.md §5).
//!
//! Opt-in writeback mode (`ORLOP_METADATA_PIPELINE=1`): `unlink` replies to
//! the kernel once the delete is queued, and a pool of sender threads issues
//! the CAS-guarded `MANIFEST_DELETE`s concurrently. This is the delete-tree
//! gate: with a fresh mirror an unlink is one round trip, but `rm -rf` still
//! pays them serially; overlapping them is where the remaining 5x lives.
//!
//! Durability contract (the fences): an acknowledged-but-unsent unlink is
//! lost if the client crashes — the file simply still exists, exactly the
//! statement POSIX makes about unlink before `fsync` of the parent
//! directory. Every fence (`fsync`/`flush`/`fsyncdir`, `rmdir`, `rename`,
//! unmount/destroy) drains the queue and surfaces the first queued failure
//! as its errno, writeback-error style. Mutating ops that could contradict
//! a queued delete (create/mkdir/link/symlink/mknod/setattr) drain without
//! consuming the error, so it still reports at the next true fence.
//!
//! Ordering: per-path order is enforced by construction — an unlink is
//! queued at most once per path (the mirror serves ENOENT for it
//! immediately), and any later op that could touch the path drains first.
//! Cross-path deletes are independent and run concurrently.

use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;

use parking_lot::{Condvar, Mutex};

use crate::store::Store;

/// Concurrent in-flight MANIFEST_DELETEs. RTT-bound work; 16 keeps a 200-file
/// tree at ~13 round-trip batches without stampeding the server.
const SEND_CONCURRENCY: usize = 16;

/// Queue depth bound. At the cap, unlinks fall back to synchronous — the
/// no-backpressure failure mode (dirty set growing until OOM) is one of the
/// documented pitfalls this design refuses to inherit.
const MAX_QUEUED: usize = 512;

struct Job {
    store: Arc<dyn Store>,
    path: String,
    expected_version: u64,
}

struct Shared {
    /// Queued + in-flight jobs not yet resolved.
    outstanding: Mutex<usize>,
    drained: Condvar,
    /// First errno since the last error-consuming fence; 0 = none.
    errno: AtomicI32,
    /// Semaphore for sender concurrency.
    permits: Mutex<usize>,
    permit_free: Condvar,
    queued: AtomicUsize,
}

pub struct UnlinkPipe {
    tx: Sender<Job>,
    shared: Arc<Shared>,
}

impl UnlinkPipe {
    pub fn start() -> Arc<Self> {
        let (tx, rx) = channel::<Job>();
        let shared = Arc::new(Shared {
            outstanding: Mutex::new(0),
            drained: Condvar::new(),
            errno: AtomicI32::new(0),
            permits: Mutex::new(SEND_CONCURRENCY),
            permit_free: Condvar::new(),
            queued: AtomicUsize::new(0),
        });
        let dispatcher_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("orlop-unlink-pipe".into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    // Bound in-flight senders.
                    {
                        let mut permits = dispatcher_shared.permits.lock();
                        while *permits == 0 {
                            dispatcher_shared.permit_free.wait(&mut permits);
                        }
                        *permits -= 1;
                    }
                    dispatcher_shared.queued.fetch_sub(1, Ordering::AcqRel);
                    let shared = Arc::clone(&dispatcher_shared);
                    std::thread::spawn(move || {
                        let result = job.store.manifest_delete(&job.path, job.expected_version);
                        match &result {
                            Ok(()) => job.store.resolve_pending_unlink(&job.path, true),
                            Err(e) => {
                                let errno =
                                    crate::backend::backend_errno(e, libc::EIO);
                                let _ = shared.errno.compare_exchange(
                                    0,
                                    errno,
                                    Ordering::AcqRel,
                                    Ordering::Acquire,
                                );
                                job.store.resolve_pending_unlink(&job.path, false);
                            }
                        }
                        {
                            let mut permits = shared.permits.lock();
                            *permits += 1;
                            shared.permit_free.notify_one();
                        }
                        let mut outstanding = shared.outstanding.lock();
                        *outstanding -= 1;
                        if *outstanding == 0 {
                            shared.drained.notify_all();
                        }
                    });
                }
            })
            .expect("spawn unlink pipe dispatcher");
        Arc::new(Self { tx, shared })
    }

    /// Queue an unlink. Returns false (caller must unlink synchronously)
    /// when the store cannot absorb the pending delete locally or the queue
    /// is at its bound.
    pub fn try_enqueue(&self, store: Arc<dyn Store>, path: String, expected_version: u64) -> bool {
        if self.shared.queued.load(Ordering::Acquire) >= MAX_QUEUED {
            return false;
        }
        if !store.note_pending_unlink(&path) {
            return false;
        }
        *self.shared.outstanding.lock() += 1;
        self.shared.queued.fetch_add(1, Ordering::AcqRel);
        if self
            .tx
            .send(Job {
                store: Arc::clone(&store),
                path: path.clone(),
                expected_version,
            })
            .is_err()
        {
            // Dispatcher gone (shutdown): undo and fall back to sync.
            store.resolve_pending_unlink(&path, false);
            let mut outstanding = self.shared.outstanding.lock();
            *outstanding -= 1;
            self.shared.queued.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    /// Wait until every queued unlink has resolved. Does NOT consume the
    /// recorded error — for mutating ops that must order after the queue but
    /// are not error-reporting fences.
    pub fn drain_wait(&self) {
        let mut outstanding = self.shared.outstanding.lock();
        while *outstanding > 0 {
            self.shared.drained.wait(&mut outstanding);
        }
    }

    /// Drain and consume the first queued failure, if any — the
    /// error-reporting fences (fsync/flush/fsyncdir, rmdir, rename,
    /// unmount).
    pub fn drain_check(&self) -> Option<i32> {
        self.drain_wait();
        match self.shared.errno.swap(0, Ordering::AcqRel) {
            0 => None,
            e => Some(e),
        }
    }
}

/// The gate: pipelined unlink is opt-in until its correctness gate is met
/// (docs/design-metadata-mirror.md §6, issue #122 fallback clause).
pub fn pipeline_enabled_from_env() -> bool {
    matches!(
        std::env::var("ORLOP_METADATA_PIPELINE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "on"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Entry;
    use crate::store::{ChunkHash, Manifest};
    use std::sync::atomic::AtomicUsize;

    /// Store stub: counts deletes, optionally failing a specific path.
    struct StubStore {
        deletes: AtomicUsize,
        fail_path: Option<String>,
        resolved_ok: Mutex<Vec<(String, bool)>>,
        absorb: bool,
    }

    impl StubStore {
        fn new(absorb: bool, fail_path: Option<&str>) -> Arc<Self> {
            Arc::new(Self {
                deletes: AtomicUsize::new(0),
                fail_path: fail_path.map(String::from),
                resolved_ok: Mutex::new(vec![]),
                absorb,
            })
        }
    }

    impl Store for StubStore {
        fn entry_for(&self, _path: &str) -> anyhow::Result<Option<Entry>> {
            Ok(None)
        }
        fn chunk_has(&self, _hash: &ChunkHash) -> anyhow::Result<bool> {
            Ok(false)
        }
        fn chunk_put(&self, _hash: &ChunkHash, _bytes: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn chunk_get(&self, _hash: &ChunkHash) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("not used")
        }
        fn manifest_get(&self, _path: &str) -> anyhow::Result<Manifest> {
            Ok(Manifest::default())
        }
        fn manifest_put(
            &self,
            _path: &str,
            _expected_version: u64,
            _mf: &Manifest,
        ) -> anyhow::Result<u64> {
            Ok(1)
        }
        fn manifest_delete(&self, path: &str, _expected_version: u64) -> anyhow::Result<()> {
            self.deletes.fetch_add(1, Ordering::AcqRel);
            if self.fail_path.as_deref() == Some(path) {
                return Err(crate::backend::BackendError::new(
                    crate::backend::dataplane::protocol::errno::ESTALE,
                    "stale",
                )
                .into());
            }
            Ok(())
        }
        fn manifest_rename(
            &self,
            _from: &str,
            _to: &str,
            _expected_version_from: u64,
            _expected_version_to: u64,
        ) -> anyhow::Result<u64> {
            Ok(1)
        }
        fn dir_list(&self, _path: &str) -> anyhow::Result<Vec<Entry>> {
            Ok(vec![])
        }
        fn dir_create(&self, _path: &str, _mode: u32) -> anyhow::Result<()> {
            Ok(())
        }
        fn dir_remove(&self, _path: &str) -> anyhow::Result<()> {
            Ok(())
        }
        fn note_pending_unlink(&self, _path: &str) -> bool {
            self.absorb
        }
        fn resolve_pending_unlink(&self, path: &str, ok: bool) {
            self.resolved_ok.lock().push((path.to_string(), ok));
        }
        fn set_session(&self, _id: Option<String>) {}
        fn set_allocation_id(&self, _id: Option<String>) {}
    }

    #[test]
    fn drains_after_concurrent_deletes() {
        let pipe = UnlinkPipe::start();
        let store = StubStore::new(true, None);
        for i in 0..100 {
            assert!(pipe.try_enqueue(store.clone(), format!("/f{i}"), 1));
        }
        assert_eq!(pipe.drain_check(), None);
        assert_eq!(store.deletes.load(Ordering::Acquire), 100);
        assert_eq!(store.resolved_ok.lock().len(), 100);
        assert!(store.resolved_ok.lock().iter().all(|(_, ok)| *ok));
    }

    #[test]
    fn failure_surfaces_at_fence_and_resolves_not_ok() {
        let pipe = UnlinkPipe::start();
        let store = StubStore::new(true, Some("/bad"));
        assert!(pipe.try_enqueue(store.clone(), "/good".into(), 1));
        assert!(pipe.try_enqueue(store.clone(), "/bad".into(), 1));
        let errno = pipe.drain_check();
        assert_eq!(
            errno,
            Some(crate::backend::dataplane::protocol::errno::ESTALE)
        );
        // Error consumed: the next fence is clean.
        assert_eq!(pipe.drain_check(), None);
        let resolved = store.resolved_ok.lock();
        assert!(resolved.iter().any(|(p, ok)| p == "/bad" && !ok));
        assert!(resolved.iter().any(|(p, ok)| p == "/good" && *ok));
    }

    #[test]
    fn refuses_when_store_cannot_absorb() {
        let pipe = UnlinkPipe::start();
        let store = StubStore::new(false, None);
        assert!(!pipe.try_enqueue(store.clone(), "/f".into(), 1));
        assert_eq!(store.deletes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn drain_wait_keeps_error_for_real_fence() {
        let pipe = UnlinkPipe::start();
        let store = StubStore::new(true, Some("/bad"));
        assert!(pipe.try_enqueue(store.clone(), "/bad".into(), 1));
        pipe.drain_wait(); // mutation-path drain: must NOT consume
        assert_eq!(
            pipe.drain_check(),
            Some(crate::backend::dataplane::protocol::errno::ESTALE)
        );
    }
}
