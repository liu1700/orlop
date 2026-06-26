use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

/// Per-FH write buffer. Memory-backed below `spill_threshold`, spills to an
/// anonymous tempfile (OS-unlinked, crash-safe) above.
pub enum Buffer {
    Mem(Vec<u8>),
    Spilled(File),
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Buffer {
    pub fn new() -> Self {
        Buffer::Mem(Vec::new())
    }

    #[allow(dead_code)] // exercised by Buffer tests; reserved for future stat path
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[allow(dead_code)] // exercised by Buffer tests; reserved for future stat path
    pub fn len(&self) -> u64 {
        match self {
            Buffer::Mem(v) => v.len() as u64,
            Buffer::Spilled(f) => f.metadata().map(|m| m.len()).unwrap_or(0),
        }
    }

    pub fn read_at(&mut self, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        match self {
            Buffer::Mem(v) => {
                let start = offset as usize;
                let end = (start + len).min(v.len());
                Ok(if start >= v.len() {
                    Vec::new()
                } else {
                    v[start..end].to_vec()
                })
            }
            Buffer::Spilled(f) => {
                f.seek(SeekFrom::Start(offset))?;
                let mut buf = vec![0u8; len];
                let n = f.read(&mut buf)?;
                buf.truncate(n);
                Ok(buf)
            }
        }
    }

    pub fn write_at(
        &mut self,
        offset: u64,
        data: &[u8],
        spill_threshold: u64,
    ) -> anyhow::Result<()> {
        // Spill if growing past threshold while Mem-backed.
        let needed = offset + data.len() as u64;
        if matches!(self, Buffer::Mem(_)) && needed > spill_threshold {
            self.spill()?;
        }
        match self {
            Buffer::Mem(v) => {
                let end = offset as usize + data.len();
                if end > v.len() {
                    v.resize(end, 0);
                }
                v[offset as usize..end].copy_from_slice(data);
            }
            Buffer::Spilled(f) => {
                f.seek(SeekFrom::Start(offset))?;
                f.write_all(data)?;
            }
        }
        Ok(())
    }

    pub fn truncate(&mut self, new_size: u64, spill_threshold: u64) -> anyhow::Result<()> {
        // Growing a Mem buffer to `new_size` would materialize that many zero
        // bytes in RAM. Past the spill threshold, move to a sparse tempfile and
        // grow it with a metadata-only set_len instead (no zero-fill, no RAM).
        if matches!(self, Buffer::Mem(_)) && new_size > spill_threshold {
            self.spill()?;
        }
        match self {
            Buffer::Mem(v) => v.resize(new_size as usize, 0),
            Buffer::Spilled(f) => f.set_len(new_size)?,
        }
        Ok(())
    }

    pub fn read_all(&mut self) -> anyhow::Result<Vec<u8>> {
        match self {
            Buffer::Mem(v) => Ok(v.clone()),
            Buffer::Spilled(f) => {
                f.seek(SeekFrom::Start(0))?;
                let mut buf = Vec::new();
                f.read_to_end(&mut buf)?;
                Ok(buf)
            }
        }
    }

    fn spill(&mut self) -> anyhow::Result<()> {
        let mem = match std::mem::take(self) {
            Buffer::Mem(v) => v,
            other => {
                *self = other;
                return Ok(());
            }
        };
        let mut f = tempfile::tempfile()?;
        f.write_all(&mem)?;
        *self = Buffer::Spilled(f);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_write_read_roundtrip() {
        let mut b = Buffer::new();
        b.write_at(0, b"hello", 1024).unwrap();
        b.write_at(5, b" world", 1024).unwrap();
        assert_eq!(b.read_all().unwrap(), b"hello world");
        assert_eq!(b.len(), 11);
    }

    #[test]
    fn spills_when_exceeds_threshold() {
        let mut b = Buffer::new();
        let big = vec![0xABu8; 100];
        b.write_at(0, &big, 50).unwrap(); // 100 bytes, threshold 50 → spill
        assert!(matches!(b, Buffer::Spilled(_)));
        assert_eq!(b.read_all().unwrap(), big);
    }

    #[test]
    fn truncate_shrinks_and_grows() {
        let mut b = Buffer::new();
        b.write_at(0, b"abcdefghij", 1024).unwrap();
        b.truncate(5, 1024).unwrap();
        assert_eq!(b.read_all().unwrap(), b"abcde");
        b.truncate(7, 1024).unwrap();
        assert_eq!(b.read_all().unwrap(), b"abcde\0\0");
    }

    #[test]
    fn truncate_grow_past_threshold_spills_without_oom() {
        // A 1 GiB grow must NOT materialize zeros in RAM: with a small spill
        // threshold it lands in a sparse tempfile. This is the regression guard
        // for the truncate-to-huge-size OOM-abort (pjdfstest ftruncate/truncate).
        let mut b = Buffer::new();
        b.write_at(0, b"hi", 64).unwrap();
        b.truncate(1024 * 1024 * 1024, 64).unwrap();
        assert!(matches!(b, Buffer::Spilled(_)), "grow should spill to file");
        assert_eq!(b.len(), 1024 * 1024 * 1024);
    }
}

use crate::backend::dataplane::messages::RecoveryHint;
use crate::backend::BackendError;
use crate::lease::LeaseHandle;
use crate::store::{ChunkRef, Manifest, Store};
use blake3::Hasher;
use std::sync::Arc;

/// `EFBIG` for a size that exceeds [`MAX_FILE_BYTES`]. Typed so the FUSE layer's
/// `backend_errno` maps it to the right errno instead of the EIO default.
fn efbig(size: u64) -> anyhow::Error {
    BackendError::new(
        libc::EFBIG,
        format!("size {size} exceeds max file size {MAX_FILE_BYTES}"),
    )
    .into()
}

pub const CHUNK_MIN: u32 = 1024 * 1024; // 1 MiB — matches cmd/orlop-server/cdc.go
pub const CHUNK_AVG: u32 = 4 * 1024 * 1024; // 4 MiB
pub const CHUNK_MAX: u32 = 16 * 1024 * 1024; // 16 MiB

/// Hard ceiling on a single file's logical size. truncate()/write past this
/// return EFBIG instead of attempting the allocation, so a stray
/// `truncate -s 1P file` can't OOM-abort the FUSE process and take the whole
/// mount down with it. It sits well above the largest disk allocation
/// (registered ceiling ~10 GiB); the *real* per-allocation limit is still
/// enforced server-side by the quota (ENOSPC on flush). This is only the
/// absolute backstop against a pathological size.
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB

#[derive(Debug, Default)]
pub struct FlushStats {
    pub bytes: u64,
    pub chunks_new: u32,
    pub chunks_reused: u32,
    pub cas_retries: u32,
    pub version_new: u64,
    /// Last `RecoveryHint` observed while retrying this flush.
    /// `None` when the flush succeeded on the first put. Carried into the
    /// audit record so `orlop audit tail` surfaces `suggested_action`.
    /// Last-wins (not first-wins) so the surfaced `current_version` matches
    /// the version the successful retry actually used as `expected`.
    pub recovery: Option<RecoveryHint>,
}

pub struct WriteHandle {
    pub(crate) path: String,
    pub(crate) base_version: u64,
    pub(crate) buffer: Buffer,
    pub(crate) dirty: bool,
    pub(crate) loaded: bool,
    pub(crate) mode: u32,
    pub(crate) mtime_ns: u64,
    pub(crate) mount_idx: usize,
    pub(crate) opener_pid: u32,
    pub(crate) spill_threshold: u64,
    /// Some(_) = cached mode (holder of lease); None = uncached (no lease).
    pub(crate) lease: Option<Arc<LeaseHandle>>,
    /// Derived from `lease.is_some()` at construction; cleared to false when the
    /// lease is revoked (so subsequent writes after revocation flush through).
    /// Kept as a plain bool so tests can set it directly without constructing a
    /// real LeaseHandle.
    pub(crate) cached: bool,
}

impl WriteHandle {
    /// Mark the buffer as already loaded (used in tests that pre-populate the buffer
    /// without going through `load_if_needed`).
    pub fn mark_loaded(&mut self) {
        self.loaded = true;
    }

    /// Force cached mode on a handle that was constructed without a lease.
    /// Only for tests that need to exercise flush-on-demand without a real LeaseHandle.
    pub fn mark_cached_for_test(&mut self) {
        self.cached = true;
    }

    pub fn new(
        path: String,
        mode: u32,
        mount_idx: usize,
        opener_pid: u32,
        spill_threshold: u64,
        lease: Option<Arc<LeaseHandle>>,
    ) -> Self {
        let cached = lease.is_some();
        Self {
            path,
            base_version: 0,
            buffer: Buffer::new(),
            dirty: false,
            loaded: false,
            mode,
            mtime_ns: 0,
            mount_idx,
            opener_pid,
            spill_threshold,
            lease,
            cached,
        }
    }

    /// True when holding a lease (cached mode); false means uncached (per-write flush).
    pub fn is_cached(&self) -> bool {
        self.cached
    }

    /// Pull the current manifest + chunks into the buffer. Idempotent.
    pub fn load_if_needed(&mut self, store: &dyn Store) -> anyhow::Result<()> {
        if self.loaded {
            return Ok(());
        }
        let mf = store.manifest_get(&self.path)?;
        if mf.version > 0 {
            self.base_version = mf.version;
            self.mode = mf.mode;
            self.mtime_ns = mf.mtime_ns;
            // Pull chunks into buffer (full-file rebuild model)
            for chunk in &mf.chunks {
                let bytes = store.chunk_get(&chunk.hash)?;
                self.buffer
                    .write_at(chunk.offset, &bytes, self.spill_threshold)?;
            }
        }
        self.loaded = true;
        Ok(())
    }

    pub fn write(&mut self, store: &dyn Store, offset: u64, data: &[u8]) -> anyhow::Result<usize> {
        // A pwrite at a huge offset grows the file to offset+len; cap it the
        // same way as truncate so it returns EFBIG rather than ballooning the
        // backing buffer.
        if offset.saturating_add(data.len() as u64) > MAX_FILE_BYTES {
            return Err(efbig(offset.saturating_add(data.len() as u64)));
        }
        self.load_if_needed(store)?;
        self.buffer.write_at(offset, data, self.spill_threshold)?;
        self.dirty = true;
        if !self.cached {
            // Uncached mode: flush synchronously so every write goes round-trip.
            let _stats = self.flush_now(store)?;
        }
        Ok(data.len())
    }

    pub fn read(&mut self, store: &dyn Store, offset: u64, len: u32) -> anyhow::Result<Vec<u8>> {
        self.load_if_needed(store)?;
        self.buffer.read_at(offset, len as usize)
    }

    pub fn truncate(&mut self, store: &dyn Store, size: u64) -> anyhow::Result<()> {
        if size > MAX_FILE_BYTES {
            return Err(efbig(size));
        }
        self.load_if_needed(store)?;
        self.buffer.truncate(size, self.spill_threshold)?;
        self.dirty = true;
        Ok(())
    }

    /// Flush the buffer to the store. Returns stats for audit.
    /// Public alias kept for callers outside this module.
    pub fn flush(&mut self, store: &dyn Store) -> anyhow::Result<FlushStats> {
        self.flush_now(store)
    }

    /// Inner flush — retries up to MAX_CAS_RETRIES times on ESTALE with exponential backoff.
    pub(crate) fn flush_now(&mut self, store: &dyn Store) -> anyhow::Result<FlushStats> {
        const MAX_CAS_RETRIES: u32 = 3;
        const RETRY_BACKOFF_MS: [u64; 3] = [50, 100, 200];

        if !self.dirty {
            return Ok(FlushStats {
                bytes: 0,
                chunks_new: 0,
                chunks_reused: 0,
                cas_retries: 0,
                version_new: self.base_version,
                recovery: None,
            });
        }
        let bytes = self.buffer.read_all()?;
        let total = bytes.len() as u64;

        // FastCDC chunk — compute all hashes first, then batch dedup in one RTT.
        let chunker = fastcdc::v2020::FastCDC::new(&bytes, CHUNK_MIN, CHUNK_AVG, CHUNK_MAX);
        struct Pending {
            hash: [u8; 32],
            offset: usize,
            length: usize,
        }
        let mut pending: Vec<Pending> = Vec::new();
        for c in chunker {
            let chunk_bytes = &bytes[c.offset..c.offset + c.length];
            let mut hasher = Hasher::new();
            hasher.update(chunk_bytes);
            let hash: [u8; 32] = hasher.finalize().into();
            pending.push(Pending {
                hash,
                offset: c.offset,
                length: c.length,
            });
        }

        // Pack all hashes into a flat buffer, batch-query presence.
        let flat: Vec<u8> = pending
            .iter()
            .flat_map(|p| p.hash.iter().copied())
            .collect();
        let bitmap = store.chunk_has_many(&flat)?;

        // Build refs in original order; collect *new* chunks for one batch put.
        let mut refs = Vec::with_capacity(pending.len());
        let mut to_put: Vec<(crate::store::ChunkHash, Vec<u8>)> = Vec::new();
        let mut chunks_reused = 0u32;
        for (i, p) in pending.iter().enumerate() {
            let present = (bitmap.get(i / 8).copied().unwrap_or(0) >> (i % 8)) & 1 != 0;
            if !present {
                to_put.push((p.hash, bytes[p.offset..p.offset + p.length].to_vec()));
            } else {
                chunks_reused += 1;
            }
            refs.push(ChunkRef {
                hash: p.hash,
                offset: p.offset as u64,
                len: p.length as u32,
            });
        }
        let chunks_new = to_put.len() as u32;
        store.chunk_put_many(&to_put)?;

        let mtime_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mf = Manifest {
            size: total,
            mode: self.mode,
            mtime_ns,
            version: 0,
            chunks: refs,
        };

        let mut expected = self.base_version;
        let mut cas_retries = 0u32;
        let mut last_recovery: Option<RecoveryHint> = None;
        let new_version: u64;
        loop {
            match store.manifest_put(&self.path, expected, &mf) {
                Ok(v) => {
                    new_version = v;
                    break;
                }
                Err(e) => {
                    let is_stale = crate::backend::backend_errno(&e, libc::EIO) == libc::ESTALE;
                    if !is_stale {
                        return Err(e);
                    }
                    if cas_retries >= MAX_CAS_RETRIES {
                        return Err(crate::backend::BackendError::new(
                            libc::EIO,
                            "CAS contention exhausted",
                        )
                        .into());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(
                        RETRY_BACKOFF_MS[cas_retries as usize],
                    ));
                    let (next_expected, hint) =
                        next_expected_after_cas_conflict(&e, store, &self.path)?;
                    expected = next_expected;
                    if hint.is_some() {
                        last_recovery = hint;
                    }
                    cas_retries += 1;
                }
            }
        }
        self.base_version = new_version;
        self.dirty = false;
        self.mtime_ns = mtime_ns;
        Ok(FlushStats {
            bytes: total,
            chunks_new,
            chunks_reused,
            cas_retries,
            version_new: new_version,
            recovery: last_recovery,
        })
    }

    /// Register a flush callback on the lease's on_revoke list.
    /// Called once after construction (by fs.rs open/create) when a lease is held.
    /// On revoke: flushes dirty bytes then clears the lease so subsequent writes
    /// fall through to uncached mode.
    pub fn register_revoke_flush(
        self_arc: Arc<parking_lot::Mutex<WriteHandle>>,
        store: Arc<dyn Store>,
    ) {
        let lease = match self_arc.lock().lease.clone() {
            Some(l) => l,
            None => return,
        };
        let wh_arc = Arc::clone(&self_arc);
        let store2 = Arc::clone(&store);
        lease.on_revoke(Box::new(move || {
            let mut wh = wh_arc.lock();
            let _ = wh.flush_now(&*store2);
            // Switch to uncached mode — subsequent writes flush through.
            wh.cached = false;
            wh.lease = None;
        }));
    }
}

/// Pick the next `expected_version` after a CAS conflict and surface the
/// server's hint (if any) for the audit layer. Prefers the hint's
/// `current_version` to avoid a `manifest_get` round-trip; falls back to
/// re-reading on legacy servers that don't populate the field.
fn next_expected_after_cas_conflict(
    err: &anyhow::Error,
    store: &dyn Store,
    path: &str,
) -> anyhow::Result<(u64, Option<RecoveryHint>)> {
    let hint = crate::backend::backend_recovery(err).cloned();
    let next = match hint.as_ref().and_then(|h| h.current_version) {
        Some(v) => v,
        None => store.manifest_get(path)?.version,
    };
    Ok((next, hint))
}

#[cfg(test)]
mod handle_tests {
    use super::*;
    use crate::store::ChunkRef;
    use std::sync::Mutex;

    /// Mock Store backed by an in-memory map. Records calls for assertions.
    pub(crate) struct MockStore {
        manifests: Mutex<std::collections::HashMap<String, Manifest>>,
        chunks: Mutex<std::collections::HashMap<[u8; 32], Vec<u8>>>,
    }

    impl MockStore {
        pub(crate) fn new() -> Self {
            Self {
                manifests: Default::default(),
                chunks: Default::default(),
            }
        }
        pub(crate) fn put_chunk(&self, h: [u8; 32], data: Vec<u8>) {
            self.chunks.lock().unwrap().insert(h, data);
        }
        pub(crate) fn put_manifest(&self, path: &str, mf: Manifest) {
            self.manifests.lock().unwrap().insert(path.to_string(), mf);
        }
    }

    impl Store for MockStore {
        fn entry_for(&self, _: &str) -> anyhow::Result<Option<crate::backend::Entry>> {
            Ok(None)
        }
        fn chunk_has(&self, h: &[u8; 32]) -> anyhow::Result<bool> {
            Ok(self.chunks.lock().unwrap().contains_key(h))
        }
        fn chunk_put(&self, h: &[u8; 32], b: &[u8]) -> anyhow::Result<()> {
            self.chunks.lock().unwrap().insert(*h, b.to_vec());
            Ok(())
        }
        fn chunk_get(&self, h: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
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
        fn manifest_put(&self, p: &str, _ev: u64, mf: &Manifest) -> anyhow::Result<u64> {
            let mut m = self.manifests.lock().unwrap();
            let v = m.get(p).map(|x| x.version).unwrap_or(0) + 1;
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
        fn dir_list(&self, _: &str) -> anyhow::Result<Vec<crate::backend::Entry>> {
            Ok(Vec::new())
        }
        fn dir_create(&self, _: &str, _: u32) -> anyhow::Result<()> {
            Ok(())
        }
        fn dir_remove(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn lazy_load_pulls_existing_chunks() {
        let s = MockStore::new();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        s.put_chunk(h1, b"hello ".to_vec());
        s.put_chunk(h2, b"world".to_vec());
        s.put_manifest(
            "/a",
            Manifest {
                size: 11,
                mode: 0o644,
                mtime_ns: 0,
                version: 7,
                chunks: vec![
                    ChunkRef {
                        hash: h1,
                        offset: 0,
                        len: 6,
                    },
                    ChunkRef {
                        hash: h2,
                        offset: 6,
                        len: 5,
                    },
                ],
            },
        );
        let mut wh = WriteHandle::new("/a".into(), 0, 0, 1234, 1024, None);
        let got = wh.read(&s, 0, 11).unwrap();
        assert_eq!(got, b"hello world");
        assert_eq!(wh.base_version, 7);
        assert!(wh.loaded);
        assert!(!wh.dirty);
    }

    #[test]
    fn write_marks_dirty_and_overlays() {
        let s = MockStore::new();
        let h1 = [1u8; 32];
        s.put_chunk(h1, b"hello world".to_vec());
        s.put_manifest(
            "/a",
            Manifest {
                size: 11,
                mode: 0,
                mtime_ns: 0,
                version: 1,
                chunks: vec![ChunkRef {
                    hash: h1,
                    offset: 0,
                    len: 11,
                }],
            },
        );
        let mut wh = WriteHandle::new("/a".into(), 0, 0, 1, 1024, None);
        wh.cached = true; // simulate cached mode so write() does not auto-flush
        wh.write(&s, 6, b"ORLOP").unwrap();
        assert!(wh.dirty);
        assert_eq!(wh.read(&s, 0, 11).unwrap(), b"hello ORLOP");
    }

    #[test]
    fn truncate_resizes_buffer() {
        let s = MockStore::new();
        let mut wh = WriteHandle::new("/a".into(), 0, 0, 1, 1024, None);
        wh.cached = true; // simulate cached mode so write() does not auto-flush
        wh.write(&s, 0, b"abcdef").unwrap();
        wh.truncate(&s, 3).unwrap();
        assert_eq!(wh.read(&s, 0, 10).unwrap(), b"abc");
        assert!(wh.dirty);
    }

    #[test]
    fn truncate_past_max_returns_efbig_without_allocating() {
        // Regression: `truncate -s <huge>` used to OOM-abort the FUSE process
        // (Vec::resize of ~1 PB) and kill the mount. Now it must return EFBIG.
        let s = MockStore::new();
        let mut wh = WriteHandle::new("/a".into(), 0, 0, 1, 1024, None);
        wh.cached = true;
        let err = wh.truncate(&s, 999_999_999_999_999).unwrap_err();
        assert_eq!(crate::backend::backend_errno(&err, libc::EIO), libc::EFBIG);
        assert!(
            !wh.dirty,
            "rejected truncate must not mark the handle dirty"
        );
    }

    #[test]
    fn write_past_max_offset_returns_efbig() {
        let s = MockStore::new();
        let mut wh = WriteHandle::new("/a".into(), 0, 0, 1, 1024, None);
        wh.cached = true;
        let err = wh.write(&s, MAX_FILE_BYTES, b"x").unwrap_err();
        assert_eq!(crate::backend::backend_errno(&err, libc::EIO), libc::EFBIG);
    }
}

#[cfg(test)]
mod flush_tests {
    use super::handle_tests::MockStore;
    use super::*;

    #[test]
    fn flush_clean_handle_is_noop() {
        let s = MockStore::new();
        let mut wh = WriteHandle::new("/a".into(), 0, 0, 1, 1024, None);
        wh.loaded = true; // skip load
        let stats = wh.flush(&s).unwrap();
        assert_eq!(stats.bytes, 0);
        assert_eq!(stats.chunks_new, 0);
    }

    #[test]
    fn flush_writes_chunks_and_manifest() {
        let s = MockStore::new();
        let mut wh = WriteHandle::new("/a".into(), 0o644, 0, 1, 64 * 1024 * 1024, None);
        wh.loaded = true;
        wh.cached = true; // simulate lease-held (cached) mode so write() does not auto-flush
                          // Write enough to produce at least 1 chunk (FastCDC may emit a single
                          // small chunk for inputs below CHUNK_MIN).
        let payload = vec![42u8; CHUNK_MIN as usize + 1024];
        wh.write(&s, 0, &payload).unwrap();
        let stats = wh.flush(&s).unwrap();
        assert_eq!(stats.bytes, payload.len() as u64);
        assert!(stats.chunks_new >= 1);
        assert_eq!(stats.cas_retries, 0);
        assert!(!wh.dirty);
        assert!(wh.base_version >= 1);
    }

    #[test]
    fn flush_dedupes_repeated_content() {
        let s = MockStore::new();
        let mut wh1 = WriteHandle::new("/a".into(), 0o644, 0, 1, 64 * 1024 * 1024, None);
        wh1.loaded = true;
        wh1.cached = true; // simulate cached mode
        let payload = vec![7u8; CHUNK_MIN as usize + 1024];
        wh1.write(&s, 0, &payload).unwrap();
        let s1 = wh1.flush(&s).unwrap();

        let mut wh2 = WriteHandle::new("/b".into(), 0o644, 0, 1, 64 * 1024 * 1024, None);
        wh2.loaded = true;
        wh2.cached = true; // simulate cached mode
        wh2.write(&s, 0, &payload).unwrap();
        let s2 = wh2.flush(&s).unwrap();
        // identical content → all reused on the second flush
        assert_eq!(s2.chunks_new, 0);
        assert_eq!(s2.chunks_reused, s1.chunks_new);
    }

    use crate::backend::BackendError;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct StaleOnceStore {
        inner: MockStore,
        stale_count: AtomicU32,
    }

    impl Store for StaleOnceStore {
        fn entry_for(&self, p: &str) -> anyhow::Result<Option<crate::backend::Entry>> {
            self.inner.entry_for(p)
        }
        fn chunk_has(&self, h: &[u8; 32]) -> anyhow::Result<bool> {
            self.inner.chunk_has(h)
        }
        fn chunk_put(&self, h: &[u8; 32], b: &[u8]) -> anyhow::Result<()> {
            self.inner.chunk_put(h, b)
        }
        fn chunk_get(&self, h: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
            self.inner.chunk_get(h)
        }
        fn manifest_get(&self, p: &str) -> anyhow::Result<Manifest> {
            self.inner.manifest_get(p)
        }
        fn manifest_put(&self, p: &str, ev: u64, mf: &Manifest) -> anyhow::Result<u64> {
            if self.stale_count.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(BackendError::new(libc::ESTALE, "stale").into());
            }
            self.inner.manifest_put(p, ev, mf)
        }
        fn manifest_delete(&self, p: &str, ev: u64) -> anyhow::Result<()> {
            self.inner.manifest_delete(p, ev)
        }
        fn manifest_rename(&self, f: &str, t: &str, e1: u64, e2: u64) -> anyhow::Result<u64> {
            self.inner.manifest_rename(f, t, e1, e2)
        }
        fn dir_list(&self, p: &str) -> anyhow::Result<Vec<crate::backend::Entry>> {
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
    fn flush_retries_once_on_stale_then_succeeds() {
        let s = StaleOnceStore {
            inner: MockStore::new(),
            stale_count: AtomicU32::new(0),
        };
        let mut wh = WriteHandle::new("/a".into(), 0o644, 0, 1, 4 * 1024 * 1024, None);
        wh.loaded = true;
        wh.cached = true; // simulate cached mode
        wh.write(&s, 0, &vec![3u8; CHUNK_MIN as usize + 100])
            .unwrap();
        let stats = wh.flush(&s).unwrap();
        assert_eq!(stats.cas_retries, 1);
        assert!(!wh.dirty);
    }

    use crate::backend::dataplane::messages::{RecoveryHint, RecoveryKind};
    use std::sync::atomic::AtomicU64;

    /// On the first put: returns ESTALE carrying a `RecoveryHint` whose
    /// `current_version = HINT_VERSION`. Records every `manifest_get` and
    /// the `expected_version` of the second put so the test can prove the
    /// client skipped the read and used the hint.
    struct StaleWithHintStore {
        inner: MockStore,
        put_calls: AtomicU32,
        get_calls: AtomicU32,
        last_expected_on_retry: AtomicU64,
    }

    const HINT_VERSION: u64 = 7;

    impl Store for StaleWithHintStore {
        fn entry_for(&self, p: &str) -> anyhow::Result<Option<crate::backend::Entry>> {
            self.inner.entry_for(p)
        }
        fn chunk_has(&self, h: &[u8; 32]) -> anyhow::Result<bool> {
            self.inner.chunk_has(h)
        }
        fn chunk_put(&self, h: &[u8; 32], b: &[u8]) -> anyhow::Result<()> {
            self.inner.chunk_put(h, b)
        }
        fn chunk_get(&self, h: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
            self.inner.chunk_get(h)
        }
        fn manifest_get(&self, p: &str) -> anyhow::Result<Manifest> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.manifest_get(p)
        }
        fn manifest_put(&self, p: &str, ev: u64, mf: &Manifest) -> anyhow::Result<u64> {
            let n = self.put_calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                let hint = RecoveryHint {
                    kind: RecoveryKind::CasConflict,
                    your_version: Some(ev),
                    current_version: Some(HINT_VERSION),
                    last_writer: None,
                    suggested_action: "use current_version=7".into(),
                };
                return Err(BackendError::new(libc::ESTALE, "stale")
                    .with_recovery(hint)
                    .into());
            }
            self.last_expected_on_retry.store(ev, Ordering::SeqCst);
            self.inner.manifest_put(p, ev, mf)
        }
        fn manifest_delete(&self, p: &str, ev: u64) -> anyhow::Result<()> {
            self.inner.manifest_delete(p, ev)
        }
        fn manifest_rename(&self, f: &str, t: &str, e1: u64, e2: u64) -> anyhow::Result<u64> {
            self.inner.manifest_rename(f, t, e1, e2)
        }
        fn dir_list(&self, p: &str) -> anyhow::Result<Vec<crate::backend::Entry>> {
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
    fn flush_skips_manifest_get_when_hint_carries_current_version() {
        let s = StaleWithHintStore {
            inner: MockStore::new(),
            put_calls: AtomicU32::new(0),
            get_calls: AtomicU32::new(0),
            last_expected_on_retry: AtomicU64::new(u64::MAX),
        };
        let mut wh = WriteHandle::new("/a".into(), 0o644, 0, 1, 4 * 1024 * 1024, None);
        wh.loaded = true;
        wh.cached = true;
        wh.write(&s, 0, &vec![3u8; CHUNK_MIN as usize + 100])
            .unwrap();
        let stats = wh.flush(&s).unwrap();
        assert_eq!(stats.cas_retries, 1);
        assert_eq!(
            s.get_calls.load(Ordering::SeqCst),
            0,
            "client must not call manifest_get when the hint provides current_version"
        );
        assert_eq!(
            s.last_expected_on_retry.load(Ordering::SeqCst),
            HINT_VERSION,
            "client must retry with expected_version pulled from the hint"
        );
        assert!(!wh.dirty);
    }

    #[test]
    fn flush_eio_after_max_retries() {
        struct AlwaysStale;
        impl Store for AlwaysStale {
            fn entry_for(&self, _: &str) -> anyhow::Result<Option<crate::backend::Entry>> {
                Ok(None)
            }
            fn chunk_has(&self, _: &[u8; 32]) -> anyhow::Result<bool> {
                Ok(false)
            }
            fn chunk_put(&self, _: &[u8; 32], _: &[u8]) -> anyhow::Result<()> {
                Ok(())
            }
            fn chunk_get(&self, _: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
                unreachable!()
            }
            fn manifest_get(&self, _: &str) -> anyhow::Result<Manifest> {
                Ok(Manifest::default())
            }
            fn manifest_put(&self, _: &str, _: u64, _: &Manifest) -> anyhow::Result<u64> {
                Err(BackendError::new(libc::ESTALE, "always stale").into())
            }
            fn manifest_delete(&self, _: &str, _: u64) -> anyhow::Result<()> {
                Ok(())
            }
            fn manifest_rename(&self, _: &str, _: &str, _: u64, _: u64) -> anyhow::Result<u64> {
                Ok(0)
            }
            fn dir_list(&self, _: &str) -> anyhow::Result<Vec<crate::backend::Entry>> {
                Ok(Vec::new())
            }
            fn dir_create(&self, _: &str, _: u32) -> anyhow::Result<()> {
                Ok(())
            }
            fn dir_remove(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
        }
        let s = AlwaysStale;
        let mut wh = WriteHandle::new("/a".into(), 0o644, 0, 1, 4 * 1024 * 1024, None);
        wh.loaded = true;
        wh.cached = true; // simulate cached mode
        wh.write(&s, 0, &vec![5u8; CHUNK_MIN as usize + 100])
            .unwrap();
        let err = wh.flush(&s).unwrap_err();
        let bound = crate::backend::backend_errno(&err, libc::EIO);
        assert_eq!(bound, libc::EIO);
    }
}

#[cfg(test)]
mod uncached_mode_tests {
    use super::handle_tests::MockStore;
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Wraps MockStore and counts `manifest_put` calls.
    struct CountingStore {
        inner: MockStore,
        pub manifest_puts: AtomicU32,
    }

    impl CountingStore {
        fn new() -> Self {
            Self {
                inner: MockStore::new(),
                manifest_puts: AtomicU32::new(0),
            }
        }
    }

    impl Store for CountingStore {
        fn entry_for(&self, p: &str) -> anyhow::Result<Option<crate::backend::Entry>> {
            self.inner.entry_for(p)
        }
        fn chunk_has(&self, h: &[u8; 32]) -> anyhow::Result<bool> {
            self.inner.chunk_has(h)
        }
        fn chunk_put(&self, h: &[u8; 32], b: &[u8]) -> anyhow::Result<()> {
            self.inner.chunk_put(h, b)
        }
        fn chunk_get(&self, h: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
            self.inner.chunk_get(h)
        }
        fn manifest_get(&self, p: &str) -> anyhow::Result<Manifest> {
            self.inner.manifest_get(p)
        }
        fn manifest_put(&self, p: &str, ev: u64, mf: &Manifest) -> anyhow::Result<u64> {
            self.manifest_puts.fetch_add(1, Ordering::SeqCst);
            self.inner.manifest_put(p, ev, mf)
        }
        fn manifest_delete(&self, p: &str, ev: u64) -> anyhow::Result<()> {
            self.inner.manifest_delete(p, ev)
        }
        fn manifest_rename(&self, f: &str, t: &str, e1: u64, e2: u64) -> anyhow::Result<u64> {
            self.inner.manifest_rename(f, t, e1, e2)
        }
        fn dir_list(&self, p: &str) -> anyhow::Result<Vec<crate::backend::Entry>> {
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
    fn uncached_write_flushes_each_call() {
        let s = CountingStore::new();
        // lease: None → uncached mode; each write() must flush immediately.
        let mut wh = WriteHandle::new("/path".into(), 0o644, 0, 1, 64 * 1024 * 1024, None);
        wh.mark_loaded();

        // Use payloads large enough that FastCDC produces at least one chunk.
        let chunk = vec![0xABu8; CHUNK_MIN as usize + 256];
        wh.write(&s, 0, &chunk).unwrap();
        wh.write(&s, chunk.len() as u64, &chunk).unwrap();
        wh.write(&s, (chunk.len() * 2) as u64, &chunk).unwrap();

        assert_eq!(
            s.manifest_puts.load(Ordering::Acquire),
            3,
            "uncached mode must flush (manifest_put) on each write call"
        );
        // Buffer still coherent — dirty is false after auto-flush.
        assert!(!wh.dirty);
    }

    #[test]
    fn uncached_write_does_not_leave_dirty() {
        let s = CountingStore::new();
        let mut wh = WriteHandle::new("/path".into(), 0o644, 0, 1, 64 * 1024 * 1024, None);
        wh.mark_loaded();
        let chunk = vec![0u8; CHUNK_MIN as usize + 128];
        wh.write(&s, 0, &chunk).unwrap();
        assert!(
            !wh.dirty,
            "uncached write should flush inline, leaving dirty=false"
        );
    }
}
