//! The `Store` trait — primitive-shaped storage interface.
//!
//! Maps 1:1 to the data-plane wire opcodes. POSIX semantics are translated in
//! `src/fs.rs` rather than living in trait methods, so xattrs / symlinks /
//! locks / fallocate land as fs.rs additions, not trait churn.

use crate::backend::Entry;

pub type ChunkHash = [u8; 32]; // BLAKE3

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRef {
    pub hash: ChunkHash,
    pub offset: u64,
    pub len: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Manifest {
    pub size: u64,
    pub mode: u32,
    pub mtime_ns: u64,
    pub version: u64,
    pub chunks: Vec<ChunkRef>,
}

pub trait Store: Send + Sync {
    /// Returns `None` for ENOENT, `Some(Entry)` otherwise. Covers FUSE
    /// `lookup` and `getattr` in one primitive.
    fn entry_for(&self, path: &str) -> anyhow::Result<Option<Entry>>;

    fn chunk_has(&self, hash: &ChunkHash) -> anyhow::Result<bool>;

    /// Batch dedup check. `hashes` is a flat buffer of `N * 32` bytes.
    /// Returns a bitmap of `ceil(N/8)` bytes where bit `i` is set iff the
    /// server holds chunk `i`.
    ///
    /// The default implementation calls `chunk_has` once per hash; override
    /// for a single round-trip (e.g., `DataStore`).
    fn chunk_has_many(&self, hashes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let n = hashes.len() / 32;
        let mut bitmap = vec![0u8; n.div_ceil(8)];
        for i in 0..n {
            let h: &ChunkHash = hashes[i * 32..(i + 1) * 32].try_into().unwrap();
            if self.chunk_has(h)? {
                bitmap[i / 8] |= 1 << (i % 8);
            }
        }
        Ok(bitmap)
    }

    fn chunk_put(&self, hash: &ChunkHash, bytes: &[u8]) -> anyhow::Result<()>;
    fn chunk_get(&self, hash: &ChunkHash) -> anyhow::Result<Vec<u8>>;

    /// Batch fetch. Default is serial; `DataStore` overrides to issue the
    /// underlying RPCs concurrently. Returned bytes match `hashes` order.
    fn chunk_get_many(&self, hashes: &[ChunkHash]) -> anyhow::Result<Vec<Vec<u8>>> {
        hashes.iter().map(|h| self.chunk_get(h)).collect()
    }

    /// Batch upload. Default is serial; `DataStore` overrides to issue the
    /// underlying RPCs concurrently. Empty input is a no-op.
    fn chunk_put_many(&self, items: &[(ChunkHash, Vec<u8>)]) -> anyhow::Result<()> {
        for (hash, bytes) in items {
            self.chunk_put(hash, bytes)?;
        }
        Ok(())
    }

    /// `version=0` in the returned manifest means absent. Callers use this
    /// for "must not exist" CAS in `manifest_put(path, 0, &mf)`.
    fn manifest_get(&self, path: &str) -> anyhow::Result<Manifest>;
    fn manifest_put(&self, path: &str, expected_version: u64, mf: &Manifest)
        -> anyhow::Result<u64>;
    fn manifest_delete(&self, path: &str, expected_version: u64) -> anyhow::Result<()>;
    fn manifest_rename(
        &self,
        from: &str,
        to: &str,
        expected_version_from: u64,
        expected_version_to: u64,
    ) -> anyhow::Result<u64>;

    fn dir_list(&self, path: &str) -> anyhow::Result<Vec<Entry>>;
    fn dir_create(&self, path: &str, mode: u32) -> anyhow::Result<()>;
    fn dir_remove(&self, path: &str) -> anyhow::Result<()>;

    /// Change the permission bits of a file, directory, or symlink (chmod).
    /// Unlike `manifest_put`, this works for directories too (which carry no
    /// manifest). Default errors; `DataStore` implements it over the wire.
    fn setattr_mode(&self, _path: &str, _mode: u32) -> anyhow::Result<()> {
        anyhow::bail!("setattr_mode not supported by this store")
    }

    /// Change the owner (uid/gid) of a file, directory, or symlink (chown).
    /// Store-and-readback only, no permission enforcement. Works for every kind
    /// (no manifest required). Default errors; `DataStore` implements it over
    /// the wire.
    fn setattr_owner(&self, _path: &str, _uid: u32, _gid: u32) -> anyhow::Result<()> {
        anyhow::bail!("setattr_owner not supported by this store")
    }

    /// Set the access time (atime, unix ns) of a file, directory, or symlink
    /// (utimensat). Store-and-readback only. Default errors; `DataStore`
    /// implements it over the wire.
    fn setattr_atime(&self, _path: &str, _atime: i64) -> anyhow::Result<()> {
        anyhow::bail!("setattr_atime not supported by this store")
    }

    /// Create a symbolic link at `path` pointing at `target`.
    fn symlink(&self, _path: &str, _target: &str, _mode: u32) -> anyhow::Result<()> {
        anyhow::bail!("symlink not supported by this store")
    }

    /// Create a POSIX special node (FIFO, socket, or block/char device) at
    /// `path`. `mode` carries the S_IF* type bits | permission bits; `rdev` is
    /// the device number (0 for fifo/socket).
    fn mknod(&self, _path: &str, _mode: u32, _rdev: u64) -> anyhow::Result<()> {
        anyhow::bail!("mknod not supported by this store")
    }

    /// Read a symbolic link's target. ENOENT-equivalent when `path` is not a link.
    fn readlink(&self, _path: &str) -> anyhow::Result<String> {
        anyhow::bail!("readlink not supported by this store")
    }

    /// Tag every subsequent write with `id` as the session_id.
    /// Stores that don't model sessions ignore this call.
    /// Pass `None` to clear the tag (e.g. on unmount).
    fn set_session(&self, _id: Option<String>) {}

    /// Tag manifest writes with `id` as the journal's allocation_id.
    /// Required by the server whenever a session_id is also set.
    /// Stores that don't model allocations ignore this call.
    fn set_allocation_id(&self, _id: Option<String>) {}

    /// Active session id. Stores that don't model sessions return `None`
    /// and the audit row is emitted untagged.
    fn current_session_id(&self) -> Option<String> {
        None
    }
}
