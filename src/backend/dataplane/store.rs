//! Store trait adapter for the data-plane binary protocol.
//!
//! Reads pull a manifest, look each chunk up in the persistent `ChunkCache`,
//! and fetch missing chunks via `CHUNK_GET`. The manifest is the source of
//! truth for file size and chunk layout; the cache makes warm reads
//! local-disk speed across mount cycles.

use std::sync::Arc;

use anyhow::Result;
use parking_lot::Mutex;

use super::cache::ChunkCache;
use super::client::DataClient;
use super::messages::{ChunkRef as WireChunkRef, EntryWire, ManifestGetResponse};
use crate::backend::{BackendError, Entry, EntryKind};

pub struct DataStore {
    client: Arc<DataClient>,
    mount_path: String,
    cache: Arc<ChunkCache>,
    session_id: Mutex<Option<String>>,
    allocation_id: Mutex<Option<String>>,
}

impl DataStore {
    pub fn new(client: Arc<DataClient>, mount_path: String, cache: Arc<ChunkCache>) -> Self {
        Self {
            client,
            mount_path: normalize_mount_path(&mount_path),
            cache,
            session_id: Mutex::new(None),
            allocation_id: Mutex::new(None),
        }
    }

    pub fn client(&self) -> &Arc<DataClient> {
        &self.client
    }

    /// Set or clear the active session id. Subsequent writes carry the new
    /// tag; reads are unaffected. Pass `None` to leave the session.
    pub fn set_session(&self, id: Option<String>) {
        *self.session_id.lock() = id;
    }

    /// Set or clear the allocation id sent with manifest writes. The server
    /// requires this whenever `session_id` is set (it's the denormalised
    /// column the dashboard's per-allocation journal feed joins on).
    pub fn set_allocation_id(&self, id: Option<String>) {
        *self.allocation_id.lock() = id;
    }

    fn current_allocation_id(&self) -> Option<String> {
        self.allocation_id.lock().clone()
    }

    /// Query the write journal for an allocation. Thin pass-through to
    /// DataClient — exposed on DataStore so callers holding a `Store` handle
    /// don't need a second client reference.
    pub fn journal_query(
        &self,
        allocation_id: &str,
        limit: u32,
        before_ts_ms: Option<i64>,
    ) -> anyhow::Result<super::messages::JournalQueryResponse> {
        self.client
            .journal_query(allocation_id, limit, before_ts_ms)
    }

    fn virtual_path(&self, path: &str) -> String {
        join_virtual_path(&self.mount_path, path)
    }
}

// ── Store trait impl ─────────────────────────────────────────────────────────

use crate::store::{ChunkHash, Manifest, Store};

impl Store for DataStore {
    fn set_session(&self, id: Option<String>) {
        DataStore::set_session(self, id);
    }

    fn set_allocation_id(&self, id: Option<String>) {
        DataStore::set_allocation_id(self, id);
    }

    fn entry_for(&self, path: &str) -> anyhow::Result<Option<Entry>> {
        match self.client.stat(&self.virtual_path(path)) {
            Ok(w) => Ok(Some(entry_from_wire(w)?)),
            Err(e) => {
                if crate::backend::backend_errno(&e, libc::EIO) == libc::ENOENT {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn chunk_has(&self, hash: &ChunkHash) -> anyhow::Result<bool> {
        // Pack the 32-byte hash into the flat hashes buffer for chunk_has.
        let bitmap = self.client.chunk_has(&hash[..])?;
        Ok(bitmap.first().copied().unwrap_or(0) != 0)
    }

    fn chunk_has_many(&self, hashes: &[u8]) -> anyhow::Result<Vec<u8>> {
        // DataClient::chunk_has already accepts a flat N*32 buffer — one RTT.
        self.client.chunk_has(hashes)
    }

    fn chunk_put(&self, hash: &ChunkHash, bytes: &[u8]) -> anyhow::Result<()> {
        let _stored = self
            .client
            .chunk_put(hash, bytes, self.current_session_id())?;
        // Warm the local cache so subsequent reads are hot.
        self.cache.put(hash, bytes)?;
        Ok(())
    }

    fn chunk_get(&self, hash: &ChunkHash) -> anyhow::Result<Vec<u8>> {
        if let Some(bytes) = self.cache.get(hash)? {
            return Ok(bytes);
        }
        let bytes = self.client.chunk_get(hash)?;
        self.cache.put(hash, &bytes)?;
        Ok(bytes)
    }

    fn chunk_get_many(&self, hashes: &[ChunkHash]) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut bytes: Vec<Option<Vec<u8>>> = Vec::with_capacity(hashes.len());
        let mut miss_indices: Vec<usize> = Vec::new();
        let mut miss_hashes: Vec<[u8; 32]> = Vec::new();
        for (i, hash) in hashes.iter().enumerate() {
            match self.cache.get(hash)? {
                Some(b) => bytes.push(Some(b)),
                None => {
                    bytes.push(None);
                    miss_indices.push(i);
                    miss_hashes.push(*hash);
                }
            }
        }
        if !miss_hashes.is_empty() {
            let fetched = self.client.chunk_get_many(&miss_hashes)?;
            for (idx, raw) in miss_indices.into_iter().zip(fetched) {
                self.cache.put(&hashes[idx], &raw)?;
                bytes[idx] = Some(raw);
            }
        }
        Ok(bytes
            .into_iter()
            .map(|b| b.expect("every slot filled by cache or fetch"))
            .collect())
    }

    fn chunk_put_many(&self, items: &[(ChunkHash, Vec<u8>)]) -> anyhow::Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let payloads: Vec<(Vec<u8>, Vec<u8>)> =
            items.iter().map(|(h, b)| (h.to_vec(), b.clone())).collect();
        let _stored = self
            .client
            .chunk_put_many(payloads, self.current_session_id())?;
        for (hash, bytes) in items {
            self.cache.put(hash, bytes)?;
        }
        Ok(())
    }

    fn manifest_get(&self, path: &str) -> anyhow::Result<Manifest> {
        let resp = self.client.manifest_get(&self.virtual_path(path))?;
        Ok(manifest_from_wire(resp))
    }

    fn manifest_put(
        &self,
        path: &str,
        expected_version: u64,
        mf: &Manifest,
    ) -> anyhow::Result<u64> {
        let wire_chunks: Vec<WireChunkRef> = mf
            .chunks
            .iter()
            .map(|c| WireChunkRef {
                hash: c.hash.to_vec(),
                offset: c.offset,
                len: c.len,
            })
            .collect();
        self.client.manifest_put(
            &self.virtual_path(path),
            expected_version,
            mf.size,
            mf.mode,
            mf.mtime_ns as i64,
            wire_chunks,
            self.current_session_id(),
            self.current_allocation_id(),
        )
    }

    fn manifest_delete(&self, path: &str, expected_version: u64) -> anyhow::Result<()> {
        self.client.manifest_delete(
            &self.virtual_path(path),
            expected_version,
            self.current_session_id(),
            self.current_allocation_id(),
        )
    }

    fn manifest_rename(
        &self,
        from: &str,
        to: &str,
        expected_version_from: u64,
        expected_version_to: u64,
    ) -> anyhow::Result<u64> {
        self.client.manifest_rename(
            &self.virtual_path(from),
            &self.virtual_path(to),
            expected_version_from,
            expected_version_to,
            self.current_session_id(),
            self.current_allocation_id(),
        )
    }

    fn dir_list(&self, path: &str) -> anyhow::Result<Vec<Entry>> {
        let entries = self.client.list(&self.virtual_path(path))?;
        entries.into_iter().map(entry_from_wire).collect()
    }

    fn dir_create(&self, path: &str, mode: u32) -> anyhow::Result<()> {
        self.client
            .dir_create(&self.virtual_path(path), mode, self.current_session_id())
    }

    fn dir_remove(&self, path: &str) -> anyhow::Result<()> {
        self.client
            .dir_remove(&self.virtual_path(path), self.current_session_id())
    }

    fn setattr_mode(&self, path: &str, mode: u32) -> anyhow::Result<()> {
        self.client.setattr(
            &self.virtual_path(path),
            mode,
            self.current_session_id(),
            self.current_allocation_id(),
        )
    }

    fn setattr_owner(&self, path: &str, uid: u32, gid: u32) -> anyhow::Result<()> {
        // The server's setattr handler always chmods to req.mode before applying
        // the owner change, so carry the path's CURRENT mode to keep the chmod a
        // no-op. stat is the source of truth for the current mode of any kind.
        let vpath = self.virtual_path(path);
        let cur_mode = self.client.stat(&vpath)?.mode;
        self.client.setattr_owner(
            &vpath,
            cur_mode,
            uid,
            gid,
            self.current_session_id(),
            self.current_allocation_id(),
        )
    }

    fn setattr_atime(&self, path: &str, atime: i64) -> anyhow::Result<()> {
        // Same current-mode preservation as setattr_owner.
        let vpath = self.virtual_path(path);
        let cur_mode = self.client.stat(&vpath)?.mode;
        self.client.setattr_atime(
            &vpath,
            cur_mode,
            atime,
            self.current_session_id(),
            self.current_allocation_id(),
        )
    }

    fn symlink(&self, path: &str, target: &str, mode: u32) -> anyhow::Result<()> {
        self.client.symlink(
            &self.virtual_path(path),
            target,
            mode,
            self.current_session_id(),
            self.current_allocation_id(),
        )
    }

    fn mknod(&self, path: &str, mode: u32, rdev: u64) -> anyhow::Result<()> {
        self.client.mknod(
            &self.virtual_path(path),
            mode,
            rdev,
            self.current_session_id(),
            self.current_allocation_id(),
        )
    }

    fn readlink(&self, path: &str) -> anyhow::Result<String> {
        self.client.readlink(&self.virtual_path(path))
    }

    fn current_session_id(&self) -> Option<String> {
        self.session_id.lock().clone()
    }
}

fn manifest_from_wire(r: ManifestGetResponse) -> Manifest {
    Manifest {
        size: r.size,
        mode: r.mode,
        mtime_ns: r.mtime as u64,
        version: r.version,
        chunks: r
            .chunks
            .into_iter()
            .map(|c| crate::store::ChunkRef {
                hash: c.hash.try_into().expect("32-byte hash"),
                offset: c.offset,
                len: c.len,
            })
            .collect(),
    }
}

fn entry_from_wire(w: EntryWire) -> Result<Entry> {
    let kind = match w.kind.as_str() {
        "file" => EntryKind::File,
        "dir" => EntryKind::Dir,
        "symlink" => EntryKind::Symlink,
        "fifo" => EntryKind::Fifo,
        "socket" => EntryKind::Socket,
        "chardev" => EntryKind::CharDev,
        "blockdev" => EntryKind::BlockDev,
        other => {
            return Err(BackendError::new(
                super::protocol::errno::EIO,
                format!("server returned unknown entry kind {other:?}"),
            )
            .into());
        }
    };
    Ok(Entry {
        name: w.name,
        kind,
        size: w.size,
        mode: w.mode,
        uid: w.uid,
        gid: w.gid,
        atime: w.atime,
        rdev: w.rdev,
    })
}

fn normalize_mount_path(p: &str) -> String {
    let trimmed = p.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("/{}", trimmed)
    }
}

// Join a normalized mount prefix with a relative path. Empty prefix means the
// mount IS the disk root, so paths land directly under server `/`.
fn join_virtual_path(prefix: &str, path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if prefix.is_empty() {
        if trimmed.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", trimmed)
        }
    } else if trimmed.is_empty() {
        prefix.to_string()
    } else {
        format!("{}/{}", prefix, trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_from_wire_maps_kinds() {
        let f = entry_from_wire(EntryWire {
            name: "x".into(),
            kind: "file".into(),
            size: 7,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(f.kind, EntryKind::File);
        assert_eq!(f.size, 7);
        let d = entry_from_wire(EntryWire {
            name: "y".into(),
            kind: "dir".into(),
            size: 0,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(d.kind, EntryKind::Dir);
    }

    #[test]
    fn entry_from_wire_rejects_unknown_kind() {
        let err = entry_from_wire(EntryWire {
            name: "x".into(),
            kind: "weird".into(),
            size: 0,
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("unknown entry kind"));
    }

    #[test]
    fn normalize_mount_path_strips_and_prefixes() {
        assert_eq!(normalize_mount_path("/sub/"), "/sub");
        assert_eq!(normalize_mount_path("sub"), "/sub");
        assert_eq!(normalize_mount_path("/"), "");
        assert_eq!(normalize_mount_path(""), "");
    }

    #[test]
    fn join_virtual_path_with_prefix() {
        assert_eq!(join_virtual_path("/sub", ""), "/sub");
        assert_eq!(join_virtual_path("/sub", "/"), "/sub");
        assert_eq!(join_virtual_path("/sub", "foo"), "/sub/foo");
        assert_eq!(join_virtual_path("/sub", "/foo/bar"), "/sub/foo/bar");
    }

    #[test]
    fn join_virtual_path_root_mount() {
        // Root-mount: disk root maps directly to server root, no prefix.
        assert_eq!(join_virtual_path("", ""), "/");
        assert_eq!(join_virtual_path("", "/"), "/");
        assert_eq!(join_virtual_path("", "foo"), "/foo");
        assert_eq!(join_virtual_path("", "/foo/bar"), "/foo/bar");
    }
}
