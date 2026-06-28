//! NFSv3 adapter (`OrlopNfs`) — kernel-edge bridge for the macOS mount path.
//!
//! On macOS we can't ship a no-install FUSE driver. Instead `orlop mount`
//! spins up a localhost NFSv3 server (driven by [`nfsserve`]) and runs
//! `mount_nfs` against it. This module is the `nfsserve::vfs::NFSFileSystem`
//! impl that bridges the kernel side to the existing [`Store`] trait, so the
//! mTLS data plane in `orlop-server` is reused as-is.
//!
//! Per-process audit attribution is *not* available here — the kernel NFS
//! client multiplexes calling processes onto a single TCP connection, so
//! `agent_pid` is omitted from audit events on macOS.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use nfsserve::nfs::{
    fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3, set_mode3, set_mtime,
    set_size3, specdata3,
};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};

use crate::audit::{event, AuditEvent, AuditIdentity, AuditLog};
use crate::backend::EntryKind;
use crate::policy::Policy;
use crate::store::{Manifest, Store};
use crate::write_handle::WriteHandle;

/// In-memory write buffer ceiling before WriteHandle spills to a tempfile.
/// 256 MiB keeps streaming writes hot for most files; large files spill.
const SPILL_THRESHOLD: u64 = 256 * 1024 * 1024;

mod inode;
use inode::{Inodes, ROOT_ID};

/// NFSv3 adapter. Bridges kernel NFS RPCs to the [`Store`] trait, applying
/// [`Policy`] checks and emitting [`AuditLog`] events on every op.
pub struct OrlopNfs {
    store: Arc<dyn Store>,
    policy: Policy,
    audit: Arc<AuditLog>,
    inodes: Inodes,
    /// Wall-clock at mount, used as the stable fallback timestamp for
    /// directories — which carry no manifest, so no stored mtime (issue #55).
    started_ns: u64,
}

impl OrlopNfs {
    pub fn new(store: Arc<dyn Store>, policy: Policy, audit: Arc<AuditLog>) -> Self {
        Self {
            store,
            policy,
            audit,
            inodes: Inodes::new(),
            started_ns: Self::now_ns(),
        }
    }

    /// A sane, stable mtime/ctime/atime for a directory. Directories have no
    /// manifest (so no stored mtime); without this they'd report the Unix epoch
    /// (Dec 31 1969) over NFS. The mount time is non-zero and stable across
    /// repeated stats, so tools that sort or filter by mtime aren't confused
    /// (issue #55).
    fn dir_time_ns(&self) -> u64 {
        self.started_ns
    }

    /// Build the macOS-flavoured audit identity. `agent_pid` is intentionally
    /// `None` because the kernel NFS client multiplexes processes onto one
    /// connection — there is no `req.pid()` equivalent.
    fn identity(&self) -> AuditIdentity {
        AuditIdentity::default()
    }

    fn record(&self, name: &'static str, path: &str, allowed: bool) {
        self.audit
            .record(AuditEvent::simple(name, path, allowed, self.identity()));
    }

    fn record_write(
        &self,
        name: &'static str,
        path: &str,
        allowed: bool,
        size: Option<u64>,
        offset: Option<i64>,
        to_path: Option<&str>,
    ) {
        let mut e = AuditEvent::simple(name, path, allowed, self.identity());
        e.size = size;
        e.offset = offset;
        if let Some(p) = to_path {
            e.to_path = Some(p.to_string());
        }
        self.audit.record(e);
    }

    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    fn join(parent: &str, child: &str) -> String {
        if parent.is_empty() {
            child.to_string()
        } else {
            format!("{parent}/{child}")
        }
    }

    fn fattr_for(&self, id: fileid3, entry_kind: EntryKind, size: u64, mtime_ns: u64) -> fattr3 {
        let ftype = match entry_kind {
            EntryKind::Dir => ftype3::NF3DIR,
            EntryKind::File => ftype3::NF3REG,
            EntryKind::Symlink => ftype3::NF3LNK,
            EntryKind::Fifo => ftype3::NF3FIFO,
            EntryKind::Socket => ftype3::NF3SOCK,
            EntryKind::CharDev => ftype3::NF3CHR,
            EntryKind::BlockDev => ftype3::NF3BLK,
        };
        let mode = match entry_kind {
            EntryKind::Dir => 0o755,
            EntryKind::File => 0o644,
            EntryKind::Symlink => 0o777,
            EntryKind::Fifo | EntryKind::Socket | EntryKind::CharDev | EntryKind::BlockDev => 0o644,
        };
        let mtime = nfstime3 {
            seconds: (mtime_ns / 1_000_000_000) as u32,
            nseconds: (mtime_ns % 1_000_000_000) as u32,
        };
        fattr3 {
            ftype,
            mode,
            nlink: 1,
            // macOS NFS client enforces per-uid permissions: uid=0 makes the
            // mount root unwritable for the user who ran `orlop mount`.
            // The daemon and the agents using the mount are the same user,
            // so reflect that uid/gid to the kernel.
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            size,
            used: size,
            rdev: specdata3::default(),
            fsid: 0,
            fileid: id,
            atime: mtime,
            mtime,
            ctime: mtime,
        }
    }
}

#[async_trait]
impl NFSFileSystem for OrlopNfs {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadWrite
    }

    fn root_dir(&self) -> fileid3 {
        ROOT_ID
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let parent = self.inodes.path_of(dirid).ok_or(nfsstat3::NFS3ERR_STALE)?;
        let name = std::str::from_utf8(filename.as_ref()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
        let rel = Self::join(&parent, name);

        if !self.policy.permits(&rel) {
            self.record(event::LOOKUP, &rel, false);
            return Err(nfsstat3::NFS3ERR_ACCES);
        }

        let entry = self
            .store
            .entry_for(&rel)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .ok_or(nfsstat3::NFS3ERR_NOENT)?;
        let id = self.inodes.intern(&rel);
        self.record(event::LOOKUP, &rel, true);
        let _ = entry;
        Ok(id)
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        let path = self.inodes.path_of(id).ok_or(nfsstat3::NFS3ERR_STALE)?;
        if path.is_empty() {
            // Root directory — no manifest, synthesise a stable timestamp.
            return Ok(self.fattr_for(id, EntryKind::Dir, 0, self.dir_time_ns()));
        }
        let entry = self
            .store
            .entry_for(&path)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .ok_or(nfsstat3::NFS3ERR_NOENT)?;
        let mtime_ns = match entry.kind {
            EntryKind::File => self
                .store
                .manifest_get(&path)
                .map(|m| m.mtime_ns)
                .unwrap_or(0),
            // Directories (and other manifest-less kinds) carry no stored
            // mtime; report a stable non-epoch timestamp instead of 0.
            EntryKind::Dir
            | EntryKind::Symlink
            | EntryKind::Fifo
            | EntryKind::Socket
            | EntryKind::CharDev
            | EntryKind::BlockDev => self.dir_time_ns(),
        };
        Ok(self.fattr_for(id, entry.kind, entry.size, mtime_ns))
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        let path = self.inodes.path_of(id).ok_or(nfsstat3::NFS3ERR_STALE)?;
        if !self.policy.permits(&path) {
            self.record(event::READ, &path, false);
            return Err(nfsstat3::NFS3ERR_ACCES);
        }

        let manifest = self
            .store
            .manifest_get(&path)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        if manifest.version == 0 {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }

        let mut out = Vec::new();
        let want_end = offset.saturating_add(count as u64).min(manifest.size);
        for chunk_ref in &manifest.chunks {
            let chunk_start = chunk_ref.offset;
            let chunk_end = chunk_ref.offset + chunk_ref.len as u64;
            if chunk_end <= offset || chunk_start >= want_end {
                continue;
            }
            let bytes = self
                .store
                .chunk_get(&chunk_ref.hash)
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;
            let slice_start = offset.saturating_sub(chunk_start) as usize;
            let slice_end = (want_end - chunk_start).min(bytes.len() as u64) as usize;
            out.extend_from_slice(&bytes[slice_start..slice_end]);
        }
        let eof = want_end >= manifest.size;
        self.record(event::READ, &path, true);
        Ok((out, eof))
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        let parent = self.inodes.path_of(dirid).ok_or(nfsstat3::NFS3ERR_STALE)?;
        let entries = self
            .store
            .dir_list(&parent)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;

        let mut out = Vec::new();
        let mut started = start_after == 0;
        for entry in entries {
            let rel = Self::join(&parent, &entry.name);
            let allowed = self.policy.permits(&rel);
            // Per-entry audit so denied directory members show up in the log
            // even though they're filtered out.
            self.record(event::READDIR_ENTRY, &rel, allowed);
            if !allowed {
                continue;
            }
            let id = self.inodes.intern(&rel);
            if !started {
                if id == start_after {
                    started = true;
                }
                continue;
            }
            if out.len() >= max_entries {
                return Ok(ReadDirResult {
                    entries: out,
                    end: false,
                });
            }
            let mtime_ns = match entry.kind {
                EntryKind::File => self
                    .store
                    .manifest_get(&rel)
                    .map(|m| m.mtime_ns)
                    .unwrap_or(0),
                // Directories (and other manifest-less kinds) carry no stored
                // mtime; report a stable non-epoch timestamp instead of 0.
                EntryKind::Dir
                | EntryKind::Symlink
                | EntryKind::Fifo
                | EntryKind::Socket
                | EntryKind::CharDev
                | EntryKind::BlockDev => self.dir_time_ns(),
            };
            let attr = self.fattr_for(id, entry.kind, entry.size, mtime_ns);
            out.push(DirEntry {
                fileid: id,
                name: entry.name.as_bytes().to_vec().into(),
                attr,
            });
        }
        Ok(ReadDirResult {
            entries: out,
            end: true,
        })
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        _attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let parent = self.inodes.path_of(dirid).ok_or(nfsstat3::NFS3ERR_STALE)?;
        let name = std::str::from_utf8(filename.as_ref()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
        let rel = Self::join(&parent, name);

        if !self.policy.permits_write(&rel) {
            self.record(event::CREATE, &rel, false);
            return Err(nfsstat3::NFS3ERR_ACCES);
        }

        let mtime_ns = Self::now_ns();
        let mf = Manifest {
            size: 0,
            mode: 0o644,
            mtime_ns,
            version: 0,
            chunks: vec![],
        };
        // version=0 = "must not exist" CAS; surfaces NFS3ERR_EXIST on collision.
        self.store
            .manifest_put(&rel, 0, &mf)
            .map_err(|_| nfsstat3::NFS3ERR_EXIST)?;
        let id = self.inodes.intern(&rel);
        self.record_write(event::CREATE, &rel, true, Some(0), None, None);
        Ok((id, self.fattr_for(id, EntryKind::File, 0, mtime_ns)))
    }

    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        // EXCLUSIVE create has the same on-disk effect as plain create for our
        // store (no verifier persistence). Reuse create's path + drop the attr.
        let (id, _attr) = self.create(dirid, filename, sattr3::default()).await?;
        Ok(id)
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        let path = self.inodes.path_of(id).ok_or(nfsstat3::NFS3ERR_STALE)?;
        if !self.policy.permits_write(&path) {
            self.record_write(
                event::FLUSH,
                &path,
                false,
                Some(data.len() as u64),
                Some(offset as i64),
                None,
            );
            return Err(nfsstat3::NFS3ERR_ACCES);
        }

        // Uncached WriteHandle — load → splice → flush per RPC. NFS is
        // stateless so we can't keep the buffer between calls; the chunk-level
        // dedup in the store keeps re-flush cost proportional to changed data.
        let mut wh = WriteHandle::new(path.clone(), 0o644, 0, 0, SPILL_THRESHOLD, None);
        wh.write(&*self.store, offset, data)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;

        let mf = self
            .store
            .manifest_get(&path)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        self.record_write(
            event::FLUSH,
            &path,
            true,
            Some(data.len() as u64),
            Some(offset as i64),
            None,
        );
        Ok(self.fattr_for(id, EntryKind::File, mf.size, mf.mtime_ns))
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        let path = self.inodes.path_of(id).ok_or(nfsstat3::NFS3ERR_STALE)?;
        if !self.policy.permits_write(&path) {
            self.record(event::SETATTR, &path, false);
            return Err(nfsstat3::NFS3ERR_ACCES);
        }

        // Truncate via WriteHandle so the buffer + chunk graph stays consistent.
        if let set_size3::size(new_size) = setattr.size {
            let mut wh = WriteHandle::new(path.clone(), 0o644, 0, 0, SPILL_THRESHOLD, None);
            wh.truncate(&*self.store, new_size)
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;
            wh.flush(&*self.store).map_err(|_| nfsstat3::NFS3ERR_IO)?;
        }

        // mode / mtime go through manifest_put directly (no chunk side-effects).
        let mut mf = self
            .store
            .manifest_get(&path)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        if mf.version == 0 {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }
        let mut changed = false;
        if let set_mode3::mode(new_mode) = setattr.mode {
            mf.mode = new_mode;
            changed = true;
        }
        if let set_mtime::SET_TO_CLIENT_TIME(t) = setattr.mtime {
            mf.mtime_ns = (t.seconds as u64) * 1_000_000_000 + t.nseconds as u64;
            changed = true;
        }
        if changed {
            let v = mf.version;
            self.store
                .manifest_put(&path, v, &mf)
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        }

        let mf = self
            .store
            .manifest_get(&path)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        self.record(event::SETATTR, &path, true);
        Ok(self.fattr_for(id, EntryKind::File, mf.size, mf.mtime_ns))
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        let parent = self.inodes.path_of(dirid).ok_or(nfsstat3::NFS3ERR_STALE)?;
        let name = std::str::from_utf8(filename.as_ref()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
        let rel = Self::join(&parent, name);

        if !self.policy.permits_write(&rel) {
            self.record(event::UNLINK, &rel, false);
            return Err(nfsstat3::NFS3ERR_ACCES);
        }

        // Distinguish file vs directory so the right primitive runs.
        let entry = self
            .store
            .entry_for(&rel)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .ok_or(nfsstat3::NFS3ERR_NOENT)?;
        match entry.kind {
            EntryKind::File => {
                let mf = self
                    .store
                    .manifest_get(&rel)
                    .map_err(|_| nfsstat3::NFS3ERR_IO)?;
                self.store
                    .manifest_delete(&rel, mf.version)
                    .map_err(|_| nfsstat3::NFS3ERR_IO)?;
                self.record(event::UNLINK, &rel, true);
            }
            EntryKind::Dir => {
                self.store
                    .dir_remove(&rel)
                    .map_err(|_| nfsstat3::NFS3ERR_IO)?;
                self.record(event::RMDIR, &rel, true);
            }
            // Symlink/special-node removal over NFS not wired yet (FUSE/k8s is
            // the production path); creation + readlink + chmod are supported.
            EntryKind::Symlink
            | EntryKind::Fifo
            | EntryKind::Socket
            | EntryKind::CharDev
            | EntryKind::BlockDev => return Err(nfsstat3::NFS3ERR_NOTSUPP),
        }
        Ok(())
    }

    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let parent = self.inodes.path_of(dirid).ok_or(nfsstat3::NFS3ERR_STALE)?;
        let name = std::str::from_utf8(dirname.as_ref()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
        let rel = Self::join(&parent, name);

        if !self.policy.permits_write(&rel) {
            self.record(event::MKDIR, &rel, false);
            return Err(nfsstat3::NFS3ERR_ACCES);
        }

        self.store
            .dir_create(&rel, 0o755)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let id = self.inodes.intern(&rel);
        self.record(event::MKDIR, &rel, true);
        Ok((id, self.fattr_for(id, EntryKind::Dir, 0, self.dir_time_ns())))
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        let from_parent = self
            .inodes
            .path_of(from_dirid)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        let to_parent = self
            .inodes
            .path_of(to_dirid)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        let from_name =
            std::str::from_utf8(from_filename.as_ref()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
        let to_name =
            std::str::from_utf8(to_filename.as_ref()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
        let from_rel = Self::join(&from_parent, from_name);
        let to_rel = Self::join(&to_parent, to_name);

        if !self.policy.permits_write(&from_rel) || !self.policy.permits_write(&to_rel) {
            self.record_write(event::RENAME, &from_rel, false, None, None, Some(&to_rel));
            return Err(nfsstat3::NFS3ERR_ACCES);
        }

        let from_mf = self
            .store
            .manifest_get(&from_rel)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        if from_mf.version == 0 {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }
        let to_mf = self
            .store
            .manifest_get(&to_rel)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        self.store
            .manifest_rename(&from_rel, &to_rel, from_mf.version, to_mf.version)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        self.record_write(event::RENAME, &from_rel, true, None, None, Some(&to_rel));
        Ok(())
    }

    async fn symlink(
        &self,
        _dirid: fileid3,
        _linkname: &filename3,
        _symlink: &nfspath3,
        _attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        // Orlop has no symlink semantics today.
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }

    async fn readlink(&self, _id: fileid3) -> Result<nfspath3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Entry;
    use crate::store::{ChunkHash, Manifest};
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// Minimal in-memory `Store` for unit tests. Only the read primitives are
    /// fleshed out; write methods bail because the NFS read-path tests don't
    /// touch them.
    struct MockStore {
        entries: Mutex<HashMap<String, Entry>>,
        manifests: Mutex<HashMap<String, Manifest>>,
        chunks: Mutex<HashMap<ChunkHash, Vec<u8>>>,
        dirs: Mutex<HashMap<String, Vec<String>>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                manifests: Mutex::new(HashMap::new()),
                chunks: Mutex::new(HashMap::new()),
                dirs: Mutex::new(HashMap::new()),
            }
        }

        fn add_file(&self, parent: &str, name: &str, body: &[u8]) {
            let path = if parent.is_empty() {
                name.to_string()
            } else {
                format!("{parent}/{name}")
            };
            let hash: ChunkHash = blake3::hash(body).into();
            self.chunks.lock().insert(hash, body.to_vec());
            let manifest = Manifest {
                size: body.len() as u64,
                mode: 0o644,
                mtime_ns: 1_000_000_000,
                version: 1,
                chunks: vec![crate::store::ChunkRef {
                    hash,
                    offset: 0,
                    len: body.len() as u32,
                }],
            };
            self.manifests.lock().insert(path.clone(), manifest);
            self.entries.lock().insert(
                path.clone(),
                Entry {
                    name: name.to_string(),
                    kind: EntryKind::File,
                    size: body.len() as u64,
                    mode: 0,
                    uid: 0,
                    gid: 0,
                    atime: 0,
                    rdev: 0,
                },
            );
            self.dirs
                .lock()
                .entry(parent.to_string())
                .or_default()
                .push(name.to_string());
        }
    }

    impl Store for MockStore {
        fn entry_for(&self, path: &str) -> anyhow::Result<Option<Entry>> {
            Ok(self.entries.lock().get(path).cloned())
        }
        fn chunk_has(&self, hash: &ChunkHash) -> anyhow::Result<bool> {
            Ok(self.chunks.lock().contains_key(hash))
        }
        fn chunk_put(&self, hash: &ChunkHash, bytes: &[u8]) -> anyhow::Result<()> {
            self.chunks.lock().insert(*hash, bytes.to_vec());
            Ok(())
        }
        fn chunk_get(&self, hash: &ChunkHash) -> anyhow::Result<Vec<u8>> {
            self.chunks
                .lock()
                .get(hash)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing chunk"))
        }
        fn manifest_get(&self, path: &str) -> anyhow::Result<Manifest> {
            Ok(self.manifests.lock().get(path).cloned().unwrap_or_default())
        }
        fn manifest_put(
            &self,
            path: &str,
            expected_version: u64,
            mf: &Manifest,
        ) -> anyhow::Result<u64> {
            let mut manifests = self.manifests.lock();
            let current = manifests.get(path).map(|m| m.version).unwrap_or(0);
            if current != expected_version {
                anyhow::bail!(
                    "MockStore CAS mismatch on {path}: have {current}, want {expected_version}"
                );
            }
            let mut new_mf = mf.clone();
            new_mf.version = current + 1;
            manifests.insert(path.to_string(), new_mf.clone());
            // Track in entries + parent dir listing too.
            let (parent, name) = match path.rsplit_once('/') {
                Some((p, n)) => (p.to_string(), n.to_string()),
                None => (String::new(), path.to_string()),
            };
            self.entries.lock().insert(
                path.to_string(),
                Entry {
                    name: name.clone(),
                    kind: EntryKind::File,
                    size: new_mf.size,
                    mode: 0,
                    uid: 0,
                    gid: 0,
                    atime: 0,
                    rdev: 0,
                },
            );
            let mut dirs = self.dirs.lock();
            let entry = dirs.entry(parent).or_default();
            if !entry.contains(&name) {
                entry.push(name);
            }
            Ok(new_mf.version)
        }
        fn manifest_delete(&self, path: &str, expected_version: u64) -> anyhow::Result<()> {
            let mut manifests = self.manifests.lock();
            let current = manifests.get(path).map(|m| m.version).unwrap_or(0);
            if current == 0 {
                anyhow::bail!("MockStore: manifest_delete on absent {path}");
            }
            if current != expected_version {
                anyhow::bail!(
                    "MockStore CAS mismatch on delete {path}: have {current}, want {expected_version}"
                );
            }
            manifests.remove(path);
            self.entries.lock().remove(path);
            let (parent, name) = match path.rsplit_once('/') {
                Some((p, n)) => (p.to_string(), n.to_string()),
                None => (String::new(), path.to_string()),
            };
            if let Some(list) = self.dirs.lock().get_mut(&parent) {
                list.retain(|n| n != &name);
            }
            Ok(())
        }
        fn manifest_rename(
            &self,
            from: &str,
            to: &str,
            expected_version_from: u64,
            expected_version_to: u64,
        ) -> anyhow::Result<u64> {
            let mut manifests = self.manifests.lock();
            let from_v = manifests.get(from).map(|m| m.version).unwrap_or(0);
            let to_v = manifests.get(to).map(|m| m.version).unwrap_or(0);
            if from_v != expected_version_from || to_v != expected_version_to {
                anyhow::bail!("MockStore CAS mismatch on rename");
            }
            let mut mf = manifests
                .remove(from)
                .ok_or_else(|| anyhow::anyhow!("rename: source missing"))?;
            mf.version += 1;
            let new_v = mf.version;
            manifests.insert(to.to_string(), mf);
            let mut entries = self.entries.lock();
            if let Some(mut e) = entries.remove(from) {
                let to_name = to.rsplit_once('/').map(|(_, n)| n).unwrap_or(to);
                e.name = to_name.to_string();
                entries.insert(to.to_string(), e);
            }
            let mut dirs = self.dirs.lock();
            let from_name = from.rsplit_once('/').map(|(_, n)| n).unwrap_or(from);
            let to_name = to.rsplit_once('/').map(|(_, n)| n).unwrap_or(to);
            let from_parent = from
                .rsplit_once('/')
                .map(|(p, _)| p.to_string())
                .unwrap_or_default();
            let to_parent = to
                .rsplit_once('/')
                .map(|(p, _)| p.to_string())
                .unwrap_or_default();
            if let Some(list) = dirs.get_mut(&from_parent) {
                list.retain(|n| n != from_name);
            }
            let to_list = dirs.entry(to_parent).or_default();
            if !to_list.contains(&to_name.to_string()) {
                to_list.push(to_name.to_string());
            }
            Ok(new_v)
        }
        fn dir_list(&self, path: &str) -> anyhow::Result<Vec<Entry>> {
            let names = self.dirs.lock().get(path).cloned().unwrap_or_default();
            let entries = self.entries.lock();
            Ok(names
                .into_iter()
                .filter_map(|n| {
                    let full = if path.is_empty() {
                        n.clone()
                    } else {
                        format!("{path}/{n}")
                    };
                    entries.get(&full).cloned()
                })
                .collect())
        }
        fn dir_create(&self, path: &str, _mode: u32) -> anyhow::Result<()> {
            let (parent, name) = match path.rsplit_once('/') {
                Some((p, n)) => (p.to_string(), n.to_string()),
                None => (String::new(), path.to_string()),
            };
            self.entries.lock().insert(
                path.to_string(),
                Entry {
                    name: name.clone(),
                    kind: EntryKind::Dir,
                    size: 0,
                    mode: 0,
                    uid: 0,
                    gid: 0,
                    atime: 0,
                    rdev: 0,
                },
            );
            let mut dirs = self.dirs.lock();
            dirs.entry(path.to_string()).or_default();
            let parent_list = dirs.entry(parent).or_default();
            if !parent_list.contains(&name) {
                parent_list.push(name);
            }
            Ok(())
        }
        fn dir_remove(&self, path: &str) -> anyhow::Result<()> {
            self.entries.lock().remove(path);
            let mut dirs = self.dirs.lock();
            dirs.remove(path);
            let (parent, name) = match path.rsplit_once('/') {
                Some((p, n)) => (p.to_string(), n.to_string()),
                None => (String::new(), path.to_string()),
            };
            if let Some(list) = dirs.get_mut(&parent) {
                list.retain(|n| n != &name);
            }
            Ok(())
        }
    }

    fn audit_log() -> (tempfile::TempDir, Arc<AuditLog>, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::new(path.clone()).unwrap();
        (dir, Arc::new(log), path)
    }

    fn read_audit(path: &PathBuf) -> Vec<serde_json::Value> {
        let body = std::fs::read_to_string(path).unwrap_or_default();
        body.lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn lookup_denied_path_returns_eacces() {
        let store = Arc::new(MockStore::new());
        store.add_file("", "secret.txt", b"hello");
        let policy = Policy::with_readonly(&[], &["secret.txt".to_string()], false).unwrap();
        let (_dir, audit, audit_path) = audit_log();
        let nfs = OrlopNfs::new(store.clone(), policy, audit.clone());

        let res = nfs
            .lookup(nfs.root_dir(), &b"secret.txt".to_vec().into())
            .await;
        assert!(
            matches!(res, Err(nfsstat3::NFS3ERR_ACCES)),
            "want NFS3ERR_ACCES, got {:?}",
            res
        );

        audit.flush().unwrap();
        let events = read_audit(&audit_path);
        let denied = events
            .iter()
            .find(|e| e["event"] == "lookup" && e["allowed"] == false)
            .expect("expected denied lookup audit event");
        assert_eq!(denied["path"], "secret.txt");
        assert!(
            denied.get("agent_pid").is_none(),
            "macOS audit must omit agent_pid; got {:?}",
            denied.get("agent_pid")
        );
    }

    #[tokio::test]
    async fn lookup_allowed_returns_id_and_audits_allowed() {
        let store = Arc::new(MockStore::new());
        store.add_file("", "ok.txt", b"hello");
        let policy = Policy::new(&[], &[]).unwrap();
        let (_dir, audit, audit_path) = audit_log();
        let nfs = OrlopNfs::new(store, policy, audit.clone());

        let id = nfs
            .lookup(nfs.root_dir(), &b"ok.txt".to_vec().into())
            .await
            .expect("lookup should succeed");
        assert!(id > ROOT_ID);

        audit.flush().unwrap();
        let events = read_audit(&audit_path);
        assert!(events
            .iter()
            .any(|e| e["event"] == "lookup" && e["path"] == "ok.txt" && e["allowed"] == true));
    }

    #[tokio::test]
    async fn read_returns_file_bytes_with_eof() {
        let store = Arc::new(MockStore::new());
        store.add_file("", "ok.txt", b"hello world");
        let policy = Policy::new(&[], &[]).unwrap();
        let (_dir, audit, _audit_path) = audit_log();
        let nfs = OrlopNfs::new(store, policy, audit);

        let id = nfs
            .lookup(nfs.root_dir(), &b"ok.txt".to_vec().into())
            .await
            .unwrap();
        let (bytes, eof) = nfs.read(id, 0, 1024).await.expect("read should succeed");
        assert_eq!(bytes, b"hello world");
        assert!(eof);
    }

    #[tokio::test]
    async fn readdir_filters_denied_entries_and_audits_each() {
        let store = Arc::new(MockStore::new());
        store.add_file("", "ok.txt", b"a");
        store.add_file("", "secret.txt", b"b");
        let policy = Policy::with_readonly(&[], &["secret.txt".to_string()], false).unwrap();
        let (_dir, audit, audit_path) = audit_log();
        let nfs = OrlopNfs::new(store, policy, audit.clone());

        let res = nfs.readdir(nfs.root_dir(), 0, 100).await.unwrap();
        let names: Vec<String> = res
            .entries
            .iter()
            .map(|e| String::from_utf8_lossy(e.name.as_ref()).into_owned())
            .collect();
        assert_eq!(names, vec!["ok.txt"]);

        audit.flush().unwrap();
        let events = read_audit(&audit_path);
        let denied = events.iter().find(|e| {
            e["event"] == "readdir_entry" && e["path"] == "secret.txt" && e["allowed"] == false
        });
        assert!(
            denied.is_some(),
            "expected denied readdir_entry for secret.txt"
        );
    }

    fn nfs_with(deny: &[&str]) -> (Arc<MockStore>, Arc<AuditLog>, PathBuf, OrlopNfs) {
        let store = Arc::new(MockStore::new());
        let policy = Policy::with_readonly(
            &[],
            &deny.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            false,
        )
        .unwrap();
        let (_dir, audit, audit_path) = audit_log();
        // Leak _dir so the tempdir survives the function return without leaking on test exit.
        std::mem::forget(_dir);
        let nfs = OrlopNfs::new(store.clone(), policy, audit.clone());
        (store, audit, audit_path, nfs)
    }

    #[tokio::test]
    async fn capabilities_advertise_readwrite() {
        let (_s, _a, _p, nfs) = nfs_with(&[]);
        assert!(matches!(nfs.capabilities(), VFSCapabilities::ReadWrite));
    }

    #[tokio::test]
    async fn directory_getattr_and_readdir_report_nonzero_mtime() {
        // issue #55: directories carry no manifest, so without a synthesised
        // timestamp they reported epoch 0 (Dec 31 1969) over NFS.
        let (store, _audit, _path, nfs) = nfs_with(&[]);
        let (dir_id, mkdir_attr) = nfs
            .mkdir(nfs.root_dir(), &b"sub".to_vec().into())
            .await
            .expect("mkdir");
        assert!(matches!(mkdir_attr.ftype, ftype3::NF3DIR));
        // mkdir's returned attr is non-epoch...
        assert_ne!(mkdir_attr.mtime.seconds, 0, "mkdir mtime should not be epoch 0");

        // ...and a later getattr is consistent (same stable value), never epoch 0.
        let got = nfs.getattr(dir_id).await.expect("getattr dir");
        assert_ne!(got.mtime.seconds, 0, "dir getattr mtime should not be epoch 0");
        assert_eq!(got.mtime.seconds, mkdir_attr.mtime.seconds, "dir mtime must be stable");
        assert_eq!(got.ctime.seconds, got.mtime.seconds);

        // The root directory must also report a non-epoch mtime.
        let root = nfs.getattr(nfs.root_dir()).await.expect("getattr root");
        assert_ne!(root.mtime.seconds, 0, "root mtime should not be epoch 0");

        // And a directory entry surfaced via readdir carries it too.
        let _ = store;
        let listing = nfs.readdir(nfs.root_dir(), 0, 64).await.expect("readdir");
        let sub = listing
            .entries
            .iter()
            .find(|e| e.name.as_ref() == b"sub")
            .expect("sub in listing");
        assert_ne!(sub.attr.mtime.seconds, 0, "readdir dir entry mtime should not be epoch 0");
    }

    #[tokio::test]
    async fn create_writes_empty_manifest_and_returns_id() {
        let (store, audit, audit_path, nfs) = nfs_with(&[]);
        let (id, attr) = nfs
            .create(
                nfs.root_dir(),
                &b"new.txt".to_vec().into(),
                sattr3::default(),
            )
            .await
            .expect("create should succeed");
        assert!(id > ROOT_ID);
        assert_eq!(attr.size, 0);
        assert!(matches!(attr.ftype, ftype3::NF3REG));

        let mf = store.manifest_get("new.txt").unwrap();
        assert!(mf.version > 0, "create must persist a manifest");
        assert_eq!(mf.size, 0);
        assert!(mf.chunks.is_empty());

        audit.flush().unwrap();
        let events = read_audit(&audit_path);
        assert!(events
            .iter()
            .any(|e| e["event"] == "create" && e["allowed"] == true && e["path"] == "new.txt"));
    }

    #[tokio::test]
    async fn create_denied_returns_eacces_and_audits() {
        let (store, audit, audit_path, nfs) = nfs_with(&["denied.txt"]);
        let res = nfs
            .create(
                nfs.root_dir(),
                &b"denied.txt".to_vec().into(),
                sattr3::default(),
            )
            .await;
        assert!(matches!(res, Err(nfsstat3::NFS3ERR_ACCES)));
        assert_eq!(store.manifest_get("denied.txt").unwrap().version, 0);

        audit.flush().unwrap();
        let events = read_audit(&audit_path);
        assert!(events
            .iter()
            .any(|e| e["event"] == "create" && e["allowed"] == false));
    }

    #[tokio::test]
    async fn write_persists_bytes_round_trip() {
        let (store, _audit, _audit_path, nfs) = nfs_with(&[]);
        let (id, _) = nfs
            .create(nfs.root_dir(), &b"f.bin".to_vec().into(), sattr3::default())
            .await
            .unwrap();
        let attr = nfs.write(id, 0, b"hello world").await.expect("write");
        assert_eq!(attr.size, 11);

        let mf = store.manifest_get("f.bin").unwrap();
        assert_eq!(mf.size, 11);
        assert!(!mf.chunks.is_empty());

        let (bytes, eof) = nfs.read(id, 0, 1024).await.unwrap();
        assert_eq!(bytes, b"hello world");
        assert!(eof);
    }

    #[tokio::test]
    async fn write_denied_returns_eacces() {
        // Pre-seed the file directly via mock so the path exists.
        let store2 = Arc::new(MockStore::new());
        store2.add_file("", "secret.txt", b"hello");
        let policy = Policy::with_readonly(&[], &["secret.txt".to_string()], false).unwrap();
        let (_dir, audit, _) = audit_log();
        let nfs = OrlopNfs::new(store2, policy, audit);
        let id = nfs.inodes.intern("secret.txt");
        let res = nfs.write(id, 0, b"x").await;
        assert!(matches!(res, Err(nfsstat3::NFS3ERR_ACCES)));
    }

    #[tokio::test]
    async fn setattr_truncates_to_smaller_size() {
        let store = Arc::new(MockStore::new());
        store.add_file("", "f.bin", b"abcdefghij");
        let policy = Policy::new(&[], &[]).unwrap();
        let (_dir, audit, _) = audit_log();
        let nfs = OrlopNfs::new(store.clone(), policy, audit);
        let id = nfs
            .lookup(nfs.root_dir(), &b"f.bin".to_vec().into())
            .await
            .unwrap();
        let mut sattr = sattr3::default();
        sattr.size = set_size3::size(4);
        let attr = nfs.setattr(id, sattr).await.expect("setattr");
        assert_eq!(attr.size, 4);
        let mf = store.manifest_get("f.bin").unwrap();
        assert_eq!(mf.size, 4);
    }

    #[tokio::test]
    async fn setattr_updates_mode_via_manifest_put() {
        let store = Arc::new(MockStore::new());
        store.add_file("", "f.bin", b"x");
        let policy = Policy::new(&[], &[]).unwrap();
        let (_dir, audit, _) = audit_log();
        let nfs = OrlopNfs::new(store.clone(), policy, audit);
        let id = nfs
            .lookup(nfs.root_dir(), &b"f.bin".to_vec().into())
            .await
            .unwrap();
        let mut sattr = sattr3::default();
        sattr.mode = set_mode3::mode(0o600);
        nfs.setattr(id, sattr).await.unwrap();
        assert_eq!(store.manifest_get("f.bin").unwrap().mode, 0o600);
    }

    #[tokio::test]
    async fn remove_file_deletes_manifest_and_audits_unlink() {
        let store = Arc::new(MockStore::new());
        store.add_file("", "doomed.txt", b"x");
        let policy = Policy::new(&[], &[]).unwrap();
        let (_dir, audit, audit_path) = audit_log();
        let nfs = OrlopNfs::new(store.clone(), policy, audit.clone());

        nfs.remove(nfs.root_dir(), &b"doomed.txt".to_vec().into())
            .await
            .expect("remove should succeed");
        assert_eq!(store.manifest_get("doomed.txt").unwrap().version, 0);

        audit.flush().unwrap();
        let events = read_audit(&audit_path);
        assert!(events
            .iter()
            .any(|e| e["event"] == "unlink" && e["allowed"] == true));
    }

    #[tokio::test]
    async fn remove_denied_returns_eacces() {
        let store = Arc::new(MockStore::new());
        store.add_file("", "keep.txt", b"x");
        let policy = Policy::with_readonly(&[], &["keep.txt".to_string()], false).unwrap();
        let (_dir, audit, _) = audit_log();
        let nfs = OrlopNfs::new(store.clone(), policy, audit);
        let res = nfs
            .remove(nfs.root_dir(), &b"keep.txt".to_vec().into())
            .await;
        assert!(matches!(res, Err(nfsstat3::NFS3ERR_ACCES)));
        assert!(store.manifest_get("keep.txt").unwrap().version > 0);
    }

    #[tokio::test]
    async fn mkdir_creates_directory_and_audits() {
        let (store, audit, audit_path, nfs) = nfs_with(&[]);
        let (id, attr) = nfs
            .mkdir(nfs.root_dir(), &b"newdir".to_vec().into())
            .await
            .expect("mkdir");
        assert!(id > ROOT_ID);
        assert!(matches!(attr.ftype, ftype3::NF3DIR));
        assert!(store.entry_for("newdir").unwrap().is_some());

        audit.flush().unwrap();
        let events = read_audit(&audit_path);
        assert!(events
            .iter()
            .any(|e| e["event"] == "mkdir" && e["allowed"] == true));
    }

    #[tokio::test]
    async fn mkdir_denied_returns_eacces() {
        let (_store, _audit, _, nfs) = nfs_with(&["forbidden"]);
        let res = nfs
            .mkdir(nfs.root_dir(), &b"forbidden".to_vec().into())
            .await;
        assert!(matches!(res, Err(nfsstat3::NFS3ERR_ACCES)));
    }

    #[tokio::test]
    async fn rmdir_via_remove_dispatches_to_dir_remove() {
        let (store, _audit, _, nfs) = nfs_with(&[]);
        nfs.mkdir(nfs.root_dir(), &b"rmme".to_vec().into())
            .await
            .unwrap();
        nfs.remove(nfs.root_dir(), &b"rmme".to_vec().into())
            .await
            .expect("remove dir");
        assert!(store.entry_for("rmme").unwrap().is_none());
    }

    #[tokio::test]
    async fn rename_moves_manifest_and_audits_to_path() {
        let store = Arc::new(MockStore::new());
        store.add_file("", "old.txt", b"hello");
        let policy = Policy::new(&[], &[]).unwrap();
        let (_dir, audit, audit_path) = audit_log();
        let nfs = OrlopNfs::new(store.clone(), policy, audit.clone());

        nfs.rename(
            nfs.root_dir(),
            &b"old.txt".to_vec().into(),
            nfs.root_dir(),
            &b"new.txt".to_vec().into(),
        )
        .await
        .expect("rename");

        assert_eq!(store.manifest_get("old.txt").unwrap().version, 0);
        assert!(store.manifest_get("new.txt").unwrap().version > 0);

        audit.flush().unwrap();
        let events = read_audit(&audit_path);
        let renamed = events
            .iter()
            .find(|e| e["event"] == "rename" && e["allowed"] == true)
            .expect("expected rename audit event");
        assert_eq!(renamed["path"], "old.txt");
        assert_eq!(renamed["to_path"], "new.txt");
    }

    #[tokio::test]
    async fn rename_denied_target_returns_eacces() {
        let store = Arc::new(MockStore::new());
        store.add_file("", "src.txt", b"x");
        let policy = Policy::with_readonly(&[], &["dst.txt".to_string()], false).unwrap();
        let (_dir, audit, _) = audit_log();
        let nfs = OrlopNfs::new(store.clone(), policy, audit);
        let res = nfs
            .rename(
                nfs.root_dir(),
                &b"src.txt".to_vec().into(),
                nfs.root_dir(),
                &b"dst.txt".to_vec().into(),
            )
            .await;
        assert!(matches!(res, Err(nfsstat3::NFS3ERR_ACCES)));
    }

    #[tokio::test]
    async fn symlink_returns_notsupp() {
        let (_s, _a, _p, nfs) = nfs_with(&[]);
        let res = nfs
            .symlink(
                nfs.root_dir(),
                &b"link".to_vec().into(),
                &b"target".to_vec().into(),
                &sattr3::default(),
            )
            .await;
        assert!(matches!(res, Err(nfsstat3::NFS3ERR_NOTSUPP)));
    }
}
