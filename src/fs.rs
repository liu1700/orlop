#[path = "fs/assemble.rs"]
pub(crate) mod assemble;

use crate::write_handle;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::num::NonZeroUsize;
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use lru::LruCache;

use fuser::{
    consts::{FOPEN_CACHE_DIR, FOPEN_KEEP_CACHE, FUSE_DO_READDIRPLUS},
    FileAttr, FileType, Filesystem, KernelConfig, Notifier, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
    TimeOrNow,
};
use libc::{EACCES, EINVAL, EIO, ENAMETOOLONG, ENOENT, ENOTDIR};

/// POSIX `NAME_MAX` (Linux): a single path component may not exceed 255 bytes.
/// pjdfstest's `*/01.t` probe this — an over-long component must be rejected
/// with ENAMETOOLONG, which by POSIX takes precedence over ENOENT.
const NAME_MAX: usize = 255;

/// `Err(ENAMETOOLONG)` when `name`'s byte length exceeds `NAME_MAX`.
fn check_name_len(name: &OsStr) -> Result<(), libc::c_int> {
    if name.as_bytes().len() > NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    Ok(())
}

use crate::store::Manifest;
use parking_lot::Mutex;

use crate::audit::{event, AuditEvent, AuditIdentity, AuditLog};
use crate::backend::{backend_errno, EntryKind, MountedStore};
use crate::config::FuseConfig;

const ROOT_INO: u64 = 1;

pub struct GatewayFs {
    mounts: Vec<MountedStore>,
    audit: AuditLog,
    attr_ttl: Duration,
    entry_ttl: Duration,
    write_buffer_bytes: u64,
    /// Process uid/gid cached at construction. Constant for the mount's
    /// lifetime, so we avoid `libc::getuid`/`getgid` syscalls on every FUSE op.
    uid: u32,
    gid: u32,
    /// Bounded LRU mapping pid → cached `comm` string. Each audited FUSE op
    /// would otherwise reopen `/proc/<pid>/comm` (and possibly `/cmdline`)
    /// — wasteful on chatty agents like `find`.
    command_cache: Mutex<LruCache<u32, Option<String>>>,
    state: Mutex<State>,
    /// Populated by `main` after `Session::new` so flush handlers can punch
    /// the kernel's attr/data cache via `inval_inode`. Without this, attrs
    /// from the create reply (size=0) hide bytes flushed later in the same
    /// mount session — see issue #135.
    notifier: Arc<OnceLock<Notifier>>,
}

const COMMAND_CACHE_CAPACITY: usize = 1024;

struct State {
    next_ino: u64,
    by_ino: HashMap<u64, Node>,
    by_path: HashMap<String, u64>,
    write_handles: HashMap<u64, std::sync::Arc<parking_lot::Mutex<write_handle::WriteHandle>>>,
    next_fh: u64,
}

impl State {
    fn new(next_ino: u64, by_ino: HashMap<u64, Node>, by_path: HashMap<String, u64>) -> Self {
        Self {
            next_ino,
            by_ino,
            by_path,
            write_handles: HashMap::new(),
            next_fh: 1,
        }
    }

    /// Allocate a new FH for a write handle. Returns the FH.
    pub fn alloc_write_fh(&mut self, wh: write_handle::WriteHandle) -> u64 {
        let fh = self.next_fh;
        self.next_fh = fh.wrapping_add(1).max(1); // never 0
        self.write_handles
            .insert(fh, std::sync::Arc::new(parking_lot::Mutex::new(wh)));
        fh
    }

    pub fn get_write_handle(
        &self,
        fh: u64,
    ) -> Option<std::sync::Arc<parking_lot::Mutex<write_handle::WriteHandle>>> {
        self.write_handles.get(&fh).cloned()
    }

    pub fn release_write_fh(
        &mut self,
        fh: u64,
    ) -> Option<std::sync::Arc<parking_lot::Mutex<write_handle::WriteHandle>>> {
        self.write_handles.remove(&fh)
    }

    /// Drop the inode mapping for `path` (called on unlink/rmdir).
    pub fn evict_node(&mut self, path: &str) {
        if let Some(ino) = self.by_path.remove(path) {
            self.by_ino.remove(&ino);
        }
    }

    /// Update a node's cached size. Called after a successful flush so the
    /// next `getattr` reflects the bytes that were just committed server-side.
    /// No-ops on unknown inodes (the entry may have been evicted concurrently).
    pub fn set_node_size(&mut self, ino: u64, size: u64) {
        if let Some(node) = self.by_ino.get_mut(&ino) {
            node.size = size;
        }
    }

    /// Keep a cached node's mode in sync after a chmod so getattr reflects it
    /// once the kernel's attr cache expires. No-op for an unknown inode.
    pub fn set_node_mode(&mut self, ino: u64, mode: u32) {
        if let Some(node) = self.by_ino.get_mut(&ino) {
            node.mode = mode;
        }
    }

    /// Keep a cached node's owner in sync after a chown so getattr reflects it
    /// once the kernel's attr cache expires. No-op for an unknown inode.
    pub fn set_node_owner(&mut self, ino: u64, uid: u32, gid: u32) {
        if let Some(node) = self.by_ino.get_mut(&ino) {
            node.uid = uid;
            node.gid = gid;
        }
    }

    /// Keep a cached node's access time in sync after a utimensat. No-op for an
    /// unknown inode.
    pub fn set_node_atime(&mut self, ino: u64, atime_ns: u64) {
        if let Some(node) = self.by_ino.get_mut(&ino) {
            node.atime_ns = atime_ns;
        }
    }

    /// Move an inode from `old` → `new` path (POSIX preserves inode # across rename).
    /// `new_rel` is the post-rename rel_path so subsequent ops (`setattr`,
    /// `read`, etc.) hit the moved manifest instead of the vacated source.
    pub fn rename_node(&mut self, old: &str, new: &str, new_rel: &str) {
        if let Some(ino) = self.by_path.remove(old) {
            self.by_path.insert(new.to_string(), ino);
            if let Some(node) = self.by_ino.get_mut(&ino) {
                node.full_path = new.to_string();
                node.rel_path = new_rel.to_string();
            }
        }
    }

    /// Return the full_path for an inode (test helper).
    #[cfg(test)]
    pub fn lookup_path(&self, ino: u64) -> Option<String> {
        self.by_ino.get(&ino).map(|n| n.full_path.clone())
    }

    /// Return the inode for a path (test helper).
    #[cfg(test)]
    pub fn lookup_path_for(&self, path: &str) -> Option<u64> {
        self.by_path.get(path).copied()
    }
}

#[derive(Debug, Clone)]
struct Node {
    ino: u64,
    full_path: String,
    mount_idx: Option<usize>,
    rel_path: String,
    kind: FileType,
    size: u64,
    /// Stored POSIX permission bits (perm only; type comes from `kind`).
    /// 0 means "unknown" — `attr` falls back to a kind-based default. Refreshed
    /// on chmod so getattr reflects the stored mode after the attr TTL expires.
    mode: u32,
    /// Stored POSIX owner uid/gid. 0/0 == root, which is the correct value on a
    /// single-identity mount; refreshed on chown so getattr reads it back.
    uid: u32,
    gid: u32,
    /// Stored access time, unix nanoseconds. 0 means "unknown" — `attr` falls
    /// back to mtime/now. Refreshed on utimensat.
    atime_ns: u64,
    /// Device number for block/char special nodes; 0 for every other kind.
    /// Surfaced in `FileAttr.rdev` so `stat` reports the right device.
    rdev: u64,
}

impl GatewayFs {
    pub fn new(
        mounts: Vec<MountedStore>,
        audit: AuditLog,
        fuse_cfg: &FuseConfig,
        write_buffer_bytes: u64,
    ) -> Self {
        let mut by_ino = HashMap::new();
        let mut by_path = HashMap::new();
        // With a single mount, the FUSE root IS that mount — `/` is the user's
        // disk, with no synthetic mount-name dir in between. With multiple mounts
        // (legacy), the root is a synthetic dir whose children are mount-name
        // sub-dirs. mount_idx=None preserves the legacy multi-mount path.
        let root_mount_idx = if mounts.len() == 1 { Some(0) } else { None };
        by_ino.insert(
            ROOT_INO,
            Node {
                ino: ROOT_INO,
                full_path: "/".to_string(),
                mount_idx: root_mount_idx,
                rel_path: String::new(),
                kind: FileType::Directory,
                size: 0,
                mode: 0,
                uid: 0,
                gid: 0,
                atime_ns: 0,
                rdev: 0,
            },
        );
        by_path.insert("/".to_string(), ROOT_INO);

        Self {
            mounts,
            audit,
            attr_ttl: Duration::from_secs(fuse_cfg.attr_ttl_seconds),
            entry_ttl: Duration::from_secs(fuse_cfg.entry_ttl_seconds),
            write_buffer_bytes,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            command_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(COMMAND_CACHE_CAPACITY).expect("nonzero cap"),
            )),
            state: Mutex::new(State::new(ROOT_INO + 1, by_ino, by_path)),
            notifier: Arc::new(OnceLock::new()),
        }
    }

    /// Hand back a clonable handle to the notifier slot so `main` can
    /// populate it with `Session::notifier()` after the mount syscall but
    /// before `Session::run()` starts dispatching kernel requests.
    pub fn notifier_handle(&self) -> Arc<OnceLock<Notifier>> {
        Arc::clone(&self.notifier)
    }

    /// After a successful flush, sync the in-memory size and tell the kernel
    /// to drop its cached attrs/data. Both halves are needed: the kernel
    /// won't reissue `getattr` until its TTL expires (or we invalidate), and
    /// once it does we must answer with the post-flush size, not the
    /// `size=0` we recorded at `create` time.
    fn refresh_after_flush(&self, ino: u64, new_size: u64) {
        self.state.lock().set_node_size(ino, new_size);
        if let Some(notifier) = self.notifier.get() {
            // Best-effort: ENOENT means the kernel already dropped the entry.
            let _ = notifier.inval_inode(ino, 0, 0);
        }
    }

    fn command_name(&self, pid: u32) -> Option<String> {
        if let Some(cached) = self.command_cache.lock().get(&pid) {
            return cached.clone();
        }
        let resolved = read_command_name(pid);
        self.command_cache.lock().put(pid, resolved.clone());
        resolved
    }

    fn attr(&self, node: &Node) -> FileAttr {
        let now = SystemTime::now();
        // Stored atime wins; fall back to now() only when unknown (node.atime_ns
        // == 0, e.g. an old server that doesn't report it).
        let atime = if node.atime_ns != 0 {
            std::time::UNIX_EPOCH + Duration::from_nanos(node.atime_ns)
        } else {
            now
        };
        FileAttr {
            ino: node.ino,
            size: node.size,
            blocks: node.size.div_ceil(512),
            atime,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: node.kind,
            // Stored mode wins; fall back to a kind default only when unknown
            // (node.mode == 0, e.g. an old server that doesn't report mode).
            perm: if node.mode != 0 {
                (node.mode & 0o7777) as u16
            } else {
                match node.kind {
                    FileType::Directory => 0o755,
                    FileType::Symlink => 0o777,
                    _ => 0o644,
                }
            },
            nlink: 1,
            // Stored owner; 0/0 (root) is the correct default on a
            // single-identity mount (== self.uid/self.gid when the mount runs
            // as root). chown stores the value, this reads it back.
            uid: node.uid,
            gid: node.gid,
            // Device number for block/char special nodes; 0 for every other kind.
            rdev: node.rdev as u32,
            blksize: 4096,
            flags: 0,
        }
    }

    fn dir_attr(&self, ino: u64, mode: u32) -> FileAttr {
        let now = SystemTime::now();
        let perm = (mode & 0o7777) as u16;
        let perm = if perm == 0 { 0o755 } else { perm };
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn file_attr(&self, ino: u64, mode: u32, size: u64, mtime_ns: u64) -> FileAttr {
        let mtime = std::time::UNIX_EPOCH + Duration::from_nanos(mtime_ns);
        // Keep suid/sgid/sticky (0o7000) alongside perms so a chmod 0o4755 reads
        // back intact, not just the low 0o777.
        let perm = (mode & 0o7777) as u16;
        let perm = if perm == 0 { 0o644 } else { perm };
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind: FileType::RegularFile,
            perm,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn symlink_attr(&self, ino: u64, mode: u32, size: u64) -> FileAttr {
        let now = SystemTime::now();
        let perm = (mode & 0o777) as u16;
        let perm = if perm == 0 { 0o777 } else { perm };
        FileAttr {
            ino,
            size,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Symlink,
            perm,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn intern_node(
        &self,
        state: &mut State,
        full_path: String,
        mount_idx: Option<usize>,
        rel_path: String,
        kind: FileType,
        size: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        atime_ns: u64,
        rdev: u64,
    ) -> Node {
        if let Some(ino) = state.by_path.get(&full_path).copied() {
            let node = state.by_ino.get_mut(&ino).unwrap();
            node.kind = kind;
            node.size = size;
            node.rdev = rdev;
            // Only overwrite a known mode; a caller that doesn't know the mode
            // passes 0 and must not clobber a mode we already learned.
            if mode != 0 {
                node.mode = mode;
            }
            // Owner: 0/0 is a real value (root), so the entry-based callers
            // always carry authoritative uid/gid — refresh from them. Synthetic
            // callers (mount dirs) never re-intern a real file.
            node.uid = uid;
            node.gid = gid;
            // Only overwrite a known atime; an unknown (0) atime must not clobber
            // one we already learned, matching the mode guard.
            if atime_ns != 0 {
                node.atime_ns = atime_ns;
            }
            return node.clone();
        }

        let ino = state.next_ino;
        state.next_ino += 1;
        let node = Node {
            ino,
            full_path: full_path.clone(),
            mount_idx,
            rel_path,
            kind,
            size,
            mode,
            uid,
            gid,
            atime_ns,
            rdev,
        };
        state.by_path.insert(full_path, ino);
        state.by_ino.insert(ino, node.clone());
        node
    }

    fn policy_allows(&self, mount_idx: usize, rel_path: &str) -> bool {
        self.mounts[mount_idx].policy.permits(rel_path)
    }

    fn record(
        &self,
        req: &Request<'_>,
        event: &str,
        path: &str,
        size: Option<u64>,
        offset: Option<i64>,
        allowed: bool,
    ) {
        let mut event = AuditEvent::simple(event, path, allowed, self.identity_for_req(req));
        event.size = size;
        event.offset = offset;
        self.audit.record(event);
    }

    /// Acquire a write lease for `full_path` if the mount supports leases.
    /// Returns `Ok(None)` when no lease manager is wired OR when the server
    /// denied the grant (other holder, EBUSY) — the latter is audited as
    /// `lease_denied` so operators can spot uncached fallbacks.
    fn acquire_write_lease(
        &self,
        req: &Request<'_>,
        mount_idx: usize,
        full_path: &str,
    ) -> anyhow::Result<Option<Arc<crate::lease::LeaseHandle>>> {
        let Some(lm) = &self.mounts[mount_idx].leases else {
            return Ok(None);
        };
        let h = lm.acquire_exclusive(full_path)?;
        if h.is_none() {
            self.audit.record(AuditEvent::simple(
                event::LEASE_DENIED,
                full_path,
                true,
                self.identity_for_req(req)
                    .with_session(self.session_for(mount_idx)),
            ));
        }
        Ok(h)
    }

    /// Hook the lease's revoke callback to flush the open WriteHandle. Skipped
    /// when no lease was acquired.
    fn register_revoke_flush_for_fh(&self, fh: u64, mount_idx: usize, lease_present: bool) {
        if !lease_present {
            return;
        }
        let Some(wh_arc) = self.state.lock().get_write_handle(fh) else {
            return;
        };
        write_handle::WriteHandle::register_revoke_flush(
            wh_arc,
            Arc::clone(&self.mounts[mount_idx].store),
        );
    }

    /// Build an `AuditEvent` for a write-side op, pre-populated with the
    /// request's identity + the mount's active session id. Caller chains
    /// `.with_mode(...)`, `.with_to_path(...)`, etc. before passing to
    /// `audit.record(...)`.
    fn write_audit_event(
        &self,
        req: &Request<'_>,
        mount_idx: usize,
        event: &'static str,
        path: &str,
        allowed: bool,
    ) -> AuditEvent {
        AuditEvent::simple(
            event,
            path,
            allowed,
            self.identity_for_req(req)
                .with_session(self.session_for(mount_idx)),
        )
    }

    /// Record a write-side audit event with no extra metadata. Sugar for the
    /// common policy-denied / backend-failed / success triple in the simple
    /// write handlers (unlink, rmdir).
    fn audit_write(
        &self,
        req: &Request<'_>,
        mount_idx: usize,
        event: &'static str,
        path: &str,
        allowed: bool,
    ) {
        self.audit
            .record(self.write_audit_event(req, mount_idx, event, path, allowed));
    }

    fn lookup_cached(&self, full_path: &str) -> Option<Node> {
        let state = self.state.lock();
        state
            .by_path
            .get(full_path)
            .and_then(|ino| state.by_ino.get(ino))
            .cloned()
    }

    fn identity_for_req(&self, req: &Request<'_>) -> AuditIdentity {
        AuditIdentity {
            agent_pid: Some(req.pid()),
            agent_id: None,
            uid: Some(req.uid()),
            gid: Some(req.gid()),
            command: self.command_name(req.pid()),
            session_id: None,
        }
    }

    fn identity_for_pid(&self, pid: u32) -> AuditIdentity {
        AuditIdentity {
            agent_pid: Some(pid),
            agent_id: None,
            uid: None,
            gid: None,
            command: self.command_name(pid),
            session_id: None,
        }
    }

    fn session_for(&self, mount_idx: usize) -> Option<String> {
        self.mounts[mount_idx].store.current_session_id()
    }

    /// Invariant: writes only reach FUSE handlers after `mount::mount` has
    /// stamped each backend with a `mount:<hex>` session id. A debug build
    /// will panic here if the wiring is broken; release builds are zero-cost.
    #[inline]
    fn assert_write_session(&self, mount_idx: usize) {
        debug_assert!(
            self.session_for(mount_idx).is_some(),
            "FUSE write path reached before set_session"
        );
    }

    /// Resolve `(parent ino, child name)` → `(mount_idx, full_path, rel_path)`.
    ///
    /// Returns `Err(errno)` for the two standard guard cases:
    ///  - parent ino not in the inode table → `ENOENT`
    ///  - parent is the virtual root (no mount) → `EACCES`
    fn resolve_child(
        &self,
        parent: u64,
        name: &OsStr,
    ) -> Result<(usize, String, String), libc::c_int> {
        let parent_node = {
            let state = self.state.lock();
            state.by_ino.get(&parent).cloned()
        };
        let Some(parent_node) = parent_node else {
            return Err(ENOENT);
        };
        let Some(mount_idx) = parent_node.mount_idx else {
            return Err(EACCES);
        };
        check_name_len(name)?;
        let name_str = name.to_string_lossy();
        let full = join_full(&parent_node.full_path, &name_str);
        let rel = join_rel(&parent_node.rel_path, &name_str);
        Ok((mount_idx, full, rel))
    }

    /// Build the (ino, kind, name) listing for any FUSE directory, used by
    /// both `readdir` and `readdirplus`. Handles two sources of entries:
    /// the virtual root (mount stubs) and real backend-backed directories.
    fn collect_dir_children(
        &self,
        req: &Request<'_>,
        ino: u64,
        node: &Node,
        audit_event: &str,
    ) -> Result<Vec<(u64, FileType, String)>, libc::c_int> {
        let mut entries: Vec<(u64, FileType, String)> = Vec::new();
        // Multi-mount legacy: synthesize a child dir per mount.
        // Single-mount: root has mount_idx=Some(0); fall through to the
        // regular dir_list path below so `/` lists the disk's real children.
        if ino == ROOT_INO && self.mounts.len() != 1 {
            entries.push((ROOT_INO, FileType::Directory, ".".to_string()));
            entries.push((ROOT_INO, FileType::Directory, "..".to_string()));
            let mut state = self.state.lock();
            for idx in 0..self.mounts.len() {
                let name = self.mounts[idx].mount_name.clone();
                let full = format!("/{name}");
                let mount_node = self.intern_node(
                    &mut state,
                    full,
                    Some(idx),
                    String::new(),
                    FileType::Directory,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                );
                entries.push((mount_node.ino, FileType::Directory, name));
            }
            return Ok(entries);
        }

        let Some(mount_idx) = node.mount_idx else {
            return Ok(entries);
        };

        entries.push((node.ino, FileType::Directory, ".".to_string()));
        entries.push((ROOT_INO, FileType::Directory, "..".to_string()));

        let list = self.mounts[mount_idx]
            .store
            .dir_list(&node.rel_path)
            .map_err(|err| backend_errno(&err, EIO))?;
        let mut state = self.state.lock();
        for entry in list {
            let rel = join_rel(&node.rel_path, &entry.name);
            let full = join_full(&node.full_path, &entry.name);
            let allowed = self.policy_allows(mount_idx, &rel);
            self.record(req, audit_event, &full, Some(entry.size), None, allowed);
            if !allowed {
                continue;
            }
            let kind = to_file_type(entry.kind);
            let child = self.intern_node(
                &mut state,
                full,
                Some(mount_idx),
                rel,
                kind,
                entry.size,
                entry.mode,
                entry.uid,
                entry.gid,
                entry.atime as u64,
                entry.rdev,
            );
            entries.push((child.ino, kind, entry.name));
        }
        Ok(entries)
    }
}

impl Filesystem for GatewayFs {
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), libc::c_int> {
        let _ = config.add_capabilities(FUSE_DO_READDIRPLUS);
        Ok(())
    }

    fn opendir(&mut self, req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let node = {
            let state = self.state.lock();
            state.by_ino.get(&ino).cloned()
        };

        let Some(node) = node else {
            reply.error(ENOENT);
            return;
        };
        if node.kind != FileType::Directory {
            reply.error(ENOTDIR);
            return;
        }

        let allowed = node
            .mount_idx
            .map(|idx| self.policy_allows(idx, &node.rel_path))
            .unwrap_or(ino == ROOT_INO);
        self.record(req, event::OPENDIR, &node.full_path, None, None, allowed);
        if !allowed {
            reply.error(EACCES);
            return;
        }

        reply.opened(0, FOPEN_CACHE_DIR | FOPEN_KEEP_CACHE);
    }

    fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if check_name_len(name).is_err() {
            reply.error(ENAMETOOLONG);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(ENOENT);
            return;
        };

        let parent_node = {
            let state = self.state.lock();
            state.by_ino.get(&parent).cloned()
        };

        let Some(parent_node) = parent_node else {
            reply.error(ENOENT);
            return;
        };

        // Multi-mount legacy: root is a virtual dir over mount-name children.
        // Single-mount: root has mount_idx=Some(0); fall through to the regular
        // lookup so any real child of the disk resolves correctly.
        if parent == ROOT_INO && self.mounts.len() != 1 {
            if let Some((idx, mount)) = self
                .mounts
                .iter()
                .enumerate()
                .find(|(_, mount)| mount.mount_name == name)
            {
                let full = format!("/{name}");
                let mut state = self.state.lock();
                let node = self.intern_node(
                    &mut state,
                    full,
                    Some(idx),
                    String::new(),
                    FileType::Directory,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                );
                self.record(
                    req,
                    "lookup",
                    &format!("/{}", mount.mount_name),
                    None,
                    None,
                    true,
                );
                reply.entry(&self.entry_ttl, &self.attr(&node), 0);
                return;
            }
            reply.error(ENOENT);
            return;
        }

        let Some(mount_idx) = parent_node.mount_idx else {
            reply.error(ENOENT);
            return;
        };

        let rel = join_rel(&parent_node.rel_path, name);
        let full = join_full(&parent_node.full_path, name);
        if !self.policy_allows(mount_idx, &rel) {
            self.record(req, event::LOOKUP, &full, None, None, false);
            reply.error(EACCES);
            return;
        }

        if let Some(node) = self.lookup_cached(&full) {
            self.record(req, event::LOOKUP, &full, Some(node.size), None, true);
            reply.entry(&self.entry_ttl, &self.attr(&node), 0);
            return;
        }

        match self.mounts[mount_idx].store.entry_for(&rel) {
            Ok(Some(entry)) => {
                let kind = to_file_type(entry.kind);
                let mut state = self.state.lock();
                let node = self.intern_node(
                    &mut state,
                    full.clone(),
                    Some(mount_idx),
                    rel,
                    kind,
                    entry.size,
                    entry.mode,
                    entry.uid,
                    entry.gid,
                    entry.atime as u64,
                    entry.rdev,
                );
                self.record(req, event::LOOKUP, &full, Some(entry.size), None, true);
                reply.entry(&self.entry_ttl, &self.attr(&node), 0);
            }
            Ok(None) => reply.error(ENOENT),
            Err(err) => reply.error(backend_errno(&err, ENOENT)),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        let state = self.state.lock();
        if let Some(node) = state.by_ino.get(&ino) {
            reply.attr(&self.attr_ttl, &self.attr(node));
        } else {
            reply.error(ENOENT);
        }
    }

    fn readdir(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let node = {
            let state = self.state.lock();
            state.by_ino.get(&ino).cloned()
        };
        let Some(node) = node else {
            reply.error(ENOENT);
            return;
        };
        let entries = match self.collect_dir_children(req, ino, &node, event::READDIR_ENTRY) {
            Ok(e) => e,
            Err(errno) => {
                reply.error(errno);
                return;
            }
        };
        for (idx, (entry_ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize)
        {
            if reply.add(entry_ino, (idx + 1) as i64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let node = {
            let state = self.state.lock();
            state.by_ino.get(&ino).cloned()
        };

        let Some(node) = node else {
            reply.error(ENOENT);
            return;
        };

        let plain = match self.collect_dir_children(req, ino, &node, event::READDIRPLUS_ENTRY) {
            Ok(e) => e,
            Err(errno) => {
                reply.error(errno);
                return;
            }
        };
        let dir_attr = self.attr(&node);
        let entries: Vec<(u64, FileAttr, String)> = {
            let state = self.state.lock();
            plain
                .into_iter()
                .map(|(child_ino, _kind, name)| {
                    let attr = if name == "." || name == ".." {
                        dir_attr
                    } else {
                        state
                            .by_ino
                            .get(&child_ino)
                            .map(|n| self.attr(n))
                            .unwrap_or(dir_attr)
                    };
                    (child_ino, attr, name)
                })
                .collect()
        };
        for (idx, (entry_ino, attr, name)) in entries.into_iter().enumerate().skip(offset as usize)
        {
            if reply.add(entry_ino, (idx + 1) as i64, name, &self.entry_ttl, &attr, 0) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&mut self, req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let write = (flags & libc::O_ACCMODE == libc::O_WRONLY)
            || (flags & libc::O_ACCMODE == libc::O_RDWR);
        let trunc = flags & libc::O_TRUNC != 0;

        let node = {
            let state = self.state.lock();
            state.by_ino.get(&ino).cloned()
        };

        let Some(node) = node else {
            reply.error(ENOENT);
            return;
        };

        let Some(mount_idx) = node.mount_idx else {
            reply.error(EIO);
            return;
        };

        // Fix A: special nodes (FIFO/socket/char/block device) have no manifest
        // and no lease. The kernel drives their open/read/write semantics from
        // the inode type — we must NOT enter the write-lease acquisition below,
        // which blocks waiting on a lease that will never be granted (an O_RDWR
        // open on a fifo would otherwise deadlock). Hand back fh=0 immediately;
        // the kernel takes over from the inode type.
        if matches!(
            node.kind,
            FileType::NamedPipe | FileType::Socket | FileType::CharDevice | FileType::BlockDevice
        ) {
            reply.opened(0, 0);
            return;
        }

        if !write {
            // Read-only path — existing behaviour.
            let allowed = self.policy_allows(mount_idx, &node.rel_path);
            self.record(
                req,
                event::OPEN,
                &node.full_path,
                Some(node.size),
                None,
                allowed,
            );
            if !allowed {
                reply.error(EACCES);
                return;
            }
            reply.opened(0, 0);
            return;
        }

        // Write path.
        if !self.mounts[mount_idx].policy.permits_write(&node.rel_path) {
            self.audit.record(AuditEvent::simple(
                event::OPEN,
                &node.full_path,
                false,
                self.identity_for_req(req),
            ));
            reply.error(EACCES);
            return;
        }

        let lease_handle = match self.acquire_write_lease(req, mount_idx, &node.full_path) {
            Ok(h) => h,
            Err(e) => {
                self.audit.record(AuditEvent::simple(
                    event::OPEN,
                    &node.full_path,
                    false,
                    self.identity_for_req(req),
                ));
                reply.error(backend_errno(&e, EIO));
                return;
            }
        };

        let mut wh = write_handle::WriteHandle::new(
            node.rel_path.clone(),
            0,
            mount_idx,
            req.pid(),
            self.write_buffer_bytes,
            lease_handle.clone(),
        );

        if trunc {
            // POSIX: O_TRUNC on an existing file — zero the manifest immediately.
            let store = &*self.mounts[mount_idx].store;
            match store.manifest_get(&node.rel_path) {
                Ok(cur) => {
                    let now = now_ns();
                    let mode = if cur.mode != 0 { cur.mode } else { 0o644 };
                    match store.manifest_put(
                        &node.rel_path,
                        cur.version,
                        &Manifest {
                            size: 0,
                            mode,
                            mtime_ns: now,
                            version: 0,
                            chunks: vec![],
                        },
                    ) {
                        Ok(new_v) => {
                            wh.base_version = new_v;
                            wh.mode = mode;
                            wh.mtime_ns = now;
                        }
                        Err(e) => {
                            reply.error(backend_errno(&e, EIO));
                            return;
                        }
                    }
                }
                Err(e) => {
                    reply.error(backend_errno(&e, EIO));
                    return;
                }
            }
            wh.loaded = true; // buffer is empty = truncated state
        }

        let fh = self.state.lock().alloc_write_fh(wh);
        self.register_revoke_flush_for_fh(fh, mount_idx, lease_handle.is_some());

        self.audit.record(AuditEvent::simple(
            event::OPEN,
            &node.full_path,
            true,
            self.identity_for_req(req),
        ));
        reply.opened(fh, 0);
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let (mount_idx, full, rel) = match self.resolve_child(parent, name) {
            Ok(t) => t,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        self.assert_write_session(mount_idx);

        if !self.mounts[mount_idx].policy.permits_write(&rel) {
            self.audit.record(
                self.write_audit_event(req, mount_idx, event::CREATE, &full, false)
                    .with_mode(mode),
            );
            reply.error(EACCES);
            return;
        }

        // Acquire a write lease if the mount supports leases.
        let lease_handle = match self.acquire_write_lease(req, mount_idx, &full) {
            Ok(h) => h,
            Err(e) => {
                self.audit.record(
                    self.write_audit_event(req, mount_idx, event::CREATE, &full, false)
                        .with_mode(mode),
                );
                reply.error(backend_errno(&e, EIO));
                return;
            }
        };

        let mtime_ns = now_ns();
        let mf = Manifest {
            size: 0,
            mode,
            mtime_ns,
            version: 0,
            chunks: vec![],
        };
        let store = &*self.mounts[mount_idx].store;
        let new_v = match store.manifest_put(&rel, 0, &mf) {
            Ok(v) => v,
            Err(e) => {
                reply.error(backend_errno(&e, EIO));
                return;
            }
        };

        let mut state = self.state.lock();
        let node = self.intern_node(
            &mut state,
            full.clone(),
            Some(mount_idx),
            rel.clone(),
            FileType::RegularFile,
            0,
            mode,
            0,
            0,
            mtime_ns,
            0,
        );
        let ino = node.ino;
        let mut wh = write_handle::WriteHandle::new(
            rel.clone(),
            mode,
            mount_idx,
            req.pid(),
            self.write_buffer_bytes,
            lease_handle.clone(),
        );
        wh.base_version = new_v;
        wh.mode = mode;
        wh.mtime_ns = mtime_ns;
        wh.loaded = true; // empty buffer = freshly created file
        let fh = state.alloc_write_fh(wh);
        drop(state);

        self.register_revoke_flush_for_fh(fh, mount_idx, lease_handle.is_some());

        self.audit.record(
            self.write_audit_event(req, mount_idx, event::CREATE, &full, true)
                .with_mode(mode),
        );

        let attr = self.file_attr(ino, mode, 0, mtime_ns);
        reply.created(&self.entry_ttl, &attr, 0, fh, 0);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let (node, handle) = {
            let state = self.state.lock();
            let node = state.by_ino.get(&ino).cloned();
            let handle = state.get_write_handle(fh);
            (node, handle)
        };

        let Some(node) = node else {
            reply.error(ENOENT);
            return;
        };
        let Some(handle) = handle else {
            reply.error(libc::EBADF);
            return;
        };
        let Some(mount_idx) = node.mount_idx else {
            reply.error(EIO);
            return;
        };
        self.assert_write_session(mount_idx);

        if !self.mounts[mount_idx].policy.permits_write(&node.rel_path) {
            reply.error(EACCES);
            return;
        }

        let store = &*self.mounts[mount_idx].store;
        let mut wh = handle.lock();
        match wh.write(store, offset as u64, data) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(backend_errno(&e, EIO)),
        }
    }

    fn read(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        // Bind the looked-up handle in its OWN statement so the state-lock guard drops
        // here. An `if let Some(h) = self.state.lock()....{ … }` would hold the guard for
        // the whole block, and the body re-locks self.state (by_ino lookup) — a
        // non-reentrant self-deadlock that hung mmap page-fault reads on O_RDWR files
        // (the read-only open path has no write handle, so it never hit this).
        let wh_handle = self.state.lock().get_write_handle(fh);
        if let Some(handle) = wh_handle {
            // Write-handle path: serve dirty bytes from the buffer so a read after a
            // write on the same FH (incl. SQLite's mmap reads of its O_RDWR DB) sees the
            // unflushed data.
            let node = {
                let state = self.state.lock();
                state.by_ino.get(&ino).cloned()
            };
            let Some(node) = node else {
                reply.error(ENOENT);
                return;
            };
            let Some(mount_idx) = node.mount_idx else {
                reply.error(EIO);
                return;
            };
            let store = &*self.mounts[mount_idx].store;
            let mut wh = handle.lock();
            match wh.read(store, offset as u64, size) {
                Ok(bytes) => reply.data(&bytes),
                Err(e) => reply.error(backend_errno(&e, EIO)),
            }
            return;
        }

        // Read-only path: manifest_get + chunk_get + assemble.
        let node = {
            let state = self.state.lock();
            state.by_ino.get(&ino).cloned()
        };

        let Some(node) = node else {
            reply.error(ENOENT);
            return;
        };
        let Some(mount_idx) = node.mount_idx else {
            reply.error(EIO);
            return;
        };

        if !self.policy_allows(mount_idx, &node.rel_path) {
            self.record(
                req,
                event::READ,
                &node.full_path,
                Some(size as u64),
                Some(offset),
                false,
            );
            reply.error(EACCES);
            return;
        }

        let manifest = match self.mounts[mount_idx].store.manifest_get(&node.rel_path) {
            Ok(mf) => mf,
            Err(err) => {
                reply.error(backend_errno(&err, EIO));
                return;
            }
        };
        let store = &self.mounts[mount_idx].store;
        let out = match assemble::assemble_range(&manifest, offset.max(0) as u64, size, |hashes| {
            store.chunk_get_many(hashes)
        }) {
            Ok(bytes) => bytes,
            Err(err) => {
                reply.error(backend_errno(&err, EIO));
                return;
            }
        };
        self.record(
            req,
            event::READ,
            &node.full_path,
            Some(out.len() as u64),
            Some(offset),
            true,
        );
        reply.data(&out);
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        let handle = match self.state.lock().get_write_handle(fh) {
            Some(h) => h,
            None => {
                reply.ok();
                return;
            } // read-only FH — no-op
        };

        let (path, mount_idx, opener_pid, was_dirty) = {
            let wh = handle.lock();
            (wh.path.clone(), wh.mount_idx, wh.opener_pid, wh.dirty)
        };

        if mount_idx >= self.mounts.len() {
            reply.error(libc::EIO);
            return;
        }
        let store = &*self.mounts[mount_idx].store;

        // Drop the WriteHandle lock at end of statement; refresh_after_flush
        // takes the state lock, and we must not hold state across
        // backend I/O — same reasoning applies in reverse here.
        let flush_res = handle.lock().flush(store);
        match flush_res {
            Ok(stats) => {
                self.audit.record(
                    AuditEvent::simple(
                        event::FLUSH,
                        &path,
                        true,
                        self.identity_for_pid(opener_pid)
                            .with_session(self.session_for(mount_idx)),
                    )
                    .with_flush_stats(&stats),
                );
                if was_dirty {
                    // `stats.bytes` is the file's new size on a dirty flush
                    // (zero on a clean handle, hence the guard).
                    self.refresh_after_flush(ino, stats.bytes);
                }
                reply.ok();
            }
            Err(e) => {
                self.audit.record(AuditEvent::simple(
                    event::FLUSH,
                    &path,
                    false,
                    self.identity_for_pid(opener_pid)
                        .with_session(self.session_for(mount_idx)),
                ));
                reply.error(backend_errno(&e, libc::EIO));
            }
        }
    }

    fn fsync(&mut self, req: &Request<'_>, ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
        self.flush(req, ino, fh, 0, reply);
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // FUSE release ignores reply errors on Linux — log and drop. Apps that need to
        // guarantee flush durability must call fsync(2) before close(2).
        // Bind in its own statement so the state-lock guard drops before the body: the
        // dirty-flush branch calls refresh_after_flush, which re-locks self.state — an
        // `if let … self.state.lock() … { … }` would hold the guard across it and
        // self-deadlock (and hold state across the network flush). Same footgun as read().
        let released = self.state.lock().release_write_fh(fh);
        if let Some(handle) = released {
            let (path, mount_idx, dirty) = {
                let wh = handle.lock();
                (wh.path.clone(), wh.mount_idx, wh.dirty)
            };
            // mount_idx is always valid: it is set at open from a looked-up Node,
            // and the mounts Vec is immutable after init.
            debug_assert!(mount_idx < self.mounts.len());
            if dirty {
                let store = &*self.mounts[mount_idx].store;
                match handle.lock().flush(store) {
                    Ok(stats) => self.refresh_after_flush(ino, stats.bytes),
                    Err(e) => eprintln!("warning: release flush failed for {path}: {e:#}"),
                }
            }
        }
        reply.ok();
    }

    fn unlink(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let (mount_idx, full, rel) = match self.resolve_child(parent, name) {
            Ok(t) => t,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        self.assert_write_session(mount_idx);

        if !self.mounts[mount_idx].policy.permits_write(&rel) {
            self.audit_write(req, mount_idx, event::UNLINK, &full, false);
            reply.error(EACCES);
            return;
        }

        let store = &*self.mounts[mount_idx].store;
        let cur = match store.manifest_get(&rel) {
            Ok(m) if m.version > 0 => m,
            // No manifest (symlink/special node): route a version-0 delete so
            // the server fans out to the symlinks table.
            Ok(_) | Err(_) => {
                match store.manifest_delete(&rel, 0) {
                    Ok(()) => {
                        self.state.lock().evict_node(&full);
                        self.audit_write(req, mount_idx, event::UNLINK, &full, true);
                        reply.ok();
                    }
                    Err(e) => {
                        self.audit_write(req, mount_idx, event::UNLINK, &full, false);
                        reply.error(backend_errno(&e, ENOENT));
                    }
                }
                return;
            }
        };
        if let Err(e) = store.manifest_delete(&rel, cur.version) {
            self.audit_write(req, mount_idx, event::UNLINK, &full, false);
            reply.error(backend_errno(&e, EIO));
            return;
        }
        self.state.lock().evict_node(&full);
        self.audit_write(req, mount_idx, event::UNLINK, &full, true);
        reply.ok();
    }

    fn rmdir(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let (mount_idx, full, rel) = match self.resolve_child(parent, name) {
            Ok(t) => t,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        self.assert_write_session(mount_idx);

        if !self.mounts[mount_idx].policy.permits_write(&rel) {
            self.audit_write(req, mount_idx, event::RMDIR, &full, false);
            reply.error(EACCES);
            return;
        }

        let store = &*self.mounts[mount_idx].store;
        if let Err(e) = store.dir_remove(&rel) {
            self.audit_write(req, mount_idx, event::RMDIR, &full, false);
            reply.error(backend_errno(&e, EIO));
            return;
        }
        self.state.lock().evict_node(&full);
        self.audit_write(req, mount_idx, event::RMDIR, &full, true);
        reply.ok();
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let (mount_idx, full, rel) = match self.resolve_child(parent, name) {
            Ok(t) => t,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        self.assert_write_session(mount_idx);

        if !self.mounts[mount_idx].policy.permits_write(&rel) {
            self.audit.record(
                self.write_audit_event(req, mount_idx, event::MKDIR, &full, false)
                    .with_mode(mode),
            );
            reply.error(EACCES);
            return;
        }

        let store = &*self.mounts[mount_idx].store;
        if let Err(e) = store.dir_create(&rel, mode) {
            reply.error(backend_errno(&e, EIO));
            return;
        }

        let mut state = self.state.lock();
        let node = self.intern_node(
            &mut state,
            full.clone(),
            Some(mount_idx),
            rel,
            FileType::Directory,
            0,
            mode,
            0,
            0,
            0,
            0,
        );
        let ino = node.ino;
        drop(state);

        self.audit.record(
            self.write_audit_event(req, mount_idx, event::MKDIR, &full, true)
                .with_mode(mode),
        );
        let attr = self.dir_attr(ino, mode);
        reply.entry(&self.entry_ttl, &attr, 0);
    }

    fn rename(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let (from_parent_node, to_parent_node) = {
            let state = self.state.lock();
            let from = state.by_ino.get(&parent).cloned();
            let to = state.by_ino.get(&newparent).cloned();
            (from, to)
        };

        let Some(from_parent_node) = from_parent_node else {
            reply.error(ENOENT);
            return;
        };
        let Some(to_parent_node) = to_parent_node else {
            reply.error(ENOENT);
            return;
        };

        let Some(from_mount_idx) = from_parent_node.mount_idx else {
            reply.error(EACCES);
            return;
        };
        let Some(to_mount_idx) = to_parent_node.mount_idx else {
            reply.error(EACCES);
            return;
        };

        if from_mount_idx != to_mount_idx {
            reply.error(libc::EXDEV);
            return;
        }
        self.assert_write_session(from_mount_idx);

        if check_name_len(name).is_err() || check_name_len(newname).is_err() {
            reply.error(ENAMETOOLONG);
            return;
        }

        let name_str = name.to_string_lossy();
        let newname_str = newname.to_string_lossy();
        let from_full = join_full(&from_parent_node.full_path, &name_str);
        let to_full = join_full(&to_parent_node.full_path, &newname_str);
        let from_rel = join_rel(&from_parent_node.rel_path, &name_str);
        let to_rel = join_rel(&to_parent_node.rel_path, &newname_str);

        let mount = &self.mounts[from_mount_idx];
        if !mount.policy.permits_write(&from_rel) || !mount.policy.permits_write(&to_rel) {
            self.audit.record(
                self.write_audit_event(req, from_mount_idx, event::RENAME, &from_full, false)
                    .with_to_path(&to_full),
            );
            reply.error(EACCES);
            return;
        }

        // If we hold a lease on the source path, flush any open WriteHandles and
        // drop the lease before the rename so the new path can acquire cleanly.
        if let Some(lm) = &self.mounts[from_mount_idx].leases {
            if let Some(_handle) = lm.acquire_exclusive_if_present(&from_full) {
                let handles: Vec<_> = {
                    let state = self.state.lock();
                    state
                        .write_handles
                        .values()
                        .filter(|wh| wh.lock().path == from_rel)
                        .cloned()
                        .collect()
                };
                let store = &*self.mounts[from_mount_idx].store;
                for wh_arc in handles {
                    let mut wh = wh_arc.lock();
                    if wh.dirty {
                        let _ = wh.flush_now(store);
                    }
                    wh.lease = None;
                    wh.cached = false;
                }
                // _handle drops here; if refcount hits zero, LeaseHandle::drop
                // sends LEASE_RELEASE to the server.
            }
        }

        let store = &*mount.store;
        // Resolve the source version best-effort: a regular file reports its
        // manifest version (used for CAS); a manifest-less node (symlink,
        // special node, or directory) has no manifest, so `manifest_get`
        // returns ENOENT — that is NOT an error here. We pass expected_from=0
        // and let the SERVER decide whether `from` exists (across all four
        // backing tables) and what POSIX rule applies. Gating on a manifest
        // here was the bug that made symlinks/special-nodes/dirs un-renameable.
        let cur_from = match store.manifest_get(&from_rel) {
            Ok(m) => m.version, // 0 means "absent as a regular file"
            Err(e) if backend_errno(&e, EIO) == ENOENT => 0,
            Err(e) => {
                reply.error(backend_errno(&e, EIO));
                return;
            }
        };
        // Destination version, best-effort: a regular-file dest reports its
        // version (the server CAS-guards it); anything else (absent, symlink,
        // special node, dir) resolves to 0. POSIX overwrite of an existing
        // dest is decided server-side by type-compatibility, not by this CAS.
        let cur_to = match store.manifest_get(&to_rel) {
            Ok(m) => m.version,
            Err(e) if backend_errno(&e, EIO) == ENOENT => 0,
            Err(e) => {
                reply.error(backend_errno(&e, EIO));
                return;
            }
        };

        if let Err(e) = store.manifest_rename(&from_rel, &to_rel, cur_from, cur_to) {
            self.audit.record(
                self.write_audit_event(req, from_mount_idx, event::RENAME, &from_full, false)
                    .with_to_path(&to_full),
            );
            reply.error(backend_errno(&e, EIO));
            return;
        }

        self.state.lock().rename_node(&from_full, &to_full, &to_rel);
        self.audit.record(
            self.write_audit_event(req, from_mount_idx, event::RENAME, &from_full, true)
                .with_to_path(&to_full),
        );
        reply.ok();
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // Resolve the node and mount.
        let node = {
            let state = self.state.lock();
            state.by_ino.get(&ino).cloned()
        };
        let Some(node) = node else {
            reply.error(ENOENT);
            return;
        };
        let Some(mount_idx) = node.mount_idx else {
            reply.error(EACCES);
            return;
        };
        self.assert_write_session(mount_idx);

        let full = node.full_path.clone();
        let rel = node.rel_path.clone();

        if !self.mounts[mount_idx].policy.permits_write(&rel) {
            self.audit.record(
                self.write_audit_event(req, mount_idx, event::SETATTR, &full, false)
                    .with_setattr_fields(0),
            );
            reply.error(EACCES);
            return;
        }

        // Build bitmask of requested fields for audit.
        let mut fields = 0u32;
        if mode.is_some() {
            fields |= 0x01;
        }
        if uid.is_some() {
            fields |= 0x02;
        }
        if gid.is_some() {
            fields |= 0x04;
        }
        if size.is_some() {
            fields |= 0x08;
        }
        if mtime.is_some() {
            fields |= 0x10;
        }
        if atime.is_some() {
            fields |= 0x20;
        }

        let store = &*self.mounts[mount_idx].store;

        // Size change: load file into WriteHandle, truncate, flush.
        if let Some(new_size) = size {
            let existing_handle = fh.and_then(|h| self.state.lock().get_write_handle(h));
            let handle = match existing_handle {
                Some(h) => h,
                None => {
                    let mut wh = write_handle::WriteHandle::new(
                        rel.clone(),
                        0,
                        mount_idx,
                        req.pid(),
                        self.write_buffer_bytes,
                        None,
                    );
                    if let Err(e) = wh.load_if_needed(store) {
                        reply.error(backend_errno(&e, EIO));
                        return;
                    }
                    std::sync::Arc::new(parking_lot::Mutex::new(wh))
                }
            };
            {
                let mut wh = handle.lock();
                if let Err(e) = wh.truncate(store, new_size) {
                    reply.error(backend_errno(&e, EIO));
                    return;
                }
                if let Err(e) = wh.flush(store) {
                    reply.error(backend_errno(&e, EIO));
                    return;
                }
            }
            self.refresh_after_flush(ino, new_size);
        }

        // chmod: works for files, directories, AND symlinks. Routed through
        // setattr_mode (a dedicated wire op) rather than manifest_get/put —
        // directories and symlinks carry no manifest, which is exactly why a
        // directory chmod used to fail with ENOENT.
        if let Some(m) = mode {
            if let Err(e) = store.setattr_mode(&rel, m) {
                reply.error(backend_errno(&e, EIO));
                return;
            }
            // Keep the interned node's mode in sync so getattr reflects the new
            // mode once the kernel's attr cache (attr_ttl) expires.
            self.state.lock().set_node_mode(ino, m);
        }
        // chown: store uid/gid. Works for files, directories, AND symlinks via a
        // dedicated wire op (no manifest needed). No permission enforcement —
        // store-and-readback. Resolve the field left unset from the cached node
        // so a partial chown (e.g. only uid) preserves the other half.
        if uid.is_some() || gid.is_some() {
            let new_uid = uid.unwrap_or(node.uid);
            let new_gid = gid.unwrap_or(node.gid);
            if let Err(e) = store.setattr_owner(&rel, new_uid, new_gid) {
                reply.error(backend_errno(&e, EIO));
                return;
            }
            self.state.lock().set_node_owner(ino, new_uid, new_gid);
        }
        // utimensat (atime): store the access time. Like chown, a dedicated wire
        // op that works for every kind. mtime keeps its own path below.
        if let Some(t) = atime {
            let atime_ns = time_or_now_ns(t);
            if let Err(e) = store.setattr_atime(&rel, atime_ns as i64) {
                reply.error(backend_errno(&e, EIO));
                return;
            }
            self.state.lock().set_node_atime(ino, atime_ns);
        }
        // mtime lives on the manifest, i.e. only regular files carry one.
        if let Some(t) = mtime {
            if node.kind == FileType::RegularFile {
                match store.manifest_get(&rel) {
                    Ok(mut mf) => {
                        mf.mtime_ns = time_or_now_ns(t);
                        let prev_version = mf.version;
                        if let Err(e) = store.manifest_put(&rel, prev_version, &mf) {
                            reply.error(backend_errno(&e, EIO));
                            return;
                        }
                    }
                    Err(e) => {
                        reply.error(backend_errno(&e, EIO));
                        return;
                    }
                }
            }
        }

        // Audit success.
        self.audit.record(
            self.write_audit_event(req, mount_idx, event::SETATTR, &full, true)
                .with_setattr_fields(fields),
        );

        // Reply with post-write attrs, shaped by the node's kind. The per-kind
        // builders hardcode the mount uid/gid and a now()-derived atime, so
        // overlay the stored owner + access time from the freshly-updated node
        // (a chown/utimensat in this same call must read back its new values).
        // Fix B: a special node (FIFO/socket/char/block device) must reply with
        // its special FileType — the `_` arm below builds file_attr, which
        // reports RegularFile and makes the kernel re-cache the fifo as a plain
        // file (a subsequent O_RDWR open then deadlocks because open's special-
        // node fast-path no longer fires). Rebuild the reply from the freshly-
        // updated node (re-fetched by ino) so the type + new mode/uid/gid/atime
        // all ride along. `self.attr` reads them straight off the node.
        if matches!(
            node.kind,
            FileType::NamedPipe | FileType::Socket | FileType::CharDevice | FileType::BlockDevice
        ) {
            let refreshed = self
                .state
                .lock()
                .by_ino
                .get(&ino)
                .cloned()
                .unwrap_or(node.clone());
            let attr = self.attr(&refreshed);
            reply.attr(&self.entry_ttl, &attr);
            return;
        }

        let mut attr = match node.kind {
            FileType::Directory => self.dir_attr(ino, mode.unwrap_or(0)),
            FileType::Symlink => {
                let target_len = store.readlink(&rel).map(|t| t.len() as u64).unwrap_or(0);
                self.symlink_attr(ino, mode.unwrap_or(0o777), target_len)
            }
            _ => {
                let mf = store.manifest_get(&rel).unwrap_or_default();
                self.file_attr(ino, mf.mode, mf.size, mf.mtime_ns)
            }
        };
        if let Some(refreshed) = self.state.lock().by_ino.get(&ino) {
            attr.uid = refreshed.uid;
            attr.gid = refreshed.gid;
            if refreshed.atime_ns != 0 {
                attr.atime = std::time::UNIX_EPOCH + Duration::from_nanos(refreshed.atime_ns);
            }
        }
        reply.attr(&self.entry_ttl, &attr);
    }

    fn symlink(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        let parent_node = {
            let state = self.state.lock();
            state.by_ino.get(&parent).cloned()
        };
        let Some(parent_node) = parent_node else {
            reply.error(ENOENT);
            return;
        };
        let Some(mount_idx) = parent_node.mount_idx else {
            reply.error(EACCES);
            return;
        };
        self.assert_write_session(mount_idx);

        if check_name_len(link_name).is_err() {
            reply.error(ENAMETOOLONG);
            return;
        }
        let name = match link_name.to_str() {
            Some(n) => n,
            None => {
                reply.error(EINVAL);
                return;
            }
        };
        let target_str = match target.to_str() {
            Some(t) => t,
            None => {
                reply.error(EINVAL);
                return;
            }
        };
        let rel = join_rel(&parent_node.rel_path, name);
        let full = join_rel(&parent_node.full_path, name);

        if !self.mounts[mount_idx].policy.permits_write(&rel) {
            self.audit
                .record(self.write_audit_event(req, mount_idx, event::SYMLINK, &full, false));
            reply.error(EACCES);
            return;
        }

        let store = &*self.mounts[mount_idx].store;
        if let Err(e) = store.symlink(&rel, target_str, 0o777) {
            reply.error(backend_errno(&e, EIO));
            return;
        }

        let ino = {
            let mut state = self.state.lock();
            self.intern_node(
                &mut state,
                full.clone(),
                Some(mount_idx),
                rel,
                FileType::Symlink,
                target_str.len() as u64,
                0o777,
                0,
                0,
                0,
                0,
            )
            .ino
        };
        self.audit
            .record(self.write_audit_event(req, mount_idx, event::SYMLINK, &full, true));
        let attr = self.symlink_attr(ino, 0o777, target_str.len() as u64);
        reply.entry(&self.entry_ttl, &attr, 0);
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let node = {
            let state = self.state.lock();
            state.by_ino.get(&ino).cloned()
        };
        let Some(node) = node else {
            reply.error(ENOENT);
            return;
        };
        let Some(mount_idx) = node.mount_idx else {
            reply.error(EACCES);
            return;
        };
        let store = &*self.mounts[mount_idx].store;
        match store.readlink(&node.rel_path) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(e) => reply.error(backend_errno(&e, EINVAL)),
        }
    }

    // mknod(2) with a regular-file (or unset) type: create an empty manifest
    // exactly like `create()`, but reply with a bare entry (mknod does not open
    // the file, so no write FH is allocated). Policy + name-length were already
    // checked by the caller.
    fn mknod(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        let (mount_idx, full, rel) = match self.resolve_child(parent, name) {
            Ok(t) => t,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        self.assert_write_session(mount_idx);

        if check_name_len(name).is_err() {
            reply.error(ENAMETOOLONG);
            return;
        }

        if !self.mounts[mount_idx].policy.permits_write(&rel) {
            self.audit.record(
                self.write_audit_event(req, mount_idx, event::CREATE, &full, false)
                    .with_mode(mode),
            );
            reply.error(EACCES);
            return;
        }

        // Derive the FileType from the POSIX type bits. mknod(2) with a regular-
        // file type (or no type bits) is just a file create — route it through
        // the empty-manifest create path, identical to `create()`, so the node
        // gets a manifest + lease and behaves like any other file.
        let ftype = mode & (libc::S_IFMT as u32);
        let file_type = match ftype {
            v if v == libc::S_IFIFO as u32 => FileType::NamedPipe,
            v if v == libc::S_IFSOCK as u32 => FileType::Socket,
            v if v == libc::S_IFCHR as u32 => FileType::CharDevice,
            v if v == libc::S_IFBLK as u32 => FileType::BlockDevice,
            v if v == libc::S_IFREG as u32 || v == 0 => {
                self.mknod_regular(req, mount_idx, full, rel, mode, reply);
                return;
            }
            _ => {
                reply.error(EINVAL);
                return;
            }
        };

        let perm = mode & 0o7777;
        let store = &*self.mounts[mount_idx].store;
        if let Err(e) = store.mknod(&rel, mode, rdev as u64) {
            self.audit.record(
                self.write_audit_event(req, mount_idx, event::CREATE, &full, false)
                    .with_mode(mode),
            );
            reply.error(backend_errno(&e, EIO));
            return;
        }

        let node = {
            let mut state = self.state.lock();
            self.intern_node(
                &mut state,
                full.clone(),
                Some(mount_idx),
                rel,
                file_type,
                0,
                perm,
                0,
                0,
                0,
                rdev as u64,
            )
        };
        self.audit.record(
            self.write_audit_event(req, mount_idx, event::CREATE, &full, true)
                .with_mode(mode),
        );
        let attr = self.attr(&node);
        reply.entry(&self.entry_ttl, &attr, 0);
    }
}

impl GatewayFs {
    /// mknod(2) with a regular-file type (or no type bits) is just a file
    /// create — route it through the empty-manifest create path, identical to
    /// `create()`, so the node gets a manifest + lease like any other file.
    /// A plain `GatewayFs` method (not a `Filesystem` trait method).
    fn mknod_regular(
        &mut self,
        req: &Request<'_>,
        mount_idx: usize,
        full: String,
        rel: String,
        mode: u32,
        reply: ReplyEntry,
    ) {
        let mtime_ns = now_ns();
        let mf = Manifest {
            size: 0,
            mode,
            mtime_ns,
            version: 0,
            chunks: vec![],
        };
        let store = &*self.mounts[mount_idx].store;
        if let Err(e) = store.manifest_put(&rel, 0, &mf) {
            self.audit.record(
                self.write_audit_event(req, mount_idx, event::CREATE, &full, false)
                    .with_mode(mode),
            );
            reply.error(backend_errno(&e, EIO));
            return;
        }
        let ino = {
            let mut state = self.state.lock();
            self.intern_node(
                &mut state,
                full.clone(),
                Some(mount_idx),
                rel,
                FileType::RegularFile,
                0,
                mode,
                0,
                0,
                mtime_ns,
                0,
            )
            .ino
        };
        self.audit.record(
            self.write_audit_event(req, mount_idx, event::CREATE, &full, true)
                .with_mode(mode),
        );
        let attr = self.file_attr(ino, mode, 0, mtime_ns);
        reply.entry(&self.entry_ttl, &attr, 0);
    }
}

fn to_file_type(kind: EntryKind) -> FileType {
    match kind {
        EntryKind::File => FileType::RegularFile,
        EntryKind::Dir => FileType::Directory,
        EntryKind::Symlink => FileType::Symlink,
        EntryKind::Fifo => FileType::NamedPipe,
        EntryKind::Socket => FileType::Socket,
        EntryKind::CharDev => FileType::CharDevice,
        EntryKind::BlockDev => FileType::BlockDevice,
    }
}

fn join_rel(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", parent.trim_end_matches('/'), name)
    }
}

fn join_full(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{}/{}", parent.trim_end_matches('/'), name)
    }
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn time_or_now_ns(t: TimeOrNow) -> u64 {
    match t {
        TimeOrNow::SpecificTime(st) => st
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
        TimeOrNow::Now => now_ns(),
    }
}

fn read_command_name(pid: u32) -> Option<String> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if comm.is_some() {
        return comm;
    }

    std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|bytes| {
            bytes
                .split(|byte| *byte == 0)
                .find(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
        })
}

#[cfg(test)]
mod fh_tests {
    use super::*;
    use crate::write_handle::WriteHandle;

    fn empty_state() -> State {
        State::new(ROOT_INO + 1, HashMap::new(), HashMap::new())
    }

    #[test]
    fn alloc_and_release_write_fh() {
        let mut state = empty_state();
        let wh = WriteHandle::new("/a".into(), 0, 0, 1, 1024, None);
        let fh = state.alloc_write_fh(wh);
        assert!(state.get_write_handle(fh).is_some());
        state.release_write_fh(fh);
        assert!(state.get_write_handle(fh).is_none());
    }

    #[test]
    fn fh_never_zero() {
        let mut state = empty_state();
        // first FH must be non-zero
        let wh = WriteHandle::new("/a".into(), 0, 0, 1, 1024, None);
        let fh = state.alloc_write_fh(wh);
        assert_ne!(fh, 0);
    }

    #[test]
    fn evict_node_removes_inode_mapping() {
        let mut state = empty_state();
        // manually intern a node so we can test eviction
        let ino = state.next_ino;
        state.next_ino += 1;
        let node = Node {
            ino,
            full_path: "/a/b.txt".to_string(),
            mount_idx: Some(0),
            rel_path: "a/b.txt".to_string(),
            kind: FileType::RegularFile,
            size: 0,
            mode: 0,
        };
        state.by_path.insert("/a/b.txt".to_string(), ino);
        state.by_ino.insert(ino, node);

        state.evict_node("/a/b.txt");

        assert!(state.lookup_path(ino).is_none());
        assert!(state.lookup_path_for("/a/b.txt").is_none());
    }

    #[test]
    fn set_node_size_updates_known_inode() {
        let mut state = empty_state();
        let ino = state.next_ino;
        state.next_ino += 1;
        let node = Node {
            ino,
            full_path: "/probe.txt".to_string(),
            mount_idx: Some(0),
            rel_path: "probe.txt".to_string(),
            kind: FileType::RegularFile,
            size: 0,
            mode: 0,
        };
        state.by_path.insert("/probe.txt".to_string(), ino);
        state.by_ino.insert(ino, node);

        // Simulates the post-flush refresh that issue #135 was missing: a
        // write to a freshly-created file flushes server-side with size=12,
        // but `Node.size` stays at 0 unless we explicitly sync it.
        state.set_node_size(ino, 12);

        assert_eq!(state.by_ino[&ino].size, 12);
    }

    #[test]
    fn set_node_size_noop_for_unknown_inode() {
        let mut state = empty_state();
        // Must not panic when the inode is unknown — releases can race with
        // unlink, and we'd rather drop the update than crash the FS.
        state.set_node_size(9999, 42);
    }

    #[test]
    fn rename_node_preserves_inode() {
        let mut state = empty_state();
        let ino = state.next_ino;
        state.next_ino += 1;
        let node = Node {
            ino,
            full_path: "/a/b.txt".to_string(),
            mount_idx: Some(0),
            rel_path: "a/b.txt".to_string(),
            kind: FileType::RegularFile,
            size: 0,
            mode: 0,
        };
        state.by_path.insert("/a/b.txt".to_string(), ino);
        state.by_ino.insert(ino, node);

        state.rename_node("/a/b.txt", "/a/c.txt", "a/c.txt");

        assert!(state.lookup_path_for("/a/b.txt").is_none());
        assert_eq!(state.lookup_path_for("/a/c.txt"), Some(ino));
        // inode still maps to new path
        assert_eq!(state.lookup_path(ino), Some("/a/c.txt".to_string()));
        // rel_path is rewritten so post-rename ops resolve the moved manifest.
        assert_eq!(
            state.by_ino.get(&ino).map(|n| n.rel_path.clone()),
            Some("a/c.txt".to_string())
        );
    }
}
