//! Client-side metadata mirror (issue #122, docs/design-metadata-mirror.md).
//!
//! A per-mount SQLite mirror of the server's metadata for this cert's agent
//! subtree, hydrated and invalidated by the change feed (CHANGES_FETCH /
//! CHANGES_SUBSCRIBE / CHANGES_EVENT). The server remains the source of
//! truth; the mirror serves lookup / stat / readdir / readlink / manifest
//! reads locally, and only while freshness is PROVEN:
//!
//!   1. a change-feed subscription is live on the current data connection
//!      (checked via `DataClient::conn_generation` — a subscription dies
//!      with its connection),
//!   2. the applied cursor has reached the server's `current_rev`, and
//!   3. the path is inside the server-declared answerable subtree.
//!
//! Anything else falls back to the network path unchanged. Freshness is
//! proven by revisions, never by leases and never by elapsed time: journal
//! revert and agent purge legitimately mutate metadata without holding the
//! mount's leases, and both ring the feed.
//!
//! The mirror file is a pure cache: any validation failure deletes and
//! rehydrates it, and deleting it out from under a stopped mount is always
//! safe. Local mutations are applied to the mirror immediately after the
//! server acknowledges them (so the window between an ack and its doorbell
//! stays coherent); feed entries then reconcile idempotently under their
//! `rev` guard.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::mpsc::unbounded_channel;

use super::client::DataClient;
use super::messages::{
    ChangeEntryWire, ChangesEventPush, ChangesFetchRequest, SYNC_PROTOCOL_V1,
};
use super::protocol::errno;
use crate::backend::{BackendError, Entry, EntryKind};
use crate::store::{ChunkRef, Manifest};

/// Feed page size. Matches the server's clamp ceiling so "page not full"
/// reliably means "drained".
const FETCH_LIMIT: u32 = 1000;

/// How often the sync worker wakes without a doorbell to re-check the
/// subscription (it re-subscribes after a reconnect it would otherwise only
/// discover on the next doorbell-less freshness check).
const RESYNC_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Mirror schema version; bump on any incompatible change (the mirror is
/// fail-closed: mismatch deletes and rehydrates).
const MIRROR_SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "
create table if not exists meta (
  k text primary key,
  v text not null
);
create table if not exists entries (
  path text primary key,
  parent text not null,
  kind text not null,
  rev integer not null,
  size integer not null default 0,
  mode integer not null default 0,
  mtime integer not null default 0,
  uid integer not null default 0,
  gid integer not null default 0,
  atime integer not null default 0,
  inode_id integer not null default 0,
  nlink integer not null default 0,
  version integer not null default 0,
  target text not null default '',
  rdev integer not null default 0,
  chunks blob,
  has_chunks integer not null default 0
);
create index if not exists entries_parent on entries(parent);
";

/// One row of the mirror, in memory. Field meanings match `ChangeEntryWire`.
#[derive(Debug, Clone, Default)]
struct MirrorRow {
    path: String,
    kind: String,
    size: u64,
    mode: u32,
    mtime: i64,
    uid: u32,
    gid: u32,
    atime: i64,
    inode_id: u64,
    nlink: u32,
    version: u64,
    target: String,
    rdev: u64,
    chunks: Option<Vec<u8>>,
    has_chunks: bool,
}

pub struct MetadataMirror {
    client: Arc<DataClient>,
    db: Mutex<Connection>,
    db_path: PathBuf,
    /// Answerable domain, learned from the server on subscribe (empty until
    /// then). Never trusted from local config: negative answers outside the
    /// feed's real coverage would turn EACCES paths into ENOENT lies.
    subtree: Mutex<String>,
    /// True only when subscription + cursor prove the mirror current. Also
    /// requires `sub_generation == client.conn_generation()` at read time.
    fresh: AtomicBool,
    applied_rev: AtomicU64,
    target_rev: AtomicU64,
    /// Connection generation the live subscription was made on;
    /// `u64::MAX` = not subscribed.
    sub_generation: AtomicU64,
    /// Set when the server has no feed (old server / protocol mismatch):
    /// the mirror stays off for the life of the mount.
    disabled: AtomicBool,
    wake_tx: SyncSender<()>,
}

impl MetadataMirror {
    /// Open (or fail-closed recreate) the mirror DB and start the sync
    /// worker. `key` must be stable per (server, mount) pair — it names the
    /// DB file under `<cache_root>/mirror/`.
    pub fn start(client: Arc<DataClient>, cache_root: &Path, key: &str) -> Result<Arc<Self>> {
        let dir = cache_root.join("mirror");
        std::fs::create_dir_all(&dir).context("create mirror dir")?;
        let db_path = dir.join(format!("{}.sqlite", blake3::hash(key.as_bytes()).to_hex()));

        let db = open_validated(&db_path, key)?;
        let applied = read_meta_u64(&db, "cursor_rev").unwrap_or(0);

        // Conflating wake channel: a doorbell that lands while the worker is
        // busy just leaves the single slot full.
        let (wake_tx, wake_rx) = sync_channel::<()>(1);

        let mirror = Arc::new(Self {
            client,
            db: Mutex::new(db),
            db_path,
            subtree: Mutex::new(String::new()),
            fresh: AtomicBool::new(false),
            applied_rev: AtomicU64::new(applied),
            target_rev: AtomicU64::new(applied),
            sub_generation: AtomicU64::new(u64::MAX),
            disabled: AtomicBool::new(false),
            wake_tx,
        });

        mirror.spawn_doorbell_forwarder();
        mirror.spawn_worker(wake_rx);
        // Kick the first sync immediately rather than waiting a tick.
        let _ = mirror.wake_tx.try_send(());
        Ok(mirror)
    }

    /// Route CHANGES_EVENT pushes into `target_rev` + a worker wake. Runs on
    /// the client's runtime, exits when the client (and its push slot) drop.
    fn spawn_doorbell_forwarder(self: &Arc<Self>) {
        let (tx, mut rx) = unbounded_channel();
        self.client.set_changes_push_handler(tx);
        let weak = Arc::downgrade(self);
        self.client.runtime().spawn(async move {
            while let Some(frame) = rx.recv().await {
                let Some(mirror) = weak.upgrade() else { return };
                let Ok(ev) = rmp_serde::from_slice::<ChangesEventPush>(&frame.payload) else {
                    continue;
                };
                mirror.note_target(ev.current_rev);
            }
        });
    }

    fn spawn_worker(self: &Arc<Self>, wake_rx: Receiver<()>) {
        let mirror = Arc::clone(self);
        std::thread::Builder::new()
            .name("orlop-mirror-sync".into())
            .spawn(move || loop {
                match wake_rx.recv_timeout(RESYNC_CHECK_INTERVAL) {
                    Ok(()) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
                if mirror.disabled.load(Ordering::Acquire) {
                    return;
                }
                mirror.sync_once();
            })
            .expect("spawn mirror sync worker");
    }

    /// Record a newer server revision and drop freshness until re-synced.
    fn note_target(&self, rev: u64) {
        self.target_rev.fetch_max(rev, Ordering::AcqRel);
        if self.target_rev.load(Ordering::Acquire) > self.applied_rev.load(Ordering::Acquire) {
            self.fresh.store(false, Ordering::Release);
        }
        match self.wake_tx.try_send(()) {
            Ok(()) | Err(TrySendError::Full(())) => {}
            Err(TrySendError::Disconnected(())) => {}
        }
    }

    /// The freshness invariant, evaluated at read time. All three legs must
    /// hold; a reconnect (generation change) silently kills the subscription
    /// leg without any callback, which is exactly why it is re-checked here
    /// rather than cached in `fresh`.
    pub fn is_fresh(&self) -> bool {
        !self.disabled.load(Ordering::Acquire)
            && self.fresh.load(Ordering::Acquire)
            && self.sub_generation.load(Ordering::Acquire) == self.client.conn_generation()
    }

    /// True when `vpath` is inside the server-declared answerable subtree.
    fn in_domain(&self, vpath: &str) -> bool {
        let subtree = self.subtree.lock();
        !subtree.is_empty()
            && (vpath == subtree.as_str() || vpath.starts_with(&format!("{}/", subtree.as_str())))
    }

    fn can_answer(&self, vpath: &str) -> bool {
        self.is_fresh() && self.in_domain(vpath)
    }

    // ── one sync pass (worker thread) ───────────────────────────────────

    fn sync_once(&self) {
        // Re-subscribe when the subscription's connection is gone (or was
        // never made). Subscribe FIRST, then catch up: doorbells that land
        // mid-catch-up just re-ring.
        let gen_now = self.client.conn_generation();
        if self.sub_generation.load(Ordering::Acquire) != gen_now {
            self.fresh.store(false, Ordering::Release);
            match self.client.changes_subscribe() {
                Ok((resp, sub_gen)) => {
                    if resp.sync_protocol != SYNC_PROTOCOL_V1 {
                        self.disable("server negotiated unknown sync_protocol");
                        return;
                    }
                    self.adopt_subtree(&resp.subtree);
                    self.sub_generation.store(sub_gen, Ordering::Release);
                    self.target_rev.fetch_max(resp.current_rev, Ordering::AcqRel);
                }
                Err(e) => {
                    if crate::backend::backend_errno(&e, errno::EIO) == errno::EINVAL {
                        // Old server: unknown op (or unknown protocol
                        // version). Permanently mirror-less, today's
                        // behavior exactly.
                        self.disable("server has no change feed");
                    }
                    return;
                }
            }
        }

        // Catch up to the target through the compound cursor.
        loop {
            let (cursor_rev, cursor_path) = self.stored_cursor();
            let resp = match self.client.changes_fetch(&ChangesFetchRequest {
                sync_protocol: SYNC_PROTOCOL_V1,
                cursor_rev,
                cursor_path,
                limit: FETCH_LIMIT,
                include_chunks: true,
            }) {
                Ok(resp) => resp,
                Err(e) => {
                    if crate::backend::backend_errno(&e, errno::EIO) == errno::EINVAL {
                        self.disable("server has no change feed");
                    }
                    return;
                }
            };
            if resp.sync_protocol != SYNC_PROTOCOL_V1 {
                self.disable("server negotiated unknown sync_protocol");
                return;
            }
            if resp.resync_required {
                // Cursor predates pruned tombstones: full rebaseline.
                if self.wipe().is_err() {
                    return;
                }
                continue;
            }
            self.adopt_subtree(&resp.subtree);
            self.target_rev.fetch_max(resp.current_rev, Ordering::AcqRel);
            let page_len = resp.entries.len();
            if self
                .apply_page(&resp.entries, resp.next_rev, &resp.next_path)
                .is_err()
            {
                // A mirror write failure means unknown local state: wipe on
                // the next pass rather than serving from it.
                let _ = self.wipe();
                return;
            }
            self.applied_rev.store(resp.next_rev, Ordering::Release);
            if page_len < FETCH_LIMIT as usize {
                break; // drained
            }
        }

        // Caught up — fresh iff the subscription still belongs to the live
        // connection and nothing newer was committed meanwhile.
        let caught_up = self.applied_rev.load(Ordering::Acquire)
            >= self.target_rev.load(Ordering::Acquire);
        let sub_live =
            self.sub_generation.load(Ordering::Acquire) == self.client.conn_generation();
        self.fresh.store(caught_up && sub_live, Ordering::Release);
    }

    fn adopt_subtree(&self, server_subtree: &str) {
        if server_subtree.is_empty() {
            return;
        }
        let mut cur = self.subtree.lock();
        if cur.as_str() == server_subtree {
            return;
        }
        if !cur.is_empty() {
            // The feed's coverage changed identity — everything mirrored so
            // far is for a different domain. Rebaseline.
            drop(cur);
            let _ = self.wipe();
            cur = self.subtree.lock();
        }
        *cur = server_subtree.to_string();
        let db = self.db.lock();
        let _ = write_meta(&db, "subtree", server_subtree);
    }

    fn disable(&self, why: &str) {
        if !self.disabled.swap(true, Ordering::AcqRel) {
            eprintln!("orlop: metadata mirror disabled: {why}");
        }
        self.fresh.store(false, Ordering::Release);
    }

    fn stored_cursor(&self) -> (u64, String) {
        let db = self.db.lock();
        (
            read_meta_u64(&db, "cursor_rev").unwrap_or(0),
            read_meta(&db, "cursor_path").unwrap_or_default(),
        )
    }

    /// Apply one feed page and advance the cursor, atomically. Entries are
    /// final-state and guarded by `rev`, so replays and reorders are no-ops.
    fn apply_page(&self, entries: &[ChangeEntryWire], next_rev: u64, next_path: &str) -> Result<()> {
        let mut db = self.db.lock();
        apply_page_db(&mut db, entries, next_rev, next_path)
    }

    /// Full rebaseline: drop every entry and reset the cursor to (0, "").
    fn wipe(&self) -> Result<()> {
        self.fresh.store(false, Ordering::Release);
        let db = self.db.lock();
        db.execute_batch(
            "delete from entries;
             delete from meta where k in ('cursor_rev', 'cursor_path');",
        )?;
        self.applied_rev.store(0, Ordering::Release);
        Ok(())
    }

    // ── read path (hot; called under the freshness invariant) ───────────

    /// Answer a lookup/stat. Outer `None` = the mirror cannot answer (stale
    /// or out of domain) — fall through to the network. Inner `None` = the
    /// path authoritatively does not exist.
    pub fn entry_for(&self, vpath: &str) -> Option<Option<Entry>> {
        if !self.can_answer(vpath) {
            return None;
        }
        let db = self.db.lock();
        let row = query_row(&db, vpath)?;
        drop(db);
        match row {
            Some(r) => Some(Some(row_to_entry(&r)?)),
            None => Some(None),
        }
    }

    /// Answer a readdir. `None` = cannot answer.
    pub fn dir_list(&self, vpath: &str) -> Option<Vec<Entry>> {
        if !self.can_answer(vpath) {
            return None;
        }
        let db = self.db.lock();
        let mut stmt = db
            .prepare_cached(
                "select path, kind, size, mode, mtime, uid, gid, atime, inode_id,
                        nlink, version, target, rdev, chunks, has_chunks
                 from entries where parent = ?1 order by path",
            )
            .ok()?;
        let rows = stmt
            .query_map(params![vpath], scan_row)
            .ok()?
            .collect::<std::result::Result<Vec<_>, _>>()
            .ok()?;
        drop(stmt);
        drop(db);
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(row_to_entry(&r)?);
        }
        Some(out)
    }

    /// Answer a readlink. Outer `None` = cannot answer; inner = ENOENT vs
    /// target.
    pub fn readlink(&self, vpath: &str) -> Option<Option<String>> {
        if !self.can_answer(vpath) {
            return None;
        }
        let db = self.db.lock();
        let row = query_row(&db, vpath)?;
        match row {
            Some(r) if r.kind == "symlink" => Some(Some(r.target)),
            _ => Some(None),
        }
    }

    /// Answer a manifest read for a regular file with a mirrored chunk list.
    /// Outer `None` = cannot answer; inner `None` = no manifest (ENOENT).
    pub fn manifest_get(&self, vpath: &str) -> Option<Option<Manifest>> {
        if !self.can_answer(vpath) {
            return None;
        }
        let db = self.db.lock();
        let row = query_row(&db, vpath)?;
        match row {
            Some(r) if r.kind == "file" => {
                if !r.has_chunks {
                    return None; // chunk list not mirrored: use the network
                }
                let chunks = unpack_chunks(r.chunks.as_deref().unwrap_or(&[]))?;
                Some(Some(Manifest {
                    size: r.size,
                    mode: r.mode,
                    mtime_ns: r.mtime as u64,
                    version: r.version,
                    chunks,
                }))
            }
            Some(_) => Some(None),
            None => Some(None),
        }
    }

    // ── local apply (after a server-acked mutation) ─────────────────────
    //
    // Keeps the mirror coherent between our own ack and its doorbell. Rows
    // written here keep their previous rev (or 0), so the feed's rev-guarded
    // upsert reconciles them on the next fetch. Errors are swallowed into a
    // freshness drop: a mirror we failed to update must not keep serving.

    pub fn apply_local_put(&self, vpath: &str, mf: &Manifest, new_version: u64) {
        let chunks = pack_store_chunks(&mf.chunks);
        self.apply_local(|tx| {
            tx.execute(
                "insert into entries (path, parent, kind, rev, size, mode, mtime,
                                      nlink, version, chunks, has_chunks)
                 values (?1, ?2, 'file', 0, ?3, ?4, ?5, 1, ?6, ?7, 1)
                 on conflict(path) do update set
                   kind='file', size=excluded.size, mode=excluded.mode,
                   mtime=excluded.mtime, version=excluded.version,
                   chunks=excluded.chunks, has_chunks=1",
                params![
                    vpath,
                    parent_of(vpath),
                    mf.size as i64,
                    mf.mode,
                    mf.mtime_ns as i64,
                    new_version as i64,
                    chunks,
                ],
            )?;
            Ok(())
        });
    }

    pub fn apply_local_delete(&self, vpath: &str) {
        self.apply_local(|tx| {
            tx.execute("delete from entries where path = ?1", params![vpath])?;
            Ok(())
        });
    }

    pub fn apply_local_rename(&self, from: &str, to: &str, new_version: u64) {
        self.apply_local(|tx| local_rename_tx(tx, from, to, new_version));
    }

    pub fn apply_local_dir_create(&self, vpath: &str, mode: u32) {
        self.apply_local(|tx| {
            tx.execute(
                "insert into entries (path, parent, kind, rev, mode, nlink)
                 values (?1, ?2, 'dir', 0, ?3, 1)
                 on conflict(path) do update set kind='dir', mode=excluded.mode",
                params![vpath, parent_of(vpath), if mode == 0 { 0o755 } else { mode & 0o7777 }],
            )?;
            Ok(())
        });
    }

    pub fn apply_local_symlink(&self, vpath: &str, target: &str, mode: u32) {
        self.apply_local(|tx| {
            tx.execute(
                "insert into entries (path, parent, kind, rev, size, mode, target, nlink)
                 values (?1, ?2, 'symlink', 0, ?3, ?4, ?5, 1)
                 on conflict(path) do update set
                   kind='symlink', size=excluded.size, mode=excluded.mode,
                   target=excluded.target",
                params![
                    vpath,
                    parent_of(vpath),
                    target.len() as i64,
                    if mode == 0 { 0o777 } else { mode & 0o7777 },
                    target,
                ],
            )?;
            Ok(())
        });
    }

    pub fn apply_local_mknod(&self, vpath: &str, mode: u32, rdev: u64) {
        let kind = match mode & 0o170000 {
            0o010000 => "fifo",
            0o140000 => "socket",
            0o020000 => "chardev",
            0o060000 => "blockdev",
            _ => "fifo",
        };
        self.apply_local(|tx| {
            tx.execute(
                "insert into entries (path, parent, kind, rev, mode, rdev, nlink)
                 values (?1, ?2, ?3, 0, ?4, ?5, 1)
                 on conflict(path) do update set
                   kind=excluded.kind, mode=excluded.mode, rdev=excluded.rdev",
                params![vpath, parent_of(vpath), kind, mode, rdev as i64],
            )?;
            Ok(())
        });
    }

    pub fn apply_local_link(&self, from: &str, to: &str, nlink: u32) {
        self.apply_local(|tx| local_link_tx(tx, from, to, nlink));
    }

    pub fn apply_local_setattr_mode(&self, vpath: &str, mode: u32) {
        self.apply_local(|tx| {
            tx.execute(
                "update entries set mode = ?2 where path = ?1",
                params![vpath, mode & 0o7777],
            )?;
            Ok(())
        });
    }

    pub fn apply_local_setattr_owner(&self, vpath: &str, uid: u32, gid: u32) {
        self.apply_local(|tx| {
            tx.execute(
                "update entries set uid = ?2, gid = ?3 where path = ?1",
                params![vpath, uid, gid],
            )?;
            Ok(())
        });
    }

    pub fn apply_local_setattr_atime(&self, vpath: &str, atime: i64) {
        self.apply_local(|tx| {
            tx.execute(
                "update entries set atime = ?2 where path = ?1",
                params![vpath, atime],
            )?;
            Ok(())
        });
    }

    fn apply_local(&self, f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<()>) {
        let mut db = self.db.lock();
        let ok = (|| -> Result<()> {
            let tx = db.transaction()?;
            f(&tx)?;
            tx.commit()?;
            Ok(())
        })();
        if ok.is_err() {
            // Unknown local state: stop serving until the feed reconciles.
            drop(db);
            let _ = self.wipe();
            let _ = self.wake_tx.try_send(());
        }
    }
}

// ── DB plumbing ─────────────────────────────────────────────────────────

/// Apply one feed page + cursor advance in one transaction. Free function so
/// tests can drive it against an in-memory database without a `DataClient`.
fn apply_page_db(
    db: &mut Connection,
    entries: &[ChangeEntryWire],
    next_rev: u64,
    next_path: &str,
) -> Result<()> {
    let tx = db.transaction()?;
    for e in entries {
        if e.kind == "tombstone" {
            tx.execute(
                "delete from entries where path = ?1 and rev <= ?2",
                params![e.path, e.rev as i64],
            )?;
            continue;
        }
        let chunks: Option<Vec<u8>> = e.has_chunks.then(|| pack_wire_chunks(&e.chunks));
        tx.execute(
            "insert into entries
               (path, parent, kind, rev, size, mode, mtime, uid, gid, atime,
                inode_id, nlink, version, target, rdev, chunks, has_chunks)
             values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             on conflict(path) do update set
               parent=excluded.parent, kind=excluded.kind, rev=excluded.rev,
               size=excluded.size, mode=excluded.mode, mtime=excluded.mtime,
               uid=excluded.uid, gid=excluded.gid, atime=excluded.atime,
               inode_id=excluded.inode_id, nlink=excluded.nlink,
               version=excluded.version, target=excluded.target,
               rdev=excluded.rdev, chunks=excluded.chunks,
               has_chunks=excluded.has_chunks
             where excluded.rev >= entries.rev",
            params![
                e.path,
                parent_of(&e.path),
                e.kind,
                e.rev as i64,
                e.size as i64,
                e.mode,
                e.mtime,
                e.uid,
                e.gid,
                e.atime,
                e.inode_id as i64,
                e.nlink,
                e.version as i64,
                e.target,
                e.rdev as i64,
                chunks,
                e.has_chunks,
            ],
        )?;
    }
    write_meta_tx(&tx, "cursor_rev", &next_rev.to_string())?;
    write_meta_tx(&tx, "cursor_path", next_path)?;
    tx.commit()?;
    Ok(())
}

/// Local apply for a server-acked rename: displaced dest overwritten, the
/// row (and, for directories, the whole mirrored subtree) moved.
fn local_rename_tx(tx: &rusqlite::Transaction<'_>, from: &str, to: &str, new_version: u64) -> Result<()> {
    tx.execute("delete from entries where path = ?1", params![to])?;
    tx.execute(
        "update entries set path = ?2, parent = ?3, version = ?4 where path = ?1",
        params![from, to, parent_of(to), new_version as i64],
    )?;
    tx.execute(
        "update entries
            set path = ?2 || substr(path, ?3),
                parent = case
                  when parent = ?4 then ?5
                  else ?2 || substr(parent, ?3)
                end
          where path like ?1 || '/%' escape '\\'",
        params![escape_like(from), to, from.len() as i64 + 1, from, to],
    )?;
    Ok(())
}

/// Local apply for a server-acked hard link: copy the source row to the new
/// name and update nlink on every name of the inode.
fn local_link_tx(tx: &rusqlite::Transaction<'_>, from: &str, to: &str, nlink: u32) -> Result<()> {
    tx.execute(
        "insert into entries (path, parent, kind, rev, size, mode, mtime, uid, gid,
                              atime, inode_id, nlink, version, chunks, has_chunks)
         select ?2, ?3, kind, 0, size, mode, mtime, uid, gid,
                atime, inode_id, ?4, version, chunks, has_chunks
           from entries where path = ?1
         on conflict(path) do nothing",
        params![from, to, parent_of(to), nlink],
    )?;
    tx.execute(
        "update entries set nlink = ?2
          where inode_id != 0 and inode_id = (select inode_id from entries where path = ?1)",
        params![from, nlink],
    )?;
    Ok(())
}

/// Open the mirror DB, validating schema version + identity key. Any
/// mismatch or error deletes the file and starts empty (a mirror is a pure
/// cache; the only unsafe failure mode is serving from a file we do not
/// fully understand).
fn open_validated(db_path: &Path, key: &str) -> Result<Connection> {
    match try_open(db_path, key) {
        Ok(db) => Ok(db),
        Err(_) => {
            let _ = std::fs::remove_file(db_path);
            let _ = std::fs::remove_file(db_path.with_extension("sqlite-wal"));
            let _ = std::fs::remove_file(db_path.with_extension("sqlite-shm"));
            try_open(db_path, key)
        }
    }
}

fn try_open(db_path: &Path, key: &str) -> Result<Connection> {
    let db = Connection::open(db_path)
        .with_context(|| format!("open mirror db {}", db_path.display()))?;
    db.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA temp_store = MEMORY;",
    )?;
    db.execute_batch(SCHEMA)?;
    // integrity before identity: a torn file must not pass the key check.
    let ok: String = db.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    anyhow::ensure!(ok == "ok", "mirror integrity check failed: {ok}");
    match read_meta(&db, "schema_version") {
        Some(v) if v == MIRROR_SCHEMA_VERSION.to_string() => {}
        Some(_) => anyhow::bail!("mirror schema version mismatch"),
        None => write_meta(&db, "schema_version", &MIRROR_SCHEMA_VERSION.to_string())?,
    }
    match read_meta(&db, "identity") {
        Some(v) if v == key => {}
        Some(_) => anyhow::bail!("mirror identity mismatch"),
        None => write_meta(&db, "identity", key)?,
    }
    Ok(db)
}

fn read_meta(db: &Connection, k: &str) -> Option<String> {
    db.query_row("select v from meta where k = ?1", params![k], |r| r.get(0))
        .optional()
        .ok()
        .flatten()
}

fn read_meta_u64(db: &Connection, k: &str) -> Option<u64> {
    read_meta(db, k)?.parse().ok()
}

fn write_meta(db: &Connection, k: &str, v: &str) -> Result<()> {
    db.execute(
        "insert into meta(k, v) values(?1, ?2)
         on conflict(k) do update set v = excluded.v",
        params![k, v],
    )?;
    Ok(())
}

fn write_meta_tx(tx: &rusqlite::Transaction<'_>, k: &str, v: &str) -> Result<()> {
    tx.execute(
        "insert into meta(k, v) values(?1, ?2)
         on conflict(k) do update set v = excluded.v",
        params![k, v],
    )?;
    Ok(())
}

/// Outer `None` models a DB error (callers treat it as cannot-answer);
/// inner `Option` is row presence, where absence is an authoritative ENOENT
/// under the freshness invariant.
fn query_row(db: &Connection, vpath: &str) -> Option<Option<MirrorRow>> {
    let mut stmt = db
        .prepare_cached(
            "select path, kind, size, mode, mtime, uid, gid, atime, inode_id,
                    nlink, version, target, rdev, chunks, has_chunks
             from entries where path = ?1",
        )
        .ok()?;
    stmt.query_row(params![vpath], scan_row).optional().ok()
}

fn scan_row(r: &rusqlite::Row<'_>) -> std::result::Result<MirrorRow, rusqlite::Error> {
    Ok(MirrorRow {
        path: r.get(0)?,
        kind: r.get(1)?,
        size: r.get::<_, i64>(2)? as u64,
        mode: r.get(3)?,
        mtime: r.get(4)?,
        uid: r.get(5)?,
        gid: r.get(6)?,
        atime: r.get(7)?,
        inode_id: r.get::<_, i64>(8)? as u64,
        nlink: r.get(9)?,
        version: r.get::<_, i64>(10)? as u64,
        target: r.get(11)?,
        rdev: r.get::<_, i64>(12)? as u64,
        chunks: r.get(13)?,
        has_chunks: r.get(14)?,
    })
}

fn row_to_entry(r: &MirrorRow) -> Option<Entry> {
    let kind = match r.kind.as_str() {
        "file" => EntryKind::File,
        "dir" => EntryKind::Dir,
        "symlink" => EntryKind::Symlink,
        "fifo" => EntryKind::Fifo,
        "socket" => EntryKind::Socket,
        "chardev" => EntryKind::CharDev,
        "blockdev" => EntryKind::BlockDev,
        // Unknown kind (newer server): refuse to answer rather than guess.
        _ => return None,
    };
    Some(Entry {
        name: basename_of(&r.path).to_string(),
        kind,
        size: r.size,
        inode_id: r.inode_id,
        nlink: r.nlink,
        mode: r.mode,
        uid: r.uid,
        gid: r.gid,
        atime: r.atime,
        rdev: r.rdev,
        mtime: r.mtime,
        version: r.version,
    })
}

/// Authoritative-ENOENT error with the same errno shape the network path
/// produces, so FUSE/NFS translation is identical either way.
pub fn mirror_enoent(what: &str) -> anyhow::Error {
    BackendError::new(errno::ENOENT, format!("{what} not found")).into()
}

// ── path + chunk helpers ────────────────────────────────────────────────

fn parent_of(p: &str) -> String {
    match p.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => p[..i].to_string(),
        None => "/".to_string(),
    }
}

fn basename_of(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

const CHUNK_REF_SIZE: usize = 32 + 8 + 4;

fn pack_wire_chunks(chunks: &[super::messages::ChunkRef]) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunks.len() * CHUNK_REF_SIZE);
    for c in chunks {
        let mut hash = [0u8; 32];
        if c.hash.len() == 32 {
            hash.copy_from_slice(&c.hash);
        }
        out.extend_from_slice(&hash);
        out.extend_from_slice(&c.offset.to_be_bytes());
        out.extend_from_slice(&c.len.to_be_bytes());
    }
    out
}

fn pack_store_chunks(chunks: &[ChunkRef]) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunks.len() * CHUNK_REF_SIZE);
    for c in chunks {
        out.extend_from_slice(&c.hash);
        out.extend_from_slice(&c.offset.to_be_bytes());
        out.extend_from_slice(&c.len.to_be_bytes());
    }
    out
}

fn unpack_chunks(blob: &[u8]) -> Option<Vec<ChunkRef>> {
    if !blob.len().is_multiple_of(CHUNK_REF_SIZE) {
        return None;
    }
    let mut out = Vec::with_capacity(blob.len() / CHUNK_REF_SIZE);
    for c in blob.chunks_exact(CHUNK_REF_SIZE) {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&c[..32]);
        out.push(ChunkRef {
            hash,
            offset: u64::from_be_bytes(c[32..40].try_into().ok()?),
            len: u32::from_be_bytes(c[40..44].try_into().ok()?),
        });
    }
    Some(out)
}

/// The mount-level opt-out: `ORLOP_METADATA_MIRROR=0|false|off` disables the
/// mirror; anything else (including unset) leaves it on.
pub fn mirror_enabled_from_env() -> bool {
    match std::env::var("ORLOP_METADATA_MIRROR") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off"
        ),
        Err(_) => true,
    }
}

impl std::fmt::Debug for MetadataMirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetadataMirror")
            .field("db_path", &self.db_path)
            .field("fresh", &self.fresh.load(Ordering::Relaxed))
            .field("applied_rev", &self.applied_rev.load(Ordering::Relaxed))
            .field("target_rev", &self.target_rev.load(Ordering::Relaxed))
            .field("disabled", &self.disabled.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(SCHEMA).unwrap();
        db
    }

    fn file_entry(path: &str, rev: u64, version: u64, size: u64) -> ChangeEntryWire {
        ChangeEntryWire {
            path: path.into(),
            rev,
            kind: "file".into(),
            size,
            mode: 0o644,
            mtime: 1_000,
            nlink: 1,
            version,
            chunks: vec![super::super::messages::ChunkRef {
                hash: vec![0xAB; 32],
                offset: 0,
                len: size as u32,
            }],
            has_chunks: true,
            ..Default::default()
        }
    }

    fn tombstone(path: &str, rev: u64) -> ChangeEntryWire {
        ChangeEntryWire {
            path: path.into(),
            rev,
            kind: "tombstone".into(),
            ..Default::default()
        }
    }

    fn dir_entry(path: &str, rev: u64) -> ChangeEntryWire {
        ChangeEntryWire {
            path: path.into(),
            rev,
            kind: "dir".into(),
            mode: 0o755,
            nlink: 1,
            ..Default::default()
        }
    }

    #[test]
    fn apply_page_upserts_and_advances_cursor() {
        let mut db = mem_db();
        apply_page_db(
            &mut db,
            &[dir_entry("/a", 1), file_entry("/a/f", 2, 1, 4)],
            2,
            "/a/f",
        )
        .unwrap();
        let row = query_row(&db, "/a/f").unwrap().unwrap();
        assert_eq!(row.kind, "file");
        assert_eq!(row.version, 1);
        assert!(row.has_chunks);
        assert_eq!(read_meta_u64(&db, "cursor_rev"), Some(2));
        assert_eq!(read_meta(&db, "cursor_path").as_deref(), Some("/a/f"));
    }

    #[test]
    fn apply_is_rev_guarded_and_idempotent() {
        let mut db = mem_db();
        apply_page_db(&mut db, &[file_entry("/f", 5, 3, 10)], 5, "/f").unwrap();
        // An older (replayed / reordered) entry must not clobber a newer row.
        apply_page_db(&mut db, &[file_entry("/f", 4, 2, 999)], 5, "/f").unwrap();
        let row = query_row(&db, "/f").unwrap().unwrap();
        assert_eq!(row.version, 3);
        assert_eq!(row.size, 10);
        // Same-rev replay is a no-op rewrite of identical state.
        apply_page_db(&mut db, &[file_entry("/f", 5, 3, 10)], 5, "/f").unwrap();
        assert_eq!(query_row(&db, "/f").unwrap().unwrap().version, 3);
    }

    #[test]
    fn tombstone_is_rev_guarded_too() {
        let mut db = mem_db();
        apply_page_db(&mut db, &[file_entry("/f", 7, 2, 1)], 7, "/f").unwrap();
        // A stale tombstone (recreated path, tombstone from before) must not
        // delete the newer live row.
        apply_page_db(&mut db, &[tombstone("/f", 6)], 7, "/f").unwrap();
        assert!(query_row(&db, "/f").unwrap().is_some());
        // A newer tombstone deletes.
        apply_page_db(&mut db, &[tombstone("/f", 8)], 8, "/f").unwrap();
        assert!(query_row(&db, "/f").unwrap().is_none());
    }

    #[test]
    fn dir_list_serves_children_sorted() {
        let mut db = mem_db();
        apply_page_db(
            &mut db,
            &[
                dir_entry("/a", 1),
                file_entry("/a/b", 2, 1, 1),
                file_entry("/a/a", 3, 1, 1),
                dir_entry("/a/c", 4),
                file_entry("/other", 5, 1, 1),
            ],
            5,
            "/other",
        )
        .unwrap();
        let mut stmt = db
            .prepare(
                "select path, kind, size, mode, mtime, uid, gid, atime, inode_id,
                        nlink, version, target, rdev, chunks, has_chunks
                 from entries where parent = '/a' order by path",
            )
            .unwrap();
        let rows: Vec<MirrorRow> = stmt
            .query_map([], scan_row)
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        let names: Vec<&str> = rows.iter().map(|r| basename_of(&r.path)).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn manifest_round_trips_through_packed_chunks() {
        let mut db = mem_db();
        apply_page_db(&mut db, &[file_entry("/f", 1, 4, 44)], 1, "/f").unwrap();
        let row = query_row(&db, "/f").unwrap().unwrap();
        let chunks = unpack_chunks(row.chunks.as_deref().unwrap()).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].hash, [0xAB; 32]);
        assert_eq!(chunks[0].len, 44);
    }

    #[test]
    fn local_rename_moves_subtree() {
        let mut db = mem_db();
        apply_page_db(
            &mut db,
            &[
                dir_entry("/d", 1),
                file_entry("/d/f1", 2, 1, 1),
                dir_entry("/d/sub", 3),
                file_entry("/d/sub/f2", 4, 1, 1),
            ],
            4,
            "/d/sub/f2",
        )
        .unwrap();
        let tx = db.transaction().unwrap();
        local_rename_tx(&tx, "/d", "/e", 1).unwrap();
        tx.commit().unwrap();

        for gone in ["/d", "/d/f1", "/d/sub", "/d/sub/f2"] {
            assert!(query_row(&db, gone).unwrap().is_none(), "{gone} survived");
        }
        for (p, parent) in [("/e", "/"), ("/e/f1", "/e"), ("/e/sub", "/e"), ("/e/sub/f2", "/e/sub")] {
            let row = query_row(&db, p).unwrap().unwrap_or_else(|| panic!("{p} missing"));
            let stored_parent: String = db
                .query_row("select parent from entries where path = ?1", params![p], |r| r.get(0))
                .unwrap();
            assert_eq!(stored_parent, parent, "parent of {p}");
            let _ = row;
        }
    }

    #[test]
    fn local_link_copies_row_and_bumps_nlink() {
        let mut db = mem_db();
        let mut e = file_entry("/f", 1, 2, 8);
        e.inode_id = 42;
        apply_page_db(&mut db, &[e], 1, "/f").unwrap();
        let tx = db.transaction().unwrap();
        local_link_tx(&tx, "/f", "/g", 2).unwrap();
        tx.commit().unwrap();
        let f = query_row(&db, "/f").unwrap().unwrap();
        let g = query_row(&db, "/g").unwrap().unwrap();
        assert_eq!(f.nlink, 2);
        assert_eq!(g.nlink, 2);
        assert_eq!(g.inode_id, 42);
        assert_eq!(g.version, f.version);
    }

    #[test]
    fn open_validated_recreates_on_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.sqlite");
        std::fs::write(&path, b"this is not a sqlite database at all").unwrap();
        let db = open_validated(&path, "key-1").unwrap();
        assert_eq!(read_meta(&db, "identity").as_deref(), Some("key-1"));
        drop(db);
        // Reopening with a different identity is fail-closed: fresh file.
        write_meta(&open_validated(&path, "key-1").unwrap(), "cursor_rev", "9").unwrap();
        let db2 = open_validated(&path, "key-2").unwrap();
        assert_eq!(read_meta(&db2, "identity").as_deref(), Some("key-2"));
        assert_eq!(read_meta(&db2, "cursor_rev"), None);
    }

    #[test]
    fn row_to_entry_maps_kinds_and_refuses_unknown() {
        let r = MirrorRow {
            path: "/a/b".into(),
            kind: "symlink".into(),
            target: "t".into(),
            ..Default::default()
        };
        let e = row_to_entry(&r).unwrap();
        assert_eq!(e.kind, EntryKind::Symlink);
        assert_eq!(e.name, "b");
        let bad = MirrorRow {
            kind: "hologram".into(),
            ..Default::default()
        };
        assert!(row_to_entry(&bad).is_none());
    }

    #[test]
    fn env_flag_parses() {
        assert!(super::mirror_enabled_from_env()); // unset in tests → on
    }
}
