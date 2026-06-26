//! In-process smoke test for the macOS NFSv3 adapter (`OrlopNfs`).
//!
//! Drives the adapter end-to-end through its public `NFSFileSystem` trait
//! against an in-memory `Store`. No kernel mount, no `mount_nfs`, no socket —
//! the same code path the kernel NFS client will hit on macOS, exercised here
//! on whatever platform `cargo test` is running.
//!
//! Issue #149 / tracker #143.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use nfsserve::nfs::{filename3, nfsstat3, sattr3};
use nfsserve::vfs::NFSFileSystem;
use parking_lot::Mutex;

use orlop::audit::AuditLog;
use orlop::backend::{Entry, EntryKind};
use orlop::nfs::OrlopNfs;
use orlop::policy::Policy;
use orlop::store::{ChunkHash, ChunkRef, Manifest, Store};

#[derive(Default)]
struct InMemStore {
    entries: Mutex<HashMap<String, Entry>>,
    manifests: Mutex<HashMap<String, Manifest>>,
    chunks: Mutex<HashMap<ChunkHash, Vec<u8>>>,
    dirs: Mutex<HashMap<String, Vec<String>>>,
}

impl InMemStore {
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
            chunks: vec![ChunkRef {
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

impl Store for InMemStore {
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
            anyhow::bail!("CAS mismatch on {path}: have {current}, want {expected_version}");
        }
        let mut new_mf = mf.clone();
        new_mf.version = current + 1;
        manifests.insert(path.to_string(), new_mf.clone());
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
            anyhow::bail!("manifest_delete on absent {path}");
        }
        if current != expected_version {
            anyhow::bail!("CAS mismatch on delete {path}");
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
    fn manifest_rename(&self, _: &str, _: &str, _: u64, _: u64) -> anyhow::Result<u64> {
        anyhow::bail!("rename not exercised in this smoke")
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
    fn dir_create(&self, _: &str, _: u32) -> anyhow::Result<()> {
        Ok(())
    }
    fn dir_remove(&self, _: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

fn fname(s: &str) -> filename3 {
    s.as_bytes().to_vec().into()
}

fn read_all_audit(path: &PathBuf) -> Vec<serde_json::Value> {
    let body = std::fs::read_to_string(path).unwrap_or_default();
    body.lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test]
async fn nfs_adapter_round_trip_lookup_read_write_unlink() {
    let store = Arc::new(InMemStore::default());
    store.add_file("", "hello.txt", b"hi");

    let policy = Policy::new(&[], &[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditLog::new(audit_path.clone()).unwrap());

    let nfs = OrlopNfs::new(store.clone(), policy, audit.clone());

    // (1) lookup
    let id = nfs
        .lookup(nfs.root_dir(), &fname("hello.txt"))
        .await
        .expect("lookup hello.txt");
    assert!(id > nfs.root_dir());

    // (2) read original bytes
    let (bytes, eof) = nfs.read(id, 0, 4096).await.expect("read");
    assert_eq!(bytes, b"hi");
    assert!(eof);

    // (3) overwrite with "bye" then read back
    let attr = nfs.write(id, 0, b"bye").await.expect("write");
    assert_eq!(attr.size, 3);
    let (bytes, eof) = nfs.read(id, 0, 4096).await.expect("read after write");
    assert_eq!(bytes, b"bye");
    assert!(eof);

    // (4) unlink → store entry vanishes
    nfs.remove(nfs.root_dir(), &fname("hello.txt"))
        .await
        .expect("remove");
    assert!(store.entry_for("hello.txt").unwrap().is_none());
    assert_eq!(store.manifest_get("hello.txt").unwrap().version, 0);

    // (5) lookup-after-unlink → NOENT
    let res = nfs.lookup(nfs.root_dir(), &fname("hello.txt")).await;
    assert!(matches!(res, Err(nfsstat3::NFS3ERR_NOENT)));

    // (6) audit log: one event per op, no agent_pid on any (macOS-emitted shape)
    audit.flush().unwrap();
    let events = read_all_audit(&audit_path);

    let kinds: Vec<&str> = events
        .iter()
        .map(|e| e["event"].as_str().unwrap_or(""))
        .collect();
    for required in ["lookup", "read", "flush", "unlink"] {
        assert!(
            kinds.contains(&required),
            "audit must include {required}; got {kinds:?}"
        );
    }

    for e in &events {
        assert!(
            e.get("agent_pid").is_none(),
            "macOS-emitted audit must omit agent_pid; offender: {e}"
        );
    }
}

#[tokio::test]
async fn nfs_adapter_create_then_write_persists_and_reads_back() {
    // Mirrors the kernel-side smoke test:
    //   touch + write + read + remove  via the adapter only.
    let store = Arc::new(InMemStore::default());
    let policy = Policy::new(&[], &[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditLog::new(audit_path.clone()).unwrap());
    let nfs = OrlopNfs::new(store.clone(), policy, audit.clone());

    let (id, attr) = nfs
        .create(nfs.root_dir(), &fname("test.txt"), sattr3::default())
        .await
        .expect("create");
    assert_eq!(attr.size, 0);

    nfs.write(id, 0, b"content\n").await.expect("write");
    let (bytes, _eof) = nfs.read(id, 0, 4096).await.expect("read");
    assert_eq!(bytes, b"content\n");

    nfs.remove(nfs.root_dir(), &fname("test.txt"))
        .await
        .expect("remove");
    assert!(store.entry_for("test.txt").unwrap().is_none());

    audit.flush().unwrap();
    let events = read_all_audit(&audit_path);
    for e in &events {
        assert!(
            e.get("agent_pid").is_none(),
            "macOS-emitted audit must omit agent_pid; offender: {e}"
        );
    }
}
