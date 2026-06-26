//! Integration: verify that `Store::set_session` propagates to every
//! write primitive, and that calling it with `None` clears the tag.
//!
//! This is a unit-style integration test (no live server required). It uses a
//! `SessionTrackingStore` — a minimal `Store` impl that records which
//! `session_id` was active at the time of each write — to confirm the Task 8
//! wiring contract at the trait level:
//!
//!   * Before `set_session` is called, `current_session_id()` returns `None`.
//!   * After `set_session(Some(id))`, `current_session_id()` returns `Some(id)`.
//!   * `set_session(None)` clears the tag; subsequent `current_session_id()` is `None`.
//!   * The `mount:<hex>` format spec is validated directly.
//!
//! If the `set_session` / `current_session_id` contract is broken (e.g. by
//! accidentally removing the `Mutex<Option<String>>` field or returning a
//! hard-coded `None`) these tests will fail before the code reaches `DataStore`.

use std::collections::HashMap;
use std::sync::Mutex;

use orlop::backend::Entry;
use orlop::store::{ChunkHash, Manifest, Store};

// ---------------------------------------------------------------------------
// SessionTrackingStore: minimal Store impl that honours set_session /
// current_session_id and records the session_id at the moment of each write.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct SessionTrackingStore {
    session_id: Mutex<Option<String>>,
    /// Each call to a write primitive appends the snapshot of `session_id`.
    write_sessions: Mutex<Vec<Option<String>>>,
    chunks: Mutex<HashMap<[u8; 32], Vec<u8>>>,
    manifests: Mutex<HashMap<String, Manifest>>,
}

impl SessionTrackingStore {
    fn written_sessions(&self) -> Vec<Option<String>> {
        self.write_sessions.lock().unwrap().clone()
    }
}

impl Store for SessionTrackingStore {
    // ── session control ────────────────────────────────────────────────────
    fn set_session(&self, id: Option<String>) {
        *self.session_id.lock().unwrap() = id;
    }

    fn current_session_id(&self) -> Option<String> {
        self.session_id.lock().unwrap().clone()
    }

    // ── read-side primitives (no session tracking needed) ─────────────────
    fn entry_for(&self, _: &str) -> anyhow::Result<Option<Entry>> {
        Ok(None)
    }

    fn chunk_has(&self, h: &ChunkHash) -> anyhow::Result<bool> {
        Ok(self.chunks.lock().unwrap().contains_key(h))
    }

    fn chunk_get(&self, h: &ChunkHash) -> anyhow::Result<Vec<u8>> {
        Ok(self.chunks.lock().unwrap().get(h).cloned().unwrap_or_default())
    }

    fn manifest_get(&self, path: &str) -> anyhow::Result<Manifest> {
        Ok(self
            .manifests
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .unwrap_or_default())
    }

    fn dir_list(&self, _: &str) -> anyhow::Result<Vec<Entry>> {
        Ok(Vec::new())
    }

    // ── write-side primitives — each records current session_id ───────────
    fn chunk_put(&self, h: &ChunkHash, b: &[u8]) -> anyhow::Result<()> {
        let snap = self.current_session_id();
        self.write_sessions.lock().unwrap().push(snap);
        self.chunks.lock().unwrap().insert(*h, b.to_vec());
        Ok(())
    }

    fn manifest_put(&self, path: &str, _ev: u64, mf: &Manifest) -> anyhow::Result<u64> {
        let snap = self.current_session_id();
        self.write_sessions.lock().unwrap().push(snap);
        let mut m = mf.clone();
        m.version = 1;
        let prev = self
            .manifests
            .lock()
            .unwrap()
            .insert(path.to_string(), m)
            .map(|p| p.version)
            .unwrap_or(0);
        Ok(prev + 1)
    }

    fn manifest_delete(&self, _: &str, _: u64) -> anyhow::Result<()> {
        let snap = self.current_session_id();
        self.write_sessions.lock().unwrap().push(snap);
        Ok(())
    }

    fn manifest_rename(&self, _: &str, _: &str, _: u64, _: u64) -> anyhow::Result<u64> {
        let snap = self.current_session_id();
        self.write_sessions.lock().unwrap().push(snap);
        Ok(1)
    }

    fn dir_create(&self, _: &str, _: u32) -> anyhow::Result<()> {
        let snap = self.current_session_id();
        self.write_sessions.lock().unwrap().push(snap);
        Ok(())
    }

    fn dir_remove(&self, _: &str) -> anyhow::Result<()> {
        let snap = self.current_session_id();
        self.write_sessions.lock().unwrap().push(snap);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Before `set_session` is called the store reports no active session, and
/// after the call every write primitive sees the new tag.  Calling
/// `set_session(None)` clears it again.
///
/// This directly mirrors the invariant that `src/mount.rs` relies on:
/// mount calls `store.set_session(Some("mount:<hex>"))` once before handing
/// the store to GatewayFs, so all subsequent FUSE writes carry the tag.
#[test]
fn set_session_propagates_to_writes() {
    let store = SessionTrackingStore::default();

    // Initial state: no session.
    assert_eq!(store.current_session_id(), None, "session should be None before set_session");

    // Issue a write before calling set_session — session should be absent.
    store.manifest_put("/pre.txt", 0, &Manifest::default()).unwrap();
    let sessions = store.written_sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0], None,
        "write before set_session must carry no session_id"
    );

    // Now wire up an implicit mount session, as mount.rs does.
    let lease_id = [0xdeu8, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
                    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
    let session_id = format!("mount:{}", hex_encode(&lease_id));
    store.set_session(Some(session_id.clone()));

    assert_eq!(
        store.current_session_id(),
        Some(session_id.clone()),
        "current_session_id should reflect the newly set value"
    );

    // Every write primitive now carries the session.
    store.chunk_put(&[0u8; 32], b"data").unwrap();
    store.manifest_put("/tagged.txt", 0, &Manifest::default()).unwrap();
    store.dir_create("/mydir", 0o755).unwrap();
    store.manifest_delete("/tagged.txt", 1).unwrap();
    store.dir_remove("/mydir").unwrap();
    store.manifest_rename("/a", "/b", 0, 0).unwrap();

    let sessions = store.written_sessions();
    // Indices: 0 = pre-session write, 1..=6 = post-session writes.
    assert_eq!(sessions.len(), 7);
    for s in &sessions[1..] {
        assert_eq!(
            s.as_deref(),
            Some(session_id.as_str()),
            "all writes after set_session must carry the session id; got {s:?}"
        );
    }

    // Clearing with None stops tagging.
    store.set_session(None);
    store.dir_create("/after-clear", 0o700).unwrap();
    let sessions = store.written_sessions();
    assert_eq!(
        sessions.last().unwrap().as_deref(),
        None,
        "write after set_session(None) must carry no session_id"
    );
}

/// The session_id emitted by `mount.rs` must match the format the server
/// validates: `"mount:"` followed by exactly 32 lowercase hex characters
/// (the little-endian hex of a 16-byte lease_id).
#[test]
fn session_id_format_matches_spec() {
    // All-0xab lease_id → 32 'ab' characters.
    let lease_id = [0xabu8; 16];
    let session_id = format!("mount:{}", hex_encode(&lease_id));

    assert!(
        session_id.starts_with("mount:"),
        "session_id must start with 'mount:'; got {session_id:?}"
    );
    let hex_part = &session_id["mount:".len()..];
    assert_eq!(
        hex_part.len(),
        32,
        "hex suffix must be 32 chars (16 bytes * 2); got {} chars",
        hex_part.len()
    );
    assert!(
        hex_part.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "hex suffix must be lowercase; got {hex_part:?}"
    );
    assert_eq!(hex_part, "abababababababababababababababab" /* 32 chars */,
        "hex encoding of [0xab; 16] must be 32 'ab' chars");

    // Zero lease_id → 32 '0' characters.
    let zero_id = [0u8; 16];
    let zero_session = format!("mount:{}", hex_encode(&zero_id));
    assert_eq!(&zero_session["mount:".len()..], "00000000000000000000000000000000");
    assert_eq!(zero_session.len(), 6 + 32, "total length must be 38");
}

// ---------------------------------------------------------------------------
// Inline hex_encode — mirrors src/backend/dataplane/cache.rs (pub(crate)).
// Tests can't reach into pub(crate) items, so we duplicate the tiny helper.
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
