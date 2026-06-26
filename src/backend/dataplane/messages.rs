//! msgpack request/response payload types for the data plane.
//!
//! Field ordering and naming MUST be kept in sync with
//! `cmd/orlop-server/dataplane/messages.go`. We use `serde_bytes` for
//! large byte payloads (READ_RESP) so they encode to msgpack `bin` with no
//! extra wrapping.

use serde::{Deserialize, Serialize};

use super::protocol::errno;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRequest {
    pub path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryWire {
    pub name: String,
    /// "file" or "dir".
    pub kind: String,
    pub size: u64,
    /// POSIX permission + type bits. msgpack-named append-only field — an old
    /// server omits it, in which case `attr()` falls back to a kind default.
    /// 0 means "unset" (server didn't send it).
    #[serde(default)]
    pub mode: u32,
    /// POSIX owner uid. msgpack-named append-only field — an old server omits
    /// it; 0 (root) is the correct fallback on a single-identity mount.
    #[serde(default)]
    pub uid: u32,
    /// POSIX owner gid. Same append-only/default semantics as `uid`.
    #[serde(default)]
    pub gid: u32,
    /// Access time, unix nanoseconds. msgpack-named append-only field — an old
    /// server omits it, in which case `attr()` falls back to mtime/now.
    #[serde(default)]
    pub atime: i64,
    /// Link destination, set only when `kind == "symlink"`.
    #[serde(default)]
    pub target: String,
    /// Device number, set only when `kind` is a block/char device. msgpack-named
    /// append-only field — an old server omits it (defaults to 0).
    #[serde(default)]
    pub rdev: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub entries: Vec<EntryWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatRequest {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatResponse {
    pub entry: EntryWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingRequest {
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResponse {
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub errno: i32,
    pub message: String,
    /// Optional structured retry hint. Always omitted from the wire when
    /// `None` so older clients (that don't know the field) decode unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryHint>,
}

impl ErrorPayload {
    pub fn new(errno: i32, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
            recovery: None,
        }
    }

    pub fn eio(message: impl Into<String>) -> Self {
        Self::new(errno::EIO, message)
    }

    pub fn enoent(message: impl Into<String>) -> Self {
        Self::new(errno::ENOENT, message)
    }

    pub fn estale(message: impl Into<String>) -> Self {
        Self::new(errno::ESTALE, message)
    }

    pub fn with_recovery(mut self, hint: RecoveryHint) -> Self {
        self.recovery = Some(hint);
        self
    }
}

/// Structured retry hint attached to an `ErrorPayload`. Lets agent clients
/// self-correct in one round-trip instead of replaying `manifest_get`-then-
/// retry, and gives the audit log + `orlop audit tail` a human-readable
/// `suggested_action` to surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryHint {
    pub kind: RecoveryKind,
    /// Version the client tried to CAS against (for CAS conflicts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub your_version: Option<u64>,
    /// Server's current version. Lets the client skip the re-read RTT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_writer: Option<LastWriter>,
    pub suggested_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastWriter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Populated once Pillar 2 (#102) lands; always `None` for now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub at_unix_ms: i64,
}

/// Categorises a `RecoveryHint`. New variants may appear server-side at any
/// time; older clients see them as `Other(<wire string>)` and surface the
/// `suggested_action` verbatim — they never fail to decode an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryKind {
    CasConflict,
    NotFound,
    LockHeld,
    /// A `session_revert` could not undo `path` because the live manifest's
    /// version no longer matches what the session journaled before its own
    /// write. `current_version` carries the live version so the agent can
    /// inspect or reconcile.
    RevertConflict,
    Other(String),
}

impl RecoveryKind {
    pub fn as_wire_str(&self) -> &str {
        match self {
            Self::CasConflict => "cas_conflict",
            Self::NotFound => "not_found",
            Self::LockHeld => "lock_held",
            Self::RevertConflict => "revert_conflict",
            Self::Other(s) => s.as_str(),
        }
    }
}

impl Serialize for RecoveryKind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_wire_str())
    }
}

impl<'de> Deserialize<'de> for RecoveryKind {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(match s.as_str() {
            "cas_conflict" => Self::CasConflict,
            "not_found" => Self::NotFound,
            "lock_held" => Self::LockHeld,
            "revert_conflict" => Self::RevertConflict,
            _ => Self::Other(s),
        })
    }
}

// ---- Layer 3: chunks + manifests --------------------------------------

/// One entry in a manifest's chunk list. `hash` is BLAKE3 (32 raw bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    pub offset: u64,
    pub len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestGetRequest {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestGetResponse {
    pub version: u64,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub chunks: Vec<ChunkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPutRequest {
    pub path: String,
    /// 0 → new file (fail if a manifest already exists).
    pub version_expected: u64,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub chunks: Vec<ChunkRef>,
    /// Active session id. msgpack-named encoding makes this an append-only
    /// optional field — old servers ignore it, old clients omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Allocation that owns this write's session. Required by the server when
    /// `session_id` is set (the journal row's denormalised allocation_id
    /// column is what the dashboard's per-allocation feed joins on).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPutResponse {
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkGetRequest {
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkGetResponse {
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkHasRequest {
    /// One concatenated buffer of N×32 bytes — flat layout keeps the wire
    /// small for manifests with many chunks.
    #[serde(with = "serde_bytes")]
    pub hashes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkHasResponse {
    /// Bitmap parallel to the request's hash list. Bit i set → server has
    /// the i-th hash.
    #[serde(with = "serde_bytes")]
    pub present: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPutRequest {
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPutResponse {
    /// True on success; CHUNK_PUT is idempotent (already-present is also true).
    pub stored: bool,
}

// ---- Layer 4: write surface -------------------------------------------

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestDeleteRequest {
    pub path: String,
    pub expected_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestDeleteResponse {}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestRenameRequest {
    pub from: String,
    pub to: String,
    pub expected_version_from: u64,
    pub expected_version_to: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestRenameResponse {
    pub new_version_at_to: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirCreateRequest {
    pub path: String,
    pub mode: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirCreateResponse {}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirRemoveRequest {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirRemoveResponse {}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetattrRequest {
    pub path: String,
    pub mode: u32,
    /// chown owner uid; `None` leaves it unchanged. Pointer/option so chown to
    /// uid 0 (a real operation) is distinguishable from "not set".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// chown owner gid; `None` leaves it unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// utimensat access time (unix ns); `None` leaves it unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetattrResponse {}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymlinkRequest {
    pub path: String,
    pub target: String,
    pub mode: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymlinkResponse {}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MknodRequest {
    pub path: String,
    /// POSIX mode: type bits (S_IFIFO/S_IFSOCK/S_IFBLK/S_IFCHR) | permission bits.
    pub mode: u32,
    /// Device number for block/char special files; 0 for fifos and sockets.
    pub rdev: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MknodResponse {}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadlinkRequest {
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadlinkResponse {
    pub target: String,
}

// ---- Layer 5: leases ---------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LeaseMode {
    SharedRead = 1,
    ExclusiveWrite = 2,
}

// LeaseMode goes over the wire as a uint8 to match Go's
// `type LeaseMode uint8` in cmd/orlop-server/dataplane/messages.go. The
// derived Serialize would emit the variant name as a string ("ExclusiveWrite"),
// which the Go server decodes as `malformed lease_grant payload`.
impl Serialize for LeaseMode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for LeaseMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match u8::deserialize(d)? {
            1 => Ok(Self::SharedRead),
            2 => Ok(Self::ExclusiveWrite),
            n => Err(serde::de::Error::custom(format!("invalid LeaseMode: {n}"))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseGrantRequest {
    pub path: String,
    pub mode: LeaseMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseGrantResponse {
    #[serde(with = "serde_bytes")]
    pub lease_id: Vec<u8>,
    pub expires_at_unix_ms: i64,
    pub mode_granted: LeaseMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRefreshRequest {
    #[serde(with = "serde_bytes")]
    pub lease_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRefreshResponse {
    pub expires_at_unix_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseReleaseRequest {
    #[serde(with = "serde_bytes")]
    pub lease_id: Vec<u8>,
    pub dirty_flushed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LeaseReleaseResponse {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRevokeRequest {
    #[serde(with = "serde_bytes")]
    pub lease_id: Vec<u8>,
    pub reason: String,
}

// ---- Layer 7: journal RPCs -----------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalQueryRequest {
    pub allocation_id: String,
    #[serde(default)]
    pub limit: u32,
    #[serde(default)]
    pub before_ts_ms: i64,
}

/// One row from the server's per-allocation write journal.
///
/// `before_version` is `None` for `Create`. `after_version` is `None` when
/// the manifest has since been deleted (or, for `Delete` rows, always — the
/// row that recorded the delete *is* the after-state). `rename_from` is
/// empty for non-Rename rows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalEntry {
    pub session_id: String,
    pub allocation_id: String,
    pub seq: u64,
    pub ts_unix_ms: i64,
    pub path: String,
    pub op: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_version: Option<u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rename_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_before: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_after: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct JournalQueryResponse {
    pub entries: Vec<JournalEntry>,
    #[serde(default)]
    pub next_before_ts_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalRevertPathRequest {
    pub allocation_id: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct JournalRevertPathResponse {
    #[serde(default)]
    pub reverted_paths: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<RevertConflict>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevertConflict {
    pub path: String,
    pub reason: String,
}

impl ErrorPayload {
    pub fn ebusy(message: impl Into<String>) -> Self {
        Self::new(super::protocol::errno::EBUSY, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_response_round_trips_via_msgpack() {
        let r = ListResponse {
            entries: vec![
                EntryWire {
                    name: "a".into(),
                    kind: "file".into(),
                    size: 7,
                    ..Default::default()
                },
                EntryWire {
                    name: "b".into(),
                    kind: "dir".into(),
                    size: 0,
                    ..Default::default()
                },
            ],
        };
        let bytes = rmp_serde::to_vec_named(&r).unwrap();
        let parsed: ListResponse = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed.entries[0].name, "a");
        assert_eq!(parsed.entries[1].kind, "dir");
    }

    #[test]
    fn error_payload_carries_errno() {
        let e = ErrorPayload::enoent("missing.md");
        let bytes = rmp_serde::to_vec_named(&e).unwrap();
        let parsed: ErrorPayload = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed.errno, errno::ENOENT);
        assert_eq!(parsed.message, "missing.md");
        assert!(parsed.recovery.is_none());
    }

    #[test]
    fn error_payload_round_trips_with_recovery_hint() {
        let hint = RecoveryHint {
            kind: RecoveryKind::CasConflict,
            your_version: Some(5),
            current_version: Some(7),
            last_writer: Some(LastWriter {
                agent_id: Some("agent_a".into()),
                session_id: None,
                at_unix_ms: 1_700_000_000_123,
            }),
            suggested_action:
                "re-read manifest at version 7, re-apply your edit, re-put with expected=7".into(),
        };
        let e = ErrorPayload::estale("CAS conflict on /x").with_recovery(hint.clone());
        let bytes = rmp_serde::to_vec_named(&e).unwrap();
        let parsed: ErrorPayload = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed.errno, errno::ESTALE);
        let got = parsed.recovery.expect("recovery must round-trip");
        assert_eq!(got.kind, RecoveryKind::CasConflict);
        assert_eq!(got.your_version, Some(5));
        assert_eq!(got.current_version, Some(7));
        let writer = got.last_writer.expect("last_writer round-trips");
        assert_eq!(writer.agent_id.as_deref(), Some("agent_a"));
        assert_eq!(writer.at_unix_ms, 1_700_000_000_123);
        assert!(got.suggested_action.contains("expected=7"));
    }

    #[test]
    fn legacy_error_payload_without_recovery_field_still_decodes() {
        // Simulates an older server that doesn't know about RecoveryHint:
        // the wire frame is just {errno, message} with no `recovery` key.
        // New clients must accept this and treat recovery as None.
        #[derive(Serialize)]
        struct OldErrorPayload {
            errno: i32,
            message: String,
        }
        let old = OldErrorPayload {
            errno: errno::ENOENT,
            message: "missing".into(),
        };
        let bytes = rmp_serde::to_vec_named(&old).unwrap();
        let parsed: ErrorPayload = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed.errno, errno::ENOENT);
        assert!(parsed.recovery.is_none());
    }

    #[test]
    fn recovery_kind_unknown_decodes_to_other_variant() {
        // A future server may add new RecoveryKind variants. Old clients must
        // not blow up — they should see `Other(<string>)` and surface the
        // suggested_action verbatim.
        let raw = serde_json::json!({
            "errno": 116,
            "message": "future error",
            "recovery": {
                "kind": "future_kind_we_dont_know_yet",
                "suggested_action": "wait and retry"
            }
        });
        // Convert through msgpack to mirror the wire path.
        let bytes = rmp_serde::to_vec_named(&raw).unwrap();
        let parsed: ErrorPayload = rmp_serde::from_slice(&bytes).unwrap();
        let recovery = parsed.recovery.expect("recovery present");
        match recovery.kind {
            RecoveryKind::Other(ref s) => assert_eq!(s, "future_kind_we_dont_know_yet"),
            other => panic!("expected Other variant, got {other:?}"),
        }
        assert_eq!(recovery.suggested_action, "wait and retry");
    }

    #[test]
    fn manifest_delete_round_trip() {
        let req = ManifestDeleteRequest {
            path: "/a".into(),
            expected_version: 7,
            session_id: None,
            allocation_id: None,
        };
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        let got: ManifestDeleteRequest = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(req, got);
    }

    #[test]
    fn manifest_rename_round_trip() {
        let req = ManifestRenameRequest {
            from: "/a".into(),
            to: "/b".into(),
            expected_version_from: 1,
            expected_version_to: 0,
            session_id: None,
            allocation_id: None,
        };
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        let got: ManifestRenameRequest = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(req, got);
    }

    #[test]
    fn dir_create_round_trip() {
        let req = DirCreateRequest {
            path: "/d".into(),
            mode: 0o755,
            session_id: None,
        };
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        let got: DirCreateRequest = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(req, got);
    }

    #[test]
    fn dir_remove_round_trip() {
        let req = DirRemoveRequest {
            path: "/d".into(),
            session_id: None,
        };
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        let got: DirRemoveRequest = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(req, got);
    }

    #[test]
    fn manifest_put_session_id_round_trips() {
        let req = ManifestPutRequest {
            path: "/x".into(),
            version_expected: 0,
            size: 0,
            mode: 0o644,
            mtime: 0,
            chunks: vec![],
            session_id: Some("s_test".into()),
            allocation_id: Some("alloc_test".into()),
        };
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        // Cheap on-wire smoke check: the field name is present as a literal
        // msgpack str — guards against accidentally renaming the serde tag.
        assert!(
            bytes
                .windows(b"session_id".len())
                .any(|w| w == b"session_id"),
            "session_id key must appear on the wire"
        );
        let parsed: ManifestPutRequest = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed.session_id.as_deref(), Some("s_test"));
    }

    /// New server must decode an old client's payload that lacks the
    /// `session_id` field — the wire field is `#[serde(default)]` so it
    /// resolves to `None`.
    #[test]
    fn manifest_put_decodes_old_payload_without_session_id() {
        // Construct an "old" payload by encoding a sibling struct that has
        // every field except session_id. Using a serde_json::Value-like
        // approach via rmp_serde::to_vec_named on a serde-tagged literal.
        #[derive(serde::Serialize)]
        struct LegacyManifestPut {
            path: String,
            version_expected: u64,
            size: u64,
            mode: u32,
            mtime: i64,
            chunks: Vec<ChunkRef>,
        }
        let legacy = LegacyManifestPut {
            path: "/x".into(),
            version_expected: 0,
            size: 0,
            mode: 0o644,
            mtime: 0,
            chunks: vec![],
        };
        let bytes = rmp_serde::to_vec_named(&legacy).unwrap();
        let parsed: ManifestPutRequest = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed.path, "/x");
        assert!(parsed.session_id.is_none());
    }

    /// Old server (a decoder built without `session_id`) must accept a new
    /// client's payload — modelled by a struct that ignores extra msgpack
    /// fields.
    #[test]
    fn old_decoder_ignores_unknown_session_id_field() {
        let req = ManifestPutRequest {
            path: "/x".into(),
            version_expected: 0,
            size: 0,
            mode: 0o644,
            mtime: 0,
            chunks: vec![],
            session_id: Some("s_test".into()),
            allocation_id: None,
        };
        let bytes = rmp_serde::to_vec_named(&req).unwrap();

        #[derive(serde::Deserialize)]
        struct LegacyManifestPut {
            path: String,
            #[allow(dead_code)]
            version_expected: u64,
            #[allow(dead_code)]
            size: u64,
            #[allow(dead_code)]
            mode: u32,
            #[allow(dead_code)]
            mtime: i64,
            #[allow(dead_code)]
            chunks: Vec<ChunkRef>,
        }
        let parsed: LegacyManifestPut = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed.path, "/x");
    }

    #[test]
    fn lease_grant_round_trip() {
        let req = LeaseGrantRequest {
            path: "/a.txt".into(),
            mode: LeaseMode::ExclusiveWrite,
        };
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        // Mode must encode as a single uint8 (0x02) so the Go server's
        // `type LeaseMode uint8` decodes it. A string encoding would tail-end
        // with `ae 45 78 63 6c ...` ("ExclusiveWrite") instead of `02`.
        assert_eq!(*bytes.last().unwrap(), 2u8);
        let got: LeaseGrantRequest = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(got.path, "/a.txt");
        assert!(matches!(got.mode, LeaseMode::ExclusiveWrite));

        let resp = LeaseGrantResponse {
            lease_id: vec![7u8; 16],
            expires_at_unix_ms: 1_700_000_000_000,
            mode_granted: LeaseMode::ExclusiveWrite,
        };
        let encoded = rmp_serde::to_vec_named(&resp).unwrap();
        // lease_id should be a msgpack bin (0xc4..0xc6)
        assert!(encoded.iter().any(|b| (0xc4..=0xc6).contains(b)));
        let parsed: LeaseGrantResponse = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(parsed.lease_id.len(), 16);
    }

    #[test]
    fn recovery_kind_revert_conflict_round_trip() {
        // RevertConflict serializes as the wire string "revert_conflict".
        let bytes = rmp_serde::to_vec_named(&RecoveryKind::RevertConflict).unwrap();
        let parsed: RecoveryKind = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed, RecoveryKind::RevertConflict);
        assert_eq!(
            RecoveryKind::RevertConflict.as_wire_str(),
            "revert_conflict"
        );
    }
}
