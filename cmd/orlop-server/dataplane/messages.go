package dataplane

// Field naming matches the Rust serde-named structs in
// src/backend/dataplane/messages.rs. msgpack uses field names because
// rmp-serde::to_vec_named is what the Rust client emits, and that
// guarantees layout doesn't shift when fields are added.

type ListRequest struct {
	Path string `msgpack:"path"`
}

type EntryWire struct {
	Name string `msgpack:"name"`
	Kind string `msgpack:"kind"` // "file", "dir", or "symlink"
	Size uint64 `msgpack:"size"`
	// InodeID is stable for every directory entry that names the same regular
	// file. Nlink is the current number of such names. Zero/omitted keeps
	// compatibility with pre-hard-link clients.
	InodeID uint64 `msgpack:"inode_id,omitempty"`
	Nlink   uint32 `msgpack:"nlink,omitempty"`
	// Mode is the POSIX permission bits. Append-only msgpack field — old
	// clients/servers omit it and fall back to kind-based defaults.
	Mode uint32 `msgpack:"mode,omitempty"`
	// Uid/Gid/Atime are POSIX ownership + access-time metadata. Append-only
	// msgpack fields — old clients/servers omit them and fall back to the
	// mount's uid/gid (0) and now() respectively.
	Uid   uint32 `msgpack:"uid,omitempty"`
	Gid   uint32 `msgpack:"gid,omitempty"`
	Atime int64  `msgpack:"atime,omitempty"`
	// Target is the link destination, set only when Kind == "symlink".
	Target string `msgpack:"target,omitempty"`
	// Rdev is the device number, set only for block/char device special nodes.
	// Append-only msgpack field — old clients/servers omit it (defaults to 0).
	Rdev uint64 `msgpack:"rdev,omitempty"`
	// Mtime is the modification time in the manifest's own units (the client
	// writes unix nanoseconds), and Version the manifest CAS version; both are
	// populated for regular files. Append-only msgpack fields (issue #122):
	// they let stat/readdir answer without a per-file MANIFEST_GET round trip,
	// and give a metadata mirror a freshness token to store per entry. Old
	// clients/servers omit them and keep today's manifest-fetch fallback.
	Mtime   int64  `msgpack:"mtime,omitempty"`
	Version uint64 `msgpack:"version,omitempty"`
}

type ListResponse struct {
	Entries []EntryWire `msgpack:"entries"`
}

type StatRequest struct {
	Path string `msgpack:"path"`
}

type StatResponse struct {
	Entry EntryWire `msgpack:"entry"`
}

type ErrorPayload struct {
	Errno   int32  `msgpack:"errno"`
	Message string `msgpack:"message"`
	// Recovery is an optional structured retry hint (issue #103). The
	// `omitempty` tag keeps the wire byte-identical to legacy responses
	// when no hint is attached.
	Recovery *RecoveryHint `msgpack:"recovery,omitempty"`
}

// WithRecovery attaches a `RecoveryHint`. Returns the value (not a pointer)
// so call sites can chain `dataplane.ErrESTALE(msg).WithRecovery(hint)`.
func (e ErrorPayload) WithRecovery(h *RecoveryHint) ErrorPayload {
	e.Recovery = h
	return e
}

// RecoveryHint mirrors the Rust `RecoveryHint` in
// src/backend/dataplane/messages.rs. Optional fields use pointers so they
// serialize as msgpack-nil only when explicitly set (rather than as zero
// values that would mislead the client).
type RecoveryHint struct {
	Kind            string      `msgpack:"kind"`
	YourVersion     *uint64     `msgpack:"your_version,omitempty"`
	CurrentVersion  *uint64     `msgpack:"current_version,omitempty"`
	LastWriter      *LastWriter `msgpack:"last_writer,omitempty"`
	SuggestedAction string      `msgpack:"suggested_action"`
}

// LastWriter mirrors the Rust struct. `AgentID`/`SessionID` are set when the
// journal names the writer that landed the conflicting version (see the
// server's buildCasConflictHint) and stay nil otherwise.
type LastWriter struct {
	AgentID   *string `msgpack:"agent_id,omitempty"`
	SessionID *string `msgpack:"session_id,omitempty"`
	AtUnixMs  int64   `msgpack:"at_unix_ms"`
}

// RecoveryKindCasConflict is the only `RecoveryHint.Kind` the server emits.
// Mirrors the Rust wire protocol (the `RecoveryKind` enum's `as_wire_str`
// mapping).
const RecoveryKindCasConflict = "cas_conflict"

func ErrEIO(msg string) ErrorPayload       { return ErrorPayload{Errno: ErrnoEIO, Message: msg} }
func ErrEACCES(msg string) ErrorPayload    { return ErrorPayload{Errno: ErrnoEACCES, Message: msg} }
func ErrENOENT(msg string) ErrorPayload    { return ErrorPayload{Errno: ErrnoENOENT, Message: msg} }
func ErrEINVAL(msg string) ErrorPayload    { return ErrorPayload{Errno: ErrnoEINVAL, Message: msg} }
func ErrESTALE(msg string) ErrorPayload    { return ErrorPayload{Errno: ErrnoESTALE, Message: msg} }
func ErrEEXIST(msg string) ErrorPayload    { return ErrorPayload{Errno: ErrnoEEXIST, Message: msg} }
func ErrENOTEMPTY(msg string) ErrorPayload { return ErrorPayload{Errno: ErrnoENOTEMPTY, Message: msg} }
func ErrENOTDIR(msg string) ErrorPayload   { return ErrorPayload{Errno: ErrnoENOTDIR, Message: msg} }
func ErrEISDIR(msg string) ErrorPayload    { return ErrorPayload{Errno: ErrnoEISDIR, Message: msg} }

// ---- Layer 3: chunks + manifests --------------------------------------

// ChunkRef is one entry in a manifest's chunk list.
type ChunkRef struct {
	Hash   []byte `msgpack:"hash"` // BLAKE3, 32 bytes
	Offset uint64 `msgpack:"offset"`
	Len    uint32 `msgpack:"len"`
}

type ManifestGetRequest struct {
	Path string `msgpack:"path"`
}

type ManifestGetResponse struct {
	Version uint64     `msgpack:"version"`
	Size    uint64     `msgpack:"size"`
	Mode    uint32     `msgpack:"mode"`
	Mtime   int64      `msgpack:"mtime"`
	Chunks  []ChunkRef `msgpack:"chunks"`
}

type ManifestPutRequest struct {
	Path            string     `msgpack:"path"`
	VersionExpected uint64     `msgpack:"version_expected"`
	Size            uint64     `msgpack:"size"`
	Mode            uint32     `msgpack:"mode"`
	Mtime           int64      `msgpack:"mtime"`
	Chunks          []ChunkRef `msgpack:"chunks"`
	// SessionID tags the write with the client's active session.
	// Append-only msgpack field — old clients omit it, old servers ignore it.
	SessionID *string `msgpack:"session_id,omitempty"`
	// AllocationID is the allocation that owns this write's session.
	// Append-only msgpack field — old clients omit it, old servers ignore it.
	AllocationID *string `msgpack:"allocation_id,omitempty"`
}

type ManifestPutResponse struct {
	Version uint64 `msgpack:"version"`
}

type ChunkGetRequest struct {
	Hash []byte `msgpack:"hash"`
}

type ChunkGetResponse struct {
	Bytes []byte `msgpack:"bytes"`
}

// ChunkHasRequest packs N×32 hashes into a single byte slice. Flat layout
// keeps the wire small when manifests have many chunks.
type ChunkHasRequest struct {
	Hashes []byte `msgpack:"hashes"`
}

type ChunkHasResponse struct {
	Present []byte `msgpack:"present"` // bitmap parallel to the request hash list
}

type ChunkPutRequest struct {
	Hash      []byte  `msgpack:"hash"`
	Bytes     []byte  `msgpack:"bytes"`
	SessionID *string `msgpack:"session_id,omitempty"`
}

type ChunkPutResponse struct {
	Stored bool `msgpack:"stored"`
}

// ---- Layer 4: write surface ------------------------------------------

type ManifestDeleteRequest struct {
	Path            string  `msgpack:"path"`
	ExpectedVersion uint64  `msgpack:"expected_version"`
	SessionID       *string `msgpack:"session_id,omitempty"`
	AllocationID    *string `msgpack:"allocation_id,omitempty"`
}

type ManifestDeleteResponse struct{}

type ManifestRenameRequest struct {
	From                string  `msgpack:"from"`
	To                  string  `msgpack:"to"`
	ExpectedVersionFrom uint64  `msgpack:"expected_version_from"`
	ExpectedVersionTo   uint64  `msgpack:"expected_version_to"`  // 0 = no dest CAS (overwrite if present); >0 = replace only if the dest is at that version
	NoReplace           bool    `msgpack:"no_replace,omitempty"` // true = create-only: fail with EEXIST if the dest exists (RENAME_NOREPLACE), never overwrite
	SessionID           *string `msgpack:"session_id,omitempty"`
	AllocationID        *string `msgpack:"allocation_id,omitempty"`
}

type ManifestRenameResponse struct {
	NewVersionAtTo uint64 `msgpack:"new_version_at_to"`
}

type LinkRequest struct {
	From         string  `msgpack:"from"`
	To           string  `msgpack:"to"`
	SessionID    *string `msgpack:"session_id,omitempty"`
	AllocationID *string `msgpack:"allocation_id,omitempty"`
}

type LinkResponse struct {
	Nlink uint32 `msgpack:"nlink"`
}

type DirCreateRequest struct {
	Path      string  `msgpack:"path"`
	Mode      uint32  `msgpack:"mode"`
	SessionID *string `msgpack:"session_id,omitempty"`
}

type DirCreateResponse struct{}

type DirRemoveRequest struct {
	Path      string  `msgpack:"path"`
	SessionID *string `msgpack:"session_id,omitempty"`
}

type DirRemoveResponse struct{}

// SetattrRequest changes the permission bits / ownership / access time of a
// file, directory, or symlink. Mode (chmod) is always carried; UID/GID (chown)
// and Atime (utimensat) are pointers so "not set" is distinguishable from a
// real zero value (chown to uid 0 is a valid operation). SessionID/AllocationID
// tag the journaled write for files.
type SetattrRequest struct {
	Path         string  `msgpack:"path"`
	Mode         uint32  `msgpack:"mode"`
	UID          *uint32 `msgpack:"uid,omitempty"`
	GID          *uint32 `msgpack:"gid,omitempty"`
	Atime        *int64  `msgpack:"atime,omitempty"`
	SessionID    *string `msgpack:"session_id,omitempty"`
	AllocationID *string `msgpack:"allocation_id,omitempty"`
}

type SetattrResponse struct{}

// SymlinkRequest creates a symbolic link at Path pointing at Target.
type SymlinkRequest struct {
	Path         string  `msgpack:"path"`
	Target       string  `msgpack:"target"`
	Mode         uint32  `msgpack:"mode"`
	SessionID    *string `msgpack:"session_id,omitempty"`
	AllocationID *string `msgpack:"allocation_id,omitempty"`
}

type SymlinkResponse struct{}

// MknodRequest creates a POSIX special node (FIFO, socket, block/char device)
// at Path. Mode carries the S_IF* type bits | permission bits; Rdev is the
// device number (0 for fifo/socket).
type MknodRequest struct {
	Path         string  `msgpack:"path"`
	Mode         uint32  `msgpack:"mode"`
	Rdev         uint64  `msgpack:"rdev"`
	SessionID    *string `msgpack:"session_id,omitempty"`
	AllocationID *string `msgpack:"allocation_id,omitempty"`
}

type MknodResponse struct{}

type ReadlinkRequest struct {
	Path string `msgpack:"path"`
}

type ReadlinkResponse struct {
	Target string `msgpack:"target"`
}

// ---- Layer 5: leases --------------------------------------------------

type LeaseMode uint8

const (
	LeaseSharedRead     LeaseMode = 1
	LeaseExclusiveWrite LeaseMode = 2
)

type LeaseGrantRequest struct {
	Path string    `msgpack:"path"`
	Mode LeaseMode `msgpack:"mode"`
}

type LeaseGrantResponse struct {
	LeaseID         []byte    `msgpack:"lease_id"` // 16 bytes
	ExpiresAtUnixMs int64     `msgpack:"expires_at_unix_ms"`
	ModeGranted     LeaseMode `msgpack:"mode_granted"`
}

type LeaseRefreshRequest struct {
	LeaseID []byte `msgpack:"lease_id"`
}

type LeaseRefreshResponse struct {
	ExpiresAtUnixMs int64 `msgpack:"expires_at_unix_ms"`
}

type LeaseReleaseRequest struct {
	LeaseID      []byte `msgpack:"lease_id"`
	DirtyFlushed bool   `msgpack:"dirty_flushed"`
}

type LeaseReleaseResponse struct{}

// LeaseRevokeRequest is server-pushed; payload only, no response frame.
type LeaseRevokeRequest struct {
	LeaseID []byte `msgpack:"lease_id"`
	Reason  string `msgpack:"reason"`
}

// ---- Layer 7: agent-native journal (issue #104) -----------------------

// JournalQueryRequest asks for journal rows filtered by allocation.
// AllocationID may be empty to return rows across all of the caller's
// allocations (the merged-feed case). Limit is capped at 200 by the server;
// 0 means "use 50". Cursor is an opaque keyset pagination token: pass "" for
// the first page and the NextCursor from the prior reply for the next.
type JournalQueryRequest struct {
	AllocationID string `msgpack:"allocation_id"`
	Limit        uint32 `msgpack:"limit"`
	Cursor       string `msgpack:"cursor,omitempty"`
}

// JournalEntry is one row from session_journal enriched with size metadata.
// Op is one of the wire-stable string constants below.
type JournalEntry struct {
	SessionID     string  `msgpack:"session_id"`
	AllocationID  string  `msgpack:"allocation_id"`
	Seq           uint64  `msgpack:"seq"`
	TsUnixMs      int64   `msgpack:"ts_unix_ms"`
	Path          string  `msgpack:"path"`
	Op            string  `msgpack:"op"`
	AgentID       string  `msgpack:"agent_id"`
	BeforeVersion *uint64 `msgpack:"before_version,omitempty"`
	AfterVersion  *uint64 `msgpack:"after_version,omitempty"`
	RenameFrom    string  `msgpack:"rename_from,omitempty"`
	SizeBefore    *uint64 `msgpack:"size_before,omitempty"`
	SizeAfter     *uint64 `msgpack:"size_after,omitempty"`
}

// JournalQueryResponse is the server's reply to JournalQueryRequest.
// NextCursor is the opaque pagination cursor: pass it as Cursor in the next
// request to fetch the next page. "" means there are no more rows.
type JournalQueryResponse struct {
	Entries    []JournalEntry `msgpack:"entries"`
	NextCursor string         `msgpack:"next_cursor,omitempty"`
}

// Wire-string constants for JournalEntry.Op. Keep in sync with the server's
// SessionOp* constants in journal.go and the Rust SessionOp enum.
const (
	SessionOpWireCreate = "create"
	SessionOpWireUpdate = "update"
	SessionOpWireDelete = "delete"
	SessionOpWireRename = "rename"
)

// JournalRevertPathRequest asks the server to replay journal entries for the
// given paths in reverse, restoring each path's before-state under CAS.
// AllocationID is required. Paths must be canonical absolute paths recorded
// in the journal; an empty Paths list is rejected (use explicit paths only).
//
// Force=true bypasses the concurrent-writer CAS check: the inverse write
// proceeds against whatever live version exists, and the resulting journal
// row records the divergence honestly per spec §10.1. Defaults to false;
// older clients omit the field entirely (msgpack omitempty).
type JournalRevertPathRequest struct {
	AllocationID string   `msgpack:"allocation_id"`
	Paths        []string `msgpack:"paths"` // each must be a canonical absolute path in journal
	Force        bool     `msgpack:"force,omitempty"`
}

type JournalRevertPathResponse struct {
	RevertedPaths []string         `msgpack:"reverted_paths"`
	Conflicts     []RevertConflict `msgpack:"conflicts,omitempty"`
}

// RevertConflict describes one path that could not be reverted. Reason is a
// machine-readable token: "concurrent_writer", "no_journal_row", etc.
type RevertConflict struct {
	Path   string `msgpack:"path"`
	Reason string `msgpack:"reason"`
}

// ---- Layer 8: metadata change feed (issue #122) -----------------------

// SyncProtocolV1 is the only change-feed protocol version this build speaks.
// Every CHANGES_FETCH / CHANGES_SUBSCRIBE request carries the version the
// client wants and the response echoes the version the server will speak;
// any other value is EINVAL. Negotiation is deliberately explicit (an
// issue #122 acceptance gate): an old client must never silently interpret
// a newer sync stream, and a new client learns "no feed" from the unknown-op
// EINVAL an old server returns.
const SyncProtocolV1 uint32 = 1

// ChangesFetchRequest pages through the coalesced change feed. The compound
// (CursorRev, CursorPath) cursor is a resume point, not a snapshot: entries
// are delivered ordered by (rev, path), strictly greater than the cursor,
// and a path mutated mid-hydration simply reappears later at its new
// revision. A fresh mirror starts from (0, "").
type ChangesFetchRequest struct {
	SyncProtocol uint32 `msgpack:"sync_protocol"`
	CursorRev    uint64 `msgpack:"cursor_rev"`
	CursorPath   string `msgpack:"cursor_path"`
	// Limit caps the page size; the server clamps it to [1, 1000], 0 means 500.
	Limit uint32 `msgpack:"limit"`
	// IncludeChunks asks for each file entry's manifest chunk list, so a
	// mirror can serve manifest reads locally too.
	IncludeChunks bool `msgpack:"include_chunks,omitempty"`
}

// ChangeEntryWire is one coalesced final-state entry: the current state of
// one path, or its tombstone, stamped with the revision of the last mutation
// that touched it. There is no rename opcode and no operation history —
// final-state entries are idempotent to apply and indifferent to receiver
// history.
type ChangeEntryWire struct {
	Path    string     `msgpack:"path"`
	Rev     uint64     `msgpack:"rev"`
	Kind    string     `msgpack:"kind"` // file|dir|symlink|fifo|socket|chardev|blockdev|tombstone
	Size    uint64     `msgpack:"size,omitempty"`
	Mode    uint32     `msgpack:"mode,omitempty"`
	Mtime   int64      `msgpack:"mtime,omitempty"`
	Uid     uint32     `msgpack:"uid,omitempty"`
	Gid     uint32     `msgpack:"gid,omitempty"`
	Atime   int64      `msgpack:"atime,omitempty"`
	InodeID uint64     `msgpack:"inode_id,omitempty"`
	Nlink   uint32     `msgpack:"nlink,omitempty"`
	Version uint64     `msgpack:"version,omitempty"`
	Target  string     `msgpack:"target,omitempty"`
	Rdev    uint64     `msgpack:"rdev,omitempty"`
	Chunks  []ChunkRef `msgpack:"chunks,omitempty"`
	// HasChunks distinguishes "chunk list included and empty" (a zero-length
	// file) from "chunk list not requested" — msgpack omitempty erases the
	// empty list itself.
	HasChunks bool `msgpack:"has_chunks,omitempty"`
}

// ChangesFetchResponse carries one feed page. NextRev/NextPath is the cursor
// for the next call; CurrentRev is the tenant's latest committed revision at
// serve time — when the client's applied cursor reaches it, the mirror is
// caught up. ResyncRequired means the cursor predates pruned tombstones: the
// client must discard its mirror and restart from (0, "").
type ChangesFetchResponse struct {
	SyncProtocol   uint32            `msgpack:"sync_protocol"`
	Entries        []ChangeEntryWire `msgpack:"entries"`
	NextRev        uint64            `msgpack:"next_rev"`
	NextPath       string            `msgpack:"next_path"`
	CurrentRev     uint64            `msgpack:"current_rev"`
	ResyncRequired bool              `msgpack:"resync_required,omitempty"`
}

// ChangesSubscribeRequest registers this connection for CHANGES_EVENT pushes.
type ChangesSubscribeRequest struct {
	SyncProtocol uint32 `msgpack:"sync_protocol"`
}

type ChangesSubscribeResponse struct {
	SyncProtocol uint32 `msgpack:"sync_protocol"`
	CurrentRev   uint64 `msgpack:"current_rev"`
}

// ChangesEventPush is server-pushed after a metadata mutation commits: a
// conflated doorbell carrying only the latest committed revision. The client
// compares it against its applied cursor and pulls the delta with
// CHANGES_FETCH; the event itself never carries entries, so bursts coalesce
// and a slow consumer can never be dropped for buffering reasons. The
// subscription dies with the connection.
type ChangesEventPush struct {
	CurrentRev uint64 `msgpack:"current_rev"`
}

func ErrEBUSY(msg string) ErrorPayload { return ErrorPayload{Errno: ErrnoEBUSY, Message: msg} }

// ErrnoLeaseUnknown is a custom errno returned for stale or unknown lease ids.
// It maps to EINVAL on the client (close enough; the lease is gone, the op is
// no longer meaningful). Defined as a distinct constant to keep audit logs
// disambiguated.
const ErrnoLeaseUnknown int32 = 100

func ErrLeaseUnknown(msg string) ErrorPayload {
	return ErrorPayload{Errno: ErrnoLeaseUnknown, Message: msg}
}
