package main

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"strings"
)

// Manifest is the per-path record describing how a file maps to chunks.
type Manifest struct {
	Path    string
	InodeID uint64
	Nlink   uint32
	Size    uint64
	Mode    uint32
	Mtime   int64
	Version uint64
	Chunks  []ChunkRef
	// Uid/Gid/Atime are POSIX ownership + access-time metadata stored
	// alongside the manifest row. Single-identity agent disk: no permission
	// enforcement, these are store-and-readback only (chown/utimensat).
	Uid   uint32
	Gid   uint32
	Atime int64
}

// ChunkRef is one entry in a manifest's chunk list.
type ChunkRef struct {
	Hash   [HashLen]byte
	Offset uint64
	Len    uint32
}

// chunkRefSize is the wire size of one packed chunk entry inside the
// manifests.chunks BLOB column: hash(32) | offset(8) | len(4).
const chunkRefSize = HashLen + 8 + 4

// ErrManifestNotFound is returned by Get when no manifest exists for the path.
var ErrManifestNotFound = errors.New("manifest not found")

// ErrVersionConflict is returned by Put when expected_version doesn't match.
// Callers that want the existing version (for a `RecoveryHint`, issue #103)
// should `errors.As` to a `*VersionConflictError`.
var ErrVersionConflict = errors.New("manifest version conflict")

// VersionConflictError augments ErrVersionConflict with the existing version
// the server saw at conflict time. Wraps `ErrVersionConflict` so existing
// `errors.Is(err, ErrVersionConflict)` checks keep working.
type VersionConflictError struct {
	// Existing is the manifest version actually stored on the server when
	// the CAS check failed. Zero means "no manifest existed" (insert
	// conflict where the row was inserted concurrently).
	Existing uint64
}

func (e *VersionConflictError) Error() string { return ErrVersionConflict.Error() }
func (e *VersionConflictError) Unwrap() error { return ErrVersionConflict }

// ErrParentNotFound is returned by Put when the parent directory does not exist.
var ErrParentNotFound = errors.New("parent directory not found")

// ErrAlreadyExists is returned by DirCreate/Symlink/Mknod when the target path
// already exists. Rename does NOT return it: Rename overwrites a compatible dest
// (expectedTo==0 skips the dest CAS; expectedTo>0 CAS-checks the dest version).
var ErrAlreadyExists = errors.New("path already exists")

// ErrNotEmpty is returned by DirRemove when the directory still has children.
var ErrNotEmpty = errors.New("directory not empty")

// ErrNotDir is returned by Rename when the source is a directory but the
// existing destination is not a directory (POSIX ENOTDIR).
var ErrNotDir = errors.New("not a directory")

// ErrIsDir is returned by Rename when the source is not a directory but the
// existing destination is a directory (POSIX EISDIR).
var ErrIsDir = errors.New("is a directory")

// POSIX file-type bits (st_mode & sIFMT). Mirror the libc S_IF* values so the
// type a mknod request carries round-trips to stat unchanged. Defined here (not
// pulling in syscall) so the value is identical across platforms.
const (
	sIFMT   uint32 = 0o170000 // type mask
	sIFIFO  uint32 = 0o010000 // FIFO
	sIFCHR  uint32 = 0o020000 // character device
	sIFBLK  uint32 = 0o060000 // block device
	sIFSOCK uint32 = 0o140000 // socket
)

// specialNodeKind maps a mode's type bits to the wire-string kind used by
// EntryWire/handleStat/ListChildren. Returns "" for an unknown/zero type.
func specialNodeKind(mode uint32) string {
	switch mode & sIFMT {
	case sIFIFO:
		return "fifo"
	case sIFSOCK:
		return "socket"
	case sIFCHR:
		return "chardev"
	case sIFBLK:
		return "blockdev"
	default:
		return ""
	}
}

// ManifestStore reads and writes manifest rows out of a routes.db.
type ManifestStore struct {
	db      *sql.DB
	metrics *serverMetrics
	// chunks gates manifest refcount commits against GC unlinks. Nil in unit
	// tests that exercise metadata in isolation.
	chunks *ChunkStore
	// journal is the live-event sink; when non-nil, Put/Delete/Rename
	// broadcast each committed journal entry through its pub/sub. Set by
	// tenantState construction via SetJournal; nil in unit tests that
	// don't exercise the subscription path.
	journal *SessionJournal
	// onChange, when non-nil, is called with the allocated change revision
	// after a mutation's transaction commits (issue #122). Unlike the
	// journal it fires for EVERY metadata mutation — a mirror that misses
	// even one writer's changes serves stale data. Set by tenantState
	// construction via SetChangeNotify.
	onChange func(rev uint64)
}

// NewManifestStore wraps the same sqlite handle the TenantDB opened.
func NewManifestStore(db *sql.DB, metrics *serverMetrics) *ManifestStore {
	return &ManifestStore{db: db, metrics: metrics}
}

// SetJournal wires the live-event sink for post-commit broadcasts. Safe to
// call once at construction; not safe to swap concurrently with writes.
func (m *ManifestStore) SetJournal(j *SessionJournal) {
	m.journal = j
}

// SetChangeNotify wires the change-feed doorbell for post-commit
// notifications. Same construction-time contract as SetJournal.
func (m *ManifestStore) SetChangeNotify(fn func(rev uint64)) {
	m.onChange = fn
}

// SetChunkStore enables the production invariant that every newly committed
// manifest reference is present on disk at commit time. Safe to call once at
// construction; not safe to swap concurrently with writes.
func (m *ManifestStore) SetChunkStore(chunks *ChunkStore) {
	m.chunks = chunks
}

// notifyChange rings the change-feed doorbell after a committed mutation.
// Post-commit invariant mirrors the journal Broadcast: only revisions that
// actually landed are announced.
func (m *ManifestStore) notifyChange(rev uint64) {
	if m.onChange != nil && rev != 0 {
		m.onChange(rev)
	}
}

// Get returns the manifest for path. ErrManifestNotFound if missing.
func (m *ManifestStore) Get(p string) (Manifest, error) {
	row := m.db.QueryRow(`
		select mf.path, mf.inode_id,
		       (select count(*) from manifests links where links.inode_id = mf.inode_id),
		       mf.size, mf.mode, mf.mtime, mf.version, mf.chunks, mf.uid, mf.gid, mf.atime
		from manifests mf
		where mf.path = ?
	`, p)
	var blob []byte
	out := Manifest{}
	err := row.Scan(&out.Path, &out.InodeID, &out.Nlink, &out.Size, &out.Mode, &out.Mtime, &out.Version, &blob, &out.Uid, &out.Gid, &out.Atime)
	if errors.Is(err, sql.ErrNoRows) {
		return Manifest{}, ErrManifestNotFound
	}
	if err != nil {
		return Manifest{}, fmt.Errorf("scan manifest %s: %w", p, err)
	}
	chunks, err := unpackChunks(blob)
	if err != nil {
		return Manifest{}, fmt.Errorf("unpack manifest %s: %w", p, err)
	}
	out.Chunks = chunks
	return out, nil
}

// Put writes (or updates) the manifest. CAS semantics:
//   - expectedVersion == 0: insert; fails with ErrVersionConflict if a row
//     already exists.
//   - expectedVersion > 0: update; fails with ErrVersionConflict if the
//     stored version doesn't match.
//
// On success returns the new version (always expectedVersion + 1).
// Also enforces parent-existence (ErrParentNotFound) and updates chunk
// refcounts in the chunks table atomically.
//
// When sessionID is non-empty, a row is appended to session_journal in the
// same transaction so the write can be reverted later. Empty sessionID (no
// active session) skips the journal — used by the migrate-to-chunks tool
// and by clients that haven't called session_begin.
//
// agentID is the cert-bound writer identity captured on the journal row so
// the LastWriter recovery hint (issue #100) can name who landed the prior
// version on a CAS conflict. Empty agentID is allowed (e.g., internal tools)
// and stored as the column's empty-string default.
func (m *ManifestStore) Put(p string, expectedVersion uint64, mf Manifest, sessionID, allocationID, agentID string) (uint64, error) {
	if p != mf.Path {
		return 0, fmt.Errorf("manifest path %q != argument %q", mf.Path, p)
	}
	if sessionID != "" && allocationID == "" {
		return 0, fmt.Errorf("manifest_put: empty allocation_id required")
	}
	unlockChunks, err := m.lockAndValidateChunks(mf.Chunks)
	if err != nil {
		return 0, err
	}
	defer unlockChunks()

	tx, err := m.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	// A new inode takes the SQLite writer lock before any reads. This avoids
	// SQLITE_BUSY_SNAPSHOT under concurrent creates and makes allocation +
	// manifest insertion one serialized transaction.
	var allocatedInodeID uint64
	if expectedVersion == 0 {
		if err := tx.QueryRow(`
			update inode_counter set next_id = next_id + 1
			where singleton = 1
			returning next_id
		`).Scan(&allocatedInodeID); err != nil {
			return 0, fmt.Errorf("allocate inode id: %w", err)
		}
	}

	// 1. Parent-existence check.
	parent, name := splitParentName(p)
	if err := checkParentExists(tx, p); err != nil {
		return 0, err
	}

	// 2. Read old manifest (if any) for refcount diff and (when journaling)
	// for the before-state blob.
	var (
		oldChunks       []ChunkRef
		oldBlob         []byte
		existingVersion uint64
		oldSize         uint64
		oldMode         uint32
		oldMtime        int64
		oldUID          uint32
		oldGID          uint32
		oldAtime        int64
		oldInodeID      uint64
		haveOld         bool
	)
	scanErr := tx.QueryRow(
		`select version, size, mode, mtime, chunks, uid, gid, atime, inode_id from manifests where path = ?`, p,
	).Scan(&existingVersion, &oldSize, &oldMode, &oldMtime, &oldBlob, &oldUID, &oldGID, &oldAtime, &oldInodeID)
	if scanErr == nil {
		haveOld = true
		oldChunks, err = unpackChunks(oldBlob)
		if err != nil {
			return 0, fmt.Errorf("unpack old chunks for %s: %w", p, err)
		}
	} else if !errors.Is(scanErr, sql.ErrNoRows) {
		return 0, fmt.Errorf("read existing manifest %s: %w", p, scanErr)
	}

	// 3. CAS check.
	if existingVersion != expectedVersion {
		return 0, &VersionConflictError{Existing: existingVersion}
	}
	newVersion := expectedVersion + 1
	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return 0, err
	}

	// 3b. Journal the inverse op before the write lands. Failure here aborts
	// the manifest write — better to refuse than leave an unrevertable change.
	var journalEntry *SessionJournalEntry
	if sessionID != "" {
		op, prior := SessionOpCreate, (*Manifest)(nil)
		if expectedVersion != 0 {
			op = SessionOpUpdate
			prior = &Manifest{
				Path: p, Size: oldSize, Mode: oldMode, Mtime: oldMtime,
				Version: existingVersion, Chunks: oldChunks,
			}
		}
		entry, err := journalBeforeWrite(tx, sessionID, allocationID, agentID, op, p, prior, &newVersion, "", m.metrics)
		if err != nil {
			return 0, err
		}
		journalEntry = entry
	}

	// 4. Compute multiset delta (old → new) and apply to chunks table.
	delta := chunkRefDelta(oldChunks, mf.Chunks)
	if err := applyChunkRefDelta(tx, delta); err != nil {
		return 0, err
	}

	// 5. Upsert manifest row (CAS-guarded as before).
	blob := packChunks(mf.Chunks)
	if expectedVersion == 0 {
		// Insert; conflict if path already exists. New file: take owner from the
		// supplied manifest (default 0/0); seed atime from the manifest's atime
		// when set, else from mtime (POSIX: a fresh file's atime ~= mtime).
		newAtime := mf.Atime
		if newAtime == 0 {
			newAtime = mf.Mtime
		}
		res, err := tx.Exec(`
			insert into manifests (path, inode_id, size, mode, mtime, version, chunks, uid, gid, atime, rev)
			values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			on conflict(path) do nothing
		`, p, allocatedInodeID, mf.Size, mf.Mode, mf.Mtime, newVersion, blob, mf.Uid, mf.Gid, newAtime, rev)
		if err != nil {
			return 0, fmt.Errorf("insert manifest %s: %w", p, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, ErrVersionConflict
		}
		if err := clearTombstoneTx(tx, p); err != nil {
			return 0, err
		}
	} else {
		// Update (content write): PRESERVE the stored owner and access time —
		// a content write must not silently reset uid/gid/atime. Dedicated
		// chown/utimensat go through SetOwner/SetAtime instead.
		keepUID, keepGID, keepAtime := mf.Uid, mf.Gid, mf.Atime
		if haveOld {
			keepUID, keepGID, keepAtime = oldUID, oldGID, oldAtime
		}
		res, err := tx.Exec(`
			update manifests
			set size = ?, mode = ?, mtime = ?, version = ?, chunks = ?, uid = ?, gid = ?, atime = ?, rev = ?
			where inode_id = ?
		`, mf.Size, mf.Mode, mf.Mtime, newVersion, blob, keepUID, keepGID, keepAtime, rev, oldInodeID)
		if err != nil {
			return 0, fmt.Errorf("update manifest %s: %w", p, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, ErrVersionConflict
		}
	}

	// 6. Refresh dir_entries: insert (parent, name) for this path's parent.
	if name != "" {
		if _, err := tx.Exec(
			`insert or ignore into dir_entries (parent, name) values (?, ?)`,
			parent, name,
		); err != nil {
			return 0, fmt.Errorf("upsert dir_entry %s/%s: %w", parent, name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit manifest %s: %w", p, err)
	}
	// Post-commit invariant: only broadcast entries that actually landed.
	if journalEntry != nil && m.journal != nil {
		m.journal.Broadcast(journalEntry.AllocationID, *journalEntry)
	}
	m.notifyChange(rev)
	return newVersion, nil
}

func (m *ManifestStore) lockAndValidateChunks(chunks []ChunkRef) (func(), error) {
	if m.chunks == nil || len(chunks) == 0 {
		return func() {}, nil
	}
	hashes := make([][]byte, len(chunks))
	for i := range chunks {
		hashes[i] = chunks[i].Hash[:]
	}
	unlock, err := m.chunks.lockHashes(hashes)
	if err != nil {
		return nil, fmt.Errorf("lock manifest chunks: %w", err)
	}
	present, err := m.chunks.HasMany(hashes)
	if err != nil {
		unlock()
		return nil, fmt.Errorf("validate manifest chunks: %w", err)
	}
	for i, ok := range present {
		if !ok {
			unlock()
			return nil, fmt.Errorf("manifest references missing chunk %x", hashes[i][:4])
		}
	}
	return unlock, nil
}

// Link creates a second directory entry for the same regular-file inode.
// Content/chunk ownership remains per inode: linking does not increment chunk
// refcounts, and deleting a non-final link does not decrement them.
func (m *ManifestStore) Link(from, to, sessionID, allocationID, agentID string) (uint32, error) {
	if sessionID != "" && allocationID == "" {
		return 0, fmt.Errorf("link: empty allocation_id required")
	}
	tx, err := m.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := checkParentExists(tx, to); err != nil {
		return 0, err
	}
	kind, err := resolveKindTx(tx, to)
	if err != nil {
		return 0, err
	}
	if kind != nodeAbsent {
		return 0, ErrAlreadyExists
	}

	var (
		inodeID uint64
		size    uint64
		mode    uint32
		mtime   int64
		version uint64
		blob    []byte
		uid     uint32
		gid     uint32
		atime   int64
	)
	err = tx.QueryRow(`
		select inode_id, size, mode, mtime, version, chunks, uid, gid, atime
		from manifests where path = ?
	`, from).Scan(&inodeID, &size, &mode, &mtime, &version, &blob, &uid, &gid, &atime)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrManifestNotFound
	}
	if err != nil {
		return 0, err
	}
	// SQLite scans a zero-length BLOB into a nil []byte; passing that slice
	// back to database/sql encodes SQL NULL, which violates chunks NOT NULL.
	if blob == nil {
		blob = []byte{}
	}

	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`
		insert into manifests(path, inode_id, size, mode, mtime, version, chunks, uid, gid, atime, rev)
		values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, to, inodeID, size, mode, mtime, version, blob, uid, gid, atime, rev); err != nil {
		return 0, fmt.Errorf("insert hard link %s -> %s: %w", to, from, err)
	}
	// nlink changed for every name of this inode; restamp them all so a
	// mirror re-fetches their entries (nlink is computed live at feed time).
	if _, err := tx.Exec(`update manifests set rev = ? where inode_id = ?`, rev, inodeID); err != nil {
		return 0, fmt.Errorf("restamp linked inode %d: %w", inodeID, err)
	}
	if err := clearTombstoneTx(tx, to); err != nil {
		return 0, err
	}
	parent, name := splitParentName(to)
	if _, err := tx.Exec(`insert into dir_entries(parent, name) values(?, ?)`, parent, name); err != nil {
		return 0, fmt.Errorf("register hard link %s: %w", to, err)
	}

	var journalEntry *SessionJournalEntry
	if sessionID != "" {
		entry, err := journalBeforeWrite(
			tx, sessionID, allocationID, agentID, SessionOpCreate, to, nil, &version, "", m.metrics,
		)
		if err != nil {
			return 0, err
		}
		journalEntry = entry
	}
	var nlink uint32
	if err := tx.QueryRow(`select count(*) from manifests where inode_id = ?`, inodeID).Scan(&nlink); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if journalEntry != nil && m.journal != nil {
		m.journal.Broadcast(journalEntry.AllocationID, *journalEntry)
	}
	m.notifyChange(rev)
	return nlink, nil
}

// deleteSymlink removes the symlinks row (and its dir_entry) for p. Returns
// ErrManifestNotFound when no symlink exists at p, so Delete can fall through
// to the manifest path.
func (m *ManifestStore) deleteSymlink(p string) error {
	return m.deletePathRow("symlinks", "symlink", p)
}

// deletePathRow removes the path-keyed row in `table` plus its dir_entry in
// one transaction, recording a change-feed tombstone. Returns
// ErrManifestNotFound when no row exists at p. Backs deleteSymlink and
// deleteSpecialNode; `label` names the node kind in errors.
func (m *ManifestStore) deletePathRow(table, label, p string) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`delete from `+table+` where path = ?`, p)
	if err != nil {
		return fmt.Errorf("delete %s %s: %w", label, p, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrManifestNotFound
	}
	parent, name := splitParentName(p)
	if name != "" {
		if _, err := tx.Exec(`delete from dir_entries where parent = ? and name = ?`, parent, name); err != nil {
			return fmt.Errorf("delete %s dir_entry %s/%s: %w", label, parent, name, err)
		}
	}
	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return err
	}
	if err := upsertTombstoneTx(tx, p, rev); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.notifyChange(rev)
	return nil
}

// Delete removes the manifest for p using CAS semantics on expectedVersion.
// Returns ErrManifestNotFound if the path does not exist, ErrVersionConflict
// if expectedVersion does not match the stored version. On success chunk
// refcounts are decremented atomically.
//
// When sessionID is non-empty the prior manifest is captured in the journal
// so a later revert can restore it. agentID names the writer on the journal
// row (see Put for context).
func (m *ManifestStore) Delete(p string, expectedVersion uint64, sessionID, allocationID, agentID string) error {
	if sessionID != "" && allocationID == "" {
		return fmt.Errorf("manifest_delete: empty allocation_id required")
	}

	// Special node (manifest-less): an unlink arrives with expectedVersion 0.
	// Remove the special_nodes row + dir_entry and return. ErrManifestNotFound
	// falls through to the symlink/manifest paths below.
	if snErr := m.deleteSpecialNode(p); snErr == nil {
		return nil
	} else if !errors.Is(snErr, ErrManifestNotFound) {
		return snErr
	}

	// Symlink (manifest-less): an unlink arrives with expectedVersion 0. Remove
	// the symlink row + dir_entry and return. ErrManifestNotFound falls through.
	if slErr := m.deleteSymlink(p); slErr == nil {
		return nil
	} else if !errors.Is(slErr, ErrManifestNotFound) {
		return slErr
	}

	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		version uint64
		inodeID uint64
		nlink   uint32
		size    uint64
		mode    uint32
		mtime   int64
		blob    []byte
	)
	err = tx.QueryRow(
		`select mf.version, mf.inode_id,
		        (select count(*) from manifests links where links.inode_id = mf.inode_id),
		        mf.size, mf.mode, mf.mtime, mf.chunks
		   from manifests mf where mf.path = ?`, p,
	).Scan(&version, &inodeID, &nlink, &size, &mode, &mtime, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrManifestNotFound
	}
	if err != nil {
		return fmt.Errorf("read manifest %s: %w", p, err)
	}
	if version != expectedVersion {
		return &VersionConflictError{Existing: version}
	}

	oldChunks, err := unpackChunks(blob)
	if err != nil {
		return fmt.Errorf("unpack chunks for %s: %w", p, err)
	}

	var journalEntry *SessionJournalEntry
	if sessionID != "" {
		prior := Manifest{
			Path: p, Size: size, Mode: mode, Mtime: mtime,
			Version: version, Chunks: oldChunks,
		}
		// For a non-final hard-link delete, remember a surviving alias. Revert
		// must LINK that inode back rather than Put a duplicate inode (which
		// would double-own the chunks and break inode identity).
		var survivingAlias string
		if nlink > 1 {
			if err := tx.QueryRow(
				`select path from manifests where inode_id = ? and path <> ? order by path limit 1`,
				inodeID, p,
			).Scan(&survivingAlias); err != nil {
				return fmt.Errorf("find surviving hard-link alias for %s: %w", p, err)
			}
		}
		entry, err := journalBeforeWrite(tx, sessionID, allocationID, agentID, SessionOpDelete, p, &prior, nil, survivingAlias, m.metrics)
		if err != nil {
			return err
		}
		journalEntry = entry
	}

	// Chunks belong to the inode, not each directory entry. Reclaim only when
	// this is the final hard link.
	if nlink == 1 {
		if err := applyChunkRefDelta(tx, chunkRefDelta(oldChunks, nil)); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`delete from manifests where path = ?`, p); err != nil {
		return fmt.Errorf("delete manifest %s: %w", p, err)
	}
	parent, name := splitParentName(p)
	if name != "" {
		if _, err := tx.Exec(
			`delete from dir_entries where parent = ? and name = ?`, parent, name,
		); err != nil {
			return fmt.Errorf("delete dir_entry %s/%s: %w", parent, name, err)
		}
	}
	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return err
	}
	if err := upsertTombstoneTx(tx, p, rev); err != nil {
		return err
	}
	// A non-final hard-link delete changes nlink for the surviving names;
	// restamp them (p's own row is already gone) so a mirror re-fetches them.
	if nlink > 1 {
		if _, err := tx.Exec(`update manifests set rev = ? where inode_id = ?`, rev, inodeID); err != nil {
			return fmt.Errorf("restamp surviving hard links of inode %d: %w", inodeID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Post-commit invariant: only broadcast entries that actually landed.
	if journalEntry != nil && m.journal != nil {
		m.journal.Broadcast(journalEntry.AllocationID, *journalEntry)
	}
	m.notifyChange(rev)
	return nil
}

// nodeKind classifies what kind of filesystem node, if any, lives at `p`.
type nodeKind int

const (
	nodeAbsent  nodeKind = iota // nothing at this path
	nodeRegular                 // regular file (manifests row + chunks)
	nodeSymlink                 // symbolic link (symlinks row)
	nodeSpecial                 // fifo/socket/dev (special_nodes row)
	nodeDir                     // directory (dir_entries-as-dir)
)

// resolveKindTx probes the four backing tables in priority order to determine
// the kind of node at `p` within tx. A path is a directory when it appears as a
// parent of children in dir_entries OR is a registered dir_entry that is not a
// file/symlink/special node. Mirrors the IsDir two-arm semantics but in-tx so
// the rename matrix sees a consistent snapshot.
func resolveKindTx(tx *sql.Tx, p string) (nodeKind, error) {
	var one int
	// Regular file.
	err := tx.QueryRow(`select 1 from manifests where path = ? limit 1`, p).Scan(&one)
	if err == nil {
		return nodeRegular, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nodeAbsent, err
	}
	// Symlink.
	err = tx.QueryRow(`select 1 from symlinks where path = ? limit 1`, p).Scan(&one)
	if err == nil {
		return nodeSymlink, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nodeAbsent, err
	}
	// Special node.
	err = tx.QueryRow(`select 1 from special_nodes where path = ? limit 1`, p).Scan(&one)
	if err == nil {
		return nodeSpecial, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nodeAbsent, err
	}
	// Directory: has children, OR is a registered (parent,name) dir_entry.
	err = tx.QueryRow(`select 1 from dir_entries where parent = ? limit 1`, p).Scan(&one)
	if err == nil {
		return nodeDir, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nodeAbsent, err
	}
	parent, name := splitParentName(p)
	if name == "" {
		// Root is always a directory.
		return nodeDir, nil
	}
	err = tx.QueryRow(`select 1 from dir_entries where parent = ? and name = ? limit 1`, parent, name).Scan(&one)
	if err == nil {
		return nodeDir, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nodeAbsent, nil
	}
	return nodeAbsent, err
}

// dirIsEmptyTx reports whether the directory `p` has any children (sub-dir_entries
// or files/symlinks/special nodes directly underneath). Used to enforce
// ENOTEMPTY before overwriting a directory destination.
func dirIsEmptyTx(tx *sql.Tx, p string) (bool, error) {
	var n int
	if err := tx.QueryRow(`select count(*) from dir_entries where parent = ?`, p).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	glob := p + "/*"
	for _, table := range []string{"manifests", "symlinks", "special_nodes"} {
		if err := tx.QueryRow(`select count(*) from `+table+` where path glob ?`, glob).Scan(&n); err != nil {
			return false, err
		}
		if n > 0 {
			return false, nil
		}
	}
	return true, nil
}

// removeDirEntryTx deletes the (parent,name) dir_entry registration for `p`.
func removeDirEntryTx(tx *sql.Tx, p string) error {
	parent, name := splitParentName(p)
	if name == "" {
		return nil
	}
	if _, err := tx.Exec(`delete from dir_entries where parent = ? and name = ?`, parent, name); err != nil {
		return fmt.Errorf("delete dir_entry %s/%s: %w", parent, name, err)
	}
	return nil
}

// deleteDestTx removes the destination node `to` of kind `k` inside tx so the
// rename can move `from` onto it. Regular files decref their chunks; symlinks
// and special nodes drop their backing row; empty directories drop their
// dir_entry. The dir_entry registration is removed for every kind. rev is the
// rename's change revision: a displaced regular dest with surviving hard
// links gets those survivors restamped (their nlink changed). No tombstone is
// recorded for `to` — the moved source immediately re-occupies the path.
func deleteDestTx(tx *sql.Tx, to string, k nodeKind, rev uint64) error {
	switch k {
	case nodeRegular:
		var (
			blob    []byte
			inodeID uint64
			nlink   uint32
		)
		if err := tx.QueryRow(`
			select mf.chunks, mf.inode_id,
			       (select count(*) from manifests links where links.inode_id = mf.inode_id)
			from manifests mf where mf.path = ?
		`, to).Scan(&blob, &inodeID, &nlink); err != nil {
			return fmt.Errorf("read dest chunks %s: %w", to, err)
		}
		if nlink == 1 {
			dstChunks, err := unpackChunks(blob)
			if err != nil {
				return fmt.Errorf("unpack dest chunks %s: %w", to, err)
			}
			if err := applyChunkRefDelta(tx, chunkRefDelta(dstChunks, nil)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`delete from manifests where path = ?`, to); err != nil {
			return fmt.Errorf("delete dest manifest %s: %w", to, err)
		}
		if nlink > 1 {
			if _, err := tx.Exec(`update manifests set rev = ? where inode_id = ?`, rev, inodeID); err != nil {
				return fmt.Errorf("restamp displaced dest inode %d: %w", inodeID, err)
			}
		}
	case nodeSymlink:
		if _, err := tx.Exec(`delete from symlinks where path = ?`, to); err != nil {
			return fmt.Errorf("delete dest symlink %s: %w", to, err)
		}
	case nodeSpecial:
		if _, err := tx.Exec(`delete from special_nodes where path = ?`, to); err != nil {
			return fmt.Errorf("delete dest special node %s: %w", to, err)
		}
	case nodeDir:
		// Caller has already verified emptiness; just drop the row.
	}
	return removeDirEntryTx(tx, to)
}

// reparentDescendantsTx rewrites every descendant path of a renamed directory.
// Children live under `from + "/"`; rewrite their `path` columns (and the
// dir_entries `parent` column) to sit under `to` instead. Called only when a
// directory itself is moved.
//
// Change-feed bookkeeping (issue #122): the old descendant paths vanish, so
// they are tombstoned BEFORE the rewrite (the SELECTs must still see them),
// every moved row is stamped with the rename's revision, and stale tombstones
// under the destination are cleared. The whole subtree lands at ONE revision
// — this is exactly why the feed cursor is a (rev, path) pair rather than a
// scalar watermark.
func reparentDescendantsTx(tx *sql.Tx, from, to string, rev uint64) error {
	if err := tombstoneSubtreeTx(tx, from, rev); err != nil {
		return err
	}
	// For the three path-keyed tables, rewrite the path prefix.
	// path = to || substr(path, len(from)+1) for rows where path like from||'/%'.
	likePat := from + "/%"
	prefixLen := len(from) + 1 // 1-based substr index of the first char after `from`
	for _, table := range []string{"manifests", "symlinks", "special_nodes"} {
		if _, err := tx.Exec(
			`update `+table+` set path = ? || substr(path, ?), rev = ? where path like ?`,
			to, prefixLen, rev, likePat,
		); err != nil {
			return fmt.Errorf("reparent %s paths %s->%s: %w", table, from, to, err)
		}
	}
	// dir_entries are keyed by (parent, name): rewrite the `parent` prefix for
	// every descendant whose parent is `from` or nested under `from/`.
	if _, err := tx.Exec(
		`update dir_entries set parent = ?, rev = ? where parent = ?`, to, rev, from,
	); err != nil {
		return fmt.Errorf("reparent dir_entries direct children %s->%s: %w", from, to, err)
	}
	if _, err := tx.Exec(
		`update dir_entries set parent = ? || substr(parent, ?), rev = ? where parent like ?`,
		to, prefixLen, rev, likePat,
	); err != nil {
		return fmt.Errorf("reparent dir_entries nested %s->%s: %w", from, to, err)
	}
	if err := clearTombstoneSubtreeTx(tx, to); err != nil {
		return err
	}
	return nil
}

// Rename moves a regular file, OVERWRITING a compatible destination (the
// historical default). It is renameOpt with noReplace=false.
func (m *ManifestStore) Rename(from, to string, expectedFrom, expectedTo uint64, sessionID, allocationID, agentID string) (uint64, error) {
	return m.renameOpt(from, to, expectedFrom, expectedTo, false, sessionID, allocationID, agentID)
}

// renameOpt implements POSIX rename(from, to) across every node kind in one
// transaction. `from` must exist (ErrManifestNotFound/ENOENT otherwise). When
// `to` already exists the destination is OVERWRITTEN if the source and dest
// types are compatible; the type-combo rules are:
//
//   - from is a dir, to is NOT a dir  → ErrNotDir (ENOTDIR)
//   - from is NOT a dir, to IS a dir  → ErrIsDir (EISDIR)
//   - from is a dir, to is a non-empty dir → ErrNotEmpty (ENOTEMPTY)
//   - otherwise (compatible) → remove `to` in-tx, then move `from` onto it.
//
// A from == to (same path) call is a no-op success. The parent of `to` must
// exist (ErrParentNotFound/ENOENT). expectedFrom CAS-checks a regular-file
// source; expectedTo CAS-checks a regular-file dest when non-zero (the Rust
// client resolves both live before the call, so this still guards races).
// Manifest-less nodes (symlink/special/dir) carry no version and return 1.
//
// When noReplace is true, an existing destination of ANY kind makes the call
// fail with ErrAlreadyExists (POSIX RENAME_NOREPLACE) instead of being
// overwritten — a create-only move for callers that must not clobber.
//
// Only the regular-file source path is journaled (matching the prior behavior
// and the revert engine, which only renames regular files); symlink/special/dir
// renames are not journaled, as they are not journaled anywhere else either.
func (m *ManifestStore) renameOpt(from, to string, expectedFrom, expectedTo uint64, noReplace bool, sessionID, allocationID, agentID string) (uint64, error) {
	if sessionID != "" && allocationID == "" {
		return 0, fmt.Errorf("manifest_rename: empty allocation_id required")
	}

	tx, err := m.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	// 1. Resolve source kind. Must exist.
	srcKind, err := resolveKindTx(tx, from)
	if err != nil {
		return 0, fmt.Errorf("resolve source %s: %w", from, err)
	}
	if srcKind == nodeAbsent {
		return 0, ErrManifestNotFound
	}

	// 2. Same path: no-op success. Report the source's version (best-effort).
	if from == to {
		return samePathVersionTx(tx, from, srcKind), nil
	}

	// 3+4. Resolve the destination and enforce the overwrite rules
	// (RENAME_NOREPLACE, type-combo matrix, dest CAS).
	dstKind, dstVersion, err := resolveRenameDestTx(tx, to, srcKind, noReplace, expectedTo)
	if err != nil {
		return 0, err
	}

	// 5. Parent of `to` must exist (POSIX-correct).
	if err := checkParentExists(tx, to); err != nil {
		return 0, err
	}

	// 6. Read the regular-file source's row up front (needed for CAS, journal,
	// and the manifest move).
	var src renameSource
	if srcKind == nodeRegular {
		if src, err = readRenameSourceTx(tx, from, expectedFrom); err != nil {
			return 0, err
		}
		// POSIX: if both names already resolve to the same inode, rename is a
		// no-op. In particular, do not remove one of the hard-link names.
		if dstKind == nodeRegular {
			var dstInodeID uint64
			if err := tx.QueryRow(`select inode_id from manifests where path = ?`, to).Scan(&dstInodeID); err != nil {
				return 0, fmt.Errorf("read dest inode %s: %w", to, err)
			}
			if dstInodeID == src.inodeID {
				return src.version, nil
			}
		}
	}

	// 6b. One change revision for the whole rename: displaced dest, moved
	// source (subtree included for directories), and the old-path tombstone
	// all land at the same rev.
	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return 0, err
	}

	// 7. Overwrite the destination in-tx (if present and compatible).
	if dstKind != nodeAbsent {
		if err := deleteDestTx(tx, to, dstKind, rev); err != nil {
			return 0, err
		}
	}

	// 8. Version bookkeeping + journal — only for a regular-file source.
	newVersion, journalEntry, err := m.journalRenameTx(tx, from, to, srcKind, dstVersion, src, sessionID, allocationID, agentID)
	if err != nil {
		return 0, err
	}

	// 9. Move the source's backing row to `to`.
	if err := moveRenameSourceTx(tx, from, to, srcKind, newVersion, src.inodeID, rev); err != nil {
		return 0, err
	}

	// 10. Rewrite the source's own dir_entry: drop (fromParent,fromName), add
	// (toParent,toName).
	if err := rewriteRenameDirEntriesTx(tx, from, to, srcKind, rev); err != nil {
		return 0, err
	}

	// 11. The source path no longer exists; the destination does.
	if err := upsertTombstoneTx(tx, from, rev); err != nil {
		return 0, err
	}
	if err := clearTombstoneTx(tx, to); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	// Post-commit invariant: only broadcast entries that actually landed.
	if journalEntry != nil && m.journal != nil {
		m.journal.Broadcast(journalEntry.AllocationID, *journalEntry)
	}
	m.notifyChange(rev)
	return newVersion, nil
}

// samePathVersionTx reports the version a from == to no-op rename returns: the
// stored manifest version for a regular file (best-effort), 1 otherwise.
func samePathVersionTx(tx *sql.Tx, p string, kind nodeKind) uint64 {
	if kind == nodeRegular {
		var v uint64
		if err := tx.QueryRow(`select version from manifests where path = ?`, p).Scan(&v); err == nil {
			return v
		}
	}
	return 1
}

// resolveRenameDestTx resolves the destination of a rename and enforces the
// overwrite rules documented on renameOpt: RENAME_NOREPLACE first (an existing
// destination of ANY kind → ErrAlreadyExists), then the type-combo matrix.
// dstVersion is the dest's prior version (0 when absent / non-regular); a
// regular-file dest is CAS-guarded against expectedTo when non-zero.
func resolveRenameDestTx(tx *sql.Tx, to string, srcKind nodeKind, noReplace bool, expectedTo uint64) (nodeKind, uint64, error) {
	dstKind, err := resolveKindTx(tx, to)
	if err != nil {
		return nodeAbsent, 0, fmt.Errorf("resolve dest %s: %w", to, err)
	}
	if dstKind == nodeAbsent {
		return dstKind, 0, nil
	}
	if noReplace {
		return dstKind, 0, ErrAlreadyExists
	}
	srcIsDir := srcKind == nodeDir
	dstIsDir := dstKind == nodeDir
	switch {
	case srcIsDir && !dstIsDir:
		return dstKind, 0, ErrNotDir
	case !srcIsDir && dstIsDir:
		return dstKind, 0, ErrIsDir
	case srcIsDir && dstIsDir:
		empty, eErr := dirIsEmptyTx(tx, to)
		if eErr != nil {
			return dstKind, 0, eErr
		}
		if !empty {
			return dstKind, 0, ErrNotEmpty
		}
	}
	var dstVersion uint64
	if dstKind == nodeRegular {
		if qErr := tx.QueryRow(`select version from manifests where path = ?`, to).Scan(&dstVersion); qErr != nil {
			return dstKind, 0, fmt.Errorf("read dest version %s: %w", to, qErr)
		}
		// CAS-guard a regular-file dest the caller resolved a version for.
		if expectedTo != 0 && dstVersion != expectedTo {
			return dstKind, 0, &VersionConflictError{Existing: dstVersion}
		}
	}
	return dstKind, dstVersion, nil
}

// renameSource is the regular-file source row renameOpt reads up front — the
// CAS check, the journal entry, and the manifest move all need it.
type renameSource struct {
	inodeID uint64
	version uint64
	blob    []byte
	size    uint64
	mode    uint32
	mtime   int64
	uid     uint32
	gid     uint32
	atime   int64
}

// readRenameSourceTx reads the regular-file source's manifest row and
// CAS-checks it against expectedFrom.
func readRenameSourceTx(tx *sql.Tx, from string, expectedFrom uint64) (renameSource, error) {
	var src renameSource
	if qErr := tx.QueryRow(
		`select inode_id, version, size, mode, mtime, chunks, uid, gid, atime from manifests where path = ?`, from,
	).Scan(&src.inodeID, &src.version, &src.size, &src.mode, &src.mtime, &src.blob, &src.uid, &src.gid, &src.atime); qErr != nil {
		return renameSource{}, fmt.Errorf("read source manifest %s: %w", from, qErr)
	}
	if src.version != expectedFrom {
		return renameSource{}, &VersionConflictError{Existing: src.version}
	}
	return src, nil
}

// journalRenameTx computes the version the rename lands at `to` and journals
// the rename — only for a regular-file source, matching the prior behavior and
// the revert engine (which only renames regular files). The new version at
// `to` is dstVersion+1 (the historical contract): a move onto a vacant path
// yields version 1, an overwrite bumps the displaced dest's version.
// Manifest-less sources carry no version and return 1.
func (m *ManifestStore) journalRenameTx(tx *sql.Tx, from, to string, srcKind nodeKind, dstVersion uint64, src renameSource, sessionID, allocationID, agentID string) (uint64, *SessionJournalEntry, error) {
	if srcKind != nodeRegular {
		return 1, nil, nil
	}
	newVersion := dstVersion + 1
	if sessionID == "" {
		return newVersion, nil, nil
	}
	srcChunks, uErr := unpackChunks(src.blob)
	if uErr != nil {
		return 0, nil, fmt.Errorf("unpack src chunks for %s: %w", from, uErr)
	}
	prior := Manifest{
		Path: from, Size: src.size, Mode: src.mode, Mtime: src.mtime,
		Version: src.version, Chunks: srcChunks,
		Uid: src.uid, Gid: src.gid, Atime: src.atime,
	}
	entry, jErr := journalBeforeWrite(tx, sessionID, allocationID, agentID, SessionOpRename, to, &prior, &newVersion, from, m.metrics)
	if jErr != nil {
		return 0, nil, jErr
	}
	return newVersion, entry, nil
}

// moveRenameSourceTx moves the source's backing row to `to`: a path (and, for
// regular files, version) rewrite on the kind's own table, or a descendant
// re-parent for directories. Every moved row is stamped with the rename's
// change revision.
func moveRenameSourceTx(tx *sql.Tx, from, to string, srcKind nodeKind, newVersion, inodeID, rev uint64) error {
	switch srcKind {
	case nodeRegular:
		if _, err := tx.Exec(`update manifests set path = ? where path = ?`, to, from); err != nil {
			return fmt.Errorf("move manifest %s->%s: %w", from, to, err)
		}
		// Version is inode metadata: every hard-link name must observe the same
		// value or later CAS writes through another name would spuriously fail.
		// The rev stamp rides along for every alias for the same reason.
		if _, err := tx.Exec(`update manifests set version = ?, rev = ? where inode_id = ?`, newVersion, rev, inodeID); err != nil {
			return fmt.Errorf("update renamed inode version %d: %w", inodeID, err)
		}
	case nodeSymlink:
		if _, err := tx.Exec(`update symlinks set path = ?, rev = ? where path = ?`, to, rev, from); err != nil {
			return fmt.Errorf("move symlink %s->%s: %w", from, to, err)
		}
	case nodeSpecial:
		if _, err := tx.Exec(`update special_nodes set path = ?, rev = ? where path = ?`, to, rev, from); err != nil {
			return fmt.Errorf("move special node %s->%s: %w", from, to, err)
		}
	case nodeDir:
		// Re-parent every descendant path/parent BEFORE moving the dir's own
		// entry, so the prefix rewrite still matches `from/...`.
		if err := reparentDescendantsTx(tx, from, to, rev); err != nil {
			return err
		}
	}
	return nil
}

// rewriteRenameDirEntriesTx rewrites the source's own dir_entry: drop
// (fromParent,fromName), add (toParent,toName). A directory carries its stored
// mode/owner/atime so a moved directory keeps its metadata.
func rewriteRenameDirEntriesTx(tx *sql.Tx, from, to string, srcKind nodeKind, rev uint64) error {
	fromParent, fromName := splitParentName(from)
	toParent, toName := splitParentName(to)

	var dMode, dUID, dGID uint32
	var dAtime int64
	if srcKind == nodeDir {
		if qErr := tx.QueryRow(
			`select mode, uid, gid, atime from dir_entries where parent = ? and name = ?`, fromParent, fromName,
		).Scan(&dMode, &dUID, &dGID, &dAtime); qErr != nil && !errors.Is(qErr, sql.ErrNoRows) {
			return fmt.Errorf("read dir metadata %s: %w", from, qErr)
		}
	}
	if fromName != "" {
		if _, err := tx.Exec(`delete from dir_entries where parent = ? and name = ?`, fromParent, fromName); err != nil {
			return fmt.Errorf("delete dir_entry %s/%s: %w", fromParent, fromName, err)
		}
	}
	if toName != "" {
		if srcKind == nodeDir {
			if _, err := tx.Exec(
				`insert into dir_entries(parent, name, mode, uid, gid, atime, rev) values(?, ?, ?, ?, ?, ?, ?)
				 on conflict(parent, name) do update set mode=excluded.mode, uid=excluded.uid, gid=excluded.gid, atime=excluded.atime, rev=excluded.rev`,
				toParent, toName, dMode, dUID, dGID, dAtime, rev,
			); err != nil {
				return fmt.Errorf("insert dir_entry %s/%s: %w", toParent, toName, err)
			}
		} else {
			if _, err := tx.Exec(
				`insert or ignore into dir_entries(parent, name) values(?, ?)`, toParent, toName,
			); err != nil {
				return fmt.Errorf("insert dir_entry %s/%s: %w", toParent, toName, err)
			}
		}
	}
	return nil
}

// RegisterDir ensures (parent, name) exists in dir_entries. Used by migration
// and directory-create handlers to register a directory before any files are
// Put under it.
func (m *ManifestStore) RegisterDir(parent, name string) error {
	_, err := m.db.Exec(
		`insert or ignore into dir_entries (parent, name) values (?, ?)`,
		parent, name,
	)
	return err
}

// DirChild is one row returned by ListChildren — name + size + kind + mode +
// owner + atime. Kind is "file", "dir", or "symlink". Size is the content size
// for files, the target length for symlinks, and zero for directories.
type DirChild struct {
	Name    string
	IsDir   bool
	Kind    string
	Mode    uint32
	Size    uint64
	Uid     uint32
	Gid     uint32
	Atime   int64
	InodeID uint64
	Nlink   uint32
	// Mtime is the modification time; real for files (manifest mtime), the
	// stored (rarely set) value for symlinks/dirs. Version is the manifest
	// CAS version, files only. Carried so listings can answer stat-shaped
	// questions without a per-file manifest fetch (issue #122).
	Mtime   int64
	Version uint64
}

// ListChildren returns the children of `parent` from dir_entries, joined with
// manifests and symlinks to derive (kind, size, mode). A child is a file when a
// manifest row exists, a symlink when a symlinks row exists, otherwise a
// directory. Children are sorted by name.
func (m *ManifestStore) ListChildren(parent string) ([]DirChild, error) {
	rows, err := m.db.Query(`
		SELECT d.name,
		       CASE WHEN mf.path IS NOT NULL THEN 'file'
		            WHEN sl.path IS NOT NULL THEN 'symlink'
		            ELSE 'dir' END AS kind,
		       COALESCE(mf.size, COALESCE(LENGTH(sl.target), 0)) AS size,
		       COALESCE(mf.mode, sl.mode, d.mode, 493) AS mode,
		       COALESCE(mf.uid, sl.uid, d.uid, 0) AS uid,
		       COALESCE(mf.gid, sl.gid, d.gid, 0) AS gid,
		       COALESCE(mf.atime, sl.atime, d.atime, 0) AS atime,
		       COALESCE(mf.inode_id, 0) AS inode_id,
		       CASE WHEN mf.inode_id IS NULL THEN 1
		            ELSE (select count(*) from manifests links where links.inode_id = mf.inode_id)
		       END AS nlink,
		       COALESCE(mf.mtime, sl.mtime, d.mtime, 0) AS mtime,
		       COALESCE(mf.version, 0) AS version
		FROM dir_entries d
		LEFT JOIN manifests mf
		  ON mf.path = CASE WHEN d.parent = '/' THEN '/' || d.name
		                    ELSE d.parent || '/' || d.name END
		LEFT JOIN symlinks sl
		  ON sl.path = CASE WHEN d.parent = '/' THEN '/' || d.name
		                    ELSE d.parent || '/' || d.name END
		WHERE d.parent = ?
		ORDER BY d.name
	`, parent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DirChild
	for rows.Next() {
		var c DirChild
		if err := rows.Scan(&c.Name, &c.Kind, &c.Size, &c.Mode, &c.Uid, &c.Gid, &c.Atime, &c.InodeID, &c.Nlink, &c.Mtime, &c.Version); err != nil {
			return nil, err
		}
		c.IsDir = c.Kind == "dir"
		out = append(out, c)
	}
	return out, rows.Err()
}

// IsDir reports whether `path` is a directory in the manifest tree. A path
// counts as a directory when EITHER it has children (appears as a parent in
// dir_entries) OR it has been registered as a name under its own parent
// (explicit mkdir, or transitively created when a descendant was Put). The
// two-arm check matches DirCreate's existence semantics so a stat after a
// failed mkdir(EEXIST) returns the same answer the mkdir saw — without
// this, an empty / drained directory shows up as ENOENT to handleStat
// while DirCreate still rejects it as already-exists, and `mkdir -p`
// prints "File exists" then aborts.
func (m *ManifestStore) IsDir(path string) (bool, error) {
	var n int
	err := m.db.QueryRow(`select 1 from dir_entries where parent = ? limit 1`, path).Scan(&n)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	parent, name := splitParentName(path)
	if name == "" {
		// Root: always a directory.
		return true, nil
	}
	err = m.db.QueryRow(
		`select 1 from dir_entries where parent = ? and name = ? limit 1`,
		parent, name,
	).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// DirCreate creates a new directory at p. ErrParentNotFound if the parent
// directory does not exist; ErrAlreadyExists if p is already registered.
func (m *ManifestStore) DirCreate(p string, mode uint32) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	parent, name := splitParentName(p)

	// Parent must exist (unless it is root which always exists implicitly).
	if err := checkParentExists(tx, p); err != nil {
		return err
	}

	// Conflict if already exists.
	var existing int
	err = tx.QueryRow(
		`select 1 from dir_entries where parent = ? and name = ? limit 1`, parent, name,
	).Scan(&existing)
	if err == nil {
		return ErrAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if mode == 0 {
		mode = 0o755
	}
	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(
		`insert into dir_entries(parent, name, mode, uid, gid, atime, rev) values(?, ?, ?, 0, 0, 0, ?)`, parent, name, mode&0o7777, rev,
	); err != nil {
		return fmt.Errorf("insert dir_entry %s: %w", p, err)
	}
	if err := clearTombstoneTx(tx, p); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.notifyChange(rev)
	return nil
}

// DirInfo returns the stored mode + owner + atime for a directory path.
// ok=false when p is not a registered directory. The root ("/") is an implicit
// 0755 directory owned by uid/gid 0.
func (m *ManifestStore) DirInfo(p string) (mode uint32, uid, gid uint32, atime int64, ok bool, err error) {
	parent, name := splitParentName(p)
	if name == "" {
		return 0o755, 0, 0, 0, true, nil
	}
	row := m.db.QueryRow(
		`select mode, uid, gid, atime from dir_entries where parent = ? and name = ?`, parent, name,
	)
	err = row.Scan(&mode, &uid, &gid, &atime)
	if errors.Is(err, sql.ErrNoRows) {
		// May still be a directory if it only appears as a parent of children
		// (transitively created). Treat as a default-mode dir in that case.
		isDir, dErr := m.IsDir(p)
		if dErr != nil {
			return 0, 0, 0, 0, false, dErr
		}
		if isDir {
			return 0o755, 0, 0, 0, true, nil
		}
		return 0, 0, 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, 0, 0, false, err
	}
	if mode == 0 {
		mode = 0o755
	}
	return mode, uid, gid, atime, true, nil
}

// Symlink creates a symbolic link at p pointing at target. ErrParentNotFound if
// the parent dir is missing; ErrAlreadyExists if p already exists (file, dir, or
// symlink). The link is registered in dir_entries too so it appears in listings.
func (m *ManifestStore) Symlink(p, target string, mode uint32) error {
	if mode == 0 {
		mode = 0o777
	}
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	parent, name := splitParentName(p)
	if name == "" {
		return fmt.Errorf("cannot symlink root")
	}
	if err := checkParentExists(tx, p); err != nil {
		return err
	}
	// Conflict if any entry already occupies p.
	var existing int
	err = tx.QueryRow(`select 1 from dir_entries where parent = ? and name = ? limit 1`, parent, name).Scan(&existing)
	if err == nil {
		return ErrAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(
		`insert into symlinks(path, target, mode, mtime, uid, gid, atime, rev) values(?, ?, ?, 0, 0, 0, 0, ?)`, p, target, mode&0o7777, rev,
	); err != nil {
		return fmt.Errorf("insert symlink %s: %w", p, err)
	}
	if _, err := tx.Exec(
		`insert into dir_entries(parent, name, mode, uid, gid, atime) values(?, ?, ?, 0, 0, 0)`, parent, name, mode&0o7777,
	); err != nil {
		return fmt.Errorf("register symlink dir_entry %s: %w", p, err)
	}
	if err := clearTombstoneTx(tx, p); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.notifyChange(rev)
	return nil
}

// Readlink returns the target of the symlink at p. ErrManifestNotFound if p is
// not a symlink.
func (m *ManifestStore) Readlink(p string) (string, error) {
	var target string
	err := m.db.QueryRow(`select target from symlinks where path = ?`, p).Scan(&target)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrManifestNotFound
	}
	if err != nil {
		return "", err
	}
	return target, nil
}

// SymlinkInfo reports a symlink's target+mode+owner+atime. ok=false when p is
// not a symlink.
func (m *ManifestStore) SymlinkInfo(p string) (target string, mode uint32, uid, gid uint32, atime int64, ok bool, err error) {
	err = m.db.QueryRow(`select target, mode, uid, gid, atime from symlinks where path = ?`, p).Scan(&target, &mode, &uid, &gid, &atime)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, 0, 0, 0, false, nil
	}
	if err != nil {
		return "", 0, 0, 0, 0, false, err
	}
	if mode == 0 {
		mode = 0o777
	}
	return target, mode, uid, gid, atime, true, nil
}

// Mknod creates a POSIX special node (FIFO, socket, or block/char device) at p.
// mode carries the S_IF* type bits | permission bits; rdev is the device number
// (0 for fifo/socket). ErrParentNotFound if the parent dir is missing;
// ErrAlreadyExists if p already exists (file, dir, symlink, or special node).
// Registered in dir_entries so it appears in listings. Mirrors Symlink.
func (m *ManifestStore) Mknod(p string, mode uint32, rdev uint64) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	parent, name := splitParentName(p)
	if name == "" {
		return fmt.Errorf("cannot mknod root")
	}
	if err := checkParentExists(tx, p); err != nil {
		return err
	}
	// Conflict if any entry already occupies p.
	var existing int
	err = tx.QueryRow(`select 1 from dir_entries where parent = ? and name = ? limit 1`, parent, name).Scan(&existing)
	if err == nil {
		return ErrAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(
		`insert into special_nodes(path, mode, rdev, mtime, uid, gid, atime, rev) values(?, ?, ?, 0, 0, 0, 0, ?)`, p, mode, rdev, rev,
	); err != nil {
		return fmt.Errorf("insert special node %s: %w", p, err)
	}
	if _, err := tx.Exec(
		`insert into dir_entries(parent, name, mode, uid, gid, atime) values(?, ?, ?, 0, 0, 0)`, parent, name, mode&0o7777,
	); err != nil {
		return fmt.Errorf("register special node dir_entry %s: %w", p, err)
	}
	if err := clearTombstoneTx(tx, p); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.notifyChange(rev)
	return nil
}

// SpecialNodeInfo reports a special node's mode+rdev+owner+atime and the derived
// kind ("fifo"/"socket"/"chardev"/"blockdev"). ok=false when p is not a special
// node. Mirrors SymlinkInfo.
func (m *ManifestStore) SpecialNodeInfo(p string) (mode uint32, rdev uint64, uid, gid uint32, atime int64, kind string, ok bool, err error) {
	err = m.db.QueryRow(`select mode, rdev, uid, gid, atime from special_nodes where path = ?`, p).Scan(&mode, &rdev, &uid, &gid, &atime)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, 0, 0, 0, "", false, nil
	}
	if err != nil {
		return 0, 0, 0, 0, 0, "", false, err
	}
	return mode, rdev, uid, gid, atime, specialNodeKind(mode), true, nil
}

// deleteSpecialNode removes the special node row + its dir_entry. Returns
// ErrManifestNotFound if p is not a special node. Mirrors deleteSymlink.
func (m *ManifestStore) deleteSpecialNode(p string) error {
	return m.deletePathRow("special_nodes", "special node", p)
}

// SetMode changes the permission bits of the file, directory, or symlink at p.
// Files route through a journaled manifest version bump (revert-complete);
// directories and symlinks update their metadata row directly (dir/symlink
// metadata is not journaled, matching the existing dir-op model). ENOENT-
// equivalent (ErrManifestNotFound) when p does not exist.
func (m *ManifestStore) SetMode(p string, mode uint32, sessionID, allocationID, agentID, activeLeaseHex string) (err error) {
	// chmod is metadata-only (no fsync'd chunk backing it): under WAL + synchronous=NORMAL the
	// commit sits in the un-checkpointed WAL tail, so a metadata-only change can be lost on an
	// unclean restart while file CONTENT survives (chunks are fsync'd to the chunk store
	// independently). Force a checkpoint on success so the new mode is durable immediately;
	// chmod is rare relative to content writes, so the extra fsync is negligible amortized.
	defer func() {
		if err == nil {
			_, _ = m.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		}
	}()
	mode &= 0o7777
	// File: bump the manifest's mode under a journaled, lease-fenced version
	// increment (same authenticity guarantees as a content write).
	mf, err := m.Get(p)
	if err == nil {
		mf.Mode = mode
		_, perr := m.PutWithLeaseCheck(p, mf.Version, mf, sessionID, allocationID, agentID, activeLeaseHex)
		return perr
	}
	if !errors.Is(err, ErrManifestNotFound) {
		return err
	}
	// Symlink / special node / directory: metadata-only rows, one transaction
	// so the change-rev allocation commits (or rolls back) with the stamp.
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return err
	}
	commitNotify := func() error {
		if cErr := tx.Commit(); cErr != nil {
			return cErr
		}
		m.notifyChange(rev)
		return nil
	}
	// Symlink.
	if res, sErr := tx.Exec(`update symlinks set mode = ?, rev = ? where path = ?`, mode, rev, p); sErr != nil {
		return sErr
	} else if n, _ := res.RowsAffected(); n > 0 {
		return commitNotify()
	}
	// Special node: chmod must preserve the type bits (S_IF*) so a fifo/device
	// stays a fifo/device. Read the stored mode, replace only the perm bits.
	var oldMode uint32
	snErr := tx.QueryRow(`select mode from special_nodes where path = ?`, p).Scan(&oldMode)
	if snErr == nil {
		newMode := (oldMode & sIFMT) | (mode & 0o7777)
		if _, uErr := tx.Exec(`update special_nodes set mode = ?, rev = ? where path = ?`, newMode, rev, p); uErr != nil {
			return uErr
		}
		return commitNotify()
	}
	if !errors.Is(snErr, sql.ErrNoRows) {
		return snErr
	}
	// Directory.
	parent, name := splitParentName(p)
	if name == "" {
		return nil // root: nothing to persist, succeed (rollback discards the rev)
	}
	res, dErr := tx.Exec(`update dir_entries set mode = ?, rev = ? where parent = ? and name = ?`, mode, rev, parent, name)
	if dErr != nil {
		return dErr
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrManifestNotFound
	}
	return commitNotify()
}

// SetOwner stores uid+gid for the file, directory, or symlink at p (chown).
// Store-and-readback only — no permission enforcement on a single-identity
// agent disk. Unlike SetMode, ownership is metadata-only and not journaled
// (matching the dir/symlink mode model). Fan-out order mirrors handleStat:
// manifests (file) → symlinks → dir_entries (directory). ENOENT-equivalent
// (ErrManifestNotFound) when p does not exist; root ("/") succeeds as a no-op.
func (m *ManifestStore) SetOwner(p string, uid, gid uint32) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return err
	}
	commitNotify := func() error {
		if cErr := tx.Commit(); cErr != nil {
			return cErr
		}
		m.notifyChange(rev)
		return nil
	}
	// File.
	if res, fErr := tx.Exec(`
		update manifests set uid = ?, gid = ?, rev = ?
		where inode_id = (select inode_id from manifests where path = ?)
	`, uid, gid, rev, p); fErr != nil {
		return fErr
	} else if n, _ := res.RowsAffected(); n > 0 {
		return commitNotify()
	}
	// Symlink.
	if res, sErr := tx.Exec(`update symlinks set uid = ?, gid = ?, rev = ? where path = ?`, uid, gid, rev, p); sErr != nil {
		return sErr
	} else if n, _ := res.RowsAffected(); n > 0 {
		return commitNotify()
	}
	// Special node.
	if res, snErr := tx.Exec(`update special_nodes set uid = ?, gid = ?, rev = ? where path = ?`, uid, gid, rev, p); snErr != nil {
		return snErr
	} else if n, _ := res.RowsAffected(); n > 0 {
		return commitNotify()
	}
	// Directory.
	parent, name := splitParentName(p)
	if name == "" {
		return nil // root: nothing to persist, succeed (rollback discards the rev)
	}
	res, dErr := tx.Exec(`update dir_entries set uid = ?, gid = ?, rev = ? where parent = ? and name = ?`, uid, gid, rev, parent, name)
	if dErr != nil {
		return dErr
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrManifestNotFound
	}
	return commitNotify()
}

// SetAtime stores the access time (atime) for the file, directory, or symlink
// at p (utimensat). Store-and-readback only; same three-table fan-out and
// not-journaled model as SetOwner.
func (m *ManifestStore) SetAtime(p string, atime int64) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return err
	}
	commitNotify := func() error {
		if cErr := tx.Commit(); cErr != nil {
			return cErr
		}
		m.notifyChange(rev)
		return nil
	}
	// File.
	if res, fErr := tx.Exec(`
		update manifests set atime = ?, rev = ?
		where inode_id = (select inode_id from manifests where path = ?)
	`, atime, rev, p); fErr != nil {
		return fErr
	} else if n, _ := res.RowsAffected(); n > 0 {
		return commitNotify()
	}
	// Symlink.
	if res, sErr := tx.Exec(`update symlinks set atime = ?, rev = ? where path = ?`, atime, rev, p); sErr != nil {
		return sErr
	} else if n, _ := res.RowsAffected(); n > 0 {
		return commitNotify()
	}
	// Special node.
	if res, snErr := tx.Exec(`update special_nodes set atime = ?, rev = ? where path = ?`, atime, rev, p); snErr != nil {
		return snErr
	} else if n, _ := res.RowsAffected(); n > 0 {
		return commitNotify()
	}
	// Directory.
	parent, name := splitParentName(p)
	if name == "" {
		return nil // root: nothing to persist, succeed (rollback discards the rev)
	}
	res, dErr := tx.Exec(`update dir_entries set atime = ?, rev = ? where parent = ? and name = ?`, atime, rev, parent, name)
	if dErr != nil {
		return dErr
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrManifestNotFound
	}
	return commitNotify()
}

// DirRemove removes the directory at p. ErrManifestNotFound if it does not
// exist; ErrNotEmpty if it still has children in dir_entries or manifests.
func (m *ManifestStore) DirRemove(p string) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	parent, name := splitParentName(p)

	var ok int
	err = tx.QueryRow(
		`select 1 from dir_entries where parent = ? and name = ? limit 1`, parent, name,
	).Scan(&ok)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrManifestNotFound
	}
	if err != nil {
		return fmt.Errorf("lookup dir_entry %s: %w", p, err)
	}

	// Check child dir_entries.
	var children int
	if err := tx.QueryRow(
		`select count(*) from dir_entries where parent = ?`, p,
	).Scan(&children); err != nil {
		return err
	}
	if children > 0 {
		return ErrNotEmpty
	}

	// Check child manifests (files directly under this dir).
	var files int
	if err := tx.QueryRow(
		`select count(*) from manifests where path glob ?`, p+"/*",
	).Scan(&files); err != nil {
		return err
	}
	if files > 0 {
		return ErrNotEmpty
	}

	if _, err := tx.Exec(
		`delete from dir_entries where parent = ? and name = ?`, parent, name,
	); err != nil {
		return fmt.Errorf("delete dir_entry %s: %w", p, err)
	}
	rev, err := allocChangeRevTx(tx)
	if err != nil {
		return err
	}
	if err := upsertTombstoneTx(tx, p, rev); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.notifyChange(rev)
	return nil
}

// checkParentExists verifies that p's parent directory is registered in
// dir_entries. Skips the check when p's parent is "/" (root always exists).
// Returns ErrParentNotFound when the parent is missing.
func checkParentExists(tx *sql.Tx, p string) error {
	parent, _ := splitParentName(p)
	if parent == "/" {
		return nil
	}
	grandparent, parentName := splitParentName(parent)
	var ok int
	err := tx.QueryRow(
		`select 1 from dir_entries where parent = ? and name = ? limit 1`,
		grandparent, parentName,
	).Scan(&ok)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrParentNotFound
	}
	if err != nil {
		return fmt.Errorf("parent check: %w", err)
	}
	return nil
}

// applyChunkRefDelta writes the refcount changes described by delta into the
// chunks table inside tx. It ensures every referenced hash row exists (with
// refcount 0) before applying the delta, so negative deltas never underflow.
func applyChunkRefDelta(tx *sql.Tx, delta map[[HashLen]byte]int) error {
	for hash, d := range delta {
		if d == 0 {
			continue
		}
		if _, err := tx.Exec(
			`insert into chunks(hash, size, refcount, added_at) values(?, 0, 0, 0)
			 on conflict(hash) do nothing`,
			hash[:],
		); err != nil {
			return fmt.Errorf("chunk row init: %w", err)
		}
		if _, err := tx.Exec(
			`update chunks set refcount = refcount + ? where hash = ?`,
			d, hash[:],
		); err != nil {
			return fmt.Errorf("chunk refcount update: %w", err)
		}
	}
	return nil
}

// NoteChunkStored records that a content chunk exists on disk with an initial
// refcount of 0, so a chunk that is uploaded but whose manifest commit never
// lands (a CAS-conflicted, quota-rejected, or cancelled WriteFile) is still
// visible to the refcount GC and reclaimed after the retention window — instead
// of leaking on disk until the whole tenant is deleted. Idempotent: an existing
// row (already refcounted by a manifest, or already noted) is left untouched, so
// this never disturbs a live chunk's refcount or resets its retention clock.
// addedAt is real wall-clock Unix seconds (the GC measures the window from it)
// and size lets the GC account freed bytes — both improving on the placeholder
// 0/0 that applyChunkRefDelta writes when it has to create a row itself.
func (m *ManifestStore) NoteChunkStored(hash []byte, size, addedAt int64) error {
	if _, err := m.db.Exec(
		`insert into chunks(hash, size, refcount, added_at) values(?, ?, 0, ?)
		 on conflict(hash) do nothing`,
		hash, size, addedAt,
	); err != nil {
		return fmt.Errorf("note chunk stored: %w", err)
	}
	return nil
}

// chunkRefDelta returns the net refcount change for each hash when transitioning
// from old chunks to new chunks. Positive = gained references, negative = lost.
func chunkRefDelta(old, new []ChunkRef) map[[HashLen]byte]int {
	m := make(map[[HashLen]byte]int)
	for _, r := range new {
		m[r.Hash]++
	}
	for _, r := range old {
		m[r.Hash]--
	}
	return m
}

func splitParentName(p string) (string, string) {
	clean := path.Clean(p)
	if clean == "/" || clean == "." {
		return "/", ""
	}
	parent := path.Dir(clean)
	name := strings.TrimPrefix(clean, parent)
	name = strings.TrimPrefix(name, "/")
	return parent, name
}

func packChunks(chunks []ChunkRef) []byte {
	out := make([]byte, len(chunks)*chunkRefSize)
	for i, c := range chunks {
		off := i * chunkRefSize
		copy(out[off:off+HashLen], c.Hash[:])
		binary.BigEndian.PutUint64(out[off+HashLen:off+HashLen+8], c.Offset)
		binary.BigEndian.PutUint32(out[off+HashLen+8:off+HashLen+8+4], c.Len)
	}
	return out
}

// PutWithLeaseCheck wraps Put with session_id authenticity validation.
// Production callers (the dataplane server) use this. Direct unit tests
// can still call Put directly to bypass the check.
func (m *ManifestStore) PutWithLeaseCheck(
	p string, expectedVersion uint64, mf Manifest,
	sessionID, allocationID, agentID, activeLeaseHex string,
) (uint64, error) {
	if err := validateSessionIDForLease(sessionID, activeLeaseHex); err != nil {
		return 0, err
	}
	return m.Put(p, expectedVersion, mf, sessionID, allocationID, agentID)
}

// LinkWithLeaseCheck wraps Link with session_id authenticity validation.
func (m *ManifestStore) LinkWithLeaseCheck(
	from, to, sessionID, allocationID, agentID, activeLeaseHex string,
) (uint32, error) {
	if err := validateSessionIDForLease(sessionID, activeLeaseHex); err != nil {
		return 0, err
	}
	return m.Link(from, to, sessionID, allocationID, agentID)
}

// DeleteWithLeaseCheck wraps Delete with session_id authenticity validation.
func (m *ManifestStore) DeleteWithLeaseCheck(
	p string, expectedVersion uint64,
	sessionID, allocationID, agentID, activeLeaseHex string,
) error {
	if err := validateSessionIDForLease(sessionID, activeLeaseHex); err != nil {
		return err
	}
	return m.Delete(p, expectedVersion, sessionID, allocationID, agentID)
}

// RenameWithLeaseCheck wraps renameOpt with session_id authenticity validation.
func (m *ManifestStore) RenameWithLeaseCheck(
	from, to string, expectedFrom, expectedTo uint64, noReplace bool,
	sessionID, allocationID, agentID, activeLeaseHex string,
) (uint64, error) {
	if err := validateSessionIDForLease(sessionID, activeLeaseHex); err != nil {
		return 0, err
	}
	return m.renameOpt(from, to, expectedFrom, expectedTo, noReplace, sessionID, allocationID, agentID)
}

// sessionMountPrefix is the canonical prefix for implicit-mount session IDs:
// the client formats them as `sessionMountPrefix + hex(lease_id)`. The
// authoritative active lease (and the value compared against the client's
// session_id) is tracked per allocation in serverState.mountLeases.
const sessionMountPrefix = "mount:"

// sessionRevertPrefix tags a revert's inverse-write session_id when no
// mount lease is currently active for the allocation (all clients
// disconnected between click and dispatch). Lets the journal row still
// surface in the sidebar without colliding with the mount: namespace.
const sessionRevertPrefix = "revert:"

// validateSessionIDForLease enforces that a write's session_id matches
// sessionMountPrefix + the connection's currently-active lease (hex). Empty
// activeLeaseHex means the connection has no active lease, so any
// session_id is rejected (EACCES). See spec §4.3.
func validateSessionIDForLease(sessionID, activeLeaseHex string) error {
	if sessionID == "" {
		return nil
	}
	if activeLeaseHex == "" {
		return fmt.Errorf("session_id check: no active lease on connection")
	}
	want := sessionMountPrefix + activeLeaseHex
	if sessionID != want {
		return fmt.Errorf("session_id mismatch: got %q, want %q (EACCES)",
			sessionID, want)
	}
	return nil
}

func unpackChunks(blob []byte) ([]ChunkRef, error) {
	if len(blob)%chunkRefSize != 0 {
		return nil, fmt.Errorf("manifest chunks blob is %d bytes, not a multiple of %d", len(blob), chunkRefSize)
	}
	n := len(blob) / chunkRefSize
	out := make([]ChunkRef, n)
	for i := 0; i < n; i++ {
		off := i * chunkRefSize
		var hash [HashLen]byte
		copy(hash[:], blob[off:off+HashLen])
		out[i] = ChunkRef{
			Hash:   hash,
			Offset: binary.BigEndian.Uint64(blob[off+HashLen : off+HashLen+8]),
			Len:    binary.BigEndian.Uint32(blob[off+HashLen+8 : off+HashLen+8+4]),
		}
	}
	return out, nil
}
