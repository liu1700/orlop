package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// SessionOp is the wire-stable op tag stored in session_journal.op. Mirrored
// on the Rust side as a SessionOp enum.
type SessionOp string

const (
	SessionOpCreate SessionOp = "create"
	SessionOpUpdate SessionOp = "update"
	SessionOpDelete SessionOp = "delete"
	SessionOpRename SessionOp = "rename"
)

// SessionJournalEntry is one row read back from session_journal.
//
// BeforeVersion / BeforeManifest are nil for SessionOpCreate (no prior state
// to undo to). RenameFrom is empty unless Op == SessionOpRename. AfterVersion
// is the version the forward op left at `path`; nil for delete rows. Used by
// revert as the CAS-expected when applying the inverse so concurrent writers
// surface as RevertConflict instead of being silently overwritten. Distinct
// from the LIVE-joined after_version returned by SessionJournal.Diff() —
// that one reflects the path's current state at diff time.
type SessionJournalEntry struct {
	SessionID      string
	AllocationID   string
	AgentID        string
	Seq            uint64
	Path           string
	Op             SessionOp
	BeforeVersion  *uint64
	AfterVersion   *uint64
	BeforeManifest []byte
	RenameFrom     string
	TsUnixMs       int64
}

// appendJournal inserts one row into session_journal inside the caller's
// transaction. Returns an error on insert failure so the caller can roll back
// the manifest write — "best-effort logging" in the issue means best-effort
// for the journal *but the manifest write must fail loudly if we can't log*,
// otherwise the change is unrevertable.
//
// `seq` is computed by SQLite as max(seq)+1 inside the same INSERT, which
// keeps it serialised with the manifest write under SQLite's writer lock.
// (session_id, seq) is the table's primary key — together they keep seqs
// gap-free per session.
//
// `agentID` is the cert-bound agent identifier from the data-plane connection's
// AuditIdentity. Persisted alongside session_id so the LastWriter recovery
// hint (issue #100) can name both pieces in one query.
func appendJournal(
	tx *sql.Tx,
	sessionID string,
	allocationID string,
	agentID string,
	op SessionOp,
	path string,
	beforeVersion *uint64,
	afterVersion *uint64,
	beforeManifest []byte,
	renameFrom string,
	metrics *serverMetrics,
) error {
	if sessionID == "" {
		return fmt.Errorf("appendJournal: empty session_id")
	}
	if allocationID == "" {
		return fmt.Errorf("appendJournal: empty allocation_id")
	}

	beforeVer := sql.NullInt64{}
	if beforeVersion != nil {
		beforeVer = sql.NullInt64{Int64: int64(*beforeVersion), Valid: true}
	}
	afterVer := sql.NullInt64{}
	if afterVersion != nil {
		afterVer = sql.NullInt64{Int64: int64(*afterVersion), Valid: true}
	}
	rename := sql.NullString{}
	if renameFrom != "" {
		rename = sql.NullString{String: renameFrom, Valid: true}
	}

	if _, err := tx.Exec(
		`insert into session_journal
		   (session_id, seq, path, op, before_version, before_manifest, rename_from,
		    ts_unix_ms, after_version, agent_id, allocation_id)
		 values (?, (select coalesce(max(seq), 0) + 1 from session_journal where session_id = ?),
		         ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, sessionID,
		path, string(op), beforeVer, beforeManifest, rename,
		time.Now().UnixMilli(), afterVer, agentID, allocationID,
	); err != nil {
		return fmt.Errorf("insert journal row %s: %w", sessionID, err)
	}
	metrics.journalWrite(string(op), allocationID)
	return nil
}

// journalBeforeWrite is the shared "capture inverse op" path used by Put,
// Delete, and Rename. priorMf is nil for create-style writes (no before-
// state). Otherwise it's msgpack-encoded into before_manifest with its
// version stashed in before_version. `afterVersion` is the version the
// forward op left at `path` (nil for delete) — recorded so revert can
// CAS-detect concurrent writers without trusting a live JOIN.
//
// Returns the just-inserted SessionJournalEntry so callers can fan it out
// via the journal pub/sub once their transaction commits. The seq is read
// back inside the same tx (SQLite serialises writes per session under the
// writer lock, so max(seq) for the session is the row just inserted).
func journalBeforeWrite(
	tx *sql.Tx,
	sessionID string,
	allocationID string,
	agentID string,
	op SessionOp,
	path string,
	priorMf *Manifest,
	afterVersion *uint64,
	renameFrom string,
	metrics *serverMetrics,
) (*SessionJournalEntry, error) {
	var (
		beforeVer  *uint64
		beforeBlob []byte
	)
	if priorMf != nil {
		v := priorMf.Version
		beforeVer = &v
		blob, err := encodeJournalManifest(*priorMf)
		if err != nil {
			return nil, fmt.Errorf("encode journal manifest %s: %w", path, err)
		}
		beforeBlob = blob
	}
	if err := appendJournal(tx, sessionID, allocationID, agentID, op, path, beforeVer, afterVersion, beforeBlob, renameFrom, metrics); err != nil {
		return nil, err
	}
	var (
		seq      uint64
		tsUnixMs int64
	)
	if err := tx.QueryRow(
		`select seq, ts_unix_ms from session_journal
		 where session_id = ? order by seq desc limit 1`,
		sessionID,
	).Scan(&seq, &tsUnixMs); err != nil {
		return nil, fmt.Errorf("read back journal seq %s: %w", sessionID, err)
	}
	return &SessionJournalEntry{
		SessionID:      sessionID,
		AllocationID:   allocationID,
		AgentID:        agentID,
		Seq:            seq,
		Path:           path,
		Op:             op,
		BeforeVersion:  beforeVer,
		AfterVersion:   afterVersion,
		BeforeManifest: beforeBlob,
		RenameFrom:     renameFrom,
		TsUnixMs:       tsUnixMs,
	}, nil
}

// journalManifestBlob is the msgpack shape stored in
// session_journal.before_manifest. Server-internal only — revert decodes
// it to restore prior state. Not on the wire.
//
// Path is intentionally absent — the row's `path` column is the canonical
// location (and for rename rows, that's the destination, while the blob
// describes the source which is already named in `rename_from`).
type journalManifestBlob struct {
	Size    uint64            `msgpack:"size"`
	Mode    uint32            `msgpack:"mode"`
	Mtime   int64             `msgpack:"mtime"`
	Version uint64            `msgpack:"version"`
	Chunks  []journalChunkRef `msgpack:"chunks"`
}

type journalChunkRef struct {
	Hash   []byte `msgpack:"hash"`
	Offset uint64 `msgpack:"offset"`
	Len    uint32 `msgpack:"len"`
}

// encodeJournalManifest msgpack-encodes mf for the journal blob column.
func encodeJournalManifest(mf Manifest) ([]byte, error) {
	refs := make([]journalChunkRef, len(mf.Chunks))
	for i, c := range mf.Chunks {
		hash := c.Hash
		refs[i] = journalChunkRef{Hash: hash[:], Offset: c.Offset, Len: c.Len}
	}
	return msgpack.Marshal(journalManifestBlob{
		Size: mf.Size, Mode: mf.Mode, Mtime: mf.Mtime,
		Version: mf.Version, Chunks: refs,
	})
}

// SessionJournal reads the session_journal table. Writes go through the
// per-op manifests.go paths, which call appendJournal inside their own tx.
type SessionJournal struct {
	db      *sql.DB
	metrics *serverMetrics
	pubsub  *journalPubSub
}

func NewSessionJournal(db *sql.DB, metrics *serverMetrics) *SessionJournal {
	return &SessionJournal{db: db, metrics: metrics, pubsub: newJournalPubSub()}
}

// Subscribe registers a subscriber for live append events on allocID. See
// journalPubSub.Subscribe for the channel-lifecycle contract.
func (j *SessionJournal) Subscribe(ctx context.Context, allocID string) (<-chan SessionJournalEntry, func()) {
	return j.pubsub.Subscribe(ctx, allocID)
}

// Broadcast fans out a committed journal entry to subscribers on the same
// allocID. Must only be called after the manifest write transaction has
// committed; a pre-commit broadcast risks delivering rows that never landed.
func (j *SessionJournal) Broadcast(allocID string, entry SessionJournalEntry) {
	j.pubsub.Broadcast(allocID, entry)
}

// SnapshotRowCounts returns the current row count per allocation_id from
// session_journal. Caller compares with the previous snapshot to decide
// which gauge time series to set vs. delete (allocation cascade-deletes
// leave no rows but the in-memory gauge would otherwise retain the label).
func (j *SessionJournal) SnapshotRowCounts(ctx context.Context) (map[string]int64, error) {
	if j == nil || j.db == nil {
		return nil, nil
	}
	rows, err := j.db.QueryContext(ctx, `select allocation_id, count(*) from session_journal group by allocation_id`)
	if err != nil {
		return nil, fmt.Errorf("query journal row counts: %w", err)
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var allocID string
		var n int64
		if err := rows.Scan(&allocID, &n); err != nil {
			return nil, fmt.Errorf("scan journal row count: %w", err)
		}
		counts[allocID] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate journal row counts: %w", err)
	}
	return counts, nil
}

// EnsureSchema makes sure session_journal exists with every column the
// revert path needs. The Rust crate's init() owns the canonical schema for
// fresh routes.db files; this path is the server-side safety net for
// dynamic tenant registration (brand-new empty routes.db) and routes.db
// files written before later columns (after_version, agent_id) landed.
// Both cases are additive — nothing here mutates existing data.
func (j *SessionJournal) EnsureSchema() error {
	if _, err := j.db.Exec(`
		create table if not exists session_journal (
		  session_id text not null,
		  seq integer not null,
		  path text not null,
		  op text not null,
		  before_version integer,
		  before_manifest blob,
		  rename_from text,
		  ts_unix_ms integer not null,
		  after_version integer,
		  agent_id text not null default '',
		  allocation_id text,
		  primary key (session_id, seq)
		);
		create index if not exists session_journal_by_session
		  on session_journal(session_id);
		create index if not exists session_journal_by_path
		  on session_journal(path, ts_unix_ms desc);
	`); err != nil {
		return fmt.Errorf("ensure session_journal schema: %w", err)
	}
	have := map[string]bool{}
	rows, err := j.db.Query(`pragma table_info(session_journal)`)
	if err != nil {
		return fmt.Errorf("inspect session_journal columns: %w", err)
	}
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("scan column info: %w", err)
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if !have["after_version"] {
		if _, err := j.db.Exec(`alter table session_journal add column after_version integer`); err != nil {
			return fmt.Errorf("add after_version column: %w", err)
		}
	}
	if !have["agent_id"] {
		if _, err := j.db.Exec(
			`alter table session_journal add column agent_id text not null default ''`,
		); err != nil {
			return fmt.Errorf("add agent_id column: %w", err)
		}
	}
	if !have["allocation_id"] {
		if _, err := j.db.Exec(
			`alter table session_journal add column allocation_id text`,
		); err != nil {
			return fmt.Errorf("add allocation_id column: %w", err)
		}
	}
	if _, err := j.db.Exec(`
		create index if not exists session_journal_by_allocation_ts
		  on session_journal(allocation_id, ts_unix_ms desc)
	`); err != nil {
		return fmt.Errorf("create session_journal_by_allocation_ts index: %w", err)
	}
	return nil
}

// LastWriterRow is the most-recent journal-tracked writer for a path, used
// by the CAS conflict recovery hint (issue #100). All fields are zero-valued
// when no writer is known.
type LastWriterRow struct {
	AgentID   string
	SessionID string
	AtUnixMs  int64
}

// LookupLastWriter returns the most recent journal entry for p. Returns
// (nil, nil) when no journal row exists for the path — in that case the
// CAS conflict came from a non-sessioned writer (e.g., the migrate-to-chunks
// tool) and there is no author to surface. Reads outside the manifest_put
// transaction; the lookup is best-effort metadata for the recovery hint, not
// a correctness-critical signal.
func (j *SessionJournal) LookupLastWriter(p string) (*LastWriterRow, error) {
	// seq is per-session, so two writers to the same path in the same millisecond
	// tie on both ts_unix_ms and seq (each session's first write is seq 1). rowid
	// — monotonic insertion order — is the deterministic final tiebreak: the
	// last-inserted row is the most recent writer.
	row := j.db.QueryRow(
		`select agent_id, session_id, ts_unix_ms
		 from session_journal
		 where path = ?
		 order by ts_unix_ms desc, seq desc, rowid desc
		 limit 1`,
		p,
	)
	var (
		agentID   string
		sessionID string
		tsUnixMs  int64
	)
	switch err := row.Scan(&agentID, &sessionID, &tsUnixMs); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("lookup last_writer for %s: %w", p, err)
	}
	return &LastWriterRow{AgentID: agentID, SessionID: sessionID, AtUnixMs: tsUnixMs}, nil
}


// DeleteRow drops a single (session_id, seq) row. RevertPaths calls it
// once a row's inverse op has landed so a re-run does not undo it again.
func (j *SessionJournal) DeleteRow(sessionID string, seq uint64) error {
	if _, err := j.db.Exec(
		`delete from session_journal where session_id = ? and seq = ?`,
		sessionID, seq,
	); err != nil {
		return fmt.Errorf("delete journal row %s/%d: %w", sessionID, seq, err)
	}
	return nil
}

// decodeJournalManifest reverses encodeJournalManifest. The path column on
// the journal row is canonical, so the caller passes it in rather than
// having us re-encode it inside the blob.
func decodeJournalManifest(p string, blob []byte) (Manifest, error) {
	var raw journalManifestBlob
	if err := msgpack.Unmarshal(blob, &raw); err != nil {
		return Manifest{}, fmt.Errorf("decode journal manifest %s: %w", p, err)
	}
	chunks := make([]ChunkRef, len(raw.Chunks))
	for i, c := range raw.Chunks {
		ref := ChunkRef{Offset: c.Offset, Len: c.Len}
		if len(c.Hash) != HashLen {
			return Manifest{}, fmt.Errorf(
				"journal manifest %s: chunk %d hash len = %d, want %d",
				p, i, len(c.Hash), HashLen,
			)
		}
		copy(ref.Hash[:], c.Hash)
		chunks[i] = ref
	}
	return Manifest{
		Path: p, Size: raw.Size, Mode: raw.Mode, Mtime: raw.Mtime,
		Version: raw.Version, Chunks: chunks,
	}, nil
}

// ListAllocations returns the distinct allocation_ids recorded in the journal.
// Used by handleJournalQuery when the caller requests a merged feed across all
// of the tenant's allocations (AllocationID == ""). The tenant DB is already
// scoped to one tenant, so no additional ownership check is needed.
func (j *SessionJournal) ListAllocations() ([]string, error) {
	rows, err := j.db.Query(
		`select distinct allocation_id from session_journal
		 where allocation_id is not null and allocation_id != ''`,
	)
	if err != nil {
		return nil, fmt.Errorf("list allocations: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan allocation_id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// journalQueryCols is the shared select-list for any code path that
// materialises a JournalQueryRow. Pinning it here keeps Query and
// QueryAfterSeq from drifting on column order and forces them through
// the same scanJournalRow decoder.
const journalQueryCols = `j.session_id, j.allocation_id, j.seq, j.ts_unix_ms,
	j.path, j.op, j.agent_id, j.before_version, j.after_version,
	j.rename_from, j.before_manifest, m.size`

// scanJournalRow decodes one row from a query that selected journalQueryCols.
// Handles nullable columns and the msgpack-encoded before_manifest blob;
// SizeAfter is omitted for delete rows because the live manifest is already
// gone. `extra` scan targets are appended after journalQueryCols — Query passes
// &rowid so it can build the keyset cursor without leaking rowid into the row.
func scanJournalRow(rows *sql.Rows, extra ...any) (JournalQueryRow, error) {
	var (
		row         JournalQueryRow
		allocID     sql.NullString
		beforeVer   sql.NullInt64
		afterVer    sql.NullInt64
		renameFrom  sql.NullString
		beforeMf    []byte
		currentSize sql.NullInt64
	)
	dest := []any{
		&row.SessionID, &allocID, &row.Seq, &row.TsUnixMs,
		&row.Path, &row.Op, &row.AgentID,
		&beforeVer, &afterVer, &renameFrom, &beforeMf, &currentSize,
	}
	dest = append(dest, extra...)
	if err := rows.Scan(dest...); err != nil {
		return JournalQueryRow{}, err
	}
	if allocID.Valid {
		row.AllocationID = allocID.String
	}
	if beforeVer.Valid {
		v := uint64(beforeVer.Int64)
		row.BeforeVersion = &v
	}
	if afterVer.Valid {
		v := uint64(afterVer.Int64)
		row.AfterVersion = &v
	}
	if renameFrom.Valid {
		row.RenameFrom = renameFrom.String
	}
	if len(beforeMf) > 0 {
		if mf, decErr := decodeJournalManifest(row.Path, beforeMf); decErr == nil {
			v := mf.Size
			row.SizeBefore = &v
		}
	}
	if currentSize.Valid && row.Op != string(SessionOpDelete) {
		v := uint64(currentSize.Int64)
		row.SizeAfter = &v
	}
	return row, nil
}

// QueryAfterSeq returns journal rows for allocationID with seq strictly
// greater than afterSeq, in ascending seq order. It is the catch-up half of
// the SSE stream's "first deliver gap rows, then live-subscribe" handshake:
// the caller passes its last-seen seq, gets every row written since, and
// then subscribes to the pub/sub for live updates.
//
// `limit` caps the rows returned (0 means no limit, for back-compat with
// callers that pre-date the cap). The SSE handler passes a real value to
// bound the worst-case bulk dump when a client reconnects after a long
// idle window.
//
// Rows are decoded into the same JournalQueryRow shape as Query so the SSE
// handler can serialise both catch-up rows and live rows through the same
// JSON envelope.
func (j *SessionJournal) QueryAfterSeq(allocationID string, afterSeq uint64, limit int) ([]JournalQueryRow, error) {
	if allocationID == "" {
		return nil, fmt.Errorf("QueryAfterSeq: empty allocation_id")
	}
	var (
		rows *sql.Rows
		err  error
	)
	if limit > 0 {
		rows, err = j.db.Query(
			`select `+journalQueryCols+`
			 from session_journal j
			 left join manifests m on m.path = j.path
			 where j.allocation_id = ? and j.seq > ?
			 order by j.seq asc
			 limit ?`,
			allocationID, afterSeq, limit,
		)
	} else {
		rows, err = j.db.Query(
			`select `+journalQueryCols+`
			 from session_journal j
			 left join manifests m on m.path = j.path
			 where j.allocation_id = ? and j.seq > ?
			 order by j.seq asc`,
			allocationID, afterSeq,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("journal catch-up query: %w", err)
	}
	defer rows.Close()

	var out []JournalQueryRow
	for rows.Next() {
		row, scanErr := scanJournalRow(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan catch-up row: %w", scanErr)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// Diff returns the journal rows for sessionID in ascending seq order. Each
// entry carries the column-level after_version (set at write time). The
// parallel liveAfters slice holds the version a fresh JOIN against manifests
// reports. Used by journal_test.go and manifests_journal_test.go.
func (j *SessionJournal) Diff(sessionID string) ([]SessionJournalEntry, []*uint64, error) {
	rows, err := j.db.Query(
		`select j.session_id, j.seq, j.path, j.op, j.before_version, j.before_manifest,
		        j.rename_from, j.ts_unix_ms, j.after_version, m.version
		 from session_journal j
		 left join manifests m on m.path = j.path
		 where j.session_id = ?
		 order by j.seq asc`,
		sessionID,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("query session_journal: %w", err)
	}
	defer rows.Close()

	var (
		out        []SessionJournalEntry
		liveAfters []*uint64
	)
	for rows.Next() {
		var (
			entry           SessionJournalEntry
			opStr           string
			beforeVer       sql.NullInt64
			beforeMf        []byte
			renameFromCol   sql.NullString
			afterSessionVer sql.NullInt64
			afterLiveVer    sql.NullInt64
		)
		if err := rows.Scan(
			&entry.SessionID, &entry.Seq, &entry.Path, &opStr,
			&beforeVer, &beforeMf, &renameFromCol, &entry.TsUnixMs,
			&afterSessionVer, &afterLiveVer,
		); err != nil {
			return nil, nil, fmt.Errorf("scan session_journal row: %w", err)
		}
		entry.Op = SessionOp(opStr)
		if beforeVer.Valid {
			v := uint64(beforeVer.Int64)
			entry.BeforeVersion = &v
		}
		if afterSessionVer.Valid {
			v := uint64(afterSessionVer.Int64)
			entry.AfterVersion = &v
		}
		entry.BeforeManifest = beforeMf
		if renameFromCol.Valid {
			entry.RenameFrom = renameFromCol.String
		}
		out = append(out, entry)
		var av *uint64
		if afterLiveVer.Valid {
			v := uint64(afterLiveVer.Int64)
			av = &v
		}
		liveAfters = append(liveAfters, av)
	}
	return out, liveAfters, rows.Err()
}

// JournalQueryRow is one scanned row from Query. Mirrors dataplane.JournalEntry
// field-for-field but lives in package main to avoid an import cycle
// (journal.go is package main; dataplane.JournalEntry is package dataplane).
// The handler (handleJournalQuery) converts between the two.
type JournalQueryRow struct {
	SessionID     string
	AllocationID  string
	Seq           uint64
	TsUnixMs      int64
	Path          string
	Op            string
	AgentID       string
	BeforeVersion *uint64
	AfterVersion  *uint64
	RenameFrom    string
	SizeBefore    *uint64
	SizeAfter     *uint64
}

// Query returns journal rows in newest-first order.
//
// If allocationID is non-empty, returns rows for that allocation only.
// If allocationID is empty, returns rows for all allocations in
// userAllocations (intended for the dashboard merged-feed view). An empty
// userAllocations with an empty allocationID returns nil with no error.
//
// Pagination is keyset (seek) on the composite key (ts_unix_ms, rowid): cursor
// is an opaque token; pass "" for the first page and the returned nextCursor for
// the next; nextCursor == "" means no more rows. rowid is the tiebreaker because
// ts_unix_ms is not unique (ms-granular) and seq is only unique per session — a
// ts-only cursor silently drops rows that tie on the boundary millisecond.
//
// limit is clamped to [1, 200]; 0 defaults to 50.
func (j *SessionJournal) Query(
	allocationID string,
	limit uint32,
	cursor string,
	userAllocations []string,
) (out []JournalQueryRow, nextCursor string, err error) {
	timer := j.metrics.newJournalQueryTimer()
	defer timer.ObserveDuration()

	if limit == 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	// curTs == 0 ⇒ first page (ts_unix_ms is always > 0 for real rows). The
	// keyset predicate is the standard seek form for ORDER BY ts desc, rowid desc.
	curTs, curRowid := decodeJournalCursor(cursor)
	const keyset = `(? = 0 OR j.ts_unix_ms < ? OR (j.ts_unix_ms = ? AND j.rowid < ?))`
	const order = ` order by j.ts_unix_ms desc, j.rowid desc limit ?`

	var sqlRows *sql.Rows
	if allocationID != "" {
		sqlRows, err = j.db.Query(
			`select `+journalQueryCols+`, j.rowid
			 from session_journal j
			 left join manifests m on m.path = j.path
			 where j.allocation_id = ? and `+keyset+order,
			allocationID, curTs, curTs, curTs, curRowid, limit,
		)
	} else {
		if len(userAllocations) == 0 {
			return nil, "", nil
		}
		placeholders := strings.TrimRight(strings.Repeat("?,", len(userAllocations)), ",")
		args := make([]any, 0, len(userAllocations)+5)
		for _, a := range userAllocations {
			args = append(args, a)
		}
		args = append(args, curTs, curTs, curTs, curRowid, limit)
		sqlRows, err = j.db.Query(
			`select `+journalQueryCols+`, j.rowid
			 from session_journal j
			 left join manifests m on m.path = j.path
			 where j.allocation_id in (`+placeholders+`) and `+keyset+order,
			args...,
		)
	}
	if err != nil {
		return nil, "", fmt.Errorf("journal query: %w", err)
	}
	defer sqlRows.Close()

	out = make([]JournalQueryRow, 0, limit)
	var lastTs, lastRowid int64
	for sqlRows.Next() {
		var rowid int64
		row, scanErr := scanJournalRow(sqlRows, &rowid)
		if scanErr != nil {
			return nil, "", fmt.Errorf("scan journal row: %w", scanErr)
		}
		out = append(out, row)
		lastTs, lastRowid = row.TsUnixMs, rowid
	}
	if err := sqlRows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate journal rows: %w", err)
	}
	if uint32(len(out)) < limit {
		return out, "", nil // last page — no cursor
	}
	return out, encodeJournalCursor(lastTs, lastRowid), nil
}

// encodeJournalCursor builds the opaque keyset cursor "<ts_unix_ms>.<rowid>".
func encodeJournalCursor(tsUnixMs, rowid int64) string {
	return strconv.FormatInt(tsUnixMs, 10) + "." + strconv.FormatInt(rowid, 10)
}

// decodeJournalCursor parses a cursor token into its (ts, rowid) components.
// An empty or malformed cursor decodes to (0, 0) — i.e. start from the first
// page — so a bad token degrades to "newest" rather than erroring.
func decodeJournalCursor(s string) (tsUnixMs, rowid int64) {
	tsStr, rowidStr, ok := strings.Cut(s, ".")
	if !ok {
		return 0, 0
	}
	ts, err1 := strconv.ParseInt(tsStr, 10, 64)
	rid, err2 := strconv.ParseInt(rowidStr, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0
	}
	return ts, rid
}
