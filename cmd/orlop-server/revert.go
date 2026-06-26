package main

import (
	"database/sql"
	"errors"
	"fmt"
)

// RevertConflictError surfaces a CAS mismatch encountered while replaying a
// session journal in reverse. The agent that asked to revert can use these
// fields to render a `RecoveryHint{ kind: revert_conflict }` to the caller.
//
// `Path` is the manifest path the inverse op was applied to (for renames,
// this is the post-rename destination — the journal column where the row
// was recorded). `CurrentVersion` is the live version on the server when
// CAS failed; zero means "no manifest exists at Path right now."
type RevertConflictError struct {
	Path           string
	CurrentVersion uint64
}

func (e *RevertConflictError) Error() string {
	return fmt.Sprintf("revert conflict at %s (current version %d)", e.Path, e.CurrentVersion)
}

// JournalRevertConflict is the package-main mirror of dataplane.RevertConflict,
// used to avoid an import cycle between package main and package dataplane.
// handleJournalRevertPath converts between the two at the handler boundary.
type JournalRevertConflict struct {
	Path   string
	Reason string // one of Reason* consts below
}

// Conflict reason tokens — wire-stable strings shared with the TS client.
// Promoted to consts so the producer (this package) and the test/handler
// readers can't drift on a typo.
const (
	ReasonNoJournalRow     = "no_journal_row"
	ReasonConcurrentWriter = "concurrent_writer"
	ReasonRevertBlocked    = "revert_blocked"
)

// RevertPaths queries the journal by (allocation_id, path), walks the most
// recent journal row for each requested path in reverse, and applies the
// inverse op under CAS.
//
// For each path in `paths`:
//   - If no journal row exists → appends JournalRevertConflict{Reason: ReasonNoJournalRow}
//   - If expectedSeqs[i] is non-zero and the latest row's seq does not match
//     it (a newer write landed between page render and click), and
//     force=false → appends JournalRevertConflict{Reason: ReasonConcurrentWriter}
//   - If the live version doesn't match the journal's after_version (concurrent
//     writer) and force=false → appends JournalRevertConflict{Reason: ReasonConcurrentWriter}
//   - On success → appends the path to revertedPaths and deletes the journal row
//
// `expectedSeqs` may be nil (legacy wire — dataplane handler doesn't carry
// seqs) or the same length as paths. Each non-zero element pins the
// expected latest seq for the matching path; zero means "don't check."
//
// Unlike the old RevertSession, this does not mark any session ended. Implicit
// sessions live and die with the lease; there is no explicit lifecycle to close.
//
// The inverse manifest write is itself journaled under (writerSessionID,
// allocationID, writerAgentID) so a sidebar SSE subscriber receives a new
// entry for the revert via the post-commit Broadcast hook in
// manifests.{Put,Delete,Rename} (commit f1fb076). writerSessionID is the
// originating connection's active mount session — resolved by the handler.
//
// When force=true, both the seq-pin check and the CAS-mismatch check are
// bypassed: the inverse write proceeds against whatever live version exists.
// Per spec §10.1 the resulting journal row's before_version reflects the live
// state actually overwritten, not the pre-divergence row's after_version —
// the journal is the truth, not a tidy story.
//
// Returns (revertedPaths, conflicts, err). err is non-nil only for unexpected
// I/O failures; per-path conflicts are returned in the conflicts slice.
func (j *SessionJournal) RevertPaths(
	allocationID string,
	paths []string,
	expectedSessionIDs []string,
	expectedSeqs []uint64,
	manifests *ManifestStore,
	writerSessionID string,
	writerAgentID string,
	force bool,
) (revertedPaths []string, conflicts []JournalRevertConflict, err error) {
	if expectedSeqs != nil && len(expectedSeqs) != len(paths) {
		return nil, nil, fmt.Errorf("RevertPaths: expectedSeqs len=%d, paths len=%d", len(expectedSeqs), len(paths))
	}
	if expectedSessionIDs != nil && len(expectedSessionIDs) != len(paths) {
		return nil, nil, fmt.Errorf("RevertPaths: expectedSessionIDs len=%d, paths len=%d", len(expectedSessionIDs), len(paths))
	}
	for i, path := range paths {
		// Row lookup: when the caller supplies (session_id, seq), target the
		// exact row — seq is per-session, so a take-over boundary can leave
		// two distinct rows in the same allocation sharing the same seq, and
		// latestRowForPath would resolve to whichever happens to be newest.
		// Falls back to "latest row" when either pin is missing (dataplane
		// callers don't carry seq today).
		var (
			row     *SessionJournalEntry
			lookErr error
		)
		var pinnedSession string
		if expectedSessionIDs != nil {
			pinnedSession = expectedSessionIDs[i]
		}
		var pinnedSeq uint64
		if expectedSeqs != nil {
			pinnedSeq = expectedSeqs[i]
		}
		if pinnedSession != "" && pinnedSeq != 0 {
			row, lookErr = j.rowForSessionSeq(allocationID, path, pinnedSession, pinnedSeq)
		} else {
			row, lookErr = j.latestRowForPath(allocationID, path)
		}
		if lookErr != nil {
			return revertedPaths, conflicts, fmt.Errorf("lookup journal row for %s: %w", path, lookErr)
		}
		if row == nil {
			conflicts = append(conflicts, JournalRevertConflict{Path: path, Reason: ReasonNoJournalRow})
			continue
		}

		// Seq pin sanity-check: only meaningful when we did a latest-row
		// lookup (the pinned-row branch already guarantees seq match). Refuse
		// when latest seq doesn't match the user's click — spec §10.2 routes
		// this through the concurrent_writer modal.
		if !force && pinnedSession == "" && expectedSeqs != nil && expectedSeqs[i] != 0 && row.Seq != expectedSeqs[i] {
			conflicts = append(conflicts, JournalRevertConflict{Path: path, Reason: ReasonConcurrentWriter})
			continue
		}

		// CAS check: live version must match the journal's after_version.
		// Skipped on force=true — divergence is recorded honestly per §10.1.
		live, err := liveManifestVersion(manifests, path)
		if err != nil {
			return revertedPaths, conflicts, fmt.Errorf("read live version for %s: %w", path, err)
		}
		if !force && !equalOptVersion(live, row.AfterVersion) {
			conflicts = append(conflicts, JournalRevertConflict{Path: path, Reason: ReasonConcurrentWriter})
			continue
		}

		// working map seeds the single-row inverse (same pattern as applyInverse).
		working := map[string]*uint64{path: live}
		// For rename rows we also need to seed the source path.
		if row.Op == SessionOpRename && row.RenameFrom != "" {
			srcLive, err := liveManifestVersion(manifests, row.RenameFrom)
			if err != nil {
				return revertedPaths, conflicts, fmt.Errorf("read live version for rename_from %s: %w", row.RenameFrom, err)
			}
			working[row.RenameFrom] = srcLive
		}

		if err := applyInverse(manifests, *row, working, writerSessionID, allocationID, writerAgentID); err != nil {
			var ce *RevertConflictError
			if errors.As(err, &ce) {
				conflicts = append(conflicts, JournalRevertConflict{Path: ce.Path, Reason: ReasonConcurrentWriter})
				continue
			}
			return revertedPaths, conflicts, fmt.Errorf("apply inverse for %s: %w", path, err)
		}

		if err := j.DeleteRow(row.SessionID, row.Seq); err != nil {
			return revertedPaths, conflicts, fmt.Errorf("prune journal row %s/%d: %w", row.SessionID, row.Seq, err)
		}
		revertedPaths = append(revertedPaths, path)
	}

	// Emit revert outcome metrics aggregated by result so we don't loop twice.
	if len(revertedPaths) > 0 {
		j.metrics.journalRevert(allocationID, "reverted", len(revertedPaths))
	}
	conflictCounts := make(map[string]int, len(conflicts))
	for _, c := range conflicts {
		conflictCounts[c.Reason]++
	}
	for reason, n := range conflictCounts {
		j.metrics.journalRevert(allocationID, reason, n)
	}

	return revertedPaths, conflicts, nil
}

// latestRowForPath returns the most recent journal row for (allocation_id, path),
// or nil if none exists. Used by RevertPaths.
func (j *SessionJournal) latestRowForPath(allocationID, path string) (*SessionJournalEntry, error) {
	row := j.db.QueryRow(
		`select session_id, seq, path, op, before_version, before_manifest,
		        rename_from, ts_unix_ms, after_version
		 from session_journal
		 where allocation_id = ? and path = ?
		 order by ts_unix_ms desc, seq desc
		 limit 1`,
		allocationID, path,
	)
	return scanRevertRow(row, allocationID, path)
}

// rowForSessionSeq targets the exact row the user clicked. The primary key
// is (session_id, seq); seq is per-session, so a mount take-over can produce
// two distinct rows with the same (allocation_id, seq) tuple. allocation_id
// + path are folded in as cheap safety rails — a pinned lookup that misses
// is treated by the caller as no_journal_row.
func (j *SessionJournal) rowForSessionSeq(allocationID, path, sessionID string, seq uint64) (*SessionJournalEntry, error) {
	row := j.db.QueryRow(
		`select session_id, seq, path, op, before_version, before_manifest,
		        rename_from, ts_unix_ms, after_version
		 from session_journal
		 where session_id = ? and seq = ?
		   and allocation_id = ? and path = ?
		 limit 1`,
		sessionID, seq, allocationID, path,
	)
	return scanRevertRow(row, allocationID, path)
}

func scanRevertRow(row *sql.Row, allocationID, path string) (*SessionJournalEntry, error) {
	var (
		entry         SessionJournalEntry
		opStr         string
		beforeVer     sql.NullInt64
		beforeMf      []byte
		renameFromCol sql.NullString
		afterVer      sql.NullInt64
	)
	err := row.Scan(
		&entry.SessionID, &entry.Seq, &entry.Path, &opStr,
		&beforeVer, &beforeMf, &renameFromCol, &entry.TsUnixMs, &afterVer,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan journal row for %s/%s: %w", allocationID, path, err)
	}
	entry.Op = SessionOp(opStr)
	if beforeVer.Valid {
		v := uint64(beforeVer.Int64)
		entry.BeforeVersion = &v
	}
	if afterVer.Valid {
		v := uint64(afterVer.Int64)
		entry.AfterVersion = &v
	}
	entry.BeforeManifest = beforeMf
	if renameFromCol.Valid {
		entry.RenameFrom = renameFromCol.String
	}
	return &entry, nil
}

// applyInverse issues the per-op inverse against `manifests`, threading
// `working` so consecutive reverts on the same path use the version we just
// wrote (rather than the journal's stale joined `after_version`). On the
// first inverse for a path the entry was seeded by the pre-pass in
// RevertPaths; subsequent reverts update it in place.
//
// sessionID/allocationID/agentID are passed through to manifests.{Put,Delete,
// Rename} so the inverse write itself emits a journal row (and fires the
// post-commit Broadcast subscribers depend on for the live sidebar — see
// f1fb076). An empty sessionID would skip journaling entirely; the caller
// (RevertPaths via the dataplane handler) is responsible for supplying a
// non-empty session.
func applyInverse(
	manifests *ManifestStore,
	row SessionJournalEntry,
	working map[string]*uint64,
	sessionID, allocationID, agentID string,
) error {
	switch row.Op {
	case SessionOpCreate:
		curr := working[row.Path]
		if curr == nil {
			// Already gone — a later in-session Delete row already rolled
			// it back (we walk in reverse). No-op.
			return nil
		}
		if err := manifests.Delete(row.Path, *curr, sessionID, allocationID, agentID); err != nil {
			return wrapCAS(err, row.Path)
		}
		working[row.Path] = nil
		return nil

	case SessionOpUpdate:
		curr := working[row.Path]
		if curr == nil {
			return &RevertConflictError{Path: row.Path, CurrentVersion: 0}
		}
		prior, err := decodeJournalManifest(row.Path, row.BeforeManifest)
		if err != nil {
			return err
		}
		newV, err := manifests.Put(row.Path, *curr, prior, sessionID, allocationID, agentID)
		if err != nil {
			return wrapCAS(err, row.Path)
		}
		working[row.Path] = &newV
		return nil

	case SessionOpDelete:
		if curr := working[row.Path]; curr != nil {
			return &RevertConflictError{Path: row.Path, CurrentVersion: *curr}
		}
		prior, err := decodeJournalManifest(row.Path, row.BeforeManifest)
		if err != nil {
			return err
		}
		newV, err := manifests.Put(row.Path, 0, prior, sessionID, allocationID, agentID)
		if err != nil {
			return wrapCAS(err, row.Path)
		}
		working[row.Path] = &newV
		return nil

	case SessionOpRename:
		curr := working[row.Path]
		if curr == nil {
			return &RevertConflictError{Path: row.Path, CurrentVersion: 0}
		}
		// Lazy seed: row.RenameFrom may not have appeared in the pre-pass
		// (the journal never wrote there directly). Read live now.
		fromCurr, ok := working[row.RenameFrom]
		if !ok {
			live, err := liveManifestVersion(manifests, row.RenameFrom)
			if err != nil {
				return err
			}
			fromCurr = live
			working[row.RenameFrom] = live
		}
		if fromCurr != nil {
			return &RevertConflictError{Path: row.RenameFrom, CurrentVersion: *fromCurr}
		}
		newV, err := manifests.Rename(row.Path, row.RenameFrom, *curr, 0, sessionID, allocationID, agentID)
		if err != nil {
			if errors.Is(err, ErrAlreadyExists) {
				return &RevertConflictError{Path: row.RenameFrom, CurrentVersion: 0}
			}
			return wrapCAS(err, row.Path)
		}
		working[row.Path] = nil
		working[row.RenameFrom] = &newV
		return nil

	default:
		return fmt.Errorf("revert: unknown op %q at %s", row.Op, row.Path)
	}
}

// liveManifestVersion reads the current live version of `path` from the
// manifest store. nil = no row.
func liveManifestVersion(m *ManifestStore, path string) (*uint64, error) {
	mf, err := m.Get(path)
	if errors.Is(err, ErrManifestNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v := mf.Version
	return &v, nil
}

func equalOptVersion(a, b *uint64) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

// wrapCAS upgrades a VersionConflictError into a *RevertConflictError so the
// handler can format a RecoveryHint, and passes everything else through.
func wrapCAS(err error, path string) error {
	var vc *VersionConflictError
	if errors.As(err, &vc) {
		return &RevertConflictError{Path: path, CurrentVersion: vc.Existing}
	}
	return err
}
