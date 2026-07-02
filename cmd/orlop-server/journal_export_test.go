package main

import (
	"database/sql"
	"fmt"
)

// Diff returns the journal rows for sessionID in ascending seq order. Each
// entry carries the column-level after_version (set at write time). The
// parallel liveAfters slice holds the version a fresh JOIN against manifests
// reports. Used by journal_test.go and manifests_journal_test.go; this lives
// in a _test.go file so it cannot be linked into the orlop-server binary.
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
