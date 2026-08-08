package main

// Metadata change feed (issue #122, docs/design-metadata-mirror.md).
//
// Every metadata mutation allocates one revision from the per-tenant
// change_counter inside its own SQLite transaction and stamps the rows it
// touches; deletions record tombstones. The tenant database itself is the
// coalesced change log: "everything under a subtree that changed since
// revision N" is a query over current state plus tombstones, ordered by the
// compound (rev, path) cursor. There is no operation replay — final-state
// entries are idempotent to apply and make cold start the same code path as
// catch-up.
//
// The live side is a conflating doorbell (changeNotifier): subscribers learn
// "the tenant is now at revision R" and pull the delta with CHANGES_FETCH.
// A doorbell carries no entries, so a slow consumer can never be dropped for
// buffering reasons and duplicate or reordered delivery collapses into the
// fetch path's idempotency.

import (
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ChangeEntry is one coalesced final-state row of the change feed: the
// current state of one path (or its tombstone), stamped with the revision of
// the last mutation that touched it. Kind mirrors the EntryWire kinds plus
// "tombstone".
type ChangeEntry struct {
	Path    string
	Kind    string
	Rev     uint64
	Size    uint64
	Mode    uint32
	Mtime   int64
	Uid     uint32
	Gid     uint32
	Atime   int64
	InodeID uint64
	Nlink   uint32
	Version uint64
	Target  string
	Rdev    uint64
	// Chunks is the unpacked manifest chunk list, populated only for files
	// when the caller asked for chunks. HasChunks distinguishes "included and
	// empty" (zero-length file) from "not requested".
	Chunks    []ChunkRef
	HasChunks bool
}

// allocChangeRevTx allocates the next change revision inside tx. Exactly one
// revision per mutating transaction; the counter update and the row stamps
// commit (or roll back) together, so no committed row can ever carry a
// revision above change_counter.last_rev.
func allocChangeRevTx(tx *sql.Tx) (uint64, error) {
	var rev uint64
	if err := tx.QueryRow(`
		update change_counter set last_rev = last_rev + 1
		where singleton = 1
		returning last_rev
	`).Scan(&rev); err != nil {
		return 0, fmt.Errorf("allocate change rev: %w", err)
	}
	return rev, nil
}

// upsertTombstoneTx records that path was deleted at rev. A later re-create
// clears the tombstone (clearTombstoneTx), so at most one of {live row,
// tombstone} exists per path at any time.
func upsertTombstoneTx(tx *sql.Tx, p string, rev uint64) error {
	if _, err := tx.Exec(`
		insert into change_tombstones(path, rev, ts_unix_ms) values(?, ?, ?)
		on conflict(path) do update set rev = excluded.rev, ts_unix_ms = excluded.ts_unix_ms
	`, p, rev, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("upsert tombstone %s: %w", p, err)
	}
	return nil
}

// clearTombstoneTx removes any tombstone at p; called by every create-style
// mutation so a re-created path is represented by its live row alone.
func clearTombstoneTx(tx *sql.Tx, p string) error {
	if _, err := tx.Exec(`delete from change_tombstones where path = ?`, p); err != nil {
		return fmt.Errorf("clear tombstone %s: %w", p, err)
	}
	return nil
}

// clearTombstoneSubtreeTx removes tombstones at p and under p/. Used when a
// directory rename moves a subtree onto paths that may have tombstones.
func clearTombstoneSubtreeTx(tx *sql.Tx, p string) error {
	if _, err := tx.Exec(
		`delete from change_tombstones where path = ? or path like ? escape '\'`,
		p, escapeLike(p)+"/%",
	); err != nil {
		return fmt.Errorf("clear tombstones under %s: %w", p, err)
	}
	return nil
}

// tombstoneSubtreeTx records tombstones for every live path at p or under p/
// across all four metadata tables, at rev. Used by directory renames (old
// descendant paths vanish) and agent purge (bulk delete). Runs before the
// rows are rewritten or deleted so the SELECTs still see them.
func tombstoneSubtreeTx(tx *sql.Tx, p string, rev uint64) error {
	nowMs := time.Now().UnixMilli()
	like := escapeLike(p) + "/%"
	for _, q := range []string{
		`insert into change_tombstones(path, rev, ts_unix_ms)
		   select path, ?1, ?2 from manifests where path = ?3 or path like ?4 escape '\'
		 on conflict(path) do update set rev = excluded.rev, ts_unix_ms = excluded.ts_unix_ms`,
		`insert into change_tombstones(path, rev, ts_unix_ms)
		   select path, ?1, ?2 from symlinks where path = ?3 or path like ?4 escape '\'
		 on conflict(path) do update set rev = excluded.rev, ts_unix_ms = excluded.ts_unix_ms`,
		`insert into change_tombstones(path, rev, ts_unix_ms)
		   select path, ?1, ?2 from special_nodes where path = ?3 or path like ?4 escape '\'
		 on conflict(path) do update set rev = excluded.rev, ts_unix_ms = excluded.ts_unix_ms`,
		`insert into change_tombstones(path, rev, ts_unix_ms)
		   select case when parent = '/' then '/' || name else parent || '/' || name end, ?1, ?2
		     from dir_entries
		    where (case when parent = '/' then '/' || name else parent || '/' || name end) = ?3
		       or (case when parent = '/' then '/' || name else parent || '/' || name end) like ?4 escape '\'
		 on conflict(path) do update set rev = excluded.rev, ts_unix_ms = excluded.ts_unix_ms`,
	} {
		if _, err := tx.Exec(q, rev, nowMs, p, like); err != nil {
			return fmt.Errorf("tombstone subtree %s: %w", p, err)
		}
	}
	return nil
}

// changeFeedState reads the counter row: the last allocated revision and the
// resync watermark (cursors below prunedBefore may have missed pruned
// tombstones and must rebaseline).
func changeFeedState(db *sql.DB) (lastRev, prunedBefore uint64, err error) {
	err = db.QueryRow(
		`select last_rev, pruned_before_rev from change_counter where singleton = 1`,
	).Scan(&lastRev, &prunedBefore)
	if err != nil {
		return 0, 0, fmt.Errorf("read change feed state: %w", err)
	}
	return lastRev, prunedBefore, nil
}

// queryChanges returns feed entries strictly after the (cursorRev,
// cursorPath) compound cursor, limited to subtree (path == subtree or under
// subtree + "/"; empty subtree means the whole tenant), ordered by
// (rev, path), at most limit rows. Directories that also exist as a file /
// symlink / special node path are represented by their primary row only.
func queryChanges(db *sql.DB, subtree string, cursorRev uint64, cursorPath string, limit int, includeChunks bool) ([]ChangeEntry, error) {
	subtreeLike := ""
	if subtree != "" {
		subtreeLike = escapeLike(subtree) + "/%"
	}
	rows, err := db.Query(`
		select path, kind, rev, size, mode, mtime, uid, gid, atime, inode_id, nlink, version, target, rdev, chunks
		from (
			select mf.path as path, 'file' as kind, mf.rev as rev, mf.size as size, mf.mode as mode,
			       mf.mtime as mtime, mf.uid as uid, mf.gid as gid, mf.atime as atime,
			       mf.inode_id as inode_id,
			       (select count(*) from manifests l where l.inode_id = mf.inode_id) as nlink,
			       mf.version as version, '' as target, 0 as rdev, mf.chunks as chunks
			  from manifests mf
			union all
			select sl.path, 'symlink', sl.rev, length(sl.target), sl.mode, sl.mtime, sl.uid, sl.gid, sl.atime,
			       0, 1, 0, sl.target, 0, null
			  from symlinks sl
			union all
			select sn.path, 'special', sn.rev, 0, sn.mode, sn.mtime, sn.uid, sn.gid, sn.atime,
			       0, 1, 0, '', sn.rdev, null
			  from special_nodes sn
			union all
			select d.full_path, 'dir', d.rev, 0, d.mode, d.mtime, d.uid, d.gid, d.atime,
			       0, 1, 0, '', 0, null
			  from (select case when parent = '/' then '/' || name else parent || '/' || name end as full_path,
			               rev, mode, mtime, uid, gid, atime
			          from dir_entries) d
			 where not exists (select 1 from manifests m2 where m2.path = d.full_path)
			   and not exists (select 1 from symlinks s2 where s2.path = d.full_path)
			   and not exists (select 1 from special_nodes n2 where n2.path = d.full_path)
			union all
			select t.path, 'tombstone', t.rev, 0, 0, 0, 0, 0, 0, 0, 0, 0, '', 0, null
			  from change_tombstones t
		)
		where (rev > ?1 or (rev = ?1 and path > ?2))
		  and (?3 = '' or path = ?3 or path like ?4 escape '\')
		order by rev, path
		limit ?5
	`, cursorRev, cursorPath, subtree, subtreeLike, limit)
	if err != nil {
		return nil, fmt.Errorf("query changes: %w", err)
	}
	defer rows.Close()

	var out []ChangeEntry
	for rows.Next() {
		var (
			e    ChangeEntry
			blob []byte
		)
		if err := rows.Scan(&e.Path, &e.Kind, &e.Rev, &e.Size, &e.Mode, &e.Mtime,
			&e.Uid, &e.Gid, &e.Atime, &e.InodeID, &e.Nlink, &e.Version,
			&e.Target, &e.Rdev, &blob); err != nil {
			return nil, err
		}
		switch e.Kind {
		case "file":
			if includeChunks {
				chunks, cErr := unpackChunks(blob)
				if cErr != nil {
					return nil, fmt.Errorf("unpack chunks for %s: %w", e.Path, cErr)
				}
				e.Chunks = chunks
				e.HasChunks = true
			}
		case "dir":
			// Match DirInfo: an unset stored mode reads as 0755.
			if e.Mode == 0 {
				e.Mode = 0o755
			}
		case "symlink":
			// Match SymlinkInfo: an unset stored mode reads as 0777.
			if e.Mode == 0 {
				e.Mode = 0o777
			}
		case "special":
			// The wire speaks concrete kinds; derive from the stored type bits.
			if k := specialNodeKind(e.Mode); k != "" {
				e.Kind = k
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// pruneTombstones deletes tombstones older than cutoffUnixMs and advances the
// pruned_before_rev watermark to (highest pruned rev + 1), so a client
// resuming from a cursor below the watermark is told to rebaseline instead of
// silently missing deletions. Bounds change_tombstones growth; called from
// the GC tick with the chunk retention window.
func pruneTombstones(db *sql.DB, cutoffUnixMs int64) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var maxPruned sql.NullInt64
	if err := tx.QueryRow(
		`select max(rev) from change_tombstones where ts_unix_ms < ?`, cutoffUnixMs,
	).Scan(&maxPruned); err != nil {
		return 0, fmt.Errorf("select prunable tombstones: %w", err)
	}
	if !maxPruned.Valid {
		return 0, nil
	}
	res, err := tx.Exec(`delete from change_tombstones where ts_unix_ms < ?`, cutoffUnixMs)
	if err != nil {
		return 0, fmt.Errorf("prune tombstones: %w", err)
	}
	n, _ := res.RowsAffected()
	if _, err := tx.Exec(
		`update change_counter set pruned_before_rev = max(pruned_before_rev, ?) where singleton = 1`,
		uint64(maxPruned.Int64)+1,
	); err != nil {
		return 0, fmt.Errorf("advance pruned_before_rev: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// changeNotifier fans committed-revision doorbells out to per-connection
// subscribers. Conflating: each subscriber holds only the latest revision and
// a one-slot signal, so a slow consumer coalesces bursts instead of being
// dropped (the journal pub/sub must buffer entries and drop slow consumers;
// a doorbell has nothing to buffer). All methods are safe on a nil receiver
// so test fixtures that build tenantState by hand need no wiring.
type changeNotifier struct {
	mu   sync.Mutex
	subs map[uint64]*changeSub
}

// changeSub is one connection's doorbell: the latest revision to report and
// a conflating signal. done is closed when the subscription is replaced or
// the connection goes away; the pump goroutine exits on it.
type changeSub struct {
	rev    atomic.Uint64
	signal chan struct{}
	done   chan struct{}
}

func newChangeNotifier() *changeNotifier {
	return &changeNotifier{subs: make(map[uint64]*changeSub)}
}

// Notify records rev as the latest committed revision and rings every
// subscriber. Non-blocking; called post-commit by every metadata mutation.
func (n *changeNotifier) Notify(rev uint64) {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, sub := range n.subs {
		for {
			cur := sub.rev.Load()
			if cur >= rev || sub.rev.CompareAndSwap(cur, rev) {
				break
			}
		}
		select {
		case sub.signal <- struct{}{}:
		default:
		}
	}
}

// Subscribe registers connID for doorbells, replacing (and terminating) any
// prior subscription on the same connection.
func (n *changeNotifier) Subscribe(connID uint64) *changeSub {
	if n == nil {
		return nil
	}
	sub := &changeSub{signal: make(chan struct{}, 1), done: make(chan struct{})}
	n.mu.Lock()
	if old, ok := n.subs[connID]; ok {
		close(old.done)
	}
	n.subs[connID] = sub
	n.mu.Unlock()
	return sub
}

// DropConn terminates connID's subscription, if any. Wired as a connection
// teardown defer next to lease release.
func (n *changeNotifier) DropConn(connID uint64) {
	if n == nil {
		return
	}
	n.mu.Lock()
	if sub, ok := n.subs[connID]; ok {
		close(sub.done)
		delete(n.subs, connID)
	}
	n.mu.Unlock()
}
