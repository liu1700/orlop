package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

const leaseSchema = `
CREATE TABLE IF NOT EXISTS leases (
  lease_id    BLOB PRIMARY KEY,
  path        TEXT NOT NULL,
  mode        INTEGER NOT NULL,
  holder      TEXT NOT NULL,
  granted_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS leases_by_path ON leases(path);
`

func (m *leaseManager) Snapshot(dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(leaseSchema); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM leases"); err != nil {
		_ = tx.Rollback()
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO leases (lease_id, path, mode, holder, granted_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rec := range m.byID {
		if _, err := stmt.Exec(rec.id[:], rec.path, int(rec.mode), rec.holder, rec.grantedAt.UnixMilli(), rec.expiresAt.UnixMilli()); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (m *leaseManager) Restore(dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(leaseSchema); err != nil {
		return err
	}
	rows, err := db.Query("SELECT lease_id, path, mode, holder, granted_at, expires_at FROM leases WHERE expires_at > ?", time.Now().UnixMilli())
	if err != nil {
		return err
	}
	defer rows.Close()

	m.mu.Lock()
	defer m.mu.Unlock()
	for rows.Next() {
		var (
			leaseID   []byte
			path      string
			mode      int
			holder    string
			grantedAt int64
			expiresAt int64
		)
		if err := rows.Scan(&leaseID, &path, &mode, &holder, &grantedAt, &expiresAt); err != nil {
			return err
		}
		if len(leaseID) != 16 {
			return fmt.Errorf("invalid lease_id length %d in db", len(leaseID))
		}
		var id [16]byte
		copy(id[:], leaseID)
		rec := &leaseRecord{
			path:      path,
			mode:      dataplane.LeaseMode(mode),
			holder:    holder,
			connID:    0, // unknown until client reconnects
			grantedAt: time.UnixMilli(grantedAt),
			expiresAt: time.UnixMilli(expiresAt),
			id:        id,
		}
		m.byID[id] = rec
		m.byPath[path] = rec
		// connID 0 is conceptually "no live conn"; not added to byConn.
	}
	return rows.Err()
}
