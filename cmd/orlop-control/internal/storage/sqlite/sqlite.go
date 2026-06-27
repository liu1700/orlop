// Package sqlite is the embedded, single-node implementation of the storage
// interfaces — the zero-external-dependency backend for local quick-start and
// self-hosting. Like package postgres it is an adapter: it hand-writes
// database/sql queries against a pure-Go SQLite engine (modernc.org/sqlite) and
// converts to the driver-agnostic domain types in package storage.
//
// SQLite mapping conventions:
//   - uuid.UUID is stored as TEXT (lowercase canonical); pointers are NULL.
//   - time.Time is stored as INTEGER Unix microseconds (UTC), always written and
//     compared from Go-supplied values — never a SQL default or now() — so
//     ordering and expiry checks are exact.
//   - DB-assigned ids (users, allocations, …) are minted in Go with uuid.New().
//
// The connection pool is pinned to a single connection (SetMaxOpenConns(1)): a
// single-node control plane has no need for write concurrency, and serializing
// access sidesteps SQLite's writer-lock contention entirely.
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	sqlitelib "modernc.org/sqlite"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

//go:embed schema.sql
var schemaSQL string

// dbtx is the subset of *sql.DB and *sql.Tx the adapter methods use, so a single
// set of methods serves both the root store and a transaction-scoped one.
type dbtx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows, so a row-projection
// helper can scan a single QueryRow or a row inside a QueryContext loop.
type rowScanner interface {
	Scan(dest ...any) error
}

// Store is the SQLite-backed storage adapter. pool is the root *sql.DB
// (nil on a transaction-scoped store); db is whichever of *sql.DB / *sql.Tx the
// methods run against.
type Store struct {
	db   dbtx
	pool *sql.DB
}

// New wraps an already-open *sql.DB whose schema is assumed applied. Prefer Open.
func New(pool *sql.DB) *Store { return &Store{db: pool, pool: pool} }

// Open opens (creating if absent) the SQLite database at path, applies pragmas
// and the embedded schema, and returns a ready Store. Use ":memory:" for an
// ephemeral database (tests).
func Open(ctx context.Context, path string) (*Store, error) {
	pool, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// One connection: a single-node control plane needs no write concurrency, and
	// it keeps an in-memory database alive for the process's lifetime.
	pool.SetMaxOpenConns(1)
	if err := pool.PingContext(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if _, err := pool.ExecContext(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply sqlite schema: %w", err)
	}
	return New(pool), nil
}

// dsn builds a modernc.org/sqlite connection string with the pragmas the control
// plane relies on: foreign keys enforced, a busy timeout, WAL journaling, and
// immediate write locks so a lease/purge transaction takes its write lock up
// front rather than mid-statement.
func dsn(path string) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Set("_txlock", "immediate")
	return "file:" + path + "?" + q.Encode()
}

// Close closes the underlying pool (a no-op on a transaction-scoped store).
func (s *Store) Close() error {
	if s.pool != nil {
		return s.pool.Close()
	}
	return nil
}

// One *Store implements every role interface (storage.Store); *txStore is a Tx.
var (
	_ storage.Store = (*Store)(nil)
	_ storage.Tx    = (*txStore)(nil)
)

// --- transactions ---

func (s *Store) Begin(ctx context.Context) (storage.Tx, error) {
	if s.pool == nil {
		return nil, errors.New("sqlite: nested transactions are not supported")
	}
	tx, err := s.pool.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &txStore{Store: &Store{db: tx}, tx: tx}, nil
}

// txStore is a transaction-scoped Store: it reuses every adapter method through
// the embedded *Store (whose db is the tx) and adds Commit/Rollback.
type txStore struct {
	*Store
	tx *sql.Tx
}

func (t *txStore) Commit(context.Context) error { return t.tx.Commit() }

// Rollback is safe to call after Commit (the defer-rollback idiom): a finished
// transaction yields sql.ErrTxDone, which we treat as a no-op.
func (t *txStore) Rollback(context.Context) error {
	if err := t.tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return err
	}
	return nil
}

// --- error mapping ---

// mapErr translates driver errors into storage sentinels: no-rows to ErrNotFound
// and a unique/primary-key violation to ErrAlreadyExists.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ErrNotFound
	}
	var se *sqlitelib.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case 2067, 1555: // SQLITE_CONSTRAINT_UNIQUE, SQLITE_CONSTRAINT_PRIMARYKEY
			return storage.ErrAlreadyExists
		}
	}
	// Older driver builds surface constraint failures only in the message.
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return storage.ErrAlreadyExists
	}
	return err
}

// --- value converters (domain <-> SQLite) ---

func nowMicros() int64 { return time.Now().UTC().UnixMicro() }

func micros(t time.Time) int64 { return t.UTC().UnixMicro() }

// microsPtr returns an int64 micros value or nil (for a NULL column).
func microsPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().UnixMicro()
}

func timeFromMicros(n int64) time.Time { return time.UnixMicro(n).UTC() }

func timePtrFromMicros(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.UnixMicro(n.Int64).UTC()
	return &t
}

// uuid.UUID already implements driver.Valuer/sql.Scanner (storing the canonical
// string), so it can be passed as a query arg and scanned into directly. These
// helpers bridge the nullable (*uuid.UUID) case via uuid.NullUUID.

func nullUUID(id *uuid.UUID) uuid.NullUUID {
	if id == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *id, Valid: true}
}

func ptrUUID(n uuid.NullUUID) *uuid.UUID {
	if !n.Valid {
		return nil
	}
	id := n.UUID
	return &id
}
