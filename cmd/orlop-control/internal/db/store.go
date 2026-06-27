package db

import (
	"github.com/jackc/pgx/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// Store is the typed data-access surface the control plane depends on (issue
// #4). It is the sqlc-generated query interface exposed under a domain name, so
// HTTP/business handlers depend on an interface rather than the concrete
// pgx-backed *sqlcdb.Queries — they become mockable and carry no direct
// dependency on the Postgres driver. The live implementation is sqlcdb.New(pool);
// the transaction-owning services (devauth, allocations) keep the concrete type
// because WithTx is outside this read/write surface.
type Store = sqlcdb.Querier

// ErrNotFound is the sentinel a Store returns when a row lookup matches nothing.
// It is the pgx "no rows" error re-exported under this package, so callers can
// `errors.Is(err, db.ErrNotFound)` without importing the Postgres driver and the
// dependency stays behind the storage layer.
var ErrNotFound = pgx.ErrNoRows
