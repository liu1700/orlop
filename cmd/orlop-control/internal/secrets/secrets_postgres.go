package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is a Backend that stores secrets as rows in the dg_ca_secrets table.
// It exists so a production deploy can keep the CA (root key + tenant
// intermediates) in the same durable Postgres dg-control already depends on,
// instead of a block-storage PVC mounted at ORLOP_SECRETS_DIR. Keys are the same
// slash-separated paths the Filesystem backend uses ("ca/root/cert.pem", etc.);
// values are opaque bytes. There is no per-secret size limit (unlike a k8s
// Secret's ~1 MiB cap), so it scales to one tenant intermediate per agent.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres returns a Backend over pool. The dg_ca_secrets table must already
// exist (created by the 0007 migration).
func NewPostgres(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool} }

func (p *Postgres) Get(ctx context.Context, key string) ([]byte, bool, error) {
	var v []byte
	err := p.pool.QueryRow(ctx, `SELECT value FROM dg_ca_secrets WHERE key = $1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("secrets pg get %q: %w", key, err)
	}
	return v, true, nil
}

func (p *Postgres) Put(ctx context.Context, key string, value []byte) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO dg_ca_secrets (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		key, value)
	if err != nil {
		return fmt.Errorf("secrets pg put %q: %w", key, err)
	}
	return nil
}

func (p *Postgres) List(ctx context.Context, prefix string) ([]string, error) {
	// starts_with is an exact prefix match — no LIKE wildcard escaping needed for
	// keys/prefixes that may contain '_' (tenant ids like u_<id> / a_<agentID>).
	rows, err := p.pool.Query(ctx,
		`SELECT key FROM dg_ca_secrets WHERE starts_with(key, $1) ORDER BY key`, prefix)
	if err != nil {
		return nil, fmt.Errorf("secrets pg list %q: %w", prefix, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
