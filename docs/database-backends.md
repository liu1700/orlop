# Database backends

The control plane keeps its state behind a backend-agnostic storage layer
(`internal/storage`), so the database is a deployment choice, not a code one.
The backend is selected entirely by the `DATABASE_URL` scheme — a `sqlite:`
prefix picks the embedded backend, anything else is treated as a Postgres
connection string. No flags, no build tags.

| | **PostgreSQL** | **SQLite** (embedded) |
|---|---|---|
| Best for | Multi-replica / production control planes | Local dev, CI, single-node self-hosting |
| External dependency | A Postgres server | None; pure-Go, embedded in the binary |
| Concurrency | Multiple writers | Single writer (pool pinned to one connection) |
| Multiple control-plane replicas | Yes — shared server | No — the database is a local file |
| CA-secrets backend | `postgres` (in-DB) or `filesystem` | `filesystem` only (`ORLOP_SECRETS_DIR`) |
| `DATABASE_URL` | `postgres://user:pw@host:5432/db?sslmode=…` | `sqlite:./orlop.db` |
| Schema | goose migrations (`orlop-control migrate up`) | applied automatically on open |

## Which should I use?

**Use SQLite** when the control plane runs as a single process — a local
quickstart, a CI fixture, a self-hosted single-node box. It needs nothing
external and creates its schema on first open, so `DATABASE_URL=sqlite:./orlop.db`
is the whole setup. It's a local file with a one-connection pool, so it cannot be
shared by multiple control-plane replicas.

**Use PostgreSQL** when more than one control-plane replica must share one
database, when you need real write concurrency, or when you want to keep the CA
root key in the database instead of on a secrets volume. This is the production
path.

## PostgreSQL

```bash
export DATABASE_URL="postgres://postgres:pw@localhost:5432/orlop?sslmode=disable"
orlop-control migrate up        # applies the embedded goose migrations
```

Migrations are embedded in the binary — no migration files are needed at
runtime — and re-running `migrate up` is idempotent, so it's safe on every deploy.

The CA (root key + tenant intermediates) can live in the same database with
`ORLOP_SECRETS_BACKEND=postgres`, so there's no separate secrets volume. Pair it
with `ORLOP_SECRETS_ENC_KEY` (a hex-encoded 32-byte AES key) to encrypt the root
key at rest: boot **fails closed** if you select the postgres secrets backend
without an encryption key, unless you explicitly set
`ORLOP_SECRETS_ALLOW_PLAINTEXT=1`. See [`control-plane-runbook.md`](control-plane-runbook.md).

## SQLite

```bash
export DATABASE_URL="sqlite:./orlop.db"
orlop-control migrate up        # creates ./orlop.db and applies the schema
```

The driver is pure Go (`modernc.org/sqlite`): no cgo, no C toolchain, no server.
Accepted `DATABASE_URL` forms:

| Form | Meaning |
|---|---|
| `sqlite:orlop.db` | relative file path |
| `sqlite:///var/lib/orlop/orlop.db` | absolute file path |
| `sqlite::memory:` | ephemeral in-memory database (tests) |

The schema is applied on every open (idempotent), so `migrate up` is optional —
it exists mainly to create the file ahead of time.

> `CREATE TABLE IF NOT EXISTS` creates missing tables on open but does **not**
> add a column to a table that already exists. The boot-time schema self-check
> catches that gap and fails fast — see [`upgrade-safety.md`](upgrade-safety.md).

> The `postgres` CA-secrets backend needs a shared database pool, which SQLite
> doesn't provide, so use the **filesystem** CA backend with SQLite: set
> `ORLOP_SECRETS_DIR` and leave `ORLOP_SECRETS_BACKEND` unset. Selecting
> `ORLOP_SECRETS_BACKEND=postgres` with a `sqlite:` URL fails closed with a
> message pointing you at `ORLOP_SECRETS_DIR`.

## Switching backends

Each backend owns its own schema, applied fresh, and orlop does not port data
between them — so choose the backend at setup time. To move to Postgres, stand up
the database, point `DATABASE_URL` at it, run `migrate up`, and re-seed
(`orlop-control user seed`, `orlop-control server register`); agents re-enroll and
re-mount as usual.

## Upgrading in place

Bumping the orlop version of a running deployment and re-running `migrate up`
against the existing database is a supported, CI-tested path. The guarantee, the
supported upgrade sources, and the migration policy that keeps it safe live in
[`upgrade-safety.md`](upgrade-safety.md).

## See also

- [`upgrade-safety.md`](upgrade-safety.md): in-place upgrade guarantee, schema self-check, migration policy
- [`standalone-quickstart.md`](standalone-quickstart.md): one-command single-node bring-up (`orlop dev up`, SQLite)
- [`manual-bring-up.md`](manual-bring-up.md): single-node bring-up by hand (SQLite), where you set `DATABASE_URL`
- [`control-plane-runbook.md`](control-plane-runbook.md): CA, admin seeding, operator workflows
