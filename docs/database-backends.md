# Database backends

The control plane's data lives behind a backend-agnostic storage layer
(`internal/storage`), so the database is a deployment choice, not a code one.
Two backends ship today:

| | **PostgreSQL** | **SQLite** (embedded) |
|---|---|---|
| Best for | Production, multi-replica control planes | Local dev, CI, single-node self-hosting |
| External dependency | A Postgres server (CI runs against 16) | None — pure-Go, embedded in the binary |
| Concurrency | Full multi-writer | Single writer (the pool is pinned to one connection) |
| Multiple control-plane replicas | Yes (shared database) | No (the database is a local file) |
| CA-secrets backend | `postgres` (in-DB) or `filesystem` | `filesystem` only (`ORLOP_SECRETS_DIR`) |
| `DATABASE_URL` | `postgres://user:pw@host:5432/db?sslmode=…` | `sqlite:./orlop.db` |
| Schema | goose migrations (`orlop-control migrate up`) | applied automatically on open |

The backend is selected by the `DATABASE_URL` scheme — a `sqlite:` prefix picks
the embedded backend, anything else is treated as a Postgres connection string.
No flags, no build tags.

## Which should I use?

**Use SQLite** when the control plane runs as a single process: a local
quickstart, a CI fixture, a self-hosted single-node box. It needs nothing
external and the schema is created on first open, so `DATABASE_URL=sqlite:./orlop.db`
is the whole setup.

**Use PostgreSQL** for anything that must scale or stay up: more than one
control-plane replica (they share the database), real write concurrency, managed
backups, and the option of keeping the CA root key in the database. This is the
production path.

> SQLite is a single-node backend. The connection pool is pinned to one writer,
> and the database is a file on local disk — it cannot be shared by multiple
> control-plane replicas. Reach for Postgres before you scale out.

## PostgreSQL

```bash
export DATABASE_URL="postgres://postgres:pw@localhost:5432/orlop?sslmode=disable"
orlop-control migrate up        # applies the embedded goose migrations
```

Migrations are embedded in the binary; no migration files are needed at runtime.
Re-running `migrate up` is idempotent.

The CA (root key + tenant intermediates) can live in the same database
(`ORLOP_SECRETS_BACKEND=postgres`) so there's no separate secrets volume. Pair it
with `ORLOP_SECRETS_ENC_KEY` to encrypt the root key at rest — boot fails closed
if you select the postgres secrets backend without an encryption key (or an
explicit `ORLOP_SECRETS_ALLOW_PLAINTEXT=1`), so the master signing key is never
written to the database in plaintext by accident. See
[`control-plane-runbook.md`](control-plane-runbook.md).

## SQLite

```bash
export DATABASE_URL="sqlite:./orlop.db"
orlop-control migrate up        # creates ./orlop.db and applies the schema
```

The driver is pure Go (`modernc.org/sqlite`) — no cgo, no C toolchain, no server.
Accepted `DATABASE_URL` forms:

| Form | Meaning |
|---|---|
| `sqlite:orlop.db` | relative file path |
| `sqlite:///var/lib/orlop/orlop.db` | absolute file path |
| `sqlite::memory:` | ephemeral in-memory database (tests) |

The schema is applied on every open (idempotent), so `migrate up` is optional —
it exists mainly to create the file ahead of time.

> The `postgres` CA-secrets backend needs a shared database pool, which SQLite
> doesn't provide, so the control plane uses the **filesystem** CA backend with
> SQLite. Set `ORLOP_SECRETS_DIR` and leave `ORLOP_SECRETS_BACKEND` unset;
> selecting `ORLOP_SECRETS_BACKEND=postgres` with a `sqlite:` URL fails closed
> with a message pointing here.

## Switching backends

There is no built-in port tool: each backend owns its own schema, applied fresh,
and the two are not migrated between. Choose the backend at setup time. Because
orlop is pre-1.0 and stores no long-lived state you can't re-provision, the
practical path to "move to Postgres" is to stand up the Postgres database, point
`DATABASE_URL` at it, run `migrate up`, and re-seed (`user seed`,
`server register`) — agents re-enroll and re-mount as usual.

## See also

- [`standalone-quickstart.md`](standalone-quickstart.md) — single-node bring-up on either backend
- [`control-plane-runbook.md`](control-plane-runbook.md) — CA, admin seeding, operator workflows
