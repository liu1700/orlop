# Upgrade safety

The control-plane schema is the one piece of long-lived state you can't just
re-provision: it sits in front of a database an older orlop release already
migrated. This page is the contract for **in-place upgrades** — bumping the
pinned orlop version and running `orlop-control migrate up` against that
existing database.

## The guarantee

For every **supported upgrade source** below, HEAD's `orlop-control migrate up`
converges that database to the current schema and it passes the same schema
check the control plane runs at boot.

| Upgrade from | To | Backends verified in CI |
|---|---|---|
| v0.1.0 | HEAD | Postgres |
| v0.2.0 | HEAD | Postgres, SQLite |
| v0.2.1 | HEAD | Postgres, SQLite |

v0.1.0 predates the embedded SQLite backend, so only its Postgres path is a
supported source.

Every row is exercised on each PR by
[`.github/workflows/upgrade.yml`](https://github.com/liu1700/orlop/blob/main/.github/workflows/upgrade.yml): CI
provisions a database with *that tag's* binary, then runs HEAD's `migrate up`
against it. That second `migrate up` self-checks the result against the schema
the code requires — so a migration that leaves an older database incomplete
fails the build, not your production. (CI runs the migrate path; it does not
boot the server. The boot-time check is the *same* self-check, below, so a
database that passes `migrate up` also clears boot.)

## What keeps an upgrade safe

Two properties make the upgrade trivial to run, and one check makes a bad one
loud instead of silent.

| Mechanism | What it does | Where |
|---|---|---|
| Forward-only migrations | `up` is the only migrate subcommand. It applies migrations numbered above the database's current version and never rewrites one that already shipped — so an old database picks up exactly the migrations added since it was last upgraded. | goose `provider.Up`, `internal/storage/postgres/db/migrate.go` |
| Idempotent `migrate up` | Re-running against an up-to-date database is a no-op, so it's safe to run on every deploy. | `migrate.go` (Postgres); SQLite re-applies `CREATE TABLE IF NOT EXISTS` on open |
| Schema self-check | At the end of `migrate up` **and** on every control-plane start (when a database is configured), the live database is checked against `storage.RequiredSchema` — the tables and columns the code needs. A gap fails fast, naming exactly what's missing. | `internal/storage/schema_check.go`; boot in `main.go`; each backend's `VerifySchema` |

Why this is enough: migrations only move forward and never rewrite history, so
a database that has run every migration up to HEAD holds the current schema by
construction. The self-check is the backstop for the one way that can break — a
renumbered or squashed migration that the runner silently skips (see the
incident below). Instead of an opaque database error the first time a query
hits a missing column, you get this at `migrate up` and again at boot:

```
control-plane schema is out of date: missing columns [access_tokens.consumed_at].
Run `orlop-control migrate up` against this database. If it was already
migrated, the release may have renumbered an already-released migration —
see docs/upgrade-safety.md.
```

## Operator runbook

The minimal correct in-place upgrade, against an existing database:

```bash
orlop-control migrate up          # reads DATABASE_URL, or pass --database-url
# then start the new control-plane binary as usual
```

| Do | Don't |
|---|---|
| Run `migrate up` with the **new** binary before starting it. | Start a new binary against an un-migrated database — boot fails the schema check by design. |
| Run `migrate up` on every deploy; it's idempotent. | Hand-edit the schema to clear a `schema is out of date` error — run `migrate up` instead. |
| Treat a `schema is out of date` error after `migrate up` as a release bug and report it — a supported source must never hit it. | Upgrade from a source tag that isn't in the table; an unlisted source isn't covered. |

`migrate up` runs goose against Postgres; for the embedded SQLite backend it
opens the database — applying the schema — and runs the same self-check.

## Version policy

A release that breaks an in-place upgrade from a previously supported source is
a **breaking change**: ship it as a major/minor bump with explicit upgrade
notes, never a silent patch. A minor bump must stay in-place-safe. Maintain the
supported set by appending a tag to the CI matrix as it ships, and dropping one
only when it stops being a supported source.

## Migration rules (for contributors)

The v0.1.0→v0.2.0 incident (#39): squashing the released migrations reset goose
numbering to version 1, but a deployed v0.1.0 database was already at goose
version 9. goose only applies versions above the current max, so it skipped the
squashed baseline entirely — leaving those databases without
`access_tokens.consumed_at` and the `cert_revocations` table while goose
reported success.

| Rule | Why |
|---|---|
| Never renumber or rewrite an already-released migration. | Some deployed database is already at that version and will never re-run it. |
| If you squash, ship a forward **bridge** migration numbered above the highest released version, every statement guarded by `IF NOT EXISTS`. | An already-deployed database converges to the same baseline. `0010_post_squash_reconcile.sql` is the worked example; it's a no-op on a fresh database. |
| When the code starts depending on a new table or column, add it to `storage.RequiredSchema`. | Keeps the boot/migrate self-check honest. |
| SQLite needs the same care. Its schema is applied with `CREATE TABLE IF NOT EXISTS` on open, which adds missing *tables* but never a column to an existing table. | A column added to an existing SQLite table won't backfill; the self-check and the SQLite CI job catch it. |

## See also

- [`database-backends.md`](database-backends.md): the two backends and how each applies its schema
- [`control-plane-runbook.md`](control-plane-runbook.md): operator workflows
