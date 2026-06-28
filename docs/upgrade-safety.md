# Upgrade safety

orlop's control-plane schema is the one piece of long-lived state a consumer
can't just re-provision: it sits in front of a production database that has
already been migrated by an older release. This page is the contract for
**in-place upgrades** — bumping the orlop version a deployment pins and running
`orlop-control migrate up` against an existing database.

## The guarantee

For every **supported upgrade source** (see the table below), running HEAD's
`orlop-control migrate up` against a database last migrated by that release
converges it to the current schema, and starting the control plane against it
succeeds. This is enforced in CI, not just intended — see
[`.github/workflows/upgrade.yml`](../.github/workflows/upgrade.yml).

| Upgrade from | To | Backends verified |
|---|---|---|
| v0.1.0 | HEAD | Postgres |
| v0.2.0 | HEAD | Postgres, SQLite |
| v0.2.1 | HEAD | Postgres, SQLite |

(v0.1.0 predates the embedded SQLite backend, so only its Postgres path is a
supported upgrade source.)

A release that **breaks** an in-place upgrade from a previously supported source
is a **breaking change** — treat it as a major/minor bump with explicit upgrade
notes, never a silent patch. A minor version bump must remain in-place-safe.

## How it's enforced

Three mechanisms, each catching the failure earlier than the last:

1. **CI upgrade guard** (`upgrade.yml`). For each released tag in the table, CI
   provisions a database with *that tag's* binary, then runs HEAD's `migrate up`
   against it, for both Postgres and SQLite. Any error fails the build. Add a
   new tag to the matrix as it ships; drop one only when it stops being a
   supported source.

2. **Schema self-check** (boot + `migrate up`). After applying migrations — and
   again on every control-plane start — the live database is checked against
   `storage.RequiredSchema` (the tables and historically-skipped columns the
   code needs). A gap fails fast with an actionable message naming exactly
   what's missing, e.g.:

   ```
   control-plane schema is out of date: missing columns [access_tokens.consumed_at].
   Run `orlop-control migrate up` against this database. If it was already
   migrated, the release may have renumbered an already-released migration —
   see docs/upgrade-safety.md.
   ```

   This replaces the old failure mode (a cryptic runtime `WARN` + opaque
   SQLSTATE discovered only when a user action hit the missing column).

3. **`migrate up` idempotency.** Re-running `migrate up` is always a no-op on an
   up-to-date database, so the migrate step is safe to run on every deploy.

## Migration policy (for contributors)

The root cause of the v0.1.0→v0.2.0 incident (#39) was squashing already-released
migrations: the squash reset goose numbering to version 1, but a deployed v0.1.0
database was already at goose version 9, so goose applied **nothing** and the
schema folded into the squashed baseline never landed.

The rules that prevent a recurrence:

- **Never renumber or rewrite an already-released migration.** Once a migration
  ships in a tag, its version number and meaning are frozen — some deployed
  database is already at that version and will never re-run it.
- **If you squash, add a forward bridge.** Squashing the baseline for *new*
  databases is fine, but you must also ship a bridge migration **numbered above
  the highest already-released version**, with every statement guarded by
  `IF NOT EXISTS`, so an already-deployed database converges to the same
  baseline. (`0010_post_squash_reconcile.sql` is the worked example.)
- **A bridge is a no-op on a fresh database.** Because the squashed baseline
  already contains everything the bridge adds, the `IF NOT EXISTS` guards make
  both paths — fresh install and in-place upgrade — converge on an identical
  schema.
- **Keep `storage.RequiredSchema` honest.** When the code starts depending on a
  newly added table or a column that an older database won't have until it
  migrates, add it there so the self-check covers it.
- **SQLite is not exempt.** Its schema is applied with `CREATE TABLE IF NOT
  EXISTS` on open, which creates missing *tables* but never adds a column to an
  existing table. A column added to an existing SQLite table needs the same care
  (and is covered by the self-check + the SQLite upgrade job in CI).

## See also

- [`database-backends.md`](database-backends.md): the two backends and how the schema is applied
- [`control-plane-runbook.md`](control-plane-runbook.md): operator workflows
