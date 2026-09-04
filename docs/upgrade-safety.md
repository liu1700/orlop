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
| v0.5.1 | HEAD | Postgres, SQLite |
| v0.5.2 | HEAD | Postgres, SQLite |
| v0.5.3 | HEAD | Postgres, SQLite |
| v0.5.4 | HEAD | Postgres, SQLite |
| v0.5.5 | HEAD | Postgres, SQLite |
| v0.5.6 | HEAD | Postgres, SQLite |
| v0.5.7 | HEAD | Postgres, SQLite |
| v0.6.0 | HEAD | Postgres, SQLite |
| v0.6.1 | HEAD | Postgres, SQLite |
| v0.6.2 | HEAD | Postgres, SQLite |
| v0.6.3 | HEAD | Postgres, SQLite |
| v0.6.4 | HEAD | Postgres, SQLite |
| v0.6.5 | HEAD | Postgres, SQLite |
| v0.6.6 | HEAD | Postgres, SQLite |
| v0.6.7 | HEAD | Postgres, SQLite |
| v0.6.8 | HEAD | Postgres, SQLite |
| v0.6.9 | HEAD | Postgres, SQLite |

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

Before upgrading to v0.5.2, take a database backup. Migration
`0011_owner_capacity_reservations.sql` backfills one reservation per
owner/server pair and recalculates each server's free capacity, repairing the
legacy per-agent over-reservation. The migration is safe to retry, but the old
v0.5.1 allocator does not understand the new ledger: after migrating, restore
the backup before rolling the control plane back to v0.5.1.

Deployments that already ran v0.5.2 should upgrade to v0.5.3 and run its
`0012_repair_owner_capacity_reservations.sql`. It repairs historical allocations
whose per-agent tenant has no `server_vms` row and rebuilds `free_bytes` (#108).
The repair is automatic when only one pool server exists. In a multi-server
deployment, `migrate up` stops with an unresolved-owner count if placement
cannot be inferred; restore those `server_vms` rows (or create the matching
owner reservation explicitly) and rerun the idempotent migration.

v0.5.4 through v0.6.4 ship **no control-plane migration**, so unlike the two
upgrades above they roll back with a plain image revert and need no backup step.

v0.6.6 is a mount-client-only change and ships **no control-plane migration**,
so orlop-control and orlop-server roll independently and revert with a plain
image swap. It closes the case where a mount outlives the identity that renews
it: when a Pod API object is force-deleted while its sandbox and mount process
survive, the Pod-bound token stops verifying, certificate renewal fails
terminally, and before this release the mount-lease loop never learned that — it
read `401 expired_client` as "renewal will fix this" and retried once a second
indefinitely. Terminal renewal state now reaches that loop, so `expired_client`
becomes terminal once renewal has given up or the last lease window has closed,
taking the existing eviction path (aborted FUSE connection, exit 69 under
`--from-env`). Retries past lease expiry back off from one second to thirty.
Transport and 5xx failures stay retryable, and no lease is ever taken from
another holder — only given up (#143).

v0.6.7 ships **no control-plane migration** either — it only changes error
classification: a tenant registration blocked by the account's full shared
disk quota now surfaces as a typed `507` (`disk_quota_exceeded` from
orlop-server, `account_disk_full` from the enroll route) instead of a generic
`500 server_error`, and the mount client treats it as terminal instead of
retrying (#146). All three components roll independently and revert with a
plain image swap.

v0.6.8 also has **no control-plane migration**. It serializes root and tenant CA
bootstrap in the configured secrets backend, then rereads the winning keypair.
Postgres uses a transaction-scoped advisory lock; the memory and filesystem
backends use process-local locks. Concurrent control-plane replicas therefore
converge on one root and intermediate chain instead of minting different CAs.
The stored key format is unchanged, so rollback is a plain image swap.

v0.6.9 also has **no control-plane migration**. It replaces the per-tenant usage
walk (an O(files) `filepath.WalkDir` over the chunk store) with a bounded sum of
the local chunk index, so a storage-meter request stays within the caller's
budget under concurrent mount/quota load, and it isolates a single tenant's
remote failure so it no longer discards the whole owner's usage pass. Reported
bytes are unchanged (the sum equals the walk), and rollback is a plain image swap.

v0.6.10 also has **no control-plane migration**. A directory listing now carries
each symlink child's target, read from the same joined `symlinks` row that
already decided the child's kind and size, so a client that only issues `LIST`
can read a link without a follow-up `READLINK`. The wire field is unchanged
(`EntryWire.target`, present since the field was added and populated by `STAT`
all along), so an older client ignores it and rollback is a plain image swap.

v0.6.5 adds nullable `disk_allocations.mount_lease_token_hash` in
`0013_mount_lease_tokens.sql`. Run `orlop-control migrate up` before starting the
new control plane. The column has no backfill: existing tokenless clients keep
using their enrollment binding, while v0.6.5 clients advertise token support in
an HTTP header and install a token on their first successful refresh. Because an
older control plane does not understand renewal continuity tokens, roll out the
v0.6.5 control plane before v0.6.5 mount clients. The migration is additive and
nullable, so a database rollback is unnecessary if the binary must be reverted.

The release fixes long-lived hosted mounts aborting with exit 69 at the original
one-hour certificate boundary (#140). Certificate renewal now publishes the new
identity to control-plane lease refreshes and subsequent TCP/QUIC data-plane
dials; the opaque lease token safely rebinds the live lease to the renewed
enrollment without allowing a displaced holder to undo a takeover. Live handoff
also reloads current certificate metadata and carries the same lease token.

v0.6.4 extends the same capacity path for JuiceFS-backed deployments: a full
directory quota that stalls the backing write/`fsync` instead of returning an
errno now surfaces as `EDQUOT` to the FUSE caller, through a pre-write `statfs`
guard and a bounded write watchdog on the orlop-server data plane (#135). The
wire shape and control-plane schema are unchanged, so the server rolls
independently; the 20s watchdog default is tunable via
`quota.backing_write_timeout_ms` and applies only to the `juicefs` quota
backend.

v0.6.3 preserves backing-store capacity errors across the data-plane boundary:
filesystem `EDQUOT`/`ENOSPC` and SQLite `SQLITE_FULL` now reach the Linux FUSE
caller as `EDQUOT`/`ENOSPC` instead of being rewritten to `EIO` or `EINVAL`
(#135). The wire shape and control-plane schema are unchanged, and existing
clients already accept arbitrary errno values, so the server can roll
independently.

v0.6.2 is an orlop-server-only optimization for JuiceFS-backed chunk stores:
duplicate existence probes collapse into one stat, definitely absent hash
shards skip remote stats, and GC overlaps deletes through a process-wide
bounded worker pool (#133). Manifest commit, agent purge, and GC now share the
same deterministic hash-shard locks, so a manifest cannot commit a chunk while
GC removes it. The wire protocol, control-plane schema, and mount client are
unchanged. The server can roll independently; Plori still pins all release
images together to prevent deployment drift.

v0.6.1 is a mount-client-only change: spilled-file flushes now use single-pass
streaming CDC and a process-wide bounded upload pipeline instead of
rematerializing the full file in memory (#131). The wire protocol and both
server components are unchanged, so the mount client can roll independently.

v0.6.0 changes both halves, compatibly (the metadata change feed + client
mirror, #122): the server applies additive columns and tables to each
per-tenant data-plane SQLite database at open (`rev` columns,
`change_counter`, `change_tombstones`) — automatic, idempotent, and ignored
by an older server after a rollback. The wire changes are new op codes plus
append-only msgpack fields, negotiated explicitly: an old client never sees
the feed, and a new client against an old server runs mirror-less. Either
half can roll independently.

v0.5.7 is an orlop-server-only change (tenant registration no longer holds the
server-wide lock across JuiceFS filesystem I/O, so a cold-cache registration can't
stall other registrations or data-plane tenant lookups, #119): nothing in
orlop-control or the mount client moves, so it can roll independently.

v0.5.6 is a mount-client-only change (the mount process releases its lease on
SIGTERM/SIGINT instead of dying with it held, #117): nothing server-side moves, so
it can roll independently of orlop-control/orlop-server.

v0.5.5 does change both halves together: orlop-control asks orlop-server whether a
mount is still live before reclaiming a lease from a dead holder (#114), over a new
`GET /control/tenants/{id}/allocations/{alloc}/mount-lease`. **Roll the two together.**
A new control plane against an old server gets a 404 from that call, which is treated
as "liveness unknown" and refuses the reclaim — i.e. it degrades to the pre-v0.5.5
behaviour rather than doing anything unsafe, so a staggered roll is survivable, just
pointless until the server catches up.

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
