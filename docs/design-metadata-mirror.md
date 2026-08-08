# Orlop Metadata Mirror: Local Reads, Proven Freshness

> **Status:** design contract for
> [issue #122](https://github.com/liu1700/orlop/issues/122). The server change
> feed, the client mirror, and the pipelined write path described here land in
> separate PRs behind this document; op codes, schemas, and semantics below are
> the plan of record for those changes.

Orlop's remaining performance gap is metadata-heavy work, not bulk throughput.
Measured on a production agent disk (200 small files, five rounds, medians):

| Workload | Durable disk | Local ext4 | Gap |
|----------|-------------:|-----------:|----:|
| create small files | 115.2 files/s | 1,161.8 files/s | 10.1x |
| walk the tree | 69.1 ms | 4.6 ms | 15x |
| delete the tree | 812.5 ms | 6.9 ms | 117.8x |
| 1 GiB sequential write | 196.9 MiB/s | 953.8 MiB/s | 4.8x |

Sequential I/O is already served by the chunk data plane and the local chunk
cache. The metadata gap has a single cause: every `lookup`, `readdir`,
`readlink`, and manifest fetch is a fresh network round trip, and every
mutation pays extra round trips to learn versions the client recently saw.
`unlink` costs two round trips (`MANIFEST_GET` for the version, then
`MANIFEST_DELETE`), `rename` costs three, `create` costs two (`LEASE_GRANT`
plus `MANIFEST_PUT`).

This document specifies the fix: a **client-side metadata mirror**, hydrated
and invalidated by a **server change feed**, with **explicit durability
fences** for the one mutation path that becomes asynchronous. The server
remains the single source of truth. Nothing in this design weakens CAS
versioning, leases, audit, quota, or the per-agent path moat, and it
introduces no last-writer-wins behavior anywhere.

## 1. Shape of the solution

Three pieces:

1. **Revision stamping (server).** Every metadata mutation, from any writer,
   stamps the rows it touches with a per-tenant monotonic revision and records
   tombstones for deletions. This turns the tenant database itself into a
   coalesced change log: "everything that changed since revision N" is a
   query, not a replay.
2. **Change feed (wire).** Two new client ops and one new server push let a
   mount fetch that query incrementally through a `(rev, path)` cursor and
   subscribe to live change events on the existing data connection.
3. **Mirror (client).** The mount keeps a local SQLite mirror of its subtree's
   metadata and serves `lookup`, `getattr`, `readdir`, `readlink`, and
   manifest reads from it, but only while a live subscription plus a caught-up
   cursor prove the mirror is current. The moment that proof lapses, every
   read goes back to the server, exactly as today.

Two designs were considered and rejected:

- **Journal replay.** The session journal cannot drive a mirror: it records
  only manifest ops (`mkdir`, `rmdir`, `symlink`, `mknod`, `chown`, and
  `utimensat` write no journal rows), its `seq` is per mount session rather
  than per disk (a new session restarts at 1, so a sequence watermark silently
  skips rows across sessions), and some writers (agent purge, seeding) bypass
  it entirely. The journal keeps its job: audit and revert. The change feed is
  a separate, complete mechanism.
- **Last-writer-wins sync.** Cloudflare's `computer` project keeps a local
  SQLite workspace mirror and syncs revisioned content-addressed deltas; its
  mirror shape and cursor design inform this one. But its preview protocol
  accepts silent lost updates in three places (concurrent pushes, type
  conflicts, per-path coalescing of intermediate states). Orlop already has
  per-path CAS and returns `ESTALE` to the losing writer; this design keeps
  that behavior everywhere.

## 2. Revision stamping

The per-tenant SQLite database gains one counter, one column per metadata
table, and one tombstone table (all additive, applied by
`ensureTenantSchema` like prior column additions):

```sql
create table change_counter (
  singleton integer primary key check (singleton = 1),
  next_rev  integer not null
);

alter table manifests     add column rev integer not null default 0;
alter table dir_entries   add column rev integer not null default 0;
alter table symlinks      add column rev integer not null default 0;
alter table special_nodes add column rev integer not null default 0;

create table change_tombstones (
  path text primary key,
  rev  integer not null
);
```

Every transaction that mutates metadata allocates one revision (read
`next_rev`, increment it, same transaction) and stamps it onto every row it
creates or modifies. Deleting a path upserts a tombstone at that revision;
re-creating the path deletes the tombstone (the live row's newer revision
supersedes it). A directory rename restamps the whole subtree at one
revision, which is why the feed cursor is a `(rev, path)` pair rather than a
scalar (section 3).

Stamping is **unconditional**. It happens inside the same SQLite transaction
as the mutation for every writer: the nine data-plane mutation ops, journal
revert, agent purge, and offline seeding/migration tools. Unlike the journal
it is not gated on a session id, because a mirror that misses even one
writer's changes serves stale data. This is also why lease possession is
never used as a freshness proof: journal revert and agent purge legitimately
mutate metadata without holding the mount's leases, and the feed is the only
channel that makes those mutations visible to the client.

Because the counter, the row stamps, and the tombstones commit atomically
with the mutation itself, the feed can never observe a revision without its
rows or rows without their revision, including across a crash that rolls back
the WAL tail.

**Tombstone retention.** Tombstones are pruned after a retention window, and
a `pruned_before_rev` watermark records the oldest revision the feed can
still serve. A client resuming from a cursor older than that watermark is
told to rebaseline (section 3). This bounds table growth without any
server-side bookkeeping of client cursors.

## 3. The change feed

Three new frame types on the existing mTLS data connection, mirrored in Go
(`cmd/orlop-server/dataplane`) and Rust (`src/backend/dataplane`) like every
other op:

| Op | Hex | Direction |
|----|-----|-----------|
| `CHANGES_FETCH` | 0x1B | client → server |
| `CHANGES_SUBSCRIBE` | 0x1C | client → server |
| `CHANGES_EVENT` | 0x1D | server → client (push) |

**Negotiation is explicit.** Every `CHANGES_FETCH` and `CHANGES_SUBSCRIBE`
request carries `sync_protocol` (currently `1`); the response echoes the
version the server will speak. A server that does not implement the feed
answers with `EINVAL` (unknown op), and the client runs with the mirror
disabled, byte-for-byte identical to today's behavior. A client never
interprets feed frames until it has seen its own `sync_protocol` echoed, so
an old client cannot misread a new stream and a new client cannot misread an
old server. Unknown push frames were already discarded by older clients, so
`CHANGES_EVENT` is safe to introduce on a shared connection.

**`CHANGES_FETCH`** pages through the coalesced state:

```
request:  { sync_protocol, cursor_rev, cursor_path, limit, include_chunks }
response: { sync_protocol, entries, next_rev, next_path, current_rev,
            resync_required }
```

The response contains every live entry and tombstone in the caller's subtree
with `(rev, path)` strictly greater than `(cursor_rev, cursor_path)`, ordered
by `(rev, path)`, capped at `limit`. A fresh mirror starts from `(0, "")`;
because the comparison is lexicographic on the pair, pre-existing rows whose
stamp is still the schema default `0` are delivered too. The cursor is a
resume point, not a snapshot: a path that changes mid-hydration simply
reappears later in the stream at its new revision, and convergence holds
because the cursor never advances past a revision that still has undelivered
paths. `resync_required` is returned when `cursor_rev` predates
`pruned_before_rev`; the client must discard its mirror and restart from
`(0, "")`.

Each entry is final-state, one per path:

```
{ path, rev, kind,            -- file | dir | symlink | special | tombstone
  size, mode, mtime, uid, gid, atime, nlink, inode_id,
  version,                    -- the manifest CAS version, files only
  link_target, rdev,
  chunks }                    -- packed chunk list, when include_chunks
```

Entries carry everything `lookup`, `getattr`, `readdir`, and `readlink` need,
plus (with `include_chunks`) the manifest chunk list so reads need no
`MANIFEST_GET` either. There is no rename opcode and no operation history:
final-state entries are idempotent to apply, indifferent to receiver history,
and make cold start the same code path as catch-up.

**`CHANGES_SUBSCRIBE`** registers the connection for live events and returns
`current_rev`. From then on the server pushes `CHANGES_EVENT` frames,
`{ entries, current_rev, reset }`, from the same post-commit broadcast hook
that feeds the journal pub/sub. Delivery is per-allocation, filtered to the
agent's subtree, and non-blocking: if a subscriber's buffer overflows, the
server pushes `{ reset: true, current_rev }` and drops the buffered backlog.
A reset tells the client its event stream has a gap; it falls back to
`CHANGES_FETCH` from its last applied cursor and serves reads from the server
until it has caught back up. The subscription dies with the connection.

**Authorization and audit.** Feed requests pass the same policy check and
agent-subtree confinement as every other op: the feed for an agent-scoped
certificate contains only paths under `/<agentID>`, enforced server-side by
the same `checkAgentPath` logic, and denials audit exactly like any other
denied op. Fetch and subscribe are themselves audited ops. The deny and audit
semantics of all existing ops are untouched.

## 4. The client mirror

The mirror is one SQLite database per allocation under the existing cache
root (`$XDG_CACHE_HOME/orlop`, else `$HOME/.cache/orlop`), next to the chunk
cache index:

```
<cache-root>/
  chunks/…
  index.sqlite            # chunk LRU index (existing)
  mirror/
    <allocation-id>.sqlite
```

One `entries` table in the shape of the wire entry (plus a derived `parent`
column indexed for `readdir`), and one `mirror_meta` table holding the
applied cursor, the negotiated `sync_protocol`, the server identity, and the
mirror schema version. The database opens with WAL and `synchronous=NORMAL`;
it is a cache, not a store of record. Validation is fail-closed, in the same
spirit as the live-handoff snapshot: wrong schema version, wrong server
identity, or any integrity error deletes the file and rehydrates from
`(0, "")`. A missing or corrupt mirror never fails a mount; it only means the
first reads go to the server.

**The freshness invariant.** The mount serves a metadata read locally if and
only if all of the following hold:

1. a `CHANGES_SUBSCRIBE` is live on the current data connection,
2. the applied cursor has reached the `current_rev` reported at subscribe (or
   by a later event), and
3. no unprocessed `reset` is pending.

Otherwise, and during hydration, reconnection, or after any reset, every read
goes to the server exactly as today. Freshness is proven by revisions, never
by leases, and never by elapsed time.

**Serving matrix, once fresh:**

| Operation | Today | With mirror |
|-----------|-------|-------------|
| `lookup` / `getattr` | network on first touch, then unproven in-memory cache | mirror, proven |
| `readdir` | `LIST` every call | mirror |
| `readlink` | `READLINK` every call | mirror |
| manifest fetch for reads | `MANIFEST_GET` every open | mirror (chunk list included) |
| version lookup before `unlink` / `rename` | extra `MANIFEST_GET` round trips | mirror |
| chunk data | chunk cache, unchanged | chunk cache, unchanged |

Mutations remain synchronous wire ops. On a successful reply the client
applies the result to the mirror immediately (it knows the path and the new
version from the response) rather than waiting for its own change event;
events apply as upserts guarded by `rev`, so the echo of a local mutation is
idempotent. Mutation round trips also shrink, because the mirror already
holds the CAS version: `unlink` drops from two round trips to one and
`rename` from three to one. The CAS itself is unchanged; if the mirror's
version is stale the server answers `ESTALE` with a `RecoveryHint`, the
client refetches, reconciles the mirror, and retries, the same conflict path
that exists today.

The macOS NFS server gains the same mirror through the shared store layer.
Because the wire `EntryWire` also gains `mtime` and `version` fields
(append-only msgpack, the sanctioned compatibility path), the NFS
`getattr`/`readdir` implementation stops issuing one `MANIFEST_GET` per file
even when the mirror is cold.

**Stale manifests and GC.** A mirror entry can briefly reference chunks that
an external mutation replaced. Refcounted GC's retention window already keeps
just-unreferenced chunks alive; if a `CHUNK_GET` still misses, the client
drops the mirror entry, refetches the manifest, and repairs the mirror. A
stale read is thus detectable and self-healing, never silently wrong bytes
(chunks remain content-verified on every read).

**Audit posture.** A read served from the mirror does not produce a
server-side audit row, just as FUSE `getattr` served from the in-memory node
table produces none today. The audit stream remains complete for mutations,
for every denied operation, and for every op that reaches the wire. Paths the
policy or the agent moat would deny never enter the mirror, because the feed
is filtered server-side by the same checks; `EACCES` results are never
cached.

## 5. Durability and fences

**Read-through mode (the default).** Write acknowledgement semantics are
unchanged. A metadata mutation is durable when the server's success frame
arrives, meaning the transaction committed to the tenant SQLite database
under WAL with `synchronous=NORMAL`: it survives a server process crash; an
unclean server host crash can roll back the newest committed transactions in
the un-checkpointed WAL tail. That window predates this design and is
unchanged by it. A client crash after the reply loses nothing; a client crash
before the reply loses at most the in-flight op, which the kernel never saw
acknowledged.

**Pipelined mode (opt-in until its gate is met).** One mutation becomes
asynchronous: `unlink`. The FUSE reply returns once the unlink is appended to
a bounded, ordered, per-mount queue; queued unlinks are issued in order over
the existing connection, carrying CAS versions from the mirror. The mirror
applies the unlink immediately, so every subsequent local operation
(`lookup`, `readdir`, a recreate at the same path) observes it; ordering
guarantees the server converges to the same state.

An acknowledged-but-unsent unlink is lost if the client process or host
crashes: the file simply still exists on the durable disk afterward. POSIX
makes the same statement about local filesystems, where an unlink is durable
only after `fsync` of the parent directory. The fences below are therefore
the durability contract, and each one drains the queue (or the affected
subset) and reports any queued failure before returning:

| Fence | Scope drained |
|-------|---------------|
| `fsync` / `fdatasync` on a file or directory | whole queue |
| `syncfs` | whole queue |
| `rmdir` | queued unlinks under that directory |
| `rename` | queued ops intersecting source or destination subtree |
| clean unmount, live handoff | whole queue |
| lease revoke, connection loss, subscription reset | whole queue |
| any op whose server reply could contradict a queued op | affected paths |

A queued unlink that fails on the server (for example `ESTALE` from a
concurrent external mutation) surfaces as an error on the next fence,
`fsync`-reports-writeback-error style, and forces a mirror
reconcile. The queue is bounded (ops and bytes); when full, `unlink` becomes
synchronous rather than growing without limit. `create` stays synchronous in
all modes, but stops paying a separate `LEASE_GRANT` round trip where the
mount's exclusivity already covers the path.

If the adversarial suite (section 6) cannot demonstrate these semantics
exactly, pipelined mode does not ship and the deliverable is the read-through
mirror with synchronous mutations, per the issue's own fallback.

## 6. Acceptance gates

From [issue #122](https://github.com/liu1700/orlop/issues/122), restated as
the checklist this work merges against:

1. **Durability documented.** Section 5 is the specification: exact
   acknowledgement points, the WAL-tail caveat, the pipelined crash window,
   and the fence table.
2. **Adversarial tests.** Reconnect, cursor loss, `resync_required`
   rebaseline, duplicate and out-of-order event delivery, external mutation
   via journal revert and agent purge while mounted, lease loss, CAS
   conflict on a mirror-supplied version, and crash during a pipelined
   drain. Each must show the mirror either serving proven-fresh data or
   falling back to server reads, never serving stale data silently.
3. **Workload benchmarks.** create/stat/walk/delete on small-file trees,
   `npm install`, `git checkout` and `git status`, and large sequential
   I/O, reported with rounds, medians, and a discarded-measurements note,
   against both the previous release and a local-disk baseline.
4. **Performance.** At least 5x on two of the three worst metadata
   scenarios (create 10.1x, walk 15x, delete 117.8x), with no more than a
   10% regression in large sequential I/O. Expected sources: walk from the
   mirror alone; delete from the mirror (two round trips to one) plus
   pipelining; create from the merged lease grant.
5. **Explicit negotiation.** `sync_protocol` in every feed request and
   response; unknown op or unknown version disables the mirror cleanly.
6. **Fallback scope.** If gate 2 fails for pipelined mode, ship read-through
   only; synchronous mutation commits remain the default acknowledgement
   semantics.

## 7. Compatibility

| Client \ Server | pre-feed server | feed-capable server |
|-----------------|-----------------|---------------------|
| pre-mirror client | unchanged | unchanged (never sends feed ops, ignores unknown pushes) |
| mirror client | `EINVAL` on first fetch, mirror disabled, behavior identical to today | negotiated via `sync_protocol` |

All wire changes are additive: new op codes, append-only msgpack fields
(`EntryWire.mtime`, `EntryWire.version`), no changes to existing frames, no
reserved-byte reuse. The tenant database changes are additive columns and
tables applied by the existing schema-ensure path. The mirror file is a pure
cache: deleting it is always safe.
