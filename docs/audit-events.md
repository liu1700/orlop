# Audit Events and Metrics

orlop records what happens to a tenant's files in two complementary forms:

- **`audit.log`**: one JSON object per line (JSONL), one line per filesystem
  operation, chunk/manifest RPC, lease transition, and GC sweep. It answers
  "who touched what, when, and was it allowed?"
- **`/metrics`**: a Prometheus exposition on the server that reports the same
  activity in aggregate (latencies, byte counters, lease gauges).

The agent is untrusted, so the audit log never takes the caller's word for
identity: server-side lines carry the `tenant_id`/`agent_id` taken from the
verified client certificate, not from anything in the request. The two halves
of orlop (the Rust mount client and the Go data-plane server) write the
*same line shape* to their own `audit.log`, so a single `jq` filter works
across both.

## Where events come from

| Surface | Process | Writes |
|---|---|---|
| FUSE / NFS handlers (lookup, read, create, write, …) | `orlop` (Rust mount client) | `src/audit.rs` |
| Client read-cache integrity check | `orlop` (Rust mount client) | `src/backend/dataplane/cache.rs` |
| Agent enrollment | `orlop` (Rust mount client) | `src/main.rs` |
| Data-plane RPCs (manifest, chunk, dir, journal) | `orlop-server` (Go) | `cmd/orlop-server/dataplane_server.go` |
| Lease lifecycle | `orlop-server` (Go) | `cmd/orlop-server/lease.go` |
| Chunk GC + agent purge | `orlop-server` (Go) | `cmd/orlop-server/gc.go`, `control_purge_agent.go` |
| Control HTTP endpoint (`/audit`) | `orlop-server` (Go) | `cmd/orlop-server/handlers.go` |

Each side writes to the path named by its `audit_log` config key (default
`./audit.log`). The client streams its own file with `orlop audit tail`; the
server's `/audit` endpoint reads the server file.

A user-level operation often appears on *both* sides. A `setattr`, for example,
produces one client line (the FUSE op the kernel handed `orlop`) and one server
line (the wire op `orlop-server` executed). Tell them apart by the identity
fields: client lines name the calling process in `command` and have no
`tenant_id`; server lines have `command: "orlop-server"` plus `tenant_id` and
the cert fields.

## The envelope

Every line is a flat JSON object. These fields form the shared envelope; the
catalogue below lists only the fields specific to each event.

| Field | Type | Meaning |
|---|---|---|
| `ts` | RFC3339 string | When the event was written (UTC). |
| `event` | string | Event name (the catalogue keys below). |
| `path` | string | Mount-relative path the op acted on. Empty for content-addressed (`chunk_*`), journal, and sweep events. |
| `allowed` | bool | `true` if the op completed or was permitted; `false` for a denial. See conventions. |
| `command` | string | Client: the calling process name (from `/proc/<pid>/comm` on Linux). Server: `"orlop-server"`. |
| `agent_pid` | int | Client: PID of the process that issued the syscall. |
| `uid`, `gid` | int | Caller's user/group id. |

Identity richness depends on the emitter:

- **Server data-plane and HTTP events** add `agent_id`, `tenant_id`,
  `cert_serial`, `cert_subject`, all read from the verified client cert.
- **`session_id`** (optional) is the mount's implicit session id: at mount time
  orlop stamps each backend with a `mount:<hex>` id (derived from the
  exclusive-mount lease), and every write for the lifetime of that mount carries
  it. It is omitted on non-write events.
- **`size`, `offset`, and `command` are always-present keys** — emitted on every
  line as `null` when not applicable, not omitted (a SIEM can rely on the key
  existing). `size` holds a byte count on byte-measuring events (`read`, `flush`,
  read-only `open`, `lookup` on hit, `readdir_entry`/`readdirplus_entry`,
  `head_file`, `manifest_get`/`manifest_put`, `chunk_get`/`chunk_put`,
  `cache_corrupt`, `cache_evicted`) and is `null` elsewhere; `chunk_has` carries
  `count` instead. `offset` is set only by the client `read` (and the macOS write
  path). By contrast, the richer identity fields below (`agent_pid`, `uid`,
  `gid`, `agent_id`, `tenant_id`, `cert_*`, `session_id`) are *omitted* when
  absent, not null.
- **Lease-lifecycle and GC events carry a deliberately reduced envelope.** See
  those sections.

## Conventions

- **Success vs failure is the `allowed` boolean, not a status code.** The wire
  has no HTTP status; a failed op is logged with `allowed: false`.
- **Policy and authorization denials reuse the op's own event name.** When an
  agent cert's per-agent scope rejects a path, the server writes the normal op
  line (e.g. `manifest_put`) with `allowed: false`, rather than a distinct
  "denied" event. One wrinkle: the per-agent path-moat denial logs the lowercased
  wire op, so a denied directory listing or stat is recorded as `list`/`stat`
  (not `list_entries`/`head_file`).
- **`lease_denied` and `lease_violation` are not `allowed: false`.** Both
  hard-code `allowed: true`: `lease_denied` records that the client fell back
  to an uncached path, and `lease_violation` records a server-side lease
  invariant break. Neither is a caller-facing access denial.
- **What is not logged:** file *contents* never appear; chunk events carry the
  BLAKE3 hash and byte count only. `chunk_has` is summarized as a batch count
  rather than one line per probed hash, to bound log volume. The log is
  unredacted, so keep `audit.log` access-controlled like any sensitive log.

## Catalogue

### Mount client: FUSE/NFS surface (Rust)

These are emitted as the kernel drives the mount. Envelope identity is the
calling process (`command`, `agent_pid`, `uid`, `gid`).

| `event` | When | Extra fields |
|---|---|---|
| `lookup` | path resolution | `size` (on hit) |
| `opendir` | directory open | none |
| `readdir_entry` | one per child returned to `readdir` | `size` |
| `readdirplus_entry` | one per child returned to `readdirplus` | `size` |
| `open` | file open | `size` (read-only opens; absent on write opens) |
| `read` | `read(2)` served from the chunk cache | `size`, `offset` |
| `create` | file create | `mode` |
| `mkdir` | directory create | `mode` |
| `unlink` | file remove | none |
| `rmdir` | directory remove | none |
| `rename` | rename | `to_path` (`path` is the source) |
| `symlink` | symlink create | none |
| `setattr` | `chmod`/`chown`/`truncate`/`utimes` | `setattr_fields` (bitmask) |
| `flush` | dirty file flushed to the server | `size`, `chunks_new`, `chunks_reused`, `cas_retries`, `version_new`, `recovery_*` (on a write conflict) |
| `lease_denied` | write lease refused; client falls back | `allowed: true` |

`setattr_fields` is a bitmask of which attributes the call set:

| Bit | Field |
|---|---|
| `0x01` | mode |
| `0x02` | uid |
| `0x04` | gid |
| `0x08` | size (truncate) |
| `0x10` | mtime |
| `0x20` | atime |

Sample of a `read` of 4 KiB at offset 0:

```json
{"ts":"2026-06-27T18:21:09.114Z","event":"read","path":"/agent-7/data/model.bin",
 "size":4096,"offset":0,"command":"python3","agent_pid":48211,"uid":1000,"gid":1000,
 "allowed":true}
```

Sample of a `flush` that wrote two new chunks and reused one:

```json
{"ts":"2026-06-27T18:21:10.882Z","event":"flush","path":"/agent-7/data/out.txt",
 "size":1310720,"chunks_new":2,"chunks_reused":1,"cas_retries":0,"version_new":8,
 "command":"python3","agent_pid":48211,"uid":1000,"gid":1000,"allowed":true}
```

On a write conflict, the `flush` line also carries a flattened recovery hint:

| Field | Meaning |
|---|---|
| `recovery_kind` | conflict kind, e.g. `cas_conflict` |
| `recovery_suggested_action` | human-readable remediation |
| `recovery_your_version` | version the client wrote against |
| `recovery_current_version` | server's current version |
| `recovery_last_writer_agent_id` | agent that last won the path (if known) |
| `recovery_last_writer_session_id` | that writer's session (if known) |
| `recovery_last_writer_at_unix_ms` | when that write landed (unix ms) |

> The columns above describe the Linux **FUSE** surface (the production path). The
> macOS **NFS** surface emits the same event *names* but a leaner envelope: no
> `agent_pid`/`uid`/`gid` (`command` is `null`), `create` carries `size: 0`
> instead of `mode`, `setattr` omits `setattr_fields`, `read` and `readdir_entry`
> omit `size`, writes log as `flush` with `size`+`offset` (no chunk stats), and
> `symlink`/`readlink` are not emitted.

### Mount client: cache integrity (Rust)

| `event` | When | Extra fields |
|---|---|---|
| `cache_corrupt` | a cached chunk's bytes failed BLAKE3 re-verification; the entry is dropped and refetched | `path` = hex hash, `size`, `allowed: false` |
| `cache_evicted` | the local read-cache LRU-prunes chunks to reclaim space | `size` = bytes freed, `chunks_reused` = chunks evicted, `reason` (`low_water` \| `high_water`), `path` empty, `allowed: true` |

These cache events carry the default, empty identity — no `command`, `agent_pid`,
`uid`, or `gid`:

```json
{"ts":"2026-06-27T18:22:01.004Z","event":"cache_corrupt",
 "path":"7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
 "size":1048576,"offset":null,"command":null,"allowed":false}
```

```json
{"ts":"2026-06-27T18:25:40.512Z","event":"cache_evicted","path":"","size":104857600,
 "offset":null,"chunks_reused":128,"reason":"low_water","command":null,"allowed":true}
```

### Mount client: enrollment (Rust)

| `event` | When | Extra fields |
|---|---|---|
| `enrollment` | the agent obtains its leaf certificate at mount time | `path` = new cert serial on success; empty with `allowed: false` on failure |

### Data plane: binary RPCs (Go server)

Emitted over the long-lived mTLS data connection (binary frames + msgpack),
not over HTTP. Identity comes from the agent's client cert: these lines carry
`agent_id`, `tenant_id`, `cert_serial`, `cert_subject`, and `command:
"orlop-server"`.

| `event` | When | Extra fields |
|---|---|---|
| `list_entries` | directory listing | none |
| `head_file` | file stat | `size` (on success) |
| `manifest_get` | read a path's manifest | `size`, `version` |
| `manifest_put` | write a path's manifest (CAS on version) | `size`, `version` (post-write), `session_id?` |
| `manifest_delete` | delete a path | `session_id?` |
| `manifest_rename` | rename a path | `path` = source, `session_id?` |
| `dir_create` | create a directory | `session_id?` |
| `dir_remove` | remove a directory | `session_id?` |
| `setattr` | apply attribute change | `session_id?` |
| `symlink` | create a symlink | `session_id?` |
| `mknod` | create a special node | `session_id?` |
| `readlink` | read a symlink target | none |
| `chunk_get` | fetch a chunk | `hash`, `size` (`path` empty) |
| `chunk_put` | store a chunk | `hash`, `size`, `session_id?` (`path` empty) |
| `chunk_has` | presence probe for a batch of hashes | `count` = hashes probed (`path` empty) |
| `journal_query` | query the per-tenant journal | none (`path` empty) |
| `journal_revert_path` | revert a path via the journal | none (`path` empty) |

Sample of a `manifest_put` accepted at version 8:

```json
{"ts":"2026-06-27T18:21:10.901Z","event":"manifest_put","path":"/agent-7/data/out.txt",
 "size":1310720,"version":8,"agent_id":"agent-7","tenant_id":"acme",
 "cert_serial":"3af9...","cert_subject":"spiffe://orlop.example/agent/agent-7",
 "uid":0,"gid":0,"command":"orlop-server","allowed":true}
```

### Lease lifecycle (Go server)

Leases coordinate concurrent writers (see
[design-data-plane.md](design-data-plane.md)). These lines carry a reduced
envelope (`agent_id`, `lease_id`, `mode`, `reason`) and always
`allowed: true`. `mode` is `read` for a shared-read lease, `write` for an
exclusive-write lease.

| `event` | When | `reason` values |
|---|---|---|
| `lease_grant` | lease granted | (empty) |
| `lease_refresh` | holder renews | (empty) |
| `lease_release` | lease released | `client`, `conn_closed` |
| `lease_revoke` | holder asked to yield | `contention`, `manifest_put_contention` |
| `lease_violation` | holder did not yield in time, or the lease expired | `revoke_timeout`, `expired` |

```json
{"ts":"2026-06-27T18:21:11.220Z","event":"lease_revoke","path":"/agent-7/data/out.txt",
 "lease_id":"5f2a1c7e9b0d4a3f8c6e2d1b0a9f8e7d","mode":"write","agent_id":"agent-7",
 "reason":"contention","allowed":true}
```

### Chunk GC and agent purge (Go server)

| `event` | When | Extra fields |
|---|---|---|
| `gc_swept_chunks` | one per tenant per GC sweep cycle | `tenant_id`, `count`, `bytes_freed`, `dry_run` (`path` empty) |
| `agent_data_purged` | an agent's subtree is purged via the control endpoint | `tenant_id`, `count` (manifests deleted), `bytes_freed` |

```json
{"ts":"2026-06-27T03:00:00.000Z","event":"gc_swept_chunks","path":"","tenant_id":"acme",
 "count":42,"bytes_freed":58720256,"dry_run":false,"command":"orlop-server","allowed":true}
```

### Control HTTP endpoint (Go server)

The server's only HTTP audit events. Everything else above rides the binary
data plane.

| `event` | When | Extra fields |
|---|---|---|
| `http_get_audit` | the mTLS-gated `GET /audit` endpoint served the log | `path` = `/audit`, `size` = number of audit records returned (after tenant/agent scoping and the limit cap) |
| `http_auth` | a request failed authentication at the HTTP layer | `path` = request path+query, `allowed: false` |

## `orlop audit tail`

Streams the client's `audit.log`. Filters AND together.

```
orlop audit tail [--event <name>]   # repeatable; matches if any listed name matches
                 [--lease-id <hex>] # only lease_* events for that lease
                 [--limit N]        # print the last N matching lines
                 [--follow]         # keep streaming new lines
```

`--lease-id` skips any event that has no `lease_id`. Omitting both `--limit`
and an explicit `--follow` defaults to follow mode.

```
orlop audit tail --event lease_revoke
orlop audit tail --event manifest_put --event lease_grant --follow
orlop audit tail --lease-id 5f2a1c7e9b0d4a3f8c6e2d1b0a9f8e7d --limit 50
```

## Metrics: `/metrics`

`orlop-server` exposes a Prometheus exposition at `GET /metrics`. Both
`/metrics` and `/healthz` are unauthenticated by design: scrapers and health
checks do not carry mTLS client certs. `/audit`, by contrast, is mTLS-gated.

The four primary collectors:

- **`orlop_dataplane_op_duration_seconds{op}`**: histogram of server-side
  handler latency. Buckets are exponential, base 2, 14 buckets starting at
  500 µs. The `op` label set (no `read`; file reads are served client-side
  from the chunk cache):

  ```
  list  stat  manifest_get  manifest_put  manifest_delete  manifest_rename
  dir_create  dir_remove  setattr  symlink  readlink  mknod
  chunk_get  chunk_has  chunk_put  journal_query  journal_revert_path
  ping  close  lease_grant  lease_refresh  lease_release  lease_revoke
  ```

  Note the metric labels `list`/`stat` correspond to the audit events
  `list_entries`/`head_file`; the names differ between the two surfaces.

- **`orlop_dataplane_bytes_total{direction, op}`**: counter of payload bytes.
  `direction=in` for client→server (`chunk_put`, `manifest_put`),
  `direction=out` for server→client (`chunk_get`, `chunk_has`, `manifest_get`).

- **`orlop_chunks_total{state}`**: chunk lifecycle counter. Emitted states:
  `fetched` (a `chunk_get` hit), `cached` (a `chunk_put` that stored fresh
  bytes), `deduped` (a `chunk_put` whose content already existed). The help
  text also names `evicted`, but GC does not currently touch this counter, so
  that state is reserved and never emitted.

- **`orlop_lease_held{path}`**: gauge set to `1` while a lease is held on
  `path`, with the series removed on release. Per-path cardinality is bounded
  by the number of files under active write; watch series count on workloads
  with many short-lived leases.

Also exposed:

| Metric | Type | Labels |
|---|---|---|
| `orlop_journal_writes_total` | counter | `op`, `allocation_id` |
| `orlop_journal_query_duration_seconds` | histogram | none |
| `orlop_journal_rows_total` | gauge | `allocation_id` |
| `orlop_journal_revert_total` | counter | `allocation_id`, `result` |
| `orlop_session_forgery_rejected_total` | counter | `reason` (`bad_format`, `bad_hex`, `unknown_or_wrong_conn`, `fenced`) |
| `orlop_agent_path_denied_total` | counter | `op` |

`orlop_agent_path_denied_total` increments when a connection whose cert carries
an `/agent/<id>` SAN touches a path outside that agent's subtree, the same
event that writes an `allowed: false` op line to `audit.log`.
