# Audit + Observability — `audit.log` and `/metrics`

The Orlop data plane writes one JSONL audit event per FUSE op, every chunk
or manifest RPC, every lease lifecycle transition, and every GC sweep.
`orlop audit tail` streams these events from the client. The Prometheus
exposition at `/metrics` (server only) reports the same activity in aggregate.

This doc is the canonical schema. Operators tail it; dashboards depend on
the event names; new layers must conform.

## Where events come from

| Layer | Process | Emitter |
|---|---|---|
| FUSE handlers (lookup, readdir, open, read, write, …) | `orlop` (Rust client) | `src/audit.rs` via `crate::audit::AuditLog` |
| Chunk + manifest + lease handlers | `orlop-server` (Go) | `cmd/orlop-server/audit.go` via `*AuditLog` |
| Lease lifecycle (grant/refresh/release/revoke/violation) | `orlop-server` | `cmd/orlop-server/lease.go` |
| Cache poisoning detection | `orlop` (Rust client) | `src/backend/dataplane/cache.rs` |
| Chunk GC sweep | `orlop-server` | `cmd/orlop-server/audit.go` `RecordGCSweep` |

Both halves write to the same on-disk file (`audit.log` or
`<storeRoot>/audit.log` on the server); the line shape is identical so a
single `tail -f` works across both.

## Common fields

Every event carries:

- `ts` — RFC3339 UTC timestamp.
- `event` — event type (see table below).
- `path` — mount-relative path the op acted on. Empty for chunk events
  (chunks are content-addressed) and for `gc_swept_chunks`.
- `allowed` — `true` if the op completed (or was permitted), `false` for a
  policy denial or a `lease_violation`.
- `command` — emitter binary name (`orlop`, `orlop-server`).
- `agent_pid`, `agent_id`, `uid`, `gid` — caller identity. Server-side
  events also carry `tenant_id`, `cert_serial`, `cert_subject`.

Optional fields (omitted from JSONL when absent) are documented per event.

## Event catalogue

### FUSE / read surface (Rust client)

| `event` | Fields | When |
|---|---|---|
| `lookup` | `path`, `allowed` | FUSE lookup |
| `readdir_entry` | `path`, `allowed` | one event per entry returned to FUSE |
| `open` | `path`, `allowed` | open(2) |
| `read` | `path`, `size`, `offset`, `allowed` | read(2) chunk |

### Write surface (Rust client)

| `event` | Fields |
|---|---|
| `create`, `mkdir`, `unlink`, `rmdir` | `path`, `mode?`, `allowed` |
| `rename` | `path` (from), `to_path`, `allowed` |
| `setattr` | `path`, `setattr_fields` (bitmask), `mode?`, `allowed` |
| `flush` | `path`, `size`, `chunks_new`, `chunks_reused`, `cas_retries`, `version_new`, `allowed` |

`setattr_fields` bitmask: `0x01` mode, `0x02` uid, `0x04` gid, `0x08` size,
`0x10` mtime, `0x20` atime.

### Data plane RPCs (server)

| `event` | Fields |
|---|---|
| `manifest_get` | `path`, `size`, `version`, `allowed`, `lease_id?` |
| `manifest_put` | `path`, `size`, `version` (post-write), `allowed`, `lease_id?` |
| `chunk_get` | `hash`, `size`, `allowed` (path empty — content-addressed) |
| `chunk_put` | `hash`, `size`, `allowed` |
| `chunk_has` | `count` (number of hashes probed), `allowed` (one event per batch) |

### Lease lifecycle (server)

| `event` | Fields |
|---|---|
| `lease_grant` | `path`, `lease_id`, `mode` (`read` \| `write`), `agent_id` |
| `lease_refresh` | `path`, `lease_id`, `mode`, `agent_id` |
| `lease_release` | `path`, `lease_id`, `mode`, `reason` (`client` \| `conn_closed`) |
| `lease_revoke` | `path`, `lease_id`, `mode`, `reason` (e.g. `contention`, `manifest_put_contention`) |
| `lease_violation` | `path`, `lease_id`, `mode`, `reason` (e.g. `revoke_timeout`) |

`mode` is `read` for `LeaseSharedRead`, `write` for `LeaseExclusiveWrite`.

### Cache + GC

| `event` | Fields | When |
|---|---|---|
| `cache_corrupt` | `path` (hex hash), `size`, `allowed: false` | Client cache returned bytes that failed BLAKE3 verification; entry is dropped + refetched. |
| `gc_swept_chunks` | `tenant_id`, `count`, `bytes_freed` | One event per tenant per sweep cycle. |

### HTTP surface (legacy v1, retained for hosted demo / inspection)

`http_create_entity`, `http_get_entity`, `http_list_entries`, `http_head_file`,
`http_get_file`, `http_get_audit`, `http_auth`. Same `path` / `size` /
`allowed` shape as the v1 events.

## `orlop audit tail`

```
orlop audit tail [--limit N] [--follow]
                 [--entity <type>:<id>]
                 [--event <name>]            # repeatable
                 [--lease-id <hex>]
```

Filters AND together. `--event` may be passed multiple times; an event
matches if any listed name matches. `--lease-id` filters to the lease
lifecycle events for one lease (and skips events that don't carry a
`lease_id`).

Examples:

```
orlop audit tail --event lease_revoke
orlop audit tail --event manifest_put --event lease_grant --follow
orlop audit tail --lease-id 5f2a... --limit 50
```

## Prometheus metrics — `/metrics`

`orlop-server` exposes a Prometheus exposition at `/metrics` (unauthenticated;
mTLS-terminated externally if desired). Collectors:

- `orlop_dataplane_op_duration_seconds{op}` — histogram of server-side
  handler latency. `op` ∈ `{list, stat, read, manifest_get, manifest_put,
  manifest_delete, manifest_rename, dir_create, dir_remove, chunk_get,
  chunk_has, chunk_put, lease_grant, lease_refresh, lease_release,
  lease_revoke}`. Buckets: exponential, base 2, 14 buckets starting at
  500 µs.
- `orlop_dataplane_bytes_total{direction, op}` — counter of payload bytes.
  `direction=in` for client→server bytes (`chunk_put`, `manifest_put`),
  `direction=out` for server→client bytes (`chunk_get`, `chunk_has`,
  `manifest_get`).
- `orlop_chunks_total{state}` — counter of chunk lifecycle events.
  `state=cached` on a `chunk_put` that stored fresh bytes; `state=deduped`
  on a `chunk_put` that hit an existing object; `state=fetched` on a
  successful `chunk_get`; `state=evicted` on each chunk freed by
  `gc_swept_chunks`.
- `orlop_lease_held{path}` — gauge, set to `1` while a lease is held on
  `path`, removed when the lease releases. Per-path cardinality is
  bounded by the number of files under active write — operators on
  workloads with many short-lived leases should watch series count.

The `/metrics` endpoint is intentionally outside the mTLS-required
middleware so a non-tenant scraper can collect it.

## Out of scope

- OpenTelemetry tracing.
- Long-term metric storage and dashboard definitions.

Both are tracked as separate issues; this doc only covers the on-disk
event schema and the in-process Prometheus collectors.
