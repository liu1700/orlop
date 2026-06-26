# Orlop Data Plane — Local-Feel Filesystem Over WAN

This doc covers the data plane between `orlop` (Rust client, FUSE) and
`orlop-server` (Go, per-tenant data plane). The control plane
(`orlop-control`: auth, allocations, mount leases) is out of scope; see
`docs/design-auth.md`, `docs/control-plane.md`.

This doc covers the binary-framed mTLS data plane (chunked, leased). The
carrier is TCP+TLS today; QUIC is implemented and present in both binaries
but kept opt-in pending throughput work — see Layer 1.

## Problem

Today's data plane is HTTP/1.1 over TLS. Every FUSE op on a cache miss is one
HTTP request — `GET /v1/entries?path=…`, `HEAD /v1/files?path=…`,
`GET /v1/files?path=…`. Read returns whole-file bytes.

This is fine on a LAN. It is bad on a WAN:

- **One RTT minimum per op.** `ls -la` on a 100-entry directory is 1 list +
  100 HEAD = 101 RTTs. At 50ms RTT that's >5 seconds.
- **No persistent cache.** `orlop unmount` clears the in-memory list/metadata
  caches; the next mount re-downloads everything.
- **Whole-file reads.** Reading byte 0 of a 100 MiB file downloads 100 MiB.
- **No write side.** The `Backend` trait is read-only; FUSE writes return
  EROFS.
- **No connection migration.** Laptop sleep, IP change, WiFi switch breaks
  any in-flight stream.

The product promise is "a disk that follows you across machines and agents".
Today's wire makes that disk feel like a slow web service. This doc is the
plan to make it feel local.

## Goals

|                                         | Today                       | Goal                                     |
|-----------------------------------------|-----------------------------|------------------------------------------|
| stat / ls p50 over 50ms WAN, warm cache | ≥50 ms per entry            | <5 ms per entry                          |
| ls cold (100-entry dir)                 | >5 s                        | <100 ms                                  |
| Sequential read warm                    | n/a (no persistence)        | local-disk speeds across mount cycles    |
| Sequential read cold                    | RTT × file_size / chunk     | RTT × missing_chunks                     |
| Write                                   | full POSIX with chunked uploads | full POSIX, fsync correct            |
| Network blip survival                   | breaks the mount            | survives sleep + IP change               |
| Bandwidth on small edits                | full file uploaded          | one chunk (~4 MiB)                       |
| User-visible install                    | `orlop` binary + FUSE       | unchanged                                |

**Zero new user-side installs is a hard requirement.** Everything ships in
the `orlop` and `orlop-server` binaries. Binary framing, chunking, leases,
persistent cache — all internal.

## Non-goals

- **Multi-writer CRDT directory semantics.** Orlop is single-user; lease
  serialization handles real workloads.
- **Adapting third-party stores.** By design, no S3/rclone/local-fs
  adapters. The chunk store is Orlop's own format on the `orlop-server`
  host filesystem.
- **A generic remote-FS protocol.** Not building NFSv5.

## Architecture

```
agent → /mnt/orlop → GatewayFs (Rust FUSE)
                           │
                           ▼
                       DataStore
                           │  (data plane: binary frames over
                           │   long-lived TCP+TLS; QUIC opt-in)
                           ▼
                     orlop-server (Go)
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
        manifest store              chunk store
      (per-tenant SQLite)      (objects/<hh>/<blake3>)

control plane (auth, allocate, mount-lease):
   orlop → orlop-control (HTTP/JSON over TLS) — unchanged
```

The data plane decomposes into six layers, each independently shippable and
independently justified.

| # | Layer            | What it does                              | Why it earns its place                                              |
|---|------------------|-------------------------------------------|---------------------------------------------------------------------|
| 1 | Transport        | TCP+TLS default; QUIC opt-in              | Long-lived multiplexed binary frames over a single mTLS socket      |
| 2 | Framing          | Long-lived connection, binary frames      | Amortize handshake; carry server-push (lease revoke) on same socket |
| 3 | Storage model    | Content-addressed chunks (BLAKE3 + FastCDC) | Dedup; deltas on edit; persistent client cache hits local-disk speed |
| 4 | Manifests        | path → chunk-list, version, mode, mtime   | Atomic writes via CAS on version                                    |
| 5 | Consistency      | Capability leases (SHARED_READ / EXCLUSIVE_WRITE) | Safe write-back caching with correct fsync                  |
| 6 | Cache            | Persistent client chunk cache             | Survives unmount; second access is local-disk speed                 |

## Why each layer earns its place (first principles)

### Layer 1: Transport — TCP+TLS today, QUIC opt-in

**Bottleneck.** HTTP/1.1 forces a TCP+TLS handshake per connection or queues
ops behind keep-alive serially. The connection drops on network change.

**Today.** A single long-lived mTLS socket carries all v2 frames. Same
binary wire, same ops, regardless of carrier. The client config field
`TransportMode` selects `Tcp` (default), `Quic`, or `Auto` (try QUIC, fall
back to TCP and remember the choice).

**Why TCP is default.** We shipped both transports and benched them
end-to-end against staging WAN (see `bench-results/remote-v2-{tcp,quic}.json`,
`bench-results/par-sweep/`):

- 1000× stat-storm: QUIC slightly better (p50 169 ms vs 179 ms, p99 173 ms
  vs 186 ms). Real but small.
- 100 MiB sequential cold read: **QUIC ~38 s vs TCP ~10 s** — QUIC ~4×
  slower. Warm reads were comparable.

The cold-read regression dominates the user-visible "feels local" goal, so
TCP is the default for production. Likely causes (not fully isolated yet):
client kernel UDP receive buffer cap (non-root binaries can't `setsockopt`
past `net.core.rmem_max`), QUIC stream/connection flow-control window
defaults, and cloud UDP path quality. Issue #80 is closed against this
finding; revisiting QUIC requires throughput parity on cold large reads
first.

**What QUIC still buys (when re-enabled).**

- Multiplexed streams without TCP head-of-line blocking — a slow chunk
  read can't stall a quick stat.
- Connection migration across IP / network changes — the "follow you
  across machines" promise. Not yet validated end-to-end.
- 0-RTT resumption for safe ops (`LIST/STAT/MANIFEST_GET/CHUNK_GET/CHUNK_HAS`).

QUIC support is intentionally kept in-tree (server listens on UDP, client
opens per-RPC bidi streams for `chunk_get`) so a future throughput fix
doesn't have to re-introduce the carrier.

**Out of scope.** HTTP/3 framing — the wire is orlop-specific binary; QUIC
is just a carrier.

### Layer 2: Framing — minimal binary

**Bottleneck.** JSON parse + HTTP header overhead per op. A 4 KiB read
becomes a multi-KiB request/response. A 16-byte header is enough.

**Why custom binary, not Cap'n Proto v1.** Cap'n Proto's promise pipelining
(`open(p) → read(<promise>, …)` in 1 RTT) is real but its win mostly
disappears once chunks + leases are in place. Stat results become cache
hits; "100 stats in 1 RTT" stops being on the critical path. Cap'n Proto
stays an option for v2, gated on benchmark evidence.

**Frame shape (illustrative).**

```
+--------+--------+----------+----------+----------+
| op (1) | flags  |  rid (8) | rsv (2)  | len (4)  | payload (len bytes)
+--------+--------+----------+----------+----------+
```

Op codes mirror FUSE-side concepts: `LIST`, `STAT`, `MANIFEST_GET`,
`CHUNK_GET`, `CHUNK_HAS`, `CHUNK_PUT`, `MANIFEST_PUT`, `LEASE_GRANT`,
`LEASE_REFRESH`, `LEASE_RELEASE`, plus server-push `LEASE_REVOKE`.

### Layer 3: Storage model — content-addressed chunks

**Bottleneck.** Whole-file reads/writes. One byte changes → whole file
re-uploaded. Same file across sessions → re-downloaded every time.

**Why content addressing wins for Orlop specifically.**

- Agent workloads have massive duplication. Same `node_modules`, same
  model weights, same datasets across sessions. Content addressing dedupes
  naturally.
- Persistent client cache by hash means second-access is local-disk speed.
- Single-byte edits ship one chunk (~4 MiB), not the whole file.
- Server-side dedup is free.

**Why FastCDC, not fixed-size.** A single-byte insert in a fixed-chunked
file shifts every subsequent chunk and invalidates the entire cache.
FastCDC's content-defined boundaries mean an insert affects ~2 chunks.

> **Canonical FastCDC parameters (pinned, shared by Rust client and Go server):**
> `MIN = 1 MiB / AVG = 4 MiB / MAX = 16 MiB`
> Algorithm: FastCDC v2020, normalization level 1, seed 0. Constants in
> `src/fs/write_handle.rs` (`CHUNK_MIN/AVG/MAX`) and
> `cmd/orlop-server/cdc.go` (`ChunkMin/Avg/Max`) must stay in sync.

**Why BLAKE3.** ~3 GB/s on a single core, parallelizable, prefix-free. Hash
cost matters when streaming GB-scale files.

**Reference points.** restic, JuiceFS, Tahoe-LAFS, casync, Perkeep all
ship chunked content-addressed storage in production.

### Layer 4: Manifests

**Bottleneck.** With chunks we still need a path → chunk-list mapping with
versioning for atomic updates.

**Schema** (per-tenant SQLite):

```sql
create table manifests (
  path text primary key,
  size integer not null,
  mode integer not null,
  mtime integer not null,
  version integer not null,         -- monotonic per path
  chunks blob not null              -- packed [hash(32) | offset(8) | len(4)]
);

create table chunks (
  hash blob primary key,             -- BLAKE3, 32 bytes
  size integer not null,
  refcount integer not null,
  added_at integer not null
);

create table dir_entries (
  parent text not null,
  name text not null,
  primary key (parent, name)
);
```

`MANIFEST_PUT` is a CAS on `version`. Concurrent writers without a lease
get `409 stale_version`; with an `EXCLUSIVE_WRITE` lease they cannot
conflict.

### Layer 5: Consistency — capability leases

**Bottleneck.** Write-back caching is unsafe without consistency primitives.
Polling kills latency.

**Why leases.** CephFS / NFSv4 delegations / SMB3 oplocks all use this.
~15–20 years in production. For Orlop (single user) lease grants are
essentially permanent; revocation is rare. Write-back caching becomes a
near-free correctness improvement.

**Modes.**

- `SHARED_READ` — any number of clients, no in-flight writes.
- `EXCLUSIVE_WRITE` — single client, may buffer writes locally; `fsync`
  flushes.

**Lease scope.** Per-path. The mount-level lease (#71) is orthogonal —
that controls who holds the mount; per-path leases govern caching
semantics within a held mount.

**Eviction.** Server can revoke for any reason (contention, admin action,
TTL expiry). Client must flush any pending writes before relinquishing.
Failure to flush before TTL is a correctness bug — audit-logged loudly.

**Server-push for revoke.** Bidirectional protocol on the same long-lived
connection (Layer 2). Polling-based invalidation is expressly rejected.

### Layer 6: Cache — persistent, content-addressed

**Bottleneck.** Today's `moka` caches are in-memory and per-process.
`orlop unmount` throws everything away.

**Layout.**

```
$XDG_CACHE_HOME/orlop/
  chunks/
    ab/
      abcd1234…  (raw chunk bytes)
  index.sqlite     # LRU metadata: hash, size, last_access, refcount
```

LRU eviction with a configurable cap (default 2 GiB). Hash-on-read verifies
integrity on every cache hit — cheap with BLAKE3, catches disk corruption.

## What we are explicitly not building

- **CRDTs for directory metadata.** Single-user, lease-serialized.
- **Cap'n Proto promise pipelining.** Conditional v2; gated on benchmark
  evidence after Layers 3 + 5.
- **Distributed chunk storage / multi-region replication.** `orlop-server`
  is single-tenant per process.
- **Encrypted chunks at rest.** Tenant TLS isolates the data plane;
  filesystem encryption is the host's responsibility.
- **Adapters for S3 / rclone / local-fs.** This document is canon.

## Sequencing (ROI-ordered, not time-ordered)

Each step is shippable on its own and measurable against the benchmark
harness.

1. **Benchmark harness** — emulated WAN (`tc qdisc … netem`), workload
   fixtures, JSON output. Gates measurability of everything else.
   Implemented in `bench/` (workspace member, binary `orlop-bench`); see
   "Benchmark harness" below.
2. **Long-lived data-plane connection (TCP+TLS, binary framing)** —
   amortizes per-op handshake cost. Carries existing list/stat/read.
3. **Chunk store + manifests on `orlop-server`** —
   `MANIFEST_GET / CHUNK_GET / CHUNK_HAS`. Files become chunk lists.
4. **Persistent client chunk cache + chunked reads** — pairs with #3 for
   the read-side product win. WAN starts to feel local here.
5. ✅ **Write-side `Store` trait + chunked uploads** (PR #89) —
   `write/create/unlink/rename/mkdir/rmdir`. Client computes chunks,
   uploads novel ones, atomic manifest update.
6. **Capability leases + write-back caching** — exclusive leases enable
   immediate-ack writes; fsync blocks on durability.
7. ✅ **QUIC transport** (#80, closed) — drop-in carrier swap landed
   server-side and client-side; framing unchanged. Default kept on TCP
   after WAN bench showed QUIC ~4× slower on 100 MiB cold reads.
   Connection migration not yet validated end-to-end; revisit if the
   throughput gap closes.
8. **Chunk store GC** — server-side mark-and-sweep against manifests;
   client-side LRU on cache directory.
9. **Audit + observability extensions** — new event types, lease
   lifecycle, chunk-level metrics.
10. **(Conditional) Cap'n Proto promise pipelining** — only if benchmark
    after #2–#6 still shows stat-storm regressions.

Each item is a tracked GitHub issue. The tracking issue carries the
checklist.

## Benchmark harness

`orlop-bench` (in `bench/`) drives synthetic workloads against any mount
point and emits per-workload JSON: `name`, `status`, `p50_ms`, `p99_ms`,
`bytes_in`, `bytes_out`, `ops`, `duration_s`. Workloads:

- `stat-storm` — 1000 stats across a wide directory
- `ls-large-dir` — readdir of a 10k-entry directory
- `sequential-read` — 100 MiB file, 64 KiB reads in order
- `random-read` — same file, 64 KiB reads at deterministic random offsets
- `small-edit` — 1 KiB writes at striped 4 MiB-aligned offsets, fsync each
- `large-edit` — write a fresh 100 MiB file, fsync at the end
- `cold-warm-cycle` — sequential-read, unmount, mount, sequential-read again
  (skipped unless `--mount-cmd` and `--unmount-cmd` are provided)

Workloads are mount-agnostic: the harness measures the filesystem at the
given path, whatever it is. The default `make bench` target points at a
tmp directory as a smoke test of the pipeline; meaningful orlop numbers
come from pointing it at a live orlop mount.

Comparing two result files:

```
./scripts/bench-compare.sh bench-results/<a>.json bench-results/<b>.json
```

Renders a markdown table; flags p50 regressions above 5% (configurable via
`--threshold-pct`). Non-CI integration is intentional for the first pass —
local-first per #74's scope.

Stability note: on a fast host filesystem (tmpfs), sub-millisecond
operations show scheduler-jitter variance well above 5% across runs. The
5%-stability target is for the real measurement targets — orlop mounts
under emulated WAN where ops are ms-scale and the noise floor is small
relative to signal. Each subsequent layer (`/v2` framing, chunk store,
chunked reads, …) ships with bench numbers diffed against the prior
revision so the per-layer ROI is visible in the PR.

## Migration

- `Store` trait (`src/store.rs`) replaced the old `Backend` trait; `DataStore`
  is the only production implementation. Dead backends (`LocalBackend`,
  `S3CliBackend`, `RcloneBackend`) and the v1 HTTP wire are deleted.
- `orlop-server` now speaks only the binary-framed mTLS wire. The `/v1/*`
  HTTP endpoints are removed; the `data_plane: v1` config flag is gone.
- Audit log JSONL format is append-only; new event types coexist with old
  ones.

## Operational concerns

- **Cache disk usage.** `~/.cache/orlop/chunks/` capped (default 2 GiB,
  configurable). LRU evicts stale chunks.
- **Server chunk disk usage.** Chunks dedupe across files; refcounted.
  Background GC sweeps unreferenced chunks.
- **UDP-blocked networks.** Production default is TCP+TLS, so UDP-blocked
  networks are a non-issue today. If QUIC is ever re-enabled by default,
  `TransportMode::Auto` already falls back to TCP on connect timeout (2 s)
  and caches the preference per-server.
- **Lease expiry under network partition.** Client must assume revoked
  after TTL/2 with no contact and flush proactively. Audit-loud on any
  violation.
- **Manifest version conflicts.** Writes without a lease that race get
  `409 stale_version` and retry; with a lease they cannot conflict.

## Security

- mTLS on the data plane — tenant identity in the client cert, just as on
  `/v1`.
- Per-op policy check still runs server-side (`cmd/orlop-server/policy.go`).
- Chunk reads are not authenticated past the connection layer — chunks are
  opaque blobs, and reading a chunk you don't have the manifest for is
  cryptographically infeasible (BLAKE3-32 collision).
- Write capability is checked on `MANIFEST_PUT`, not `CHUNK_PUT`. Chunk
  uploads dedupe globally; writing a manifest pointing at a chunk you
  uploaded but don't own the path for is rejected.

## Open questions

- **Manifest store on Postgres vs SQLite per tenant.** Per memory, Postgres
  = Supabase, never self-hosted. Manifests are per-tenant data and live
  with `orlop-server`'s host (currently SQLite). Confirm during Layer 3.
- **Chunk store atop ZFS vs ext4.** ZFS gives free dedup at the block
  layer (redundant with content addressing) plus snapshots. Decide as a
  deployment knob, not a protocol concern.
- **Cap'n Proto vs hand-rolled binary v2.** Decide post-benchmark, see
  Issue 10.
