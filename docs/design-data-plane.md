# Orlop Data Plane: Chunked Storage Over mTLS

The data plane is everything between the mount client and the chunk store:
the wire it speaks, how files are split into content-addressed chunks, how
those chunks are named and reassembled, and how concurrent writes stay
consistent. The mount client is `orlop` (Rust: FUSE on Linux, an in-process
localhost NFSv3 server on macOS); the server is `orlop-server` (Go, one
process per tenant).

This doc is about the storage and transport mechanics. The control plane
(auth, disk allocation, mount leases) lives in
[`design-auth.md`](design-auth.md) and [`control-plane.md`](control-plane.md).

The guiding constraint throughout: **the agent is untrusted.** Anything the
agent could forge (which tenant it belongs to, which chunk it is allowed to
read) must be decided from its verified certificate or from cryptographic
content, never from a value it puts on the wire.

## 1. Terminology

| Term | Meaning |
|------|---------|
| **chunk** | A variable-length slice of a file's bytes, named by the BLAKE3 hash of its contents. The unit of storage, transfer, and dedup. |
| **manifest** | The per-path record that maps a file to its ordered chunk list, plus size, mode, mtime, and a version counter. |
| **chunk store** | Server-side directory of raw chunk blobs, one file per unique hash. |
| **lease** | A server-granted capability over a path (`SHARED_READ` or `EXCLUSIVE_WRITE`) that makes write-back caching safe. |
| **journal** | A per-tenant log of recent manifest changes that supports point-in-time revert (undo). |
| **frame** | One request or response on the wire: a 16-byte header plus a msgpack payload. |

## 2. Data model: the hash is the name

A file is not stored as a byte stream. It is stored as:

1. A list of chunks, each named by `BLAKE3-256(chunk_bytes)` (32 bytes).
2. A manifest that records the path, the ordered chunk list, and metadata.

Because a chunk's name *is* the hash of its bytes, two chunks with identical
contents have the same name and are stored once. This is the property the
rest of the design leans on: dedup is automatic, integrity is checkable, and
a cached chunk can be trusted by re-hashing it.

This fits agent workloads well. Agents re-create the same `node_modules`,
the same model weights, the same datasets across sessions and across machines.
Content addressing collapses all of those copies to a single stored blob, and
a single-byte edit to a large file re-uploads one chunk (~4 MiB), not the file.

## 3. Chunking: why boundaries must move with the content

If files were split at fixed offsets (every 4 MiB, say), inserting one byte
near the front would shift every later byte across a boundary. Every
subsequent chunk would get a new hash, and the entire cache for that file
would miss. Fixed-size chunking turns a 1-byte edit into a whole-file
re-transfer.

Orlop uses **FastCDC** (content-defined chunking). Boundaries are chosen by a
rolling hash over the content, so a boundary lands at the same *content*
position regardless of what came before it. An insert disturbs only the one
or two chunks around the edit; everything after it keeps its old boundaries
and old hashes, and stays a cache hit.

The parameters are pinned and identical on both sides of the wire:

```
MIN = 1 MiB    AVG = 4 MiB    MAX = 16 MiB     (FastCDC v2020)
```

- Rust client: `CHUNK_MIN` / `CHUNK_AVG` / `CHUNK_MAX` in `src/write_handle.rs`.
- Go server: `ChunkMin` / `ChunkAvg` / `ChunkMax` in `cmd/orlop-server/cdc.go`.

The two implementations must produce byte-identical boundaries, or a file
chunked by the client would fail to dedup against the same file chunked by the
server. `tests/fastcdc_parity.rs` enforces this against a golden vector
(`tests/golden/fastcdc_chunks_go.txt`).

## 4. Content addressing and dedup

Dedup happens at three points, all for free:

- **Within a file:** repeated regions chunk to the same hash.
- **Across files and sessions:** uploading a chunk that already exists is a
  no-op; the server bumps a refcount instead of writing bytes.
- **In the client cache:** a chunk fetched once is keyed by hash, so any
  later file that references it is served locally.

The server tracks how many manifests reference each chunk (`chunks.refcount`),
which is what makes garbage collection safe (section 11).

## 5. On-disk layout

**Server chunk store:** raw blobs on the `orlop-server` host filesystem,
sharded by the first two hex characters of the hash to keep directories small:

```
<store-root>/objects/
  ab/
    ab1f… (raw chunk bytes, filename = full BLAKE3 hex)
  cd/
    cdee…
```

The chunk store writes blobs to the local filesystem as plain files
(`cmd/orlop-server/chunkstore.go`).

**Client chunk cache:** the same content-addressed shape, under the user's
cache dir (`$XDG_CACHE_HOME/orlop`, else `$HOME/.cache/orlop`):

```
<cache-root>/
  chunks/
    ab/
      ab1f…
  index.sqlite     # one row per cached chunk: (hash, size, last_access)
```

`index.sqlite` is metadata only; the bytes live next to it under `chunks/`.
Its single table tracks `last_access` so eviction can pick the
least-recently-used chunks. Refcounting is a server concern; the client just
caches and evicts by size.

## 6. Manifests

Manifests and the chunk index are a per-tenant SQLite database on the server
(`cmd/orlop-server/tenantdb.go`):

```sql
create table chunks (
  hash     blob primary key,                 -- BLAKE3, 32 bytes
  size     integer not null,
  refcount integer not null default 0 check (refcount >= 0),
  added_at integer not null
);

create table manifests (
  path    text primary key,
  size    integer not null,
  mode    integer not null,
  mtime   integer not null,
  version integer not null,                   -- monotonic per path
  chunks  blob not null                       -- packed [hash(32) | offset(8) | len(4)] …
);

create table dir_entries (
  parent text not null,
  name   text not null,
  primary key (parent, name)
);
```

(`symlinks` and `special_nodes` tables hold the corresponding node types;
`uid`/`gid`/`atime` columns were added to `manifests` later for POSIX
ownership and times.)

The `manifests.chunks` BLOB is the ordered chunk list packed inline:
`hash(32) | offset(8) | len(4)` per entry. To read a file you read its
manifest, then fetch the listed chunks (most of them from cache).

**Atomic updates use compare-and-swap on `version`.** A writer sends the
version it believes is current; the server applies the write only if the
stored version still matches, then increments it. A writer that lost the race
gets back errno **ESTALE (116)**, produced by `dataplane.ErrESTALE`, carried
in the error frame, and surfaced to FUSE as a real `ESTALE`. The wire speaks
errnos, not HTTP status codes.
The error frame can also carry a `RecoveryHint` with the caller's version and
the server's current version so the client can refetch and retry.

## 7. Integrity

Every chunk is self-verifying: its name is the hash of its bytes. The client
re-hashes a chunk on every cache hit (`ChunkCache::get`); a mismatch means
on-disk corruption, so the entry is deleted and refetched. BLAKE3 makes this
cheap (it runs at multiple GB/s on one core and parallelizes), so
hash-on-read costs little even when streaming GB-scale files. A 256-bit digest
also means an attacker cannot construct a different chunk that hashes to a name
they don't already hold, so "read a chunk you have no manifest for" is not a
reachable attack.

## 8. Read path

Reading a file never hits a server "read" op; reads are reassembled
client-side from chunks:

```
open("/proj/data.bin")
  └─ MANIFEST_GET /proj/data.bin   → version, size, [chunkA, chunkB, chunkC, …]
read(off, len)
  └─ for each chunk covering [off, off+len):
       cache hit?  → serve locally (hash-verify, done)
       cache miss? → CHUNK_HAS / CHUNK_GET → store in cache → serve
```

The first read of a cold file costs one round trip per *missing* chunk; the
second read (even after unmount and remount) is served entirely from local
disk. A read of byte 0 of a 100 MiB file fetches one ~4 MiB chunk, not 100 MiB.

## 9. Write path and crash ordering

Writes go chunk-first, manifest-last, so a crash can never leave a manifest
pointing at bytes that were never stored:

```
1. Client chunks the new/changed file region (FastCDC).
2. For each chunk: CHUNK_HAS → upload only the novel ones via CHUNK_PUT.
3. MANIFEST_PUT with expected_version = the version the client last saw.
      server: CAS on version → write manifest, bump/lower chunk refcounts,
               append a journal row, all in one SQLite transaction.
```

Ordering matters: chunks are durable before any manifest references them, and
the manifest swap is a single transaction that also adjusts refcounts and
records the change in the journal. If the CAS fails, the write returns ESTALE
and nothing is mutated. Write authority is checked at `MANIFEST_PUT`, not at
`CHUNK_PUT`: chunk uploads dedup globally and are content-addressed, but
binding a path to a chunk list is the privileged step.

## 10. The journal (revert)

Each successful manifest change appends a row to a per-tenant
`session_journal` (`cmd/orlop-server/journal.go`): the path, the operation
(`create` / `update` / `delete` / `rename`), the version before and after, and
enough of the prior manifest to undo the change. The append happens inside the
same transaction as the manifest write, so a change is never left unrecordable.

Two ops expose it on the wire:

- **`JOURNAL_QUERY` (0x15):** read journal rows (filtered by allocation),
  e.g. to show what an agent changed during a run.
- **`JOURNAL_REVERT_PATH` (0x18):** replay the inverse of the most recent
  change for each named path, restoring the prior bytes. The inverse is
  applied under CAS too, so a concurrent writer surfaces as a revert conflict
  rather than being silently clobbered.

This is what lets an operator roll back an agent's writes to a known-good
state after a bad run.

Each committed entry is also broadcast over an in-process pub/sub
(`cmd/orlop-server/journal_pubsub.go`) to per-allocation subscribers — a live
feed of what an agent is changing, without polling. Delivery is non-blocking: a
subscriber whose buffer fills is dropped and is expected to reconnect and
backfill, so a slow consumer can never stall a writer's commit.

## 11. Garbage collection and leases

**GC is reference-counted, not mark-and-sweep.** Because every manifest write
already maintains `chunks.refcount`, the sweeper does not need to walk
manifests to find unreachable chunks. It simply deletes rows where the refcount
has reached zero and the chunk is older than a retention window
(`cmd/orlop-server/gc.go`):

```sql
delete from chunks where refcount = 0 and added_at < <cutoff>
```

The same predicate is re-asserted on the per-row delete, so a refcount bump
landing between select and delete leaves the chunk alive. Each sweep emits a
`gc_swept_chunks` audit event. The retention window (`added_at < cutoff`) holds
a just-unreferenced chunk back from collection until it has aged past the
window, rather than deleting it the instant its refcount hits zero.

The **client cache** is collected independently: LRU eviction down to a byte
budget (default 2 GiB, configurable), picking victims by `last_access`. Losing
a cached chunk only costs a refetch, so the cache index is kept lightweight and
non-durable.

**Leases** make write-back caching safe. Without a consistency primitive,
caching writes locally would risk serving stale data; polling the server for
invalidations would wreck latency. Instead the server grants a per-path
capability:

| Mode | Holders | Allows |
|------|---------|--------|
| `SHARED_READ` | many | cache reads; no in-flight writes |
| `EXCLUSIVE_WRITE` | one | buffer writes locally; `fsync` flushes to the server |

The server can revoke a lease at any time (contention, admin action, expiry).
Revocation is **pushed on the same long-lived connection** (`LEASE_REVOKE`,
0x13) rather than discovered by polling; the holder must flush pending writes
before releasing. This is the same approach as NFSv4 delegations, SMB3
oplocks, and CephFS capabilities. For a single-user disk, grants are
effectively long-lived and revocation is rare, so leases buy near-free
write-back correctness. (A separate mount-level lease governs who holds the
mount; that is a control-plane concern, distinct from these per-path leases.)

## 12. Transport and wire

The data path is a **single long-lived mTLS connection** carrying binary
frames. Each frame is a fixed 16-byte header followed by a msgpack payload:

```
byte:  0        1        2 .. 9          10  11     12 .. 15
      +--------+--------+----------------+--------+----------------+
      | op (1) | flags  | request id (8) | rsv(2) | payload len(4) |  msgpack payload
      +--------+--------+----------------+--------+----------------+
```

(`cmd/orlop-server/dataplane/codec.go`; `flags` carries the response and error
bits; multi-byte fields are big-endian; reserved bytes must be zero.) The op
codes and msgpack message shapes are mirrored on both sides: Go in
`cmd/orlop-server/dataplane/`, Rust in `src/backend/dataplane/`. Large reads
never travel as a single frame; they are chunk fetches, capped by
`MaxPayloadLen` (64 MiB).

**Transport carrier.** The server always listens on both TCP and QUIC on the
same bind (`runV2TCPListener` + `runV2QUICListener`). The client's
`TransportMode` defaults to **`Tcp`**; `Quic` and `Auto` (try QUIC, fall back
to TCP, remember the choice) are opt-in. So: **TCP+TLS is the default; QUIC is
implemented but opt-in.** The carrier is just a pipe: the orlop binary frame
format above is identical over either, so QUIC is not an HTTP/3 protocol, only
a different socket. QUIC stays in the tree because it offers stream
multiplexing without head-of-line blocking and connection migration across
network changes; it is held opt-in pending throughput parity on large cold
reads.

### Op codes

All ops are client→server requests except `LEASE_REVOKE`, which the server
pushes to the client. (Codes from `cmd/orlop-server/dataplane/protocol.go`.)

| Op | Hex | Direction |
|----|-----|-----------|
| `LIST` | 0x01 | client → server |
| `STAT` | 0x02 | client → server |
| `PING` | 0x04 | client → server |
| `CLOSE` | 0x05 | client → server |
| `MANIFEST_GET` | 0x06 | client → server |
| `MANIFEST_PUT` | 0x07 | client → server |
| `CHUNK_GET` | 0x08 | client → server |
| `CHUNK_HAS` | 0x09 | client → server |
| `CHUNK_PUT` | 0x0A | client → server |
| `MANIFEST_DELETE` | 0x0B | client → server |
| `MANIFEST_RENAME` | 0x0C | client → server |
| `DIR_CREATE` | 0x0D | client → server |
| `DIR_REMOVE` | 0x0E | client → server |
| `SETATTR` | 0x0F | client → server |
| `LEASE_GRANT` | 0x10 | client → server |
| `LEASE_REFRESH` | 0x11 | client → server |
| `LEASE_RELEASE` | 0x12 | client → server |
| `LEASE_REVOKE` | 0x13 | server → client (push) |
| `JOURNAL_QUERY` | 0x15 | client → server |
| `SYMLINK` | 0x16 | client → server |
| `READLINK` | 0x17 | client → server |
| `JOURNAL_REVERT_PATH` | 0x18 | client → server |
| `MKNOD` | 0x19 | client → server |

A benchmark harness (`orlop-bench`, in `bench/`) drives synthetic filesystem
workloads under emulated WAN to compare TCP and QUIC; TCP stays the default
pending QUIC throughput parity on large cold reads.

## 13. Threat model

The mount client runs next to an untrusted agent, so the data plane assumes
the agent may send anything. Defenses:

- **Tenant comes from the cert, never the request.** mTLS identifies the
  client; the per-agent identity is bound to its certificate. The session is
  gated before any frame is served: a revoked leaf is dropped, and the
  intermediate that signed the leaf must carry a tenant OU matching the leaf's
  tenant SAN (fail-closed cross-tenant gate). See [`design-auth.md`](design-auth.md).
- **Per-op policy still runs server-side** (`cmd/orlop-server/policy.go`); a
  valid connection does not imply a valid operation.
- **Chunks are content-verified, not trusted.** A chunk's name is its hash, so
  a tampered chunk fails verification on read, and a chunk cannot be addressed
  without already knowing its 256-bit hash.
- **Writes are authorized at the manifest, not the chunk.** Uploading a chunk
  is harmless (it dedups); binding a path to a chunk list is the gated step.

Chunks are not encrypted at rest: tenant TLS isolates the data plane in
transit, and at-rest encryption is left to the host filesystem. Per-tenant
process and database isolation, not in-band encryption, is the data-at-rest
boundary.
