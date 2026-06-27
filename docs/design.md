# Orlop: System Overview and Filesystem Layout

Orlop gives an agent a plain, writable filesystem that follows it across
machines. The agent runs ordinary tools (`ls`, `cat`, `rg`, `python`) against
a normal directory; orlop makes the bytes durable, content-addressed, and
isolated per tenant behind the mount.

This document is the whole-system mental model and the on-disk layout. For the
fast tour, read the README's [How it works](../README.md#how-it-works); for the
internals of any one layer, follow the [Going deeper](#going-deeper) links.

## What it is, and what it is not

The unit orlop hands an agent is a single mount root (for example
`/mnt/orlop`). Everything under it behaves like a local disk: open, read, write,
rename, delete. The mount root *is* the path, reached directly by ordinary
filesystem calls.

This is deliberately unlike mounting object storage. An agent should not have to
know which bucket holds a file, which API fetches a sibling, or how bytes are
partitioned underneath. Object storage exposes its storage layout; orlop hides
it behind a plain disk. The chunking, deduplication, and content addressing
described below are implementation details the agent never sees.

The agent is **untrusted**. It runs arbitrary code inside a sandbox, so orlop
never lets the agent name its own tenant or reach another tenant's bytes. That
single constraint forces most of the design: identity comes from a verified
certificate, not from anything the agent says (see
[Control plane vs data plane](#control-plane-vs-data-plane)).

## Whole-system view

```
        AGENT SANDBOX (untrusted)                CONTROL PLANE              DATA PLANE
   ┌──────────────────────────────┐         ┌──────────────────┐     ┌──────────────────────┐
   │  agent process               │ enroll  │  orlop-control   │     │   orlop-server       │
   │     │  syscalls              │ token   │  (Go)            │place│   (Go)               │
   │     ▼                        │────────▶│  per-tenant CA   │────▶│   chunk store        │
   │  kernel                      │         │  disk allocation │     │   per-tenant SQLite  │
   │     │  FUSE (Linux)          │◀────────│  agent enroll    │     │     manifests        │
   │     │  NFSv3 (macOS)         │ 1h leaf │  host-id verify  │     │   leases · journal   │
   │     ▼                  cert  │  cert   └──────────────────┘     │   GC · ops/metrics   │
   │  orlop  (Rust mount client)  │                                  └──────────┬───────────┘
   │   GatewayFs → DataStore ─────┼──────────────────────────────────────────────┘
   │                              │   long-lived mTLS connection (binary frames + msgpack)
   └──────────────────────────────┘
```

- The mount client enrolls **once** with the control plane to get a short-lived
  client certificate, then talks only to the data plane for the rest of the
  session.
- The data path is a single long-lived **mTLS** connection carrying binary
  frames (a small fixed header plus a msgpack payload). TCP+TLS is the
  production default; QUIC is implemented but opt-in.
- File reads are served from a local chunk cache; only cache misses and writes
  cross the network.

## Key terms

| Term | Meaning |
|---|---|
| **Control plane** | `orlop-control`. Issues identity and places disks. Off the I/O hot path. |
| **Data plane** | `orlop-server`. Stores and serves bytes for one tenant over mTLS. |
| **Mount client** | The `orlop` binary. Presents the mount and speaks the data protocol. |
| **Tenant** | The isolation unit. One namespace of files; one set of credentials. |
| **Chunk** | A variable-size byte run, named by the BLAKE3 hash of its contents. |
| **Content addressing** | A chunk's name *is* its hash, so identical bytes are stored once. |
| **Chunk store** | The server's content-addressed blob directory (`objects/`). |
| **Manifest** | Per-path record: ordered chunk list, version, mode, mtime. |
| **Lease** | A per-path shared-read or exclusive-write grant the server tracks. |
| **Enroll token** | A single-use token the host hands the sandbox to obtain a cert. |
| **Agent leaf** | The short-lived (1h) client certificate minted per enrollment. |

## Building blocks

### `orlop-control`: control plane (Go)

The certificate authority and the allocator. It runs a per-tenant CA (an org
root signs a tenant intermediate, which signs each agent leaf), allocates and
places disks on data-plane servers, and enrolls agents at `POST /agent/enroll`.
It is an HTTP service (a Go `net/http` server with the go-chi router); its API is documented in
[`control-plane.md`](control-plane.md). It does not store file bytes and is not
on the read/write path.

Operator CLI (separate from the mount client): `orlop-control migrate up`,
`ca init`, `ca mint-server-cert`, `server register`, `token issue`, `user seed`.
See [`control-plane-runbook.md`](control-plane-runbook.md).

### `orlop-server`: data plane (Go)

One per tenant's bytes. It holds the content-addressed chunk store, the
per-tenant SQLite manifests, leases, a journal, and garbage collection, and
exposes an ops/metrics endpoint. Every connection is mTLS; the server confines a
connection to the path its certificate names. It stores blobs on the local
filesystem.

### `orlop`: mount client (Rust)

Runs inside the agent sandbox, on the hot path of every filesystem syscall. Two
layers:

- **`GatewayFs`** (`src/fs.rs`): the kernel-facing filesystem. On Linux it is a
  FUSE filesystem; on macOS the same logic is served through an in-process
  localhost NFSv3 server (`src/nfs.rs`). Every handler enforces policy, then goes
  through `DataStore`; no FUSE/NFS handler touches the network or disk directly.
- **`DataStore`** (`src/backend/dataplane/store.rs`): the only `Store`
  implementation. It speaks the binary mTLS protocol to `orlop-server` and owns
  the local chunk cache. (The `Store` trait itself lives in `src/store.rs`.)

### Go client SDK (`client/`)

A stdlib-only SDK a host uses to drive the control plane: `client.New`,
`AllocateDisk(ctx, agentID, ownerID, grantBytes)`, `MintEnrollToken`,
`SetDiskQuota`, usage. A `client.Fake` backs consumer tests. A host integrates
orlop by calling this SDK and running the `orlop` binary in the sandbox.

## Mount-client CLI surface

The mount client exposes exactly these commands:

| Command | What it does |
|---|---|
| `orlop mount` | Mounts the remote disk at the configured mountpoint and blocks until unmounted. Linux = FUSE, macOS = localhost NFSv3. |
| `orlop mount --from-env` | In-sandbox mount. Reads `ORLOP_AGENT_ID`, `ORLOP_MOUNT_POINT`, `ORLOP_CONTROL_PLANE`, `ORLOP_ENROLL_TOKEN`; trades the enroll token for a 1h client cert at `/agent/enroll`; runs in the foreground (the pod supervises the process). |
| `orlop unmount [target]` | Unmounts; releases the lease and discards the local client cert. |
| `orlop audit tail` | Streams JSONL audit events from the local audit log. Filters: `--event` (repeatable), `--lease-id`, `--limit`, `--follow`. |
| `orlop doctor [--json]` | Offline preflight: FUSE/NFS support, a writable cache dir, config and credentials. Touches no network. |

`mount` takes flags only (`--mountpoint`, `--foreground`, `--no-inject`,
`--credentials`, `--from-env`), no positional arguments. The mount root is the
stable path and the agent navigates it directly. (On mount, the client also writes a
small marker-bracketed orlop stanza into the working directory's `AGENTS.md` so
file-reading agents learn the mount exists; `--no-inject` disables this.)

## Control plane vs data plane

The split exists because identity and bytes have opposite requirements.

| | Control plane (`orlop-control`) | Data plane (`orlop-server`) |
|---|---|---|
| Job | issue identity, place disks | store and serve bytes |
| Frequency | once per session (enroll) | every cache miss and write |
| Transport | HTTP (`net/http` server, go-chi router) | long-lived mTLS, binary frames + msgpack |
| Trust input | host service token / enroll token | the client certificate |

Because the agent is untrusted, the tenant a request acts on is read from the
**verified leaf certificate**, never from the request body. The leaf carries two
SPIFFE URI SANs (one for the tenant, one for the agent), and the server pins the
connection to that path. An agent cannot ask for another tenant's data because
nothing it sends names the tenant. After enrollment the agent never contacts the
control plane again for I/O; the certificate is the whole authorization story on
the data path. The certificate and isolation model is detailed in
[`design-auth.md`](design-auth.md).

## A request, end to end

A host wants an agent to read `/notes.txt` from its disk.

1. **Allocate + mint (host).** The host calls `AllocateDisk(...)` to place the
   disk, then `MintEnrollToken(agentID)` and injects the token as
   `ORLOP_ENROLL_TOKEN` into the sandbox.
2. **Enroll (mount client).** `orlop mount --from-env` posts the enroll token to
   `POST /agent/enroll`. The control plane mints a 1-hour agent leaf signed by
   the tenant intermediate and returns it with the CA chain and the data-plane
   address (`server_addr`).
3. **Connect.** The client opens a long-lived mTLS connection to `orlop-server`.
   It verifies the server's certificate **only** against the org root delivered
   at enroll (not the system trust store), so a wrong server cannot impersonate
   the data plane.
4. **Syscall.** The agent runs `cat /mnt/orlop/notes.txt`. The kernel turns the
   read into a FUSE (Linux) or NFS (macOS) request that reaches `GatewayFs`.
5. **Policy.** `GatewayFs` checks the path against the deny / read-only globs. A
   denied path returns `EACCES` and is audited; an allowed path continues.
6. **Manifest.** `DataStore` fetches the manifest (`ManifestGet`) to get the
   ordered chunk list and the current version.
7. **Chunks.** For each chunk, the local cache is consulted by BLAKE3 hash. A hit
   is hash-verified and served locally; a miss is fetched with `ChunkGet` over
   the mTLS connection and stored in the cache.
8. **Return + audit.** The reassembled bytes flow back up to the kernel, and the
   op is appended to the local JSONL audit log.

A write reverses the lower half: on `flush`, FastCDC splits the new bytes into
chunks (MIN 1 MiB / AVG 4 MiB / MAX 16 MiB), `ChunkHas`/`ChunkPut` sends only the
**novel** chunks (identical bytes already on the server are reused by hash), and
`ManifestPut` commits the new chunk list with a compare-and-swap on the version.

## Failure and edge behavior

- **Concurrent writers.** Manifests are versioned; a `ManifestPut` is a
  compare-and-swap. The losing writer gets `ESTALE` (errno 116), refetches the
  current manifest, and retries. There are no HTTP-style status codes on the
  wire.
- **Lease revoke.** The server can push a revoke for an exclusive-write lease on
  the same connection (server-initiated), so the holder learns immediately
  without polling.
- **Cache corruption.** Every cache hit is hash-verified. A mismatch deletes the
  blob, audits `cache_corrupt`, and is reported as a miss so the chunk is
  refetched; corruption can never be served.
- **Certificate expiry.** The agent leaf lives one hour; a long session refreshes
  its lease and re-enrolls as needed.
- **Nothing idle.** Between sessions nothing keeps running: `orlop unmount`
  releases the lease and discards the local client cert, leaving only durable
  bytes on the server.

## Policy

Access is gated by path globs evaluated on every filesystem op, in the mount
client (`src/policy.rs`), with a matching server-side check. Config:

```yaml
policy:
  readonly: false
  deny:
    - "**/secrets"
    - "**/secrets/**"
    - "**/.env*"
```

A path is permitted when it matches no `deny` glob (and, if an `allow` list is
set, matches it). `readonly: true` rejects every write regardless of path.
Denied access returns `EACCES` and is recorded in the audit log.

## Audit

The local audit log is append-only JSONL, one line per filesystem op. A read:

```json
{"ts":"2026-04-28T12:20:47Z","event":"read","path":"/notes.txt","size":1024,"agent_pid":12345,"agent_id":"a_demo","allowed":true}
```

Core fields written by the mount client:

| Field | Notes |
|---|---|
| `ts` | RFC 3339 timestamp |
| `event` | op name, e.g. `read`, `flush`, `lookup`, `lease_denied` |
| `path` | mount-relative path |
| `allowed` | whether policy permitted the op |
| `agent_pid` | calling process PID |
| `agent_id` | enrolled agent identity |
| `uid` / `gid` | calling user / group |
| `size`, `offset` | present on read/flush-style events only |

`orlop audit tail` streams this file with the filters in the CLI table above.
The server emits its own additional events (with `tenant_id`, `cert_serial`,
etc.); the full catalogue is in [`audit-events.md`](audit-events.md).

## Filesystem layout

orlop stores plain blobs and SQLite files on ordinary disks. The trees below
are the layouts that exist; verify any
path against the cited source before depending on it.

### Server chunk store and metadata

A hosted tenant is a chunk store under `store/objects/` plus per-tenant SQLite.
Chunks are sharded by the first byte of the BLAKE3 hex
(`chunkstore.go`); manifests, journal, and sessions live in `routes.db`, with
`leases.db` beside it (`tenantdb.go`, `server.go`). The owner directory carries
the account quota; a tenant nests under it only when it differs from the owner.

```
<tenants_root>/
  <owner>/                      # account dir, quota applied here
    [<tenant>/]                 # present only when tenant != owner
      store/
        objects/
          ab/                   # first 2 hex of the chunk hash
            ab3f9c…e9           # content-addressed blob (BLAKE3-256)

<metadata_root>/                # = tenants_root unless split onto a fast disk
  <owner>/
    [<tenant>/]
      routes.db                 # manifests + journal + sessions (SQLite, WAL)
      leases.db                 # active leases (SQLite)
```

`metadata_root` defaults to `tenants_root` (chunks and metadata co-located); it
can be split so the latency-critical SQLite sits on a fast local disk while the
bulk chunk store lives on networked storage.

### Client chunk cache

The mount client keeps a content-addressed read cache under the cache dir
(`$XDG_CACHE_HOME/orlop`, else `$HOME/.cache/orlop`). It is a per-chunk LRU
keyed by BLAKE3 hash, capped by a byte budget (default 2 GiB), evicting
least-recently-used chunks when full (`src/backend/dataplane/cache.rs`):

```
<cache_root>/
  chunks/
    ab/
      ab3f9c…e9                 # cached chunk blob (hash-verified on read)
  index.sqlite                  # chunks(hash, size, last_access), LRU index
```

### Control-plane secrets (filesystem CA backend)

With the filesystem secrets backend, the CA material lives under
`$ORLOP_SECRETS_DIR` as PEM files (`cmd/orlop-control/internal/secrets`,
`ca_cmd.go`). Keys are mode `0600`.

```
$ORLOP_SECRETS_DIR/
  ca/
    root/
      cert.pem                  # org root CA certificate (10-year)
      key.pem                   # org root key (kept offline / encrypted at rest)
    tenant/
      <tenant>/
        cert.pem                # tenant intermediate (1-year)
        key.pem
```

The alternative backend (`ORLOP_SECRETS_BACKEND=postgres`) keeps the same logical
keys (`ca/root/cert.pem`, …) in the database instead of on disk; it requires a
Postgres `DATABASE_URL`.

## Going deeper

| Topic | Doc |
|---|---|
| Chunking, dedup, manifests, journal, GC | [`design-data-plane.md`](design-data-plane.md) |
| Certificate hierarchy and tenant isolation | [`design-auth.md`](design-auth.md) |
| External-IdP / host-identity enrollment | [`design-identity.md`](design-identity.md) |
| Control-plane HTTP API | [`control-plane.md`](control-plane.md) |
| Operator workflows (CA, seeding, registration) | [`control-plane-runbook.md`](control-plane-runbook.md) |
| Audit event schema and metrics | [`audit-events.md`](audit-events.md) |
| Run the whole stack on one host | [`standalone-quickstart.md`](standalone-quickstart.md) |
