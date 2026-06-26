# Design: Cross-Agent Portable Disk

## What We Are Building

Orlop gives agents and users a plain, writable filesystem that follows them
across machines.

The shipped product has two user-visible pieces:

- a `orlop` CLI that logs in, mounts, unmounts, and tails the audit log
- an agent skill (`skill/orlop/SKILL.md`) that tells the agent when and how
  to use the mount

The primitive is:

```text
orlop login + orlop mount  →  /mnt/orlop  (ordinary rw directory)
```

Example:

```bash
orlop login                     # device flow, writes ~/.config/orlop/credentials.json
orlop mount sandbox demo        # allocates remote storage + mounts via FUSE
ls /mnt/orlop/sandbox/demo
echo "hello" > /mnt/orlop/sandbox/demo/notes.txt
orlop unmount
```

The agent uses `/mnt/orlop` with normal filesystem tools: `ls`, `cat`, `find`,
`rg`, `python`. No special commands are needed to look up paths — the mount
root is the path.

## Why This Is Different From Mounting S3

S3 exposes storage layout. Orlop exposes a plain, stable disk.

An agent should not need to know:

- which bucket stores the data
- which API fetches supporting files
- how internal storage is partitioned

The agent should know one thing: the mount is at `/mnt/orlop` and it works
like any local directory.

## Architecture

```
agent → /mnt/orlop → GatewayFs (Rust FUSE) → DataStore (binary mTLS wire) → orlop-server (Go) → server host fs
                                               ↑
                                               orlop-control (Go) — auth + allocation
```

Key components:

- **`GatewayFs`** (`src/fs.rs`) — FUSE filesystem. Interns inodes in
  `GatewayFs::state`. All storage I/O goes through `DataStore`; no direct
  fs reads/writes from FUSE handlers.
- **`DataStore`** (`src/store.rs`) — the only `Store` impl. Speaks binary-framed
  mTLS to `orlop-server`.
- **`orlop-server`** — Go per-tenant data plane. Stores bytes on the host
  filesystem via `os.*` calls.
- **`orlop-control`** — Go control plane. Device-flow login, token refresh,
  tenant CA, `/agent/enroll`, allocation.

## CLI Surface

```bash
orlop login                   # device flow; writes ~/.config/orlop/credentials.json
orlop mount <type> <id>       # allocates remote storage + FUSE mounts
orlop unmount                 # unmounts; shreds local mTLS client cert
orlop audit tail              # streams JSONL audit events
orlop audit tail --limit 20
```

There is no `orlop init`, `orlop route set`, `orlop entity create`, or
`orlop entity resolve`. The mount root is the stable path; agents navigate it
directly.

## Skill Surface

The agent skill (`skill/orlop/SKILL.md`) is short and operational. Its job is
to steer agent behavior:

- Run `orlop login` then `orlop mount` before touching data.
- Work inside `/mnt/orlop` with normal tools.
- Run `orlop unmount` when done; never kill -9 the mount process.
- Do not invent paths outside `/mnt/orlop`.

## Policy

Policy is path-based glob allow/deny, checked on every FUSE op:

```yaml
policy:
  readonly: false
  deny:
    - "**/secrets"
    - "**/secrets/**"
    - "**/.env*"
```

Denied accesses return `EACCES` and are recorded in the audit log.

## FUSE Caching

Read-side: whole-file read cache with TTL eviction. Cache key is
`{mount_name}:{rel_path}`. Writes invalidate the entry. The kernel-side
directory cache (`FOPEN_CACHE_DIR | FOPEN_KEEP_CACHE`) reduces `readdirplus`
round trips within the entry TTL window.

Write-side: chunked uploads via FastCDC (MIN 1 MiB / AVG 4 MiB / MAX 16 MiB).
`flush` sends only novel chunks; reused chunks are deduplicated by the server
via BLAKE3 content addressing. `fsync` waits for durability acknowledgment.

## Audit

The audit log is JSONL, append-only, one event per FUSE op:

```json
{"ts":"2026-04-28T12:20:47Z","event":"read","path":"/sandbox/demo/notes.txt","size":1024,"agent_pid":12345,"allowed":true}
```

Required fields: `ts`, `event`, `path`, `size` (when available), `offset`
(when available), `agent_pid`, `allowed`.

`orlop audit tail` streams events from the local audit log with optional
`--limit`, `--follow`, `--event`, and `--lease-id` filters.

## What To Avoid

- S3 / Google Drive / SharePoint / rclone adapters — out of scope.
- MCP — reserved, not implemented.
- Web UI — separate surface.
- New `Store` impls — only `DataStore` in production.
- Local-fs backend — `orlop-server` owns persistence; the client has no
  direct filesystem backend.
