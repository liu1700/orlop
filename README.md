<picture>
  <source media="(prefers-color-scheme: dark)" srcset="brand/orlop-wordmark-dark.svg">
  <img alt="orlop" src="brand/orlop-wordmark-light.svg" width="220">
</picture>

**Give each untrusted agent its own durable POSIX disk, without ever handing it your storage credentials.**

[![Go CI](https://github.com/liu1700/orlop/actions/workflows/go.yml/badge.svg)](https://github.com/liu1700/orlop/actions/workflows/go.yml)
[![Rust CI](https://github.com/liu1700/orlop/actions/workflows/orlop-cli.yml/badge.svg)](https://github.com/liu1700/orlop/actions/workflows/orlop-cli.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[Quickstart](#quickstart) · [How it works](#how-it-works) · [Architecture](#architecture) · [Docs](#documentation) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

orlop is a multi-tenant, **zero-trust file plane** for agent sandboxes. Each agent
gets one auto-expanding POSIX directory that it mounts over FUSE and uses like an
ordinary disk. The bytes live remotely in a content-addressed chunk store, so when
the sandbox dies the data persists and the next run re-mounts the same disk with
zero idle compute.

> **The credential never reaches the agent.** Each agent is issued its own
> short-lived mTLS client certificate whose identity (a SPIFFE SAN) is the only
> thing that authorizes access, and the server confines every connection to that
> agent's own path prefix. A compromised agent cannot read another tenant's bytes,
> cannot widen its own path, and has no key it could exfiltrate to reach the store
> directly.

## Highlights

- 🔒 **Zero-trust by construction**: per-agent mTLS identity, server-side path
  confinement, no shared storage credential to leak.
- 💾 **Survives the sandbox**: data lives in the remote chunk store and re-mounts
  on the next run with zero idle compute.
- 🧱 **Content-addressed & deduped**: bytes stored verbatim and deduped by hash, so
  keeping full, uncompressed history is nearly free.
- ⚡ **Incremental writes**: a single-byte edit ships one ~4 MiB chunk, not the
  whole file; a persistent client cache makes re-reads run at local-disk speed.
- 🔁 **Atomic overwrites**: versioned, compare-and-swap manifests replace a stale
  fact in place instead of appending and hoping retrieval picks the latest.
- 🧩 **Drop-in POSIX**: FUSE on Linux, in-process NFSv3 loopback on macOS; the
  agent just sees a directory.

> **Built for agent memory.** orlop is the *storage substrate* for an agent-memory
> stack (durable, cheap to update, and safe under multi-tenancy), but it does no
> extraction, ranking, or semantic consolidation; the layer above does. See
> [`docs/agent-memory.md`](docs/agent-memory.md) for what orlop gives that stack and
> where it stops.

## Quickstart

A complete single-node stack (control + server + one mounted disk) runs on one
host with no external dependencies: the control plane can use its embedded
SQLite backend (`DATABASE_URL=sqlite:./orlop.db`), so not even Postgres is
required. Follow [`docs/standalone-quickstart.md`](docs/standalone-quickstart.md)
end to end; it walks `server register` → `token issue` → `orlop mount --from-env`
→ write a file → unmount → remount and watch the data persist.

## How it works

```
  agent sandbox                control plane                data plane
  ┌──────────────┐   enroll    ┌───────────────┐   place   ┌───────────────┐
  │ orlop mount  │────token───▶│ orlop-control │──────────▶│ orlop-server  │
  │  (FUSE/NFS)  │             │ CA · alloc ·  │           │ chunk store · │
  │              │◀──mTLS cert─│ auth · enroll │           │ manifests ·   │
  │  /mnt/orlop  │             └───────────────┘           │ leases · GC   │
  └──────┬───────┘                                         └──────┬────────┘
         │   mTLS data path (per-agent client cert)               │
         └──────────────────────────────────────────────────────▶│
```

1. **Control plane** (`orlop-control`) is the CA and the allocator. It enrolls an
   agent, mints a short-lived per-agent mTLS client certificate, and places the
   agent's disk on a data-plane server.
2. **Mount client** (`orlop`) mounts the disk over FUSE (Linux) or an in-process
   NFSv3 loopback (macOS) and speaks the data protocol over mTLS.
3. **Data plane** (`orlop-server`) stores content-addressed chunks plus per-disk
   SQLite manifests, and confines each connection to the path its certificate names.

## Architecture

| Component | Lang | Role |
|---|---|---|
| `cmd/orlop-control` | Go | control plane: auth, per-tenant CA, disk allocation, enroll, mount/lease issuance |
| `cmd/orlop-server`  | Go | data plane: chunk store, manifests, journal/pub-sub, GC, lease sweep, mTLS |
| `src/` (`orlop` binary) | Rust | FUSE/NFS mount client (`orlop mount`, lease refresh, `orlop doctor`) |

<details>
<summary><strong>Why Go <em>and</em> Rust</strong></summary>

Each layer uses the language that's strongest for its job, and a clean network
boundary (mTLS + msgpack over a long-lived connection, no cgo, no FFI) makes that
split essentially free:

- **Rust for the mount client** because it runs *inside the untrusted agent sandbox*,
  on the hot path of every filesystem syscall. No GC pauses to stall I/O, a small
  static binary, low memory footprint, and a mature FUSE/NFS/QUIC ecosystem
  (`fuser`, `nfsserve`, `quinn`).
- **Go for the control and data planes** because they're network services where Go's
  ecosystem and velocity shine (HTTP router, Postgres, migrations, metrics), and the
  public [client SDK](client) is Go too, which is what host integrators orchestrating
  sandboxes actually want.

The two halves are separate binaries that only share a wire protocol, so they build
and ship independently. **Contributing to one side almost never requires the other's
toolchain.** See [`CONTRIBUTING.md`](CONTRIBUTING.md).
</details>

## Build from source

```bash
GOWORK=off go build ./...   # Go control + data plane
cargo build --release       # Rust mount client (the `orlop` binary)
```

The Go side is a single module; the Rust side is a Cargo workspace
(`orlop` + `orlop-bench`).

## Go client SDK

[`github.com/liu1700/orlop/client`](client) is a small, standard-library-only Go SDK
for the control-plane API: allocate an agent's disk, set quotas, mint the short-lived
per-agent enroll token, and read usage. A host integrates orlop by calling this SDK
and invoking the `orlop` binary in the sandbox.

```go
import "github.com/liu1700/orlop/client"

c := client.New("https://orlop-control.example", serviceToken)
disk, err := c.AllocateDisk(ctx, agentID, ownerID, 1<<30)
token, err := c.MintEnrollToken(ctx, agentID) // hand this to the sandbox
```

A `client.Fake` in-memory implementation is provided for consumer tests.

## Documentation

| Doc | What's inside |
|---|---|
| [`standalone-quickstart.md`](docs/standalone-quickstart.md) | Run the whole thing on one host |
| [`database-backends.md`](docs/database-backends.md) | Postgres vs embedded SQLite: which to use and how |
| [`design.md`](docs/design.md) | System overview and filesystem layout |
| [`design-data-plane.md`](docs/design-data-plane.md) | Chunk store / journal design |
| [`design-auth.md`](docs/design-auth.md) | Certificate / tenant isolation model |
| [`design-identity.md`](docs/design-identity.md) | Host identity: verify a host-issued JWT and map it to a tenant |
| [`control-plane.md`](docs/control-plane.md) | Control-plane API |
| [`control-plane-runbook.md`](docs/control-plane-runbook.md) | Operator workflows (CA, admin seeding) |
| [`agent-memory.md`](docs/agent-memory.md) | What orlop gives an agent-memory stack, and where it stops |
| [`audit-events.md`](docs/audit-events.md) | Audit event schema |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md), including why the Go/Rust split means you
rarely need both toolchains to contribute.

## Security

The isolation model, operator responsibilities, hardening switches, known limits, and
how to report a vulnerability are in [`SECURITY.md`](SECURITY.md). Read it before
running orlop with real tenants.

## License

[Apache-2.0](LICENSE).
