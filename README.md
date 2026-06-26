# orlop

**Give each untrusted agent its own durable POSIX disk, without ever handing it your storage credentials.**

orlop is a multi-tenant, zero-trust file plane for agent sandboxes. Each agent
gets one unique, auto-expanding POSIX directory that it mounts over FUSE and
uses like an ordinary disk. The bytes live remotely in a content-addressed chunk
store, so when the sandbox dies the data persists and the next run for the same
agent re-mounts the same disk with zero idle compute.

The point that makes orlop different from "wrap a network filesystem in a CLI":
**the agent never sees a storage credential.** Each agent is issued its own
short-lived mTLS client certificate whose identity (a SPIFFE SAN) is the only
thing that authorizes access, and the data-plane server confines every
connection to that agent's own path prefix. A compromised agent cannot read
another tenant's bytes, cannot widen its own path, and has no key it could
exfiltrate to reach the store directly.

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

1. The control plane (`orlop-control`) is the CA and the allocator. It
   enrolls an agent, mints a short-lived per-agent mTLS client certificate, and
   places the agent's disk on a data-plane server.
2. The agent runs the `orlop` client, which mounts the disk over FUSE (Linux) or
   an in-process NFSv3 loopback (macOS) and speaks the data protocol over mTLS.
3. The data plane (`orlop-server`) stores content-addressed chunks plus
   per-disk SQLite manifests, and confines each connection to the path its
   certificate names.

## Components

| Component | Lang | Role |
|---|---|---|
| `cmd/orlop-control` | Go | control plane: auth, per-tenant CA, disk allocation, enroll, mount/lease issuance |
| `cmd/orlop-server`  | Go | data plane: chunk store, manifests, journal/pub-sub, GC, lease sweep, mTLS |
| `src/` (`orlop` binary)   | Rust | FUSE/NFS mount client (`orlop mount`, lease refresh, `orlop doctor`) |

### Why Go *and* Rust

Each layer uses the language that's strongest for its job, and a clean network
boundary (mTLS + QUIC + msgpack — no cgo, no FFI) makes that split essentially
free:

- **Rust for the mount client** because it runs *inside the untrusted agent
  sandbox*, on the hot path of every filesystem syscall. No GC pauses to stall
  I/O, a small static binary, low memory footprint, and a mature FUSE/NFS/QUIC
  ecosystem (`fuser`, `nfsserve`, `quinn`).
- **Go for the control and data planes** because they're network services where
  Go's ecosystem and velocity shine (HTTP router, Postgres, migrations, metrics)
  — and the public [client SDK](client) is Go too, which is what host
  integrators orchestrating sandboxes actually want.

The two halves are separate binaries that only share a wire protocol, so they
build and ship independently. **Contributing to one side almost never requires
the other's toolchain** — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Quickstart

A complete single-node stack (Postgres + control + server + one mounted disk)
runs on one host with no external dependencies. Follow
[`docs/standalone-quickstart.md`](docs/standalone-quickstart.md) end to end; it
walks `server register` → `token issue` → `orlop mount --from-env` → write a
file → unmount → remount and watch the data persist.

## Build from source

```bash
GOWORK=off go build ./...   # Go control + data plane
cargo build --release       # Rust mount client (the `orlop` binary)
```

The Go side is a single module; the Rust side is a Cargo workspace
(`orlop` + `orlop-bench`).

## Go client SDK

[`github.com/liu1700/orlop/client`](client) is a small, standard-library-only
Go SDK for the control-plane API: allocate an agent's disk, set quotas, mint the
short-lived per-agent enroll token, and read usage. A host integrates orlop by
calling this SDK and invoking the `orlop` binary in the sandbox.

```go
import "github.com/liu1700/orlop/client"

c := client.New("https://orlop-control.example", serviceToken)
disk, err := c.AllocateDisk(ctx, agentID, ownerID, 1<<30)
token, err := c.MintEnrollToken(ctx, agentID) // hand this to the sandbox
```

A `client.Fake` in-memory implementation is provided for consumer tests.

## Design and reference docs

- [`docs/standalone-quickstart.md`](docs/standalone-quickstart.md) — run the whole thing on one host
- [`docs/control-plane.md`](docs/control-plane.md) — control-plane API
- [`docs/control-plane-runbook.md`](docs/control-plane-runbook.md) — operator workflows (CA, admin seeding)
- [`docs/design.md`](docs/design.md) — system overview and filesystem layout
- [`docs/design-data-plane.md`](docs/design-data-plane.md) — chunk store / journal design
- [`docs/design-auth.md`](docs/design-auth.md) — certificate / tenant isolation model
- [`docs/audit-events.md`](docs/audit-events.md) — audit event schema

## Security

The isolation model, operator responsibilities, hardening switches, known
limits, and how to report a vulnerability are in
[`SECURITY.md`](SECURITY.md). Read it before running orlop with real tenants.

## License

[Apache-2.0](LICENSE).
