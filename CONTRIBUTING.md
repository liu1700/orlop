# Contributing to orlop

Thanks for your interest in orlop. This guide gets you from a fresh clone to a
passing build with the least setup possible.

## You usually need only one toolchain

orlop is split into two halves that talk over the network (mTLS + msgpack over a
long-lived connection), **not** over FFI. There is no cgo and no shared linking, so the two
sides build, test, and ship completely independently. That means **most changes
touch only one side, and you only install the toolchain for the side you touch.**

| You're working on… | Directory | Language | You need |
|---|---|---|---|
| Control plane / data plane server, Go SDK | `cmd/`, `client/` | Go | Go toolchain only |
| FUSE/NFS mount client (`orlop` binary), benchmarks | `src/`, `bench/`, `tests/` | Rust | Rust toolchain only |

The CI mirrors this: [`go.yml`](.github/workflows/go.yml) runs on `**.go`
changes, [`orlop-cli.yml`](.github/workflows/orlop-cli.yml) runs on `src/**`
changes. A pure-Go change never triggers the Rust build, and vice versa.

(Why two languages at all? See [Why Go *and* Rust](README.md#architecture) in the
README. Short version: each side uses the language that's strongest for its job,
and the clean network boundary keeps that essentially free.)

## Setup

The fastest path is the **dev container**: open the repo in VS Code (or any
devcontainer-aware editor) and "Reopen in Container". It provisions both
toolchains, the Linux FUSE headers, and pre-fetched deps from
[`.devcontainer/devcontainer.json`](.devcontainer/devcontainer.json), with
nothing to install on your host.

Otherwise, install only the toolchain(s) you need from the table above and let
the Makefile do the rest. It checks each toolchain is present, installs the
Linux FUSE headers, and pre-fetches dependencies:

```bash
make setup        # both sides
make setup-go     # Go side only
make setup-rust   # Rust side only (installs libfuse3-dev on Linux)
```

The exact build/test commands per side are below.

### Go side (`cmd/`, `client/`)

Requires the Go version pinned in [`go.mod`](go.mod).

```bash
GOWORK=off go build ./...   # build control + data plane
go vet ./...
go test ./...
```

### Rust side (`src/`, `bench/`, `tests/`)

Requires a stable Rust toolchain (install via [rustup](https://rustup.rs)).
On **Linux** the mount client links libfuse3, so install the dev headers first:

```bash
# Debian/Ubuntu
sudo apt-get install -y libfuse3-dev pkg-config
```

On **macOS** the client uses an in-process NFSv3 loopback instead of FUSE, so
no FUSE headers are needed for a normal build.

```bash
cargo build --locked        # build the `orlop` mount client
cargo test --locked
```

### Both at once (full stack)

Only needed if you're changing the wire protocol or running the end-to-end
stack. The [standalone quickstart](docs/standalone-quickstart.md) brings up a
database (Postgres or the embedded SQLite backend), the control plane, the
server, and a mounted disk on one host.

## The cross-language contract

The Go and Rust halves are decoupled, but they must agree on two things, and
both are guarded by tests so you can't drift them silently:

- **Wire protocol**: message framing and msgpack payloads on the mTLS/QUIC data
  path (`src/backend/dataplane/` on the Rust side).
- **Content addressing**: both sides run FastCDC chunking and must produce
  **byte-identical chunk boundaries**, since chunks are content-addressed. This
  is pinned by golden vectors: [`tests/fastcdc_parity.rs`](tests/fastcdc_parity.rs)
  checks the Rust chunker against `tests/golden/fastcdc_chunks_go.txt`.

If you change either of these, update **both** sides and the golden fixtures in
the same PR.

## Before you open a PR

Run the checks for the side(s) you touched:

- Go: `go build ./... && go vet ./... && go test ./...`
- Rust: `cargo build --locked && cargo test --locked`

Keep PRs scoped to one concern. If a change spans both languages (e.g. a
protocol change), call that out in the PR description.

### Touching the database schema

Released migrations are frozen: never renumber, rewrite, or squash a migration
that has already shipped in a tag — a deployed database is already at that
version and will never re-run it. If you must squash the baseline, ship a
forward bridge migration numbered above the highest released version and guarded
with `IF NOT EXISTS`. The full policy, the CI upgrade guard, and the schema
self-check are in [`docs/upgrade-safety.md`](docs/upgrade-safety.md).

## License

By contributing you agree that your contributions are licensed under the
project's [Apache-2.0](LICENSE) license.
