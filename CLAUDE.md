# CLAUDE.md

orlop: multi-tenant durable-disk service for AI agents. Go control/data plane +
Rust mount client, talking mTLS + msgpack over the network — no FFI, no cgo.
Each side builds and tests independently (see CONTRIBUTING.md).

## Layout

- `cmd/orlop-control` — control plane: per-tenant CA + disk allocator (HTTP :8080),
  admin sessions, enroll tokens, journal API. Storage: Postgres (sqlc + goose
  migrations) or embedded SQLite. `migrate` is a subcommand of the same binary.
- `cmd/orlop-server` — data plane: content-addressed chunk store (FastCDC +
  BLAKE3-256), per-disk SQLite manifests with CAS versioning, journal + pub/sub,
  mount leases, refcounted GC, quota. mTLS listeners: ops :7878, data :8443.
- `src/` — Rust `orlop` mount client: FUSE (Linux) / in-process NFSv3 (macOS),
  enroll + cert renewal, chunk cache. Subcommands: mount/unmount/audit/doctor/dev/status.
- `client/` — Go SDK for the control-plane API. Published surface; nothing
  in-repo imports it — `deadcode` hits on it are expected, not dead code.
- `deploy/helm/orlop` — reference chart. `bench/` — Rust bench harness
  (Linux-only netstats). `docker/agent.*` — image family for an external spawner,
  not built by release CI.

## Build & test

- Go: `go build ./... && go test ./...` (Postgres-gated tests skip without a DB).
- Rust: `cargo build --locked && cargo test --locked`; keep
  `cargo clippy --all-targets` warning-clean.
- CI on PRs: go.yml (vet/build/test, Postgres matrix), orlop-cli.yml (Rust),
  shellcheck.yml, upgrade.yml (runs HEAD `migrate up` against DBs provisioned by
  released tags). Branch protection on main; auto-merge disabled — watch checks,
  then `gh pr merge --squash`.

## Invariants

- Never renumber or rewrite a released DB migration; code that starts depending
  on a table/column must extend `storage.RequiredSchema` (docs/upgrade-safety.md).
- Data-plane handlers are security-critical: every wire op passes policy +
  `checkAgentPath` (confined to `/<agentID>`) and records an audit event on
  deny. Keep deny/audit semantics byte-identical when refactoring.
- Wire structs in `cmd/orlop-server/dataplane` and `src/backend/dataplane`
  mirror each other — change both sides together.
- Client transport is TCP by default; QUIC is a kept, documented opt-in
  (`ORLOP_TRANSPORT`, docs/design-data-plane.md) — not dead code.

## Docs

- `docs/*.md` on main are the source of truth for orlop.dev: the orlop-www repo
  syncs them at build (`scripts/sync-docs.mjs`) and deploys via its
  scheduled-rebuild workflow. A new doc must be added to that ORDER list to
  appear in the sidebar.
- Docs are fact-checked against source — never document features that don't
  exist. Relative `.md` links resolve on orlop.dev; links to repo files must be
  absolute GitHub URLs.
