# Container images

Every `vX.Y.Z` tag publishes three **multi-arch (amd64 + arm64)** images to GHCR,
so you don't have to rebuild orlop from source — in particular the mount client,
which otherwise needs the Rust toolchain plus `libfuse3-dev`. The `images` job in
[`.github/workflows/release.yml`](https://github.com/liu1700/orlop/blob/main/.github/workflows/release.yml) cuts them on
each tag from the **same per-arch binaries that ship in the release tarballs** —
no in-Docker rebuild.

| Image | Component | Role | Base |
|---|---|---|---|
| `ghcr.io/liu1700/orlop-control` | control plane | HTTP API **and** operator CLI — `migrate` is a subcommand of this one binary, not a separate image | distroless static, nonroot |
| `ghcr.io/liu1700/orlop-server` | data plane | the data-plane server (ops + data listeners, mTLS) | distroless static, nonroot |
| `ghcr.io/liu1700/orlop-mount` | mount client | static `orlop` disk-mount binary with `fusermount3` available at runtime | debian trixie-slim |

## Tags & pinning

Each release publishes `:vX.Y.Z` and moves `:latest`. Both are multi-arch
manifests — Docker/containerd selects `linux/amd64` or `linux/arm64`
automatically. Each push also prints an immutable digest; pin it for
reproducible deploys:

```bash
docker pull ghcr.io/liu1700/orlop-control:v0.6.8
# or, pinned by digest (printed by the images job):
docker pull ghcr.io/liu1700/orlop-control@sha256:<digest>
```

## `orlop-control`

The control-plane HTTP API and the operator CLI are the **same binary**, so
`migrate` is a subcommand (`orlop-control migrate up`).

| | |
|---|---|
| Port | `8080` (HTTP API; override with `PORT`) |
| Entrypoint | `orlop-control` — no args starts the server; `migrate`, `server`, `token`, `user`, `ca` are subcommands |
| Default CMD | none (no args → serve) |
| Required env | `DATABASE_URL` (`postgres://…` or `sqlite:/data/orlop.db`); `ORLOP_CONTROL_PLANE_TOKEN` (shared service token the data plane presents back); `ORLOP_SERVER_FQDN`; and either `ORLOP_SECRETS_BACKEND=postgres` or `ORLOP_SECRETS_DIR` (filesystem CA backend) |
| Optional env | `ORLOP_MOUNT_PREFIX` controls the agent-visible `virtual_path` returned by entity APIs; default `/mnt/orlop` |
| Volumes | none declared. Stateless with Postgres **and** `ORLOP_SECRETS_BACKEND=postgres`; with SQLite or the filesystem CA backend, give it a writable volume (owned by uid `65532`) for the DB file and `ORLOP_SECRETS_DIR` |

Run `orlop-control migrate up` before serving (e.g. a Kubernetes initContainer);
it is idempotent and self-checks the schema — see
[`upgrade-safety.md`](upgrade-safety.md).

```bash
docker run --rm \
  -e DATABASE_URL="postgres://user:pw@db:5432/orlop?sslmode=disable" \
  -e ORLOP_SECRETS_BACKEND=postgres \
  ghcr.io/liu1700/orlop-control:v0.6.8 migrate up
```

## `orlop-server`

| | |
|---|---|
| Ports | `7878` (ops/HTTPS, `server.ops_bind`) and `8443` (data/mTLS, `server.data_bind`) |
| Entrypoint | `orlop-server` |
| Default CMD | `-config /etc/orlop/server.yaml` — mount your YAML config there (e.g. a ConfigMap) |
| Required env | `ORLOP_SERVICE_TOKEN` (must equal the control plane's `ORLOP_CONTROL_PLANE_TOKEN`); `ORLOP_JFS_META_URL` (only for the JuiceFS quota backend) |
| TLS | with `tls.self_provision`, the server fetches its leaf cert + client CA from the control plane; `tls.fqdn` must match the cert SAN / Service name or the control plane returns `fqdn_not_allowed` and the server exits |
| Volumes | none declared. The object store and routes DB live at the config's `store.root` / `routes.path` / `tenants_root` — back those paths with a volume |

## `orlop-mount`

The mount client with FUSE available at runtime — the image that saves you the
Rust build. Linux releases use fuser's pure backend and a static musl binary:
there is no `libfuse3.so` dependency. `fuse3` in the image supplies the
`fusermount3` helper used when the process cannot mount `/dev/fuse` directly.
The binary is therefore safe to copy into bookworm, trixie, or another Linux
base with a compatible kernel:

```dockerfile
COPY --from=ghcr.io/liu1700/orlop-mount:vX.Y.Z \
  /usr/local/bin/orlop /usr/local/bin/orlop
```

| | |
|---|---|
| Ports | none (outbound only) |
| Entrypoint | `orlop` — pass a subcommand, e.g. `orlop mount …` |
| Devices | needs `/dev/fuse` and `CAP_SYS_ADMIN` for the FUSE mount |
| Env-driven mount | `orlop mount --from-env` (designed for pods) requires `ORLOP_AGENT_ID`, `ORLOP_CONTROL_PLANE`, `ORLOP_MOUNT_POINT`, plus either `ORLOP_ENROLL_TOKEN` or both `ORLOP_SA_TOKEN_PATH` and `ORLOP_REFRESH_URL`; workload identity is preferred because each process retry mints a fresh one-shot token. `ORLOP_CERT_DIR`, `ORLOP_ON_EVICTION`, and `ORLOP_MOUNT_TAKEOVER` are optional |
| Lease takeover | acquiring the mount lease while another mount's lease is still live fails with `409 lease_live`. A spawner that knows the previous pod is gone (crash recovery) sets `ORLOP_MOUNT_TAKEOVER=1` (or passes `--takeover`) to displace it without waiting out the lease TTL |
| Eviction behavior | when the mount lease is lost involuntarily (revoked, expired, taken over, or no longer provable because the mount's certificate renewal failed terminally — for example a deleted Pod-bound enroll identity), `--from-env` mounts default to `--on-eviction=abort`: the FUSE connection is aborted so workload I/O fails with `ENOTCONN` instead of silently writing into the directory the unmount would expose. Set `ORLOP_ON_EVICTION=unmount` (or `--on-eviction=unmount`) for the old clean-unmount behavior |
| Config-driven mount | `orlop mount --config <file> [--credentials <file>]` reads no env; defaults to `~/.config/orlop/config.yaml` and `~/.config/orlop/credentials.json` |

On Kubernetes, grant FUSE access:

```yaml
securityContext:
  capabilities:
    add: ["SYS_ADMIN"]
# plus a /dev/fuse device (a device plugin, or a privileged-ish pod policy)
```

## See also

- [`control-plane-runbook.md`](control-plane-runbook.md): CA, admin seeding, operator workflows
- [`upgrade-safety.md`](upgrade-safety.md): the `migrate` step and in-place upgrade guarantee
