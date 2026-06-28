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
| `ghcr.io/liu1700/orlop-mount` | mount client | the `orlop` disk-mount binary with `fuse3` available at runtime | debian bookworm-slim |

## Tags & pinning

Each release publishes `:vX.Y.Z` and moves `:latest`. Both are multi-arch
manifests — Docker/containerd selects `linux/amd64` or `linux/arm64`
automatically. Each push also prints an immutable digest; pin it for
reproducible deploys:

```bash
docker pull ghcr.io/liu1700/orlop-control:v0.3.1
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
| Required env | `DATABASE_URL` (`postgres://…` or `sqlite:/data/orlop.db`); `ORLOP_CONTROL_PLANE_TOKEN` (shared service token the data plane presents back); `ORLOP_DATAGW_SERVER_FQDN`; and either `ORLOP_SECRETS_BACKEND=postgres` or `ORLOP_SECRETS_DIR` (filesystem CA backend) |
| Volumes | none declared. Stateless with Postgres **and** `ORLOP_SECRETS_BACKEND=postgres`; with SQLite or the filesystem CA backend, give it a writable volume (owned by uid `65532`) for the DB file and `ORLOP_SECRETS_DIR` |

Run `orlop-control migrate up` before serving (e.g. a Kubernetes initContainer);
it is idempotent and self-checks the schema — see
[`upgrade-safety.md`](upgrade-safety.md).

```bash
docker run --rm \
  -e DATABASE_URL="postgres://user:pw@db:5432/orlop?sslmode=disable" \
  -e ORLOP_SECRETS_BACKEND=postgres \
  ghcr.io/liu1700/orlop-control:v0.3.1 migrate up
```

## `orlop-server`

| | |
|---|---|
| Ports | `7878` (ops/HTTPS, `server.ops_bind`) and `8443` (data/mTLS, `server.data_bind`) |
| Entrypoint | `orlop-server` |
| Default CMD | `-config /etc/orlop/server.yaml` — mount your YAML config there (e.g. a ConfigMap) |
| Required env | `ORLOP_DATAGW_SERVICE_TOKEN` (must equal the control plane's `ORLOP_CONTROL_PLANE_TOKEN`); `ORLOP_JFS_META_URL` (only for the JuiceFS quota backend) |
| TLS | with `tls.self_provision`, the server fetches its leaf cert + client CA from the control plane; `tls.fqdn` must match the cert SAN / Service name or the control plane returns `fqdn_not_allowed` and the server exits |
| Volumes | none declared. The object store and routes DB live at the config's `store.root` / `routes.path` / `tenants_root` — back those paths with a volume |

## `orlop-mount`

The mount client with FUSE available at runtime — the image that saves you the
Rust + `libfuse3` build.

| | |
|---|---|
| Ports | none (outbound only) |
| Entrypoint | `orlop` — pass a subcommand, e.g. `orlop mount …` |
| Devices | needs `/dev/fuse` and `CAP_SYS_ADMIN` for the FUSE mount |
| Env-driven mount | `orlop mount --from-env` (designed for pods) requires `ORLOP_AGENT_ID`, `ORLOP_CONTROL_PLANE`, `ORLOP_ENROLL_TOKEN`, `ORLOP_MOUNT_POINT`; `ORLOP_CERT_DIR` is optional |
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
