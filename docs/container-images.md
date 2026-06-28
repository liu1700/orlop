# Container images

Each release publishes **multi-arch (amd64 + arm64)** images to GHCR, so
consumers don't have to rebuild orlop from source — in particular the mount
client, which otherwise needs the Rust toolchain plus `libfuse3-dev` at build
time. Images are cut by the `images` job in
[`.github/workflows/release.yml`](../.github/workflows/release.yml) on each
`vX.Y.Z` tag, reusing the same per-arch binaries that ship in the release
tarballs.

| Image | Contents | Base |
|---|---|---|
| `ghcr.io/liu1700/orlop-control` | `orlop-control` (control-plane API + operator CLI, incl. `migrate`) | distroless static (nonroot) |
| `ghcr.io/liu1700/orlop-server` | `orlop-server` (data-plane server) | distroless static (nonroot) |
| `ghcr.io/liu1700/orlop-mount` | `orlop` mount client + `fuse3` at runtime | debian slim |

### Tags & pinning

Every release publishes `:vX.Y.Z` and moves `:latest`. Each push also prints an
immutable manifest digest; pin it for reproducible deploys:

```bash
docker pull ghcr.io/liu1700/orlop-control:v0.2.1
# or, pinned by digest:
docker pull ghcr.io/liu1700/orlop-control@sha256:<digest>
```

All three tags resolve to a multi-arch manifest; Docker/containerd selects
`linux/amd64` or `linux/arm64` automatically.

## `orlop-control`

The control-plane HTTP API and the operator CLI — **the same binary**, so
`migrate` is a subcommand (`orlop-control migrate up`), not a separate image.

| | |
|---|---|
| Port | `8080` (HTTP; override with `PORT`) |
| Entrypoint | `orlop-control` (no args → serve; `migrate`, `server`, `user`, `ca`, … are subcommands) |
| Key env | `DATABASE_URL` (`postgres://…` or `sqlite:/data/orlop.db`), `ORLOP_CONTROL_PLANE_TOKEN`, `ORLOP_DATAGW_SERVER_FQDN`, and either `ORLOP_SECRETS_BACKEND=postgres` or `ORLOP_SECRETS_DIR` (filesystem CA backend) |
| Migrate | run `orlop-control migrate up` before serving (e.g. a Kubernetes initContainer); idempotent and self-checks the schema (see [`upgrade-safety.md`](upgrade-safety.md)) |
| State | stateless with Postgres + `ORLOP_SECRETS_BACKEND=postgres`; with SQLite or the filesystem CA backend, mount a writable volume (owned by uid `65532`) for the DB file and `ORLOP_SECRETS_DIR` |

```bash
docker run --rm -p 8080:8080 \
  -e DATABASE_URL="postgres://user:pw@db:5432/orlop?sslmode=disable" \
  -e ORLOP_SECRETS_BACKEND=postgres \
  ghcr.io/liu1700/orlop-control:v0.2.1 migrate up
```

## `orlop-server`

| | |
|---|---|
| Ports | `7878` (ops/HTTPS, `server.ops_bind`), `8443` (data/mTLS, `server.data_bind`) |
| Entrypoint | `orlop-server`; default CMD is `-config /etc/orlop/server.yaml` |
| Config | **required** — mount a YAML config at `/etc/orlop/server.yaml` (e.g. a ConfigMap) |
| Key env | `ORLOP_DATAGW_SERVICE_TOKEN` (must equal the control plane's `ORLOP_CONTROL_PLANE_TOKEN`), `ORLOP_JFS_META_URL` (juicefs quota backend) |
| TLS | with `tls.self_provision`, fetches its leaf cert + client CA from the control plane; `tls.fqdn` must match the cert SAN / Service name or the server exits with `fqdn_not_allowed` |
| State | object store + routes DB live under the config's `store.root` / `routes.path` / `tenants_root` — back them with a volume |

## `orlop-mount`

The mount client with FUSE available at runtime. This is the image that saves
adopters the Rust + `libfuse3` build.

| | |
|---|---|
| Entrypoint | `orlop` (pass a subcommand, e.g. `orlop mount …` or `orlop --from-env`) |
| Runtime caps | needs `/dev/fuse` and `CAP_SYS_ADMIN` for FUSE mounts |
| Key env | `ORLOP_TOKEN` (or a mounted credentials/secrets dir), `ORLOP_CONTROL_URL`, `ORLOP_MOUNT_POINT` — see `orlop --help` |

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
