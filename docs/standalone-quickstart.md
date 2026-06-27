# Standalone quickstart (single node)

Run the whole stack on one machine and give an agent a durable disk, with **no
external control plane**: Postgres, the control plane (CA + allocation), the
data-plane server, and a mount client. You will write a file, unmount, remount,
and watch the file survive because it lives in the server, not on the mount.

Every command below was run end to end on a single host. The flow is:

```
postgres → orlop-control (auto CA) → server register → orlop-server
        → token issue → orlop mount --from-env → write → unmount → remount → data persists
```

## Prerequisites

- Go and Rust (`cargo`) toolchains.
- A database: either a Postgres instance (the snippet uses Docker) **or** nothing
  at all — the control plane ships an embedded SQLite backend for single-node use
  (see the SQLite option in step 1).
- Local mount support: Linux uses FUSE (`/dev/fuse` + `fuse3`); macOS uses the
  built-in NFSv3 client (no macFUSE needed). Check with `orlop doctor` after the
  build step.

## 0. Build the three binaries

From the repo root:

```bash
GOWORK=off go build -o ./bin/orlop-control ./cmd/orlop-control
GOWORK=off go build -o ./bin/orlop-server  ./cmd/orlop-server
cargo build --release --bin orlop          # → target/release/orlop
export PATH="$PWD/bin:$PWD/target/release:$PATH"

orlop doctor            # confirms this host can mount
```

## 1. Database + schema

Pick **one** backend. The rest of the guide is identical either way — only
`DATABASE_URL` and the CA-secrets backend in step 2 differ.

**Option A — Postgres:**

```bash
docker run -d --name dg-pg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=dg -p 5432:5432 postgres:16-alpine
export DATABASE_URL="postgres://postgres:pw@localhost:5432/dg?sslmode=disable"

orlop-control migrate up
```

**Option B — SQLite (zero external dependencies):**

```bash
export DATABASE_URL="sqlite:./orlop.db"   # also: sqlite::memory:, sqlite:///abs/path.db

orlop-control migrate up                  # creates ./orlop.db and applies the schema
```

The embedded SQLite backend is pure Go (no cgo, no server). It's meant for a
single node — local dev, a self-hosted box, a CI fixture — not multi-replica
production.

## 2. Start the control plane

The CA is created automatically on first boot, so there is no separate `ca init`
step for a dev node. **With Postgres** it lives in the DB
(`ORLOP_SECRETS_BACKEND=postgres`); **with SQLite** the DB backend has no shared
pool for the CA, so use the filesystem backend instead — set `ORLOP_SECRETS_DIR`
and drop `ORLOP_SECRETS_BACKEND`:

```bash
# SQLite: store the CA on disk instead of in the database
export ORLOP_SECRETS_DIR=./dg-secrets
```

Three values are the operator's to choose, and **two of them must match the
data-plane server's config later** (called out in step 4):

```bash
export ORLOP_CONTROL_PLANE_TOKEN=$(openssl rand -hex 16)   # shared service token
export ORLOP_TRUST_DOMAIN=demo.example                     # must match server tls.trust_domain
export ORLOP_DATAGW_SERVER_FQDN=localhost                  # must match server tls.fqdn (cert SAN)

# Postgres: ORLOP_SECRETS_BACKEND=postgres PORT=8080 orlop-control &
# SQLite:   ORLOP_SECRETS_DIR=./dg-secrets    PORT=8080 orlop-control &
PORT=8080 orlop-control &
# wait for: GET /healthz → 200
```

> Why `ORLOP_DATAGW_SERVER_FQDN=localhost`: the control plane only signs a server
> certificate for an allow-listed name. The server's cert SAN must equal the host
> agents dial. Using `localhost` everywhere keeps one cert valid for both the
> control→server and agent→server connections on a single box.

## 3. Register the data-plane server in the placement pool

`/agent/enroll` places each agent on a server from the pool. With an empty pool
it has nowhere to put a disk and returns 503, so register the one local server:

```bash
orlop-control server register \
  --data-addr localhost:8443 \
  --ops-addr  localhost:7878 \
  --total-bytes $((10 * 1024 * 1024 * 1024))
```

`--data-addr` is where **agents** connect; `--ops-addr` is where the **control
plane** connects. Both use `localhost` so the one `localhost` cert covers both.

## 4. Start the data-plane server

```yaml
# server.yaml
tenant:
  id: a_demo                 # bootstrap tenant; more register dynamically at enroll
  name: demo agent disk
store:   { type: local,  root: ./dg-data/objects }
routes:  { type: sqlite, path: ./dg-data/routes.db }
server:
  ops_bind:  ":7878"         # dual-stack ":port", NOT 127.0.0.1 — see note
  data_bind: ":8443"         # must be set; the data plane is off by default
tls:
  self_provision: true       # fetches its cert + the client CA from the control plane
  control_url: http://localhost:8080
  fqdn: localhost            # must equal ORLOP_DATAGW_SERVER_FQDN
  trust_domain: demo.example # must equal ORLOP_TRUST_DOMAIN
tenants_root: ./dg-data/tenants
quota: { enforce: false }
```

```bash
mkdir -p dg-data/objects dg-data/tenants
# the service token authenticates the cert self-provisioning request
ORLOP_DATAGW_SERVICE_TOKEN="$ORLOP_CONTROL_PLANE_TOKEN" \
  orlop-server -config server.yaml &
# wait for: "data-plane TCP listening with mTLS"  bind=":8443"
```

> Why `:8443` and not `127.0.0.1:8443`: the mount client resolves `localhost` to
> IPv6 `::1` first. A `127.0.0.1`-only listener refuses that connection. The
> bare `:port` form is dual-stack, so both `::1` and `127.0.0.1` reach it while
> the cert SAN stays `localhost`.

## 5. Mint an enroll token and mount

```bash
orlop-control token issue --agent demo --control-plane http://localhost:8080
```

It prints a ready-to-paste block (the token is short-lived, ~10m, so mount
promptly):

```bash
export ORLOP_AGENT_ID=demo
export ORLOP_MOUNT_POINT=./agent-disk
export ORLOP_CONTROL_PLANE=http://localhost:8080
export ORLOP_ENROLL_TOKEN=<token from above>
orlop mount --from-env &
# wait for: "mount verified at ./agent-disk"   (the post-mount health probe)
```

## 6. Use it, then prove durability

```bash
echo "hello from a durable agent disk" > ./agent-disk/hello.txt
mkdir -p ./agent-disk/sub && echo "nested" > ./agent-disk/sub/note.md
cat ./agent-disk/hello.txt

# unmount: the bytes are NOT local — the mount point goes empty
kill -TERM %3            # the `orlop mount` job; its Drop unmounts cleanly
ls ./agent-disk          # empty

# remount with a fresh token: the files are still there
orlop-control token issue --agent demo --json    # grab a new token
export ORLOP_ENROLL_TOKEN=<new token>
orlop mount --from-env &
cat ./agent-disk/hello.txt        # → hello from a durable agent disk
cat ./agent-disk/sub/note.md      # → nested
```

The file survived the unmount/remount because it lives in the data-plane server
(here on local disk; in production behind JuiceFS-on-S3), never on the mount.

## The values that must match

A single-node bring-up only breaks where the two halves disagree. Keep these in
sync:

| control plane | data-plane server | why |
| --- | --- | --- |
| `ORLOP_CONTROL_PLANE_TOKEN` | `ORLOP_DATAGW_SERVICE_TOKEN` | authenticates cert self-provisioning |
| `ORLOP_DATAGW_SERVER_FQDN` | `tls.fqdn` | the server cert SAN agents validate |
| `ORLOP_TRUST_DOMAIN` | `tls.trust_domain` | SPIFFE trust domain on every cert |
| `server register --data-addr` host | `tls.fqdn` | agents dial the name in the cert |

## Cleanup

```bash
kill %1 %2 %3 2>/dev/null     # orlop mount, orlop-server, orlop-control
docker rm -f dg-pg            # Postgres only
rm -f ./orlop.db*             # SQLite only
```

## What this is not

This is a single-node developer bring-up. It is not the multi-server placement,
quota enforcement, JuiceFS-backed storage, or autoscaling path. It exists to let
you run the whole system end to end on one machine and see the durability
guarantee with your own eyes.
