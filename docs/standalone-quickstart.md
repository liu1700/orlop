# Quickstart

Bring up the full orlop stack on one host with embedded SQLite, give an agent a
durable disk, then write a file, unmount, and remount to watch it survive.

## Hand it to your coding agent

If a coding agent (Claude Code, Cursor, and the like) has a shell here, paste
this and let it drive the bring-up:

```text
Set up a single-node orlop stack by following
https://orlop.dev/reference/standalone-quickstart.md. Install with
`curl -fsSL https://orlop.dev/install.sh | sh`, bring up the SQLite control
plane and the data-plane server, mint an enroll token, and mount a disk. Then
write a file, unmount, and remount to prove it survives. Check first that ports
8080, 7878, and 8443 are free and that FUSE (Linux) or the built-in NFS client
(macOS) is available; stop if anything is missing.
```

Prefer to drive it yourself? The rest of this page is the same bring-up by hand.

## Prerequisites

- Linux or macOS, with three free ports: `8080` (control plane), `7878` (server
  ops), `8443` (server data).
- Mount support: Linux uses FUSE (`/dev/fuse` and `fuse3`); macOS uses its
  built-in NFS client. `orlop doctor` (step 1) confirms this host can mount.

## 1. Install the binaries

Downloads prebuilt `orlop`, `orlop-control`, and `orlop-server` for your OS and
architecture into `~/.local/bin`:

```bash
curl -fsSL https://orlop.dev/install.sh | sh
orlop doctor
```

Override the target dir with `ORLOP_BIN_DIR`, or pin a release with
`ORLOP_VERSION=v0.2.1`. If the install dir isn't on your `PATH`, the script
prints the line to add.

<details>
<summary>Build from source instead (needs the Go and Rust toolchains)</summary>

From the repo root:

```bash
GOWORK=off go build -o ./bin/orlop-control ./cmd/orlop-control
GOWORK=off go build -o ./bin/orlop-server  ./cmd/orlop-server
cargo build --release --bin orlop          # → target/release/orlop
export PATH="$PWD/bin:$PWD/target/release:$PATH"

orlop doctor
```

</details>

## 2. Start the control plane

Embedded SQLite needs nothing external: point `DATABASE_URL` at a file and the
schema is created on first open. The CA initializes itself on first boot, with
its root and tenant keys on disk under `ORLOP_SECRETS_DIR`.

```bash
export DATABASE_URL="sqlite:./orlop.db"   # schema applied on first open
export ORLOP_SECRETS_DIR=./dg-secrets     # CA keys live here

# the token, trust domain, and FQDN must match the data-plane server (step 4)
export ORLOP_CONTROL_PLANE_TOKEN=$(openssl rand -hex 16)
export ORLOP_TRUST_DOMAIN=demo.example
export ORLOP_DATAGW_SERVER_FQDN=localhost

PORT=8080 orlop-control &
# wait for: GET /healthz → 200
```

## 3. Register the data-plane server

`/agent/enroll` places each agent on a server from the pool, so register the one
local server before any agent enrolls (an empty pool returns 503):

```bash
orlop-control server register \
  --data-addr localhost:8443 \
  --ops-addr  localhost:7878 \
  --total-bytes $((10 * 1024 * 1024 * 1024))
```

`--data-addr` is where agents connect; `--ops-addr` is where the control plane
connects. Both stay `localhost`, so one cert covers both.

## 4. Start the data-plane server

```yaml
# server.yaml
tenant:
  id: a_demo                 # bootstrap tenant; more register at enroll
  name: demo agent disk
store:   { type: local,  root: ./dg-data/objects }
routes:  { type: sqlite, path: ./dg-data/routes.db }
server:
  ops_bind:  ":7878"         # bare :port (dual-stack); see the note below
  data_bind: ":8443"
tls:
  self_provision: true       # fetches its cert and the client CA from the control plane
  control_url: http://localhost:8080
  fqdn: localhost
  trust_domain: demo.example
tenants_root: ./dg-data/tenants
quota: { enforce: false }
```

Bind to `:port`, not `127.0.0.1:port`: the mount client resolves `localhost` to
IPv6 `::1` first, and a `127.0.0.1`-only listener refuses that connection. The
bare form is dual-stack while the cert SAN stays `localhost`.

```bash
mkdir -p dg-data/objects dg-data/tenants
# the service token must equal ORLOP_CONTROL_PLANE_TOKEN
ORLOP_DATAGW_SERVICE_TOKEN="$ORLOP_CONTROL_PLANE_TOKEN" \
  orlop-server -config server.yaml &
# wait for: "data-plane TCP listening with mTLS"  bind=":8443"
```

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
# wait for: "mount verified at ./agent-disk"
```

## 6. Prove durability

```bash
echo "hello from a durable agent disk" > ./agent-disk/hello.txt
mkdir -p ./agent-disk/sub && echo "nested" > ./agent-disk/sub/note.md

# unmount: the mount point goes empty
orlop unmount ./agent-disk
ls ./agent-disk              # empty

# remount with a fresh token
orlop-control token issue --agent demo --json    # grab a new token
export ORLOP_ENROLL_TOKEN=<new token>
orlop mount --from-env &
cat ./agent-disk/hello.txt        # → hello from a durable agent disk
cat ./agent-disk/sub/note.md      # → nested
```

The file is still there because it lives in the data-plane server, here on local
disk.

## Values that must match

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
rm -f ./orlop.db*             # SQLite database and its WAL sidecars
rm -rf ./dg-secrets ./dg-data ./agent-disk
```

This is a single-node developer bring-up. For multiple control-plane replicas,
Postgres, quota enforcement, or JuiceFS-backed storage, see
[`database-backends.md`](database-backends.md) and the
[`control-plane-runbook.md`](control-plane-runbook.md).
