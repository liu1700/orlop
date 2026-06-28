# Manual single-node bring-up

`orlop dev up` ([quickstart](standalone-quickstart.md)) does everything on this
page for you. Do it by hand to see the moving parts, to customize ports or
storage, or to model the sequence for your own orchestration.

You need the `orlop`, `orlop-control`, and `orlop-server` binaries on your
`PATH` ([install](standalone-quickstart.md#1-install-the-binaries)). Confirm the
host can mount and the three ports are free — the same preflight `dev up` runs:

```bash
orlop doctor --dev    # mount support + writable cache + ports 8080/7878/8443 free
```

The five steps are exactly what `dev up` automates, in order:
control plane → register server → data-plane server → enroll token → mount.

## 1. Start the control plane

Embedded SQLite needs nothing external: point `DATABASE_URL` at a file and the
schema is created on first open. The CA initializes itself on first boot and
writes its root and tenant keys under `ORLOP_SECRETS_DIR` (created if missing).

```bash
export DATABASE_URL="sqlite:./orlop.db"   # schema applied on first open
export ORLOP_SECRETS_DIR=./dg-secrets     # CA keys live here

# the token, trust domain, and FQDN must match the data-plane server (step 3)
export ORLOP_CONTROL_PLANE_TOKEN=$(openssl rand -hex 16)
export ORLOP_TRUST_DOMAIN=demo.example
export ORLOP_DATAGW_SERVER_FQDN=localhost

PORT=8080 orlop-control &
# ready when: GET http://localhost:8080/healthz → 200
```

## 2. Register the data-plane server

`/agent/enroll` places each agent on a server from the pool, so the one local
server must be registered before any agent enrolls — an empty pool returns 503.
`server register` writes straight to the database (it reads `DATABASE_URL`), so
the running control plane needs no restart.

```bash
orlop-control server register \
  --data-addr localhost:8443 \
  --ops-addr  localhost:7878 \
  --total-bytes $((10 * 1024 * 1024 * 1024))   # pool capacity (also the default)
```

`--data-addr` is where agents dial; `--ops-addr` is where the control plane
dials. Both stay `localhost`, so one self-provisioned cert covers both.
Re-running is idempotent on `--data-addr`.

## 3. Start the data-plane server

```yaml
# server.yaml
tenant:
  id: a_demo                 # bootstrap tenant; more register at enroll
  name: demo agent disk
store:   { type: local,  root: ./dg-data/objects }
routes:  { type: sqlite, path: ./dg-data/routes.db }
server:
  ops_bind:  ":7878"         # bare :port — see the note below
  data_bind: ":8443"
tls:
  self_provision: true       # fetches its cert and the client CA from the control plane
  control_url: http://localhost:8080
  fqdn: localhost
  trust_domain: demo.example
tenants_root: ./dg-data/tenants
quota: { enforce: false }
```

Bind to `:8443`, not `127.0.0.1:8443`. The mount client dials `localhost`,
which can resolve to IPv6 `::1`; a `127.0.0.1`-only listener refuses that. The
bare `:port` form listens on both stacks while the cert SAN stays `localhost`.

```bash
mkdir -p dg-data/objects dg-data/tenants
# the service token must equal ORLOP_CONTROL_PLANE_TOKEN — it authenticates
# the cert self-provisioning request to the control plane
ORLOP_DATAGW_SERVICE_TOKEN="$ORLOP_CONTROL_PLANE_TOKEN" \
  orlop-server -config server.yaml &
# ready when: "orlop-server data-plane TCP listening with mTLS"  bind=":8443"
```

## 4. Mint an enroll token and mount

```bash
orlop-control token issue --agent demo
```

It provisions the agent's disk and prints a ready-to-paste block. The token is
single-use and short-lived (10m), so mount promptly:

```text
mount it with:
  export ORLOP_AGENT_ID=demo
  export ORLOP_MOUNT_POINT=./agent-disk
  export ORLOP_CONTROL_PLANE=http://localhost:8080
  export ORLOP_ENROLL_TOKEN=<token>
  orlop mount --from-env
```

Paste those exports, then mount. `--from-env` trades the enroll token for a
short-lived client cert via `/agent/enroll` and mounts over the mTLS data path:

```bash
# ... paste the export block above, then:
orlop mount --from-env &
# ready when: "mount verified at ./agent-disk"
```

## 5. Prove it persists

```bash
echo "hello from a durable agent disk" > ./agent-disk/hello.txt

orlop unmount ./agent-disk    # the foreground mount exits cleanly; the dir goes empty
ls ./agent-disk               # empty

# the enroll token is single-use — the first mount spent it — so mint a fresh
# one and re-paste its block before remounting
orlop-control token issue --agent demo
# ... paste the new export block, then:
orlop mount --from-env &
cat ./agent-disk/hello.txt    # → hello from a durable agent disk
```

The file survived because it lives in the data-plane server's store
(`./dg-data/objects`), not in the mount point.

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

This is a single-node developer bring-up. For Postgres and multiple
control-plane replicas, quota enforcement, or JuiceFS-backed storage, see
[`database-backends.md`](database-backends.md) and
[`control-plane-runbook.md`](control-plane-runbook.md).
