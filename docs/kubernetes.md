# Deploying on Kubernetes

A reference [Helm chart](https://github.com/liu1700/orlop/tree/main/deploy/helm/orlop) stands up a working control plane
(`orlop-control`) and data-plane server (`orlop-server`) from the published GHCR
images, with the migrate step, the in-Postgres CA, and the mTLS topology already
wired. This page is the chart's guide: the topology, the values you must set, and
the cross-component constraints it derives for you.

You bring an external Postgres and two secrets; the chart does the rest.

## Topology

```
                ┌────────────────────────────┐
   DATABASE_URL │   Postgres (you provide)   │ ◄── schema + CA root key (encrypted)
                └────────────────────────────┘
                     ▲                  ▲
   migrate up        │                  │  CA in DB (ORLOP_SECRETS_BACKEND=postgres)
   (initContainer)   │                  │
            ┌────────┴─────────┐        │
            │   orlop-control  │────────┘   Deployment + ClusterIP Service :8080 (HTTP API)
            └────────▲─────────┘
                     │  POST /control/sign-server-cert  (CSR, self-provision, shared token)
            ┌────────┴─────────┐
            │   orlop-server   │   StatefulSet + headless Service
            └──────────────────┘   :7878 ops (mTLS) · :8443 data (mTLS) · PVC at /data
```

**Why control is a Deployment and server is a StatefulSet.** The control plane
keeps no local state — its schema and CA root key live in the Postgres you
provide — so any replica is interchangeable and it ships as a Deployment behind a
normal ClusterIP Service on `:8080`. The server keeps local state on a
PersistentVolumeClaim at `/data` (object store + routes DB + tenants), so it ships
as a StatefulSet: a `volumeClaimTemplates` PVC reattaches the same volume across
restarts, and the headless Service (`clusterIP: None`) resolves the pod by the
exact name that equals its TLS cert SAN — the two must agree or a client's
verification fails.

Two design choices remove the parts that are easy to get wrong by hand:

- **CA in Postgres, encrypted.** `ORLOP_SECRETS_BACKEND=postgres` keeps the CA
  root key in the same database, encrypted with `secretsEncKey`. There is no CA
  PVC to provision and keep stable — the database already is the stable store.
  (This chart wires the in-Postgres CA backend only; for other CA/DB backends see
  [`database-backends.md`](database-backends.md).)
- **Server self-provisions its cert.** The server generates a keypair in memory,
  sends a CSR to the control plane's `POST /control/sign-server-cert` at boot
  (authenticated by the shared token), and serves the returned leaf plus the
  client CA. No out-of-band `ca mint-server-cert`, no server-TLS Secret to mint
  and rotate.

## Install

You set three things; the chart wires everything else:

```bash
helm install orlop deploy/helm/orlop \
  --set auth.controlPlaneToken="$(openssl rand -hex 24)" \
  --set auth.secretsEncKey="$(openssl rand -hex 32)" \
  --set database.url="postgres://orlop:pw@my-postgres:5432/orlop?sslmode=disable"
```

After install, finish bring-up with the operator CLI — register the server and
seed an admin/tenant. `helm` prints the exact `kubectl exec … orlop-control
server register …` command; see [`control-plane-runbook.md`](control-plane-runbook.md)
for the full sequence.

## Values you must set

| Value | What it is |
|---|---|
| `auth.controlPlaneToken` | the shared control↔server token (`openssl rand -hex 24`) |
| `auth.secretsEncKey` | hex 32-byte AES key that encrypts the CA root key at rest in Postgres (`openssl rand -hex 32`) |
| `database.url` | your **external, long-lived** Postgres — the chart does **not** run Postgres |

For production, manage these in your own Secret and pass `auth.existingSecret`
(it must contain keys `control-plane-token`, `secrets-enc-key`, `database-url`);
the three values above are then ignored.

## The cross-component invariants

These are the constraints a hand-rolled deployment gets subtly wrong. The chart
derives each from a single source, so they cannot drift:

| Invariant | How the chart guarantees it |
|---|---|
| control's `ORLOP_CONTROL_PLANE_TOKEN` **==** server's `ORLOP_SERVICE_TOKEN` | both read the same Secret key `control-plane-token` |
| `ORLOP_SERVER_FQDN` (control) **==** server `tls.fqdn` **==** the server Service name | the server Service is **named** `serverFQDN`, and both sides interpolate `serverFQDN` — so the cert SAN always matches the name clients connect to. This is why you never see `fqdn_not_allowed`. |
| trust domain matches on both sides | `trustDomain` is set on control (`ORLOP_TRUST_DOMAIN`) and in the server config (`tls.trust_domain`) |

## Per-component reference

### orlop-control — Deployment + `migrate` initContainer + ClusterIP Service

| Env | Value / source |
|---|---|
| `PORT` | `control.port` (`8080`) |
| `ORLOP_MOUNT_PREFIX` | `control.mountPrefix` (`/mnt/orlop`) |
| `ORLOP_MOUNT_LEASE_TTL` | `control.mountLeaseTTL` (`60s`) |
| `DATABASE_URL` | Secret `database-url` |
| `ORLOP_SECRETS_BACKEND` | `postgres` |
| `ORLOP_SECRETS_ENC_KEY` | Secret `secrets-enc-key` (the chart requires it for the in-Postgres CA backend) |
| `ORLOP_CONTROL_PLANE_TOKEN` | Secret `control-plane-token` |
| `ORLOP_SERVER_FQDN` | `serverFQDN` |
| `ORLOP_TRUST_DOMAIN` | `trustDomain` |
| `ORLOP_ORG_NAME` | `orgName` |
| `ORLOP_METRICS_ADDR` | `:<control.metricsPort>` (`:9090`) |

The `migrate` initContainer runs `orlop-control migrate up` (the **same binary**;
`migrate` is a subcommand) before the pod serves. It is idempotent and
self-checks the schema — see [`upgrade-safety.md`](upgrade-safety.md). Disable it
with `control.runMigrations=false` (default `true`). Port-forward the Service to
reach the API: `kubectl port-forward svc/<release>-orlop-control 8080:8080`.

### orlop-server — StatefulSet + headless Service + PVC

Config is a ConfigMap mounted at `/etc/orlop/server.yaml` (the image's default
`-config` path). Ports: `7878` ops (mTLS), `8443` data (mTLS). The only env is the
shared token:

| Env | Value / source |
|---|---|
| `ORLOP_SERVICE_TOKEN` | Secret `control-plane-token` |

The config keys (`tls.self_provision`, `tls.control_url`, `tls.fqdn`,
`tls.trust_domain`, `store`, `routes`, `tenants_root`, `tenant`, `quota`) are
rendered from chart values; the object store and routes DB live on the PVC at
`/data`.

> The mTLS listeners require a client cert, so the pod uses a TCP-connect probe —
> an HTTPS health probe can't complete the handshake. The probe opening and
> closing the socket logs a benign `TLS handshake error … EOF` each interval;
> that's the probe, not a real error.

## Values reference (defaulted; override as needed)

| Key | Default | Notes |
|---|---|---|
| `image.registry` | `ghcr.io/liu1700` | |
| `image.control.tag` / `image.server.tag` | `""` → chart `appVersion` (`v0.6.3`) | pin a tag/digest for reproducible deploys |
| `serverFQDN` | `orlop-server` | the server Service name **and** cert SAN — keep it one value |
| `trustDomain` | `orlop.example` | applied to both components |
| `orgName` | `ORL` | |
| `control.replicas` | `1` | |
| `control.port` | `8080` | control HTTP API port |
| `control.metricsPort` | `9090` | private Prometheus metrics listener |
| `control.purgeSweepInterval` | `10m` | built-in revoked-allocation purge reconciliation; `0` disables |
| `server.opsPort` / `server.dataPort` | `7878` / `8443` | mTLS listeners |
| `server.persistence.size` | `10Gi` | size of the PVC at `dataDir` |
| `server.persistence.storageClass` | `""` (cluster default) | |
| `server.persistence.dataDir` | `/data` | object store + routes DB + tenants |
| `server.podSecurityContext.fsGroup` | `65532` | makes the PVC writable by the distroless nonroot uid (without it many CSI drivers leave `/data` root-owned and the pod crashes) |
| `server.quota.enforce` | `false` | |
| `server.tenant.id` / `server.tenant.name` | `a_demo` / `demo agent disk` | bootstrap tenant |

## FUSE client lifecycle

Treat a host-visible FUSE mount as node infrastructure, not as an incidental
child of a controller process. Keep the mount client's lifetime independent
from rolling control-plane or CSI/controller upgrades, give it a graceful
termination window, and run liveness/readiness checks against the mounted path.
If a mount must be visible outside its pod, configure the required mount
propagation explicitly and run inspection or cleanup in the same mount
namespace as the mount.

The reference [`orlop-mount-pod.yaml`](../deploy/examples/orlop-mount-pod.yaml)
shows the supported CSI integration boundary: one independently reconciled pod
per desired mount, pinned to the target node, with `/dev/fuse`, bidirectional
mount propagation, a fail-closed readiness probe, and graceful pre-stop
unmount. The CSI node-plugin creates/reconciles these pods but must not own the
FUSE process itself. A plugin rollout then leaves the mount pod and its open
`/dev/fuse` fd untouched.

Do not use a mounted-path liveness probe. If the FUSE request path is wedged,
killing the fd owner turns a degraded connection into an `ENOTCONN` stale
mount. `orlop mount check <path>` is intentionally a readiness check only.
Configure mount pods with a projected ServiceAccount token at
`ORLOP_SA_TOKEN_PATH` and its agent-scoped exchange endpoint in
`ORLOP_REFRESH_URL`. Every `orlop mount --from-env` process then obtains a fresh
single-use enroll token before enrolling, so retries cannot loop forever on a
consumed token. A pre-minted `ORLOP_ENROLL_TOKEN` remains supported for simple
deployments, but its caller must replace it after a failed process attempt.

For a dead client, use `orlop mount ls --json` to discover Orlop entries from
`/proc/self/mountinfo`, then `orlop unmount --stale` to lazy-detach only paths
that return `ENOTCONN`. Cleanup is safe to retry and refuses a path with a
non-Orlop filesystem stacked at the same location. A node-debug pod normally
needs to enter the host namespace first, for example with `nsenter -t 1 -m`.

Crash cleanup and live upgrade are different paths. Once the last process
holding the connection's `/dev/fuse` fd dies, Linux has no API that can attach a
new fd to that disconnected connection; the remaining mount shell can only be
detached and recreated. `orlop mount --adopt` deliberately refuses that case.

While the old client is still healthy, an operator in the same mount namespace
can attach management state without remounting:

```bash
orlop mount --adopt /mnt/orlop
```

To replace the running mount-client binary without dropping the kernel mount,
stage the new executable at an absolute path visible to the old process, then
request a live handoff:

```bash
orlop mount --adopt /mnt/orlop \
  --replace-with /var/lib/orlop/releases/0.4.0/orlop
```

The predecessor authenticates the local peer, starts the successor with a
one-time token, parks FUSE dispatch between requests, flushes dirty write
handles, and transfers the initialized `/dev/fuse` fd plus a versioned inode and
open-handle snapshot over `SCM_RIGHTS`. The successor validates the snapshot,
rebuilds data-plane connections and leases, then acknowledges readiness. Only
then does the predecessor commit and exit without unmounting. A timeout,
protocol mismatch, invalid binary, failed flush, or successor setup error
aborts the transaction: the predecessor resumes dispatch and reacquires leases.

This upgrades a process in the existing pod/namespace; it does not make a
normal Kubernetes pod replacement preserve an fd across containers. For a
mount-pod rollout, either stage releases on a volume shared with the existing
container and invoke the command there, or treat pod replacement as disruptive
and coordinate workload quiescence. Never kill the predecessor before the
handoff command reports the successor PID.

## See also

- [`container-images.md`](container-images.md): the images this chart deploys, and their runtime contracts
- [`control-plane-runbook.md`](control-plane-runbook.md): CA, admin seeding, server registration
- [`database-backends.md`](database-backends.md): Postgres details and alternative CA/DB backends
- [`upgrade-safety.md`](upgrade-safety.md): the migrate step and in-place upgrade guarantee
