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
| control's `ORLOP_CONTROL_PLANE_TOKEN` **==** server's `ORLOP_DATAGW_SERVICE_TOKEN` | both read the same Secret key `control-plane-token` |
| `ORLOP_DATAGW_SERVER_FQDN` (control) **==** server `tls.fqdn` **==** the server Service name | the server Service is **named** `serverFQDN`, and both sides interpolate `serverFQDN` — so the cert SAN always matches the name clients connect to. This is why you never see `fqdn_not_allowed`. |
| trust domain matches on both sides | `trustDomain` is set on control (`ORLOP_TRUST_DOMAIN`) and in the server config (`tls.trust_domain`) |

## Per-component reference

### orlop-control — Deployment + `migrate` initContainer + ClusterIP Service `:8080`

| Env | Value / source |
|---|---|
| `PORT` | `control.port` (`8080`) |
| `DATABASE_URL` | Secret `database-url` |
| `ORLOP_SECRETS_BACKEND` | `postgres` |
| `ORLOP_SECRETS_ENC_KEY` | Secret `secrets-enc-key` (the chart requires it for the in-Postgres CA backend) |
| `ORLOP_CONTROL_PLANE_TOKEN` | Secret `control-plane-token` |
| `ORLOP_DATAGW_SERVER_FQDN` | `serverFQDN` |
| `ORLOP_TRUST_DOMAIN` | `trustDomain` |
| `ORLOP_ORG_NAME` | `orgName` |

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
| `ORLOP_DATAGW_SERVICE_TOKEN` | Secret `control-plane-token` |

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
| `image.control.tag` / `image.server.tag` | `""` → chart `appVersion` (`0.3.1`) | pin a tag/digest for reproducible deploys |
| `serverFQDN` | `orlop-server` | the server Service name **and** cert SAN — keep it one value |
| `trustDomain` | `orlop.example` | applied to both components |
| `orgName` | `ORL` | |
| `control.replicas` | `1` | |
| `control.port` | `8080` | control HTTP API port |
| `server.opsPort` / `server.dataPort` | `7878` / `8443` | mTLS listeners |
| `server.persistence.size` | `10Gi` | size of the PVC at `dataDir` |
| `server.persistence.storageClass` | `""` (cluster default) | |
| `server.persistence.dataDir` | `/data` | object store + routes DB + tenants |
| `server.podSecurityContext.fsGroup` | `65532` | makes the PVC writable by the distroless nonroot uid (without it many CSI drivers leave `/data` root-owned and the pod crashes) |
| `server.quota.enforce` | `false` | |
| `server.tenant.id` / `server.tenant.name` | `a_demo` / `demo agent disk` | bootstrap tenant |

## See also

- [`container-images.md`](container-images.md): the images this chart deploys, and their runtime contracts
- [`control-plane-runbook.md`](control-plane-runbook.md): CA, admin seeding, server registration
- [`database-backends.md`](database-backends.md): Postgres details and alternative CA/DB backends
- [`upgrade-safety.md`](upgrade-safety.md): the migrate step and in-place upgrade guarantee
