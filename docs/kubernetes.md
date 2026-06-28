# Deploying on Kubernetes

A reference [Helm chart](../deploy/helm/orlop) stands up a working control plane
(`orlop-control`) + data-plane server (`orlop-server`) from the published GHCR
images — including the migrate step, the CA, and the mTLS topology — without
reading the source. This page is both the chart's guide and a from-scratch
reference for the deployment topology and every cross-component constraint.

## Quick start

You provide three things; the chart wires everything else:

```bash
helm install orlop deploy/helm/orlop \
  --set auth.controlPlaneToken="$(openssl rand -hex 24)" \
  --set auth.secretsEncKey="$(openssl rand -hex 32)" \
  --set database.url="postgres://orlop:pw@my-postgres:5432/orlop?sslmode=disable"
```

| Value | What it is |
|---|---|
| `auth.controlPlaneToken` | the shared control↔server token |
| `auth.secretsEncKey` | hex 32-byte AES key that encrypts the CA root key at rest in Postgres |
| `database.url` | your **external, long-lived** Postgres (the chart does not run Postgres) |

For production, manage those in your own Secret and pass `auth.existingSecret`
(keys: `control-plane-token`, `secrets-enc-key`, `database-url`).

After install, finish bring-up with the operator CLI (CA is already
bootstrapped; register the server, seed an admin/tenant) — see
[`control-plane-runbook.md`](control-plane-runbook.md).

## Topology

```
            ┌──────────────────────────┐
 DATABASE_URL│  Postgres (you provide)  │◄── schema + CA root key (encrypted)
            └──────────────────────────┘
                 ▲                ▲
   migrate up    │                │  CA in DB (ORLOP_SECRETS_BACKEND=postgres)
 (initContainer) │                │
        ┌────────┴─────────┐      │
        │   orlop-control  │──────┘   Deployment + Service :8080 (HTTP API)
        └────────▲─────────┘
                 │ POST /control/sign-server-cert  (self-provision, shared token)
        ┌────────┴─────────┐
        │   orlop-server   │   StatefulSet + headless Service
        └──────────────────┘   :7878 ops (mTLS), :8443 data (mTLS), PVC at /data
```

Two design choices make this turnkey and remove the parts that are easy to get
wrong by hand:

- **CA in Postgres, encrypted.** `ORLOP_SECRETS_BACKEND=postgres` keeps the CA
  root key in the same database (encrypted with `secretsEncKey`). No CA PVC to
  provision and keep stable — the database already is the stable store.
- **Server self-provisions its cert.** The server generates a keypair in memory
  and fetches a signed leaf + the client CA from the control plane at boot
  (`tls.self_provision`). No out-of-band `ca mint-server-cert`, no server-TLS
  Secret to mint and rotate.

## The cross-component invariants

These are the constraints a hand-rolled deployment gets subtly wrong. The chart
derives each from a single source, so they cannot drift:

| Invariant | How the chart guarantees it |
|---|---|
| control's `ORLOP_CONTROL_PLANE_TOKEN` **==** server's `ORLOP_DATAGW_SERVICE_TOKEN` | both read the same Secret key `control-plane-token` |
| `ORLOP_DATAGW_SERVER_FQDN` (control) **==** server `tls.fqdn` **==** the server Service name | the server Service is **named** `serverFQDN`; both sides interpolate `serverFQDN`. This is why you never see `fqdn_not_allowed`. |
| trust domain matches on both sides | `trustDomain` is set on control (`ORLOP_TRUST_DOMAIN`) and in the server config (`tls.trust_domain`) |

## Per-component reference

### orlop-control (Deployment + `migrate` initContainer)

| Env | Value / source |
|---|---|
| `PORT` | `8080` |
| `DATABASE_URL` | Secret `database-url` |
| `ORLOP_SECRETS_BACKEND` | `postgres` |
| `ORLOP_SECRETS_ENC_KEY` | Secret `secrets-enc-key` (required by the postgres CA backend; it fails closed without it) |
| `ORLOP_CONTROL_PLANE_TOKEN` | Secret `control-plane-token` |
| `ORLOP_DATAGW_SERVER_FQDN` | `serverFQDN` |
| `ORLOP_TRUST_DOMAIN` | `trustDomain` |
| `ORLOP_ORG_NAME` | `orgName` |

The `migrate` initContainer runs `orlop-control migrate up` (the **same binary**;
`migrate` is a subcommand) before the pod serves. It is idempotent and
self-checks the schema — see [`upgrade-safety.md`](upgrade-safety.md).

### orlop-server (StatefulSet + headless Service + PVC)

Config is a ConfigMap mounted at `/etc/orlop/server.yaml` (the image's default
`-config` path). Ports: `7878` ops (mTLS), `8443` data (mTLS). The only env is
the shared token:

| Env | Value / source |
|---|---|
| `ORLOP_DATAGW_SERVICE_TOKEN` | Secret `control-plane-token` |

Config highlights (`tls.self_provision`, `tls.control_url`, `tls.fqdn`,
`tls.trust_domain`, `store`, `routes`, `tenants_root`) are rendered from the
chart values; the object store + routes DB live on the PVC at `/data`.

> The mTLS listeners require a client cert, so the pod uses a TCP-connect probe
> (an HTTPS health probe can't complete the handshake). The probe logs a benign
> `TLS handshake error … EOF` each interval.

## Filesystem-CA alternative

If you'd rather not keep the CA in Postgres, run the control plane with the
filesystem CA backend (`ORLOP_SECRETS_DIR` on a **stable** PVC — it signs every
cert, so it must survive restarts) and drop `ORLOP_SECRETS_BACKEND` /
`ORLOP_SECRETS_ENC_KEY`. The in-Postgres backend is the chart default because it
needs no extra volume. See [`database-backends.md`](database-backends.md) and
[`control-plane-runbook.md`](control-plane-runbook.md).

## See also

- [`container-images.md`](container-images.md): the images this chart deploys, and their runtime contracts
- [`control-plane-runbook.md`](control-plane-runbook.md): CA, admin seeding, server registration
- [`upgrade-safety.md`](upgrade-safety.md): the migrate step and in-place upgrade guarantee
