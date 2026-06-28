# Control plane API

The hosted control plane (`cmd/orlop-control`, a single Go binary that is both
the service and a CLI) handles agent enrollment, short-lived bearer credentials,
per-tenant CA signing, disk placement, and admin sessions for the dashboard. The data plane is
the per-tenant `orlop-server`; once an agent is enrolled it reads and writes its
files directly against that server over mTLS, keeping the control plane out of
the data path.

See [`design-auth.md`](design-auth.md) for the certificate model,
[`design-identity.md`](design-identity.md) for host-issued JWT identity,
[`database-backends.md`](database-backends.md) for Postgres vs. SQLite, and
[`control-plane-runbook.md`](control-plane-runbook.md) for operator tasks.

A machine-readable **OpenAPI spec** for the provisioning surface the Go SDK
(`orlop/client`) exercises lives at
[`openapi/orlop-control.yaml`](https://github.com/liu1700/orlop/blob/main/docs/openapi/orlop-control.yaml) — implement a client
in any language from it. The versioning and SDK↔server compatibility policy is
in [Versioning and compatibility](#versioning-and-compatibility) below.

## Conventions

These apply to every endpoint below, so the per-endpoint sections stay short.

### Base URL and TLS

All requests go to the control plane's HTTPS origin, e.g.
`https://control.orlop.example`. The control-plane API is ordinary
`net/http`/JSON over TLS (terminated at the edge in a hosted deploy). The data
plane is a separate binary protocol on `orlop-server` and is not described here.

### Authentication

The control plane accepts several credential shapes. Each endpoint in the route
table names the one it requires.

| Credential | How it is sent | Where it comes from |
| --- | --- | --- |
| API token | `Authorization: Bearer <orlop_…>` | `POST /v1/tokens` |
| Enroll token | `Authorization: Bearer <token>` | `orlop-control token issue` / `POST /v1/agents/{id}/enroll-token` (single-use) |
| Admin session cookie | `HttpOnly` cookie set at `/admin/session?token=…` | `orlop-control user seed` |
| Service token | `Authorization: Bearer $ORLOP_CONTROL_PLANE_TOKEN` | shared static token, set by the operator |
| Host JWT | `Authorization: Bearer <jwt>` | a host-issued, signed JWT (see [`design-identity.md`](design-identity.md)) |
| Agent identity | client mTLS cert, or an `agent_fingerprint` body field | the leaf minted at enrollment |

Bearer parsing is case-insensitive on the `Bearer` keyword and tolerates
trailing whitespace.

### Request and response format

Request bodies, where present, are JSON (`Content-Type: application/json`).
Successful responses are JSON with `Content-Type: application/json`.

### Status codes

| Code | Meaning |
| --- | --- |
| `200 OK` | success, JSON body |
| `201 Created` | success, resource created (`POST /v1/tokens`) |
| `204 No Content` | success, no body (`POST /auth/logout`, `DELETE /v1/entities/...`) |
| `400 Bad Request` | malformed request |
| `401 Unauthorized` | missing/invalid/expired credential (`invalid_token`, `invalid_client`) |
| `403 Forbidden` | authenticated but not allowed (`access_denied`: suspended tenant/user, tenant not allowed, missing agent scope) |
| `404 Not Found` | unknown resource |
| `409 Conflict` | mount or capacity conflict (`wrong_agent`, `already_mounted`, `insufficient_capacity`) |
| `410 Gone` | revoked allocation or lost lease (`revoked`, `lease_lost`) |
| `429 Too Many Requests` | rate limited (`rate_limited`) |
| `503 Service Unavailable` | transient; retry. `POST /agent/enroll` adds `Retry-After: 60` when CA material or server placement is not yet ready |
| `500 Internal Server Error` | `server_error` |

### Error shape

Errors use an OAuth-style body. `error_description` is omitted when empty.

```json
{ "error": "access_denied", "error_description": "tenant_suspended" }
```

### Versioning and compatibility

The control-plane API is versioned by a single **major** number, carried by the
`/v1/...` path prefix. It is independent of the orlop **release** version: the
API was byte-identical across v0.1.0 and v0.2.0, and stays at major `1` until a
breaking change.

**Skew is detectable, not silent.** Every response carries an `Orlop-API-Version`
header naming the major the server implements, and the Go SDK sends the same
header on every request. The SDK compares them and returns a typed
`client.APIVersionError` on a **major** mismatch — so an incompatible pairing
surfaces as an explicit "version skew" error instead of an opaque 4xx. A server
that predates the header (no `Orlop-API-Version`) is treated as compatible, for
back-compat.

**Compatibility policy.**

| Client major | Server major | Result |
| --- | --- | --- |
| `N` | `N` | **Supported.** Within a major, the server only adds endpoints/fields; clients must ignore unknown response fields. |
| `N` | `M` (≠ `N`) | **Unsupported.** The SDK returns `APIVersionError`; upgrade one side to a matching major. |

Concretely today: every released orlop SDK and server (v0.1.0 through v0.2.x)
speaks API major `1`, so any combination of them is supported. A future breaking
change ships under `/v2` with `Orlop-API-Version: 2` and is called out as a
breaking change in the release notes (see [`upgrade-safety.md`](upgrade-safety.md)).

Other-language clients should: send `Authorization: Bearer <service token>`,
optionally send `Orlop-API-Version: 1`, and check the response header to detect
skew the same way the Go SDK does.

## Endpoints

The set of mounted routes depends on configuration:

- `GET /healthz` is always mounted.
- The dashboard, API-token, `/v1/entities`, `/v1/admin`, `/v1/tenants`, journal,
  and `/agent/enroll` routes are mounted only when `DATABASE_URL` is set.
  (`/v1/tenants/{owner}/usage` and `/v1/admin/purge-sweep` mount on the database
  alone but return `503` until an agent CA is configured, since they call the
  data plane.)
- `/agent/enroll` and `POST /control/sign-server-cert` additionally need an agent
  CA configured (a filesystem CA at `ORLOP_SECRETS_DIR`, or the in-DB CA via
  `ORLOP_SECRETS_BACKEND=postgres`).
- `GET /v1/whoami` is mounted only when `ORLOP_IDENTITY_AUDIENCE` is set, and is
  independent of `DATABASE_URL`.

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| GET | `/healthz` | public | liveness; returns `{"status":"ok"}` |
| GET | `/admin/session` | admin session token (`?token=`) | sets the `orlop_admin_session` cookie and redirects to the dashboard |
| POST | `/auth/logout` | admin session cookie | clears the admin cookie; `204` |
| POST | `/agent/enroll` | enroll token | mint a one-hour agent leaf cert (see below) |
| GET | `/v1/whoami` | host JWT | echo the verified tenant/subject (see below) |
| GET | `/me` | admin session cookie | dashboard: current user |
| GET | `/allocations` | admin session cookie | dashboard: list the user's disk allocations |
| GET | `/allocations/{id}/usage` | admin session cookie | dashboard: per-allocation usage |
| POST | `/allocations/{id}/revoke` | admin session cookie | revoke an allocation |
| POST | `/allocations/{id}/mount` | agent identity | acquire the exclusive mount lease |
| POST | `/allocations/{id}/mount/refresh` | agent identity | extend the mount lease |
| DELETE | `/allocations/{id}/mount` | agent identity | release the mount lease |
| POST | `/allocations/{id}/unmount` | admin session cookie | owner-forced unmount |
| POST | `/v1/tokens` | admin session cookie | mint a long-lived `orlop_…` API token (shown once; `201`) |
| GET | `/v1/tokens` | admin session cookie | list API tokens |
| DELETE | `/v1/tokens/{id}` | admin session cookie | revoke an API token (`204`) |
| GET | `/v1/journal` | admin session cookie | tenant write journal (paged) |
| POST | `/v1/journal/revert` | admin session cookie | revert a `(path, seq)` |
| GET | `/v1/journal/stream` | admin session cookie | journal SSE stream |
| POST | `/v1/entities` | service token | provision an owner/agent + disk allocation |
| GET | `/v1/entities/{type}/{id}` | service token | resolve an entity |
| PATCH | `/v1/entities/{type}/{id}` | service token | set an agent's quota |
| DELETE | `/v1/entities/{type}/{id}` | service token | revoke/delete an entity |
| POST | `/v1/entities/{type}/{id}/reassign` | service token | reassign an entity |
| POST | `/v1/entities/account/{owner}/budget` | service token | set an account's shared budget |
| POST | `/v1/agents/{id}/enroll-token` | service token | mint a per-pod, agent-scoped enroll token |
| POST | `/v1/admin/purge-sweep` | service token | erase revoked-but-unpurged allocation data |
| GET | `/v1/tenants/{owner}/usage` | service token | per-owner disk usage for the storage meter |
| POST | `/control/sign-server-cert` | service token | sign an `orlop-server` TLS cert from its CSR |

The dashboard, `/v1/entities`, `/v1/admin`, `/v1/tenants`, journal, and
`/v1/whoami` routes are also registered under an `/api/…` prefix; the production
edge strips `/api` before forwarding, so the bare paths above are what the
service actually serves.

Revocation note: `PUT /control/cert-revocations` is served by **`orlop-server`**,
not by the control plane. The control plane is the *client*: a reconcile loop
(~60s) pushes the active leaf-revocation set to each data-plane server over mTLS,
authenticated with its own control-plane cert. It is listed here only to place
where revocation propagation happens; it is not a control-plane HTTP route.

## Endpoint detail

### `POST /agent/enroll`

Trades a bearer credential for a one-hour agent leaf certificate plus the CA
chain and the data-plane address to dial. The bearer is a single-use enroll
token; the agent must already have a provisioned, agent-scoped disk allocation
(the request is rejected with `access_denied / agent_scope_required` otherwise).

```bash
curl -fsS -X POST https://control.orlop.example/agent/enroll \
  -H "Authorization: Bearer $ORLOP_ENROLL_TOKEN" | jq .
```

Success (`200`):

```json
{
  "client_cert_pem": "-----BEGIN CERTIFICATE-----\n...\n",
  "client_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n",
  "ca_chain_pem": "-----BEGIN CERTIFICATE-----\n...\n",
  "server_addr": "tenant-acme.orlop.example",
  "expires_at": "2026-04-30T13:00:00Z"
}
```

When the request resolved an allocation, the response also carries
`allocation_id` and `size_bytes`. The agent verifies the data-plane server cert
against `ca_chain_pem` (not the system trust store) and dials `server_addr`.

On a valid request the control plane:

1. Authenticates the bearer and rate-limits per `Authorization` header.
2. Confirms the tenant exists and is not suspended.
3. Looks up the allocation (if the token carries one) and rejects a
   wrong-owner or revoked allocation.
4. Resolves or lazily places the tenant's `orlop-server` via the placement
   scheduler.
5. Lazily bootstraps the tenant intermediate CA if this is the tenant's first
   enroll (subject to the CA tenant policy).
6. Requires an agent-scoped allocation, then mints a one-hour leaf bound to the
   tenant and agent.
7. Spends the enroll token (single-use) if the bearer was an enroll token.
8. Records an `agent_enrollments` row with the cert serial and expiry.

Retryable failures (tenant CA not yet available, or server placement pending)
return `503` with `Retry-After: 60` so a sidecar can retry without burning the
(still-unspent) enroll token.

### `GET /v1/whoami`

Mounted only when `ORLOP_IDENTITY_AUDIENCE` is set. The control plane acts as a
relying party for a host-issued, signed JWT: it verifies the signature against
`ORLOP_IDENTITY_PUBLIC_KEY_FILE`, checks `iss`/`aud`/`exp`, maps the
`ORLOP_IDENTITY_TENANT_CLAIM` value onto a tenant subject, and accepts it only
if that tenant is on `ORLOP_IDENTITY_TENANT_ALLOWLIST` (fail-closed). This
endpoint echoes the verified identity: a dependency-free way to confirm a host
token is accepted end to end.

```bash
curl -fsS https://control.orlop.example/v1/whoami \
  -H "Authorization: Bearer $HOST_JWT" | jq .
```

Success (`200`):

```json
{ "tenant_id": "u_acme", "subject": "host-user-42" }
```

A well-signed token whose tenant is not on the allowlist returns `403`
(`access_denied / tenant_not_allowed`); anything the verifier rejects returns
`401` (`invalid_token`).

## Service environment variables

| Variable | Meaning |
| --- | --- |
| `PORT` | HTTP listen port. Default `8080`. |
| `DATABASE_URL` | Storage backend. Accepts a `postgres://…` DSN or a `sqlite:…` URL; the scheme selects the backend. Without it, the dashboard, `/v1/entities`, journal, and enroll routes are not mounted. See [`database-backends.md`](database-backends.md). |
| `ORLOP_SECRETS_DIR` | Filesystem secrets root holding CA material (the default CA backend). |
| `ORLOP_SECRETS_BACKEND` | `postgres` keeps the CA (root key + tenant intermediates) in the shared DB instead of on disk; any other value uses the filesystem backend at `ORLOP_SECRETS_DIR`. `/agent/enroll` mounts whenever a CA is configured by *either* backend, so `ORLOP_SECRETS_DIR` is not strictly required. `postgres` requires a Postgres `DATABASE_URL`. |
| `ORLOP_SECRETS_ENC_KEY` | Hex-encoded 32-byte AES key; encrypts CA values at rest. Recommended with `ORLOP_SECRETS_BACKEND=postgres`. |
| `ORLOP_SECRETS_ALLOW_PLAINTEXT` | `1` to allow storing the CA root key unencrypted in Postgres. Without it (and without `ORLOP_SECRETS_ENC_KEY`), `postgres` backend boot fails closed. |
| `ORLOP_TRUST_DOMAIN` | SPIFFE trust domain. Default `orlop.example`. |
| `ORLOP_ORG_NAME` | X.509 Organization. Default `ORL`. |
| `ORLOP_COOKIE_DOMAIN` | Domain for the admin session cookie. |
| `ORLOP_CONTROL_PLANE_TOKEN` | Shared service token gating the `/v1/entities`, `/v1/admin`, `/v1/tenants`, and `/control/sign-server-cert` routes. Empty ⇒ those routes reject every request (fail closed). |
| `ORLOP_API_TOKEN_TTL` | Expiry for newly minted `orlop_…` API tokens (e.g. `2160h`). `0` (default) ⇒ never expire. |
| `ORLOP_INITIAL_GRANT_BYTES` | Disk granted at provision when the request specifies no explicit size. Default 1 GiB. |
| `ORLOP_DATAGW_SERVER_FQDN` | The only name `POST /control/sign-server-cert` will issue a server cert for. Default `orlop-server`. |
| `ORLOP_DATAGW_SERVER_CERT_TTL` | Validity of a self-provisioned server cert (e.g. `2160h`). Default 90 days. |
| `ORLOP_IDENTITY_AUDIENCE` | Enables the host-issued JWT identity verifier and mounts `GET /v1/whoami`; pins the JWT `aud`. The other `ORLOP_IDENTITY_*` knobs apply only when this is set. |
| `ORLOP_IDENTITY_PUBLIC_KEY_FILE` | PKIX/SPKI PEM public key the host JWT is verified against (RSA, ECDSA P-256, or Ed25519). Required when the audience is set. |
| `ORLOP_IDENTITY_ISSUER` | Optional; when set, must equal the JWT `iss`. |
| `ORLOP_IDENTITY_TENANT_CLAIM` | Claim mapped onto the tenant subject. Default `tenant`. |
| `ORLOP_IDENTITY_TENANT_ALLOWLIST` | Comma-separated, fail-closed list of tenant ids that may be provisioned via the JWT path. Required when the audience is set. |
| `ORLOP_CA_TENANT_ALLOWLIST` | Comma-separated tenant ids that may have a CA intermediate lazily bootstrapped at first enroll, on top of the dynamic prefixes. An unrecognized tenant's enroll is refused with `403 access_denied / tenant_not_allowed`. |
| `ORLOP_CA_ALLOW_DYNAMIC_TENANTS` | Allow lazy bootstrap of server-derived per-user (`u_`) and per-agent (`a_`) tenants. Default `true`. |

`ORLOP_CA_ALLOW_DYNAMIC_TENANTS` accepts `true/false/1/0/yes/no/on/off`
(case-insensitive). Unset uses the default, but a set-but-unrecognized value
fails boot rather than silently falling back: a typo on a security toggle must
not quietly leave the permissive default in force. Set it to `false` to restrict
bootstrap to `ORLOP_CA_TENANT_ALLOWLIST` only.

## CLI

`orlop-control` with a subcommand runs the CLI instead of the service. All
subcommands read `DATABASE_URL` from the environment when `--database-url` is not
passed.

| Command | Purpose |
| --- | --- |
| `orlop-control migrate up` | Apply all pending migrations. Works for both Postgres and SQLite (the SQLite backend applies its schema on open). |
| `orlop-control ca init --root` | Bootstrap the org root CA (run on an offline operator machine). |
| `orlop-control ca init --tenant <id>` | Bootstrap a tenant intermediate. |
| `orlop-control ca list` | List loaded tenant intermediates. |
| `orlop-control ca mint-server-cert --tenant <id> --fqdn <host> --out-dir <dir> [--ttl 2160h]` | Mint a TLS server cert for `orlop-server`. |
| `orlop-control user seed --tenant <id> --email <e> [--base-url <url>]` | Idempotently create tenant + user and mint an admin session; prints a one-shot URL to register the cookie. |
| `orlop-control user suspend --email <e>` | Suspend a user; outstanding access tokens stop validating on next use. |
| `orlop-control server register [--data-addr <h:p>] [--ops-addr <h:p>] [--total-bytes N] [--status S]` | Register a data-plane server in the placement pool so `/agent/enroll` has somewhere to place disks. |
| `orlop-control token issue --agent <id> [--owner <uuid>] [--size <bytes>] [--control-plane <url>] [--mount-point <path>] [--json]` | Provision an agent's disk (idempotently) and mint a short-lived (~10m), single-use enroll token; prints a ready-to-mount env block. |

`token issue` is the standalone enroll path: it prints `ORLOP_AGENT_ID`,
`ORLOP_MOUNT_POINT`, `ORLOP_CONTROL_PLANE`, and `ORLOP_ENROLL_TOKEN`, which feed
`orlop mount --from-env`. Possession of `DATABASE_URL` is the operator credential
for `token issue`, `server register`, `user seed`, and `ca init`.

## Local development

Bring up storage, migrate, bootstrap the CA, and start the service. The example
uses Postgres; substitute a `sqlite:…` `DATABASE_URL` to run with no external
database (see [`database-backends.md`](database-backends.md)).

```bash
export DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/orlop_control
export ORLOP_SECRETS_DIR=/tmp/orlop-control-secrets
export ORLOP_TRUST_DOMAIN=orlop.local
export ORLOP_ORG_NAME="ORL Dev"

orlop-control migrate up
orlop-control ca init --root
orlop-control ca init --tenant acme
orlop-control            # start the service
```

Seed an admin session (prints a one-shot URL to open in a browser):

```bash
orlop-control user seed \
  --tenant acme \
  --email operator@acme.example \
  --base-url http://127.0.0.1:8080
```

Register a data-plane server so enrollment has a placement target, then issue an
enroll token and mount:

```bash
orlop-control server register --data-addr localhost:8443 --ops-addr localhost:8443
orlop-control token issue --agent demo --control-plane http://127.0.0.1:8080
# → exports ORLOP_ENROLL_TOKEN etc.; run `orlop mount --from-env`
```

For full-stack mTLS, the `orlop-server` cert name must match the
`server register --data-addr` value, and its client CA must be the org root (the
shared client CA, with the agent presenting its tenant intermediate in the
chain). A server can self-provision that cert via `POST /control/sign-server-cert`.
