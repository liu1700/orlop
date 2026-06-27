# Control Plane

The hosted control plane handles human login, short-lived bearer credentials,
agent enrollment, and tenant CA signing. The data plane remains the per-tenant
`orlop-server`; after enrollment the agent reads entity data directly from that
server over mTLS.

See [`design-auth.md`](./design-auth.md) for the security model and
[`control-plane-runbook.md`](./control-plane-runbook.md) for operator tasks.

## Runtime

`cmd/orlop-control` is a Go service and CLI.

CLI groups:

- `orlop-control migrate`: apply Postgres migrations.
- `orlop-control ca`: bootstrap root and tenant CAs.
- `orlop-control user`: seed admin sessions and suspend users.

Service environment:

| Variable | Meaning |
| --- | --- |
| `PORT` | HTTP listen port, default `8080`. |
| `DATABASE_URL` | Postgres DSN. Without it, device-flow and enroll routes are not mounted. |
| `ORLOP_SECRETS_DIR` | Filesystem secrets root containing CA material. Required for `/agent/enroll`. |
| `ORLOP_TRUST_DOMAIN` | SPIFFE trust domain, default `orlop.example`. |
| `ORLOP_ORG_NAME` | X.509 organization, default `ORL`. |
| `ORLOP_IDENTITY_AUDIENCE` | Enables the Mode B host-identity verifier (pins the JWT `aud`). When set, the other `ORLOP_IDENTITY_*` knobs apply and `GET /v1/whoami` is mounted. |
| `ORLOP_IDENTITY_PUBLIC_KEY_FILE` | PKIX/SPKI PEM public key the host JWT is verified against (RSA, ECDSA P-256, or Ed25519). Required when audience is set. |
| `ORLOP_IDENTITY_ISSUER` | Optional; when set, required to equal the JWT `iss`. |
| `ORLOP_IDENTITY_TENANT_CLAIM` | Claim mapped onto the tenant subject. Default `tenant`. |
| `ORLOP_IDENTITY_TENANT_ALLOWLIST` | Comma-separated fail-closed allowlist of tenant ids that may be provisioned. Required when audience is set. |
| `ORLOP_CA_TENANT_ALLOWLIST` | Comma-separated tenant ids that may have a CA intermediate lazily bootstrapped at first enroll, on top of the dynamic prefixes below. Anything else is refused with 403 `tenant_not_allowed`. |
| `ORLOP_CA_ALLOW_DYNAMIC_TENANTS` | Allow lazy bootstrap of server-derived per-user (`u_`) / per-agent (`a_`) tenants. Default `true`; set `false` to restrict bootstrap to `ORLOP_CA_TENANT_ALLOWLIST` only. |

## Host identity (Mode B)

When `ORLOP_IDENTITY_AUDIENCE` is set, orlop-control acts as a relying party for
a host-issued, signed JWT: it verifies the signature against
`ORLOP_IDENTITY_PUBLIC_KEY_FILE`, checks `iss`/`aud`/`exp`, and maps the
`ORLOP_IDENTITY_TENANT_CLAIM` value onto the tenant subject — only if that value
is on `ORLOP_IDENTITY_TENANT_ALLOWLIST` (fail-closed). The host owns the human;
orlop verifies the assertion. See [`design-identity.md`](./design-identity.md)
for the full model. `GET /v1/whoami` echoes the verified tenant subject and is a
concrete check that a host token is accepted:

```bash
curl -fsS https://control.orlop.example/v1/whoami \
  -H "Authorization: Bearer $HOST_JWT"
# → {"tenant_id":"u_acme","subject":"host-user-42"}
```

Health check:

```bash
curl -fsS https://control.orlop.example/healthz
```

## Device Flow

`orlop login` uses a first-party device flow shaped like RFC 8628.

### Create code

```bash
curl -fsS -X POST https://control.orlop.example/auth/device/code \
  -H 'Content-Type: application/json' \
  -d '{}' | jq .
```

Response:

```json
{
  "device_code": "opaque",
  "user_code": "ORL-ABCD",
  "verification_uri": "https://control.orlop.example/device",
  "expires_in": 900,
  "interval": 5
}
```

The user opens `verification_uri` and enters `user_code`. The approval page
requires an admin session cookie, usually created from the one-shot URL printed
by `orlop-control user seed`.

### Poll token

```bash
curl -fsS -X POST https://control.orlop.example/auth/device/token \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
    "device_code": "opaque"
  }' | jq .
```

Pending responses are OAuth-style errors:

```json
{"error":"authorization_pending"}
```

Success:

```json
{
  "access_token": "opaque",
  "access_expires_at": "2026-04-30T13:00:00Z",
  "refresh_token": "opaque",
  "refresh_expires_at": "2026-05-30T12:00:00Z",
  "control_plane_url": "https://control.orlop.example",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

`orlop login` persists this as `~/.config/orlop/credentials.json` with mode
`0600`.

### Refresh token

```bash
curl -fsS -X POST https://control.orlop.example/auth/token/refresh \
  -H "Authorization: Bearer <refresh_token>" | jq .
```

The response shape matches the successful device-token response. The Rust
client refreshes automatically when the access token is inside its safety
window. If refresh fails with `401` or `403`, the client tells the user to run
`orlop login` again.

## Agent Enrollment

`orlop mount` calls `/agent/enroll` with the current access token.

```bash
curl -fsS -X POST https://control.orlop.example/agent/enroll \
  -H "Authorization: Bearer <access_token>" | jq .
```

Success:

```json
{
  "client_cert_pem": "-----BEGIN CERTIFICATE-----\n...\n",
  "client_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n",
  "ca_chain_pem": "-----BEGIN CERTIFICATE-----\n...\n",
  "server_fqdn": "tenant-acme.orlop.example",
  "expires_at": "2026-04-30T13:00:00Z"
}
```

The control plane:

1. Authenticates the bearer access token.
2. Confirms the tenant and user are active.
3. Looks up or creates a `server_vms` row via the placement scheduler (lazy allocation).
4. Mints a one-hour client certificate from the tenant intermediate.
5. Records an `agent_enrollments` audit row with cert serial and expiry.

Retryable enrollment failures return `503` with `Retry-After: 60`, for
example when tenant CA material is unavailable or server placement is pending.

## Request Flow

```text
orlop login
  -> POST /auth/device/code
  -> operator approves at /device
  -> POST /auth/device/token
  -> ~/.config/orlop/credentials.json

orlop mount
  -> refresh access token if needed
  -> POST /agent/enroll
  -> write cert.pem/key.pem/ca.pem under hosted.cert_dir
  -> GET https://<server_fqdn>/healthz with client cert
  -> mount remote backend over mTLS
  -> renew client cert before expiry while mounted
```

## Local Development

Run Postgres, migrate, and start the control plane:

```bash
export DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/orlop_control
export ORLOP_SECRETS_DIR=/tmp/orlop-control-secrets
export ORLOP_TRUST_DOMAIN=orlop.local
export ORLOP_ORG_NAME=ORL Dev

orlop-control migrate up
orlop-control ca init --root
orlop-control ca init --tenant acme
orlop-control
```

Seed an admin session:

```bash
orlop-control user seed \
  --tenant acme \
  --email operator@acme.example \
  --base-url http://127.0.0.1:8080
```

For manual testing without enrollment, you can seed a server VM row ahead of time:

```sql
INSERT INTO server_vms (tenant_id, fqdn, status, provisioned_at)
VALUES ('acme', 'tenant-acme.localhost', 'active', now())
ON CONFLICT (tenant_id)
DO UPDATE SET fqdn = EXCLUDED.fqdn,
              status = 'active',
              provisioned_at = now();
```

Then run:

```bash
orlop login --control-plane http://127.0.0.1:8080
```

For full-stack mTLS testing, you need an `orlop-server` certificate whose
name matches a `server_vms.fqdn` value and whose `tls.client_ca_file` points
to the tenant intermediate cert. (Server VM rows are created lazily on agent
enrollment; use the SQL above if pre-seeding is preferred.)
