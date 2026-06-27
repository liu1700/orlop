# Control-plane runbook

Operator workflows for the orlop control plane. The CA design is in
[`design-auth.md`](./design-auth.md).

## Trust hierarchy

```
org root CA           (10y, ed25519, offline)
  └── tenant CA       (1y,  ed25519, online — control-plane secret store)
        └── agent     (1h,  ed25519, minted on every /agent/enroll)
```

Cert identity is encoded as a SPIFFE URI SAN
(`spiffe://<trust-domain>/tenant/<id>`) on the agent leaf. The userID is
recorded in the leaf's Subject CommonName for audit.

## Bootstrapping

### 1. Org root (offline operator machine)

The org root signing key must never be present on a server VM. It lives
on an operator workstation; the only output that leaves that machine is
the public root cert, which is shipped with every server VM as a trust
anchor.

```sh
# on the operator workstation; pick a vault directory you control.
export ORLOP_SECRETS_DIR=/secure/operator-vault
export ORLOP_TRUST_DOMAIN=orlop.example
export ORLOP_ORG_NAME=ORL

orlop-control ca init --root
# → writes ca/root/cert.pem + ca/root/key.pem under $ORLOP_SECRETS_DIR
```

The command is idempotent: if a root already exists in
`$ORLOP_SECRETS_DIR/ca/root/`, it is loaded as-is and the command is a
no-op. Re-running never rotates the root.

Distribute `ca/root/cert.pem` (and only the cert) to every server VM
deploy bundle.

### 2. Tenant intermediate (online; signed against the root)

Run on the operator machine while the root is reachable, then upload the
resulting cert + key into the deploy target's secret manager (Fly
secrets / GCP Secret Manager). On the running control plane the
materials are decrypted into process memory at boot — never written to
disk on the VM.

```sh
orlop-control ca init --tenant acme
# → writes ca/tenant/acme/{cert.pem,key.pem} under $ORLOP_SECRETS_DIR
```

Idempotent. Repeat per tenant. Upload `ca/tenant/<id>/cert.pem` to the
matching tenant's orlop-server VM (used as `tls.Config.ClientCAs`); upload
both files to the control-plane secret store.

## Provisioning a tenant server cert

orlop-server presents a TLS server cert that must chain through the same
tenant intermediate the agent receives via `/agent/enroll` — the agent
uses that chain as its server trust anchor (`src/main.rs:709`,
`src/backend/remote.rs:348`). Mint that cert with:

```sh
orlop-control ca mint-server-cert \
    --tenant acme \
    --fqdn tenant-acme.orlop.example \
    --out-dir /etc/orlop/tls/acme
```

Outputs (mode `0600`):

- `cert.pem` — leaf signed by the tenant intermediate, with CN and
  DNS SAN set to `--fqdn`.
- `key.pem`  — ed25519 private key for the leaf.
- `chain.pem` — `intermediate || root`, written for operator
  convenience. orlop-server itself does **not** need this file: Go's
  default TLS handshake only sends `cert.pem`, and the agent has
  already learned the intermediate from `/agent/enroll`.

Wire `cert.pem` into orlop-server's `tls.cert_file` and `key.pem` into
`tls.key_file`. The flag `--ttl` defaults to `2160h` (90 days).

The command requires the tenant intermediate to be present in
`$ORLOP_SECRETS_DIR/ca/tenant/<id>/`. Run against a host where the
intermediate has not been loaded (e.g. a fresh operator vault) and the
command errors out — bootstrap the intermediate first with
`ca init --tenant <id>`.

### Server cert rotation

Server certs rotate by re-running `mint-server-cert` and reloading
orlop-server (the new files overwrite the old in place at the same paths).
There is no separate rotation flag; the command always issues a fresh
leaf. Default lifetime is 90 days, so schedule rotation accordingly.

If the tenant intermediate itself rotates (see below), every server cert
minted under the previous intermediate must be re-minted — the agent's
freshly fetched chain will not match the old leaf.

## Rotation

### Tenant intermediate (yearly, no-incident)

1. `orlop-control ca init --tenant <id>` is **not** the rotation command —
   it is idempotent and will not overwrite. To rotate, first remove the
   existing intermediate from `$ORLOP_SECRETS_DIR/ca/tenant/<id>/` (and
   from the secret store), then re-run `ca init --tenant <id>`.
2. Push the new `cert.pem` to the tenant's orlop-server VM and roll the
   process. Until both the new and old intermediates are trusted on the
   server, agents holding outstanding leaves issued by the old
   intermediate will be denied.
3. Outstanding agent leaves expire within 1h, so the rollout window is
   self-healing — no client-side action required.

### Org root (emergency only)

A root rotation invalidates every intermediate and every agent leaf
across all tenants. There is no online procedure: distribute a new root
to every server VM and re-bootstrap every tenant intermediate against
the new root. Plan on a maintenance window and announce it.

## Revocation

There is no CRL or OCSP, but there is a per-serial **deny-list kill switch**
(issue #5). Releasing a mount lease records the bound agent leaf's serial in the
`cert_revocations` table; a reconcile loop pushes the active set to every
data-plane server (`PUT /control/cert-revocations`), and `orlop-server` refuses a
matching client cert at session start. Propagation is bounded by the reconcile
interval (~60s), and entries age out automatically at the cert's own expiry. This
kills a single leaked/released leaf mid-TTL without a tenant-wide rotation.

For a broader cut-off, rotation is still the blunt instrument.

To cut a single tenant off immediately:

1. Operator: rotate that tenant's intermediate following the rotation
   procedure above.
2. Operator: push the new `cert.pem` (only) to the tenant's orlop-server
   VM and restart the server. Do not include the old intermediate in
   `ClientCAs`.
3. All outstanding leaves for that tenant fail TLS handshake from this
   point. Agents that re-enroll get leaves signed by the new
   intermediate; leaves they already hold (≤1h old) become useless.

To cut a single user off immediately, suspend the user in the control-plane
database with `orlop-control user suspend`; the next device-flow poll, token
refresh, or `/agent/enroll` returns 403 and the user's existing leaf expires
within the hour. There is no faster path under the MVP.

## Blast radius

| Compromise            | Blast radius                                                                                                  | Recovery                                                                                                                |
| --------------------- | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Agent leaf            | One user, ≤1h.                                                                                                | None needed; cert expires.                                                                                              |
| Tenant intermediate   | All agents in that tenant for as long as the intermediate is trusted by the server.                           | Rotate intermediate (above). ≤1h until all outstanding leaves expire.                                                   |
| Org root              | All tenants, all environments using that root. Attacker can mint intermediates that pass server verification. | Emergency root rotation. Every server VM and every tenant intermediate must be re-bootstrapped against the new root.    |
| Control-plane process memory | Equivalent to a tenant intermediate compromise per tenant whose intermediate was loaded at the time. | Rotate every loaded intermediate. Plan an HSM migration so future leaks expose only signing oracles, not key material. |

## Device-flow login (issue #44)

The control plane terminates a first-party device-code flow that mirrors
RFC 8628. A CLI session calls `/auth/device/code`, the operator approves
the resulting `user_code` in a browser, and the CLI then exchanges its
`device_code` for an opaque bearer token at `/auth/device/token`. That
token is what `/agent/enroll` (issue #31) consumes.

Auth0 / Dex is intentionally deferred: a real OIDC provider can replace
the four endpoints later without changing the CLI, but operating
Auth0/Dex for the MVP is more surface than the device flow itself.

### 1. Sign in (operator-seeded admin session)

Self-service email-OTP login was **removed**. An embeddable infra component does
not own the human signup/login lifecycle: identities are provisioned by the
operator, not self-served via an emailed code. See
[`design-identity.md`](./design-identity.md) for the full rationale and the
planned BYO-IdP (verify-a-signed-JWT) direction that will replace this seed flow.

Until that lands, browser sign-in is the operator-seeded admin session below.
The only remaining auth endpoint here is `POST /auth/logout`, which clears the
`orlop_admin_session` cookie. Set `ORLOP_COOKIE_DOMAIN` in staging when the web
app and control-plane API share a parent domain through the reverse proxy.

### 2. Seed an admin user for a tenant

This is the primary way to obtain a browser admin session (and is also used for
non-interactive smoke tooling).

The session is seeded by the operator running `orlop-control user seed` against
the control-plane database. The command is idempotent on tenant + user; each
run mints a fresh session token (~30d TTL).

```sh
export DATABASE_URL=postgres://control-plane/...

orlop-control user seed \
    --tenant acme \
    --email alice@acme.example \
    --base-url https://control.orlop.example
# →
# created tenant acme            (only on first run)
# created user alice@acme.example under tenant acme  (only on first run)
# admin session token: <opaque>
# expires at:          2026-05-29 12:34:56 UTC
# approval URL:        https://control.orlop.example/device?session=<opaque>
```

Register the tenant server VM in the control-plane database so `/agent/enroll`
knows which FQDN to return. There is not yet a public CLI for this row, so use
SQL during the MVP:

```sql
INSERT INTO server_vms (tenant_id, fqdn, status, provisioned_at)
VALUES ('acme', 'tenant-acme.orlop.example', 'active', now())
ON CONFLICT (tenant_id)
DO UPDATE SET fqdn = EXCLUDED.fqdn,
              status = 'active',
              provisioned_at = now();
```

The operator opens the printed `approval URL` in a browser. The
`?session=...` query param is consumed once: the response sets an
HttpOnly `orlop_admin_session` cookie and 302-redirects to `/device`.
Subsequent visits to `/device` use the cookie.

The session token lives in the same `access_tokens` table as device
bearer tokens, distinguished by `purpose = 'admin_session'`. Revoke a
session by deleting (or `revoked_at`-stamping) its row.

### 3. Approve a CLI login

1. CLI prints `Open https://control.orlop.example/device and enter ORL-XXXX`.
2. Operator visits `/device` (admin cookie present) and types `ORL-XXXX`
   into the form, then clicks **Approve**.
3. The CLI's next poll of `/auth/device/token` returns
   `{access_token, token_type:"Bearer", expires_in:3600}`. Single-use:
   subsequent polls of the same `device_code` return `expired_token`.

OAuth-style errors the CLI must handle:

| Error                   | Meaning                                                |
| ----------------------- | ------------------------------------------------------ |
| `authorization_pending` | Wait `interval` seconds and poll again.                |
| `slow_down`             | Polled inside `interval`. Back off.                    |
| `expired_token`         | `device_code` unknown, expired, or already exchanged.  |
| `access_denied`         | Operator clicked **Deny**.                             |

### 4. Suspend or revoke a user

Suspending a user invalidates access and refresh tokens on their next use
(the bearer middleware joins through `users.suspended_at`). The next
device-flow poll, token refresh, or `/agent/enroll` fails until the user is
unsuspended. Any client certificate already minted for that user can still
authenticate to `orlop-server` until its one-hour expiry because the server does
not call back to the control plane on each data-plane request.

```sh
orlop-control user suspend --email alice@acme.example
```

To revoke a single token without suspending the user, set
`access_tokens.revoked_at = now()` for that row. There is no API
endpoint for this under the MVP — go through the database.

### 5. Why Auth0 / Dex is deferred

- Provisioning Auth0/Dex per environment + per tenant is a significant
  operational surface for a hosted MVP that needs to authorise exactly
  one human action: "approve this CLI login".
- The device-flow endpoints are RFC 8628-shaped, so the CLI does not
  need to change when we eventually swap in an OIDC provider.
- The data model already separates *user identity* (`users` row) from
  *bearer credentials* (`access_tokens` row). An OIDC integration would
  populate the `users` row from an `id_token`'s `email` claim and then
  mint the same opaque bearer token; nothing downstream of `/agent/enroll`
  changes.

## Out of scope (post-MVP)

- HSM-backed root key (AWS KMS / GCP Cloud KMS / Cloud HSM). The
  package's `secrets.Backend` interface is the integration point: an HSM-backed
  implementation would replace `Filesystem` for the root key path while
  the rest of the CA package stays unchanged.
- CRL / OCSP. Rotation is the revocation primitive in the MVP.
- Stronger SSO for the approval page. The seedable admin session is
  enough for the MVP; full Auth0/OIDC is a swap, not a rewrite.
