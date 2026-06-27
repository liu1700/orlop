# Control-plane runbook

Operator workflows for the orlop control plane. The CA design and rationale live
in [`design-auth.md`](./design-auth.md). For a single-node bring-up that exercises
the whole stack end to end, see [`standalone-quickstart.md`](./standalone-quickstart.md).

## Trust hierarchy

```
org root CA           (10y, ed25519, offline operator machine)
  └── tenant CA       (1y,  ed25519, online: control-plane secret store)
        └── agent     (1h,  ed25519, minted on every /agent/enroll)
```

Each agent leaf carries **two** SPIFFE URI SANs:

- `spiffe://<trust-domain>/tenant/<id>` (the tenant), and
- `spiffe://<trust-domain>/agent/<agent-id>` (the agent).

The agent SAN is the per-agent isolation point on the data plane: a connection is
confined to that agent's path prefix. The tenant SAN is what the cross-tenant
binding check matches the signing intermediate against, so a leaf cannot be
replayed under a different tenant. The userID is recorded in the leaf Subject
CommonName for audit.

Because the agent is untrusted, the tenant always comes from the verified cert,
never from the request body.

## Bootstrapping the CA

### 1. Org root (offline operator machine)

The org root signing key must never be present on a server VM. It lives on an
operator workstation; the only output that leaves that machine is the public root
cert, which ships with every server deploy bundle as a trust anchor.

```sh
# on the operator workstation; pick a vault directory you control.
export ORLOP_SECRETS_DIR=/secure/operator-vault
export ORLOP_TRUST_DOMAIN=orlop.example
export ORLOP_ORG_NAME=ORL

orlop-control ca init --root
# → writes ca/root/cert.pem + ca/root/key.pem under $ORLOP_SECRETS_DIR
```

The command is idempotent: if a root already exists in
`$ORLOP_SECRETS_DIR/ca/root/`, it is loaded as-is and the command is a no-op.
Re-running never rotates the root.

Distribute `ca/root/cert.pem`, and only the cert, to every server deploy bundle.

### 2. Tenant intermediate (online, signed against the root)

Run on the operator machine while the root is reachable, then upload the
resulting cert and key into the deploy target's secret manager. On the running
control plane the materials are decrypted into process memory at boot, never
written to disk on the VM.

```sh
orlop-control ca init --tenant acme
# → writes ca/tenant/acme/{cert.pem,key.pem} under $ORLOP_SECRETS_DIR
```

Idempotent. Repeat per tenant. Upload `ca/tenant/<id>/cert.pem` to the matching
tenant's orlop-server VM (used as the server's client-CA trust), and upload both
files to the control-plane secret store. `orlop-control ca list` prints the tenant
intermediates currently loaded from the vault.

## Provisioning a tenant server cert

orlop-server presents a TLS server cert that must chain through the same tenant
intermediate the agent receives via `/agent/enroll`. The agent uses that chain as
its only server trust anchor (it does not consult the system trust store; see
[`design-auth.md`](./design-auth.md)). Mint that cert with:

```sh
orlop-control ca mint-server-cert \
    --tenant acme \
    --fqdn tenant-acme.orlop.example \
    --out-dir /etc/orlop/tls/acme
```

Outputs (mode `0600`):

| File        | Contents                                                        |
| ----------- | --------------------------------------------------------------- |
| `cert.pem`  | leaf signed by the tenant intermediate, CN and DNS SAN = `--fqdn` |
| `key.pem`   | ed25519 private key for the leaf                                |
| `chain.pem` | `intermediate \|\| root`, written for operator convenience      |

orlop-server itself does not need `chain.pem`: Go's default TLS handshake sends
only `cert.pem`, and the agent has already learned the intermediate from
`/agent/enroll`. Wire `cert.pem` into orlop-server's `tls.cert_file` and `key.pem`
into `tls.key_file`. The `--ttl` flag defaults to `2160h` (90 days).

The command requires the tenant intermediate to be present in
`$ORLOP_SECRETS_DIR/ca/tenant/<id>/`. Run it against a host where the intermediate
has not been loaded (for example a fresh operator vault) and it errors out: run
`ca init --tenant <id>` there first.

### Server cert rotation

Server certs rotate by re-running `mint-server-cert` and reloading orlop-server;
the new files overwrite the old in place at the same paths. There is no separate
rotation flag, the command always issues a fresh leaf. Default lifetime is 90
days, so schedule rotation accordingly.

If the tenant intermediate itself rotates (see [Rotation](#rotation)), every
server cert minted under the previous intermediate must be re-minted: the agent's
freshly fetched chain will not match the old leaf.

## Provisioning tenants, users, and agents

These commands operate on the control-plane database. They all read `DATABASE_URL`
from the environment (or take `--database-url`), and possession of `DATABASE_URL`
is the operator credential, the same trust model as `ca init`. `DATABASE_URL`
accepts either `postgres://...` or `sqlite:...`; see
[`database-backends.md`](./database-backends.md).

| Task                                   | Command                        |
| -------------------------------------- | ------------------------------ |
| Apply the schema                       | `orlop-control migrate up`     |
| Seed a tenant and its admin user       | `orlop-control user seed`      |
| Register a data-plane server           | `orlop-control server register`|
| Issue an agent enroll token            | `orlop-control token issue`    |
| Suspend a user                         | `orlop-control user suspend`   |

`migrate up` applies the embedded schema and works for both Postgres and SQLite
(SQLite applies its schema on open). Run it once before the commands below.

### Seed a tenant and an admin user

```sh
orlop-control user seed \
    --tenant acme \
    --email alice@acme.example \
    --base-url https://control.orlop.example
# →
# created tenant acme                              (only on first run)
# created user alice@acme.example under tenant acme (only on first run)
# admin session token: <opaque>
# expires at:          2026-07-27 12:34:56 UTC
# approval URL:        https://control.orlop.example/device?session=<opaque>
```

The command provisions a tenant and an admin user, and is idempotent on tenant
plus user: it creates the tenant if absent, creates the user (admin is the only
role) if absent, and always mints a fresh admin session token. Optional
`--tenant-name` sets the tenant display name (defaults to the tenant id).

The admin session token is an ~30 day bearer credential stored in the
`access_tokens` table with `purpose = 'admin_session'`. Revoke a session by
deleting its row or stamping `revoked_at` on it. When `--base-url` is set, the
command also prints a one-time URL the operator opens in a browser; it exchanges
the token for an HttpOnly `orlop_admin_session` cookie for the control-plane
dashboard, then the cookie is used on subsequent visits. Set `ORLOP_COOKIE_DOMAIN`
when the web app and the control-plane API share a parent domain through a reverse
proxy.

### Register a data-plane server in the placement pool

```sh
orlop-control server register \
    --data-addr tenant-acme.orlop.example:8443 \
    --ops-addr  10.0.0.5:7878 \
    --total-bytes $((10 * 1024 * 1024 * 1024))
```

`/agent/enroll` places each agent onto a server drawn from the placement pool.
With an empty pool, enroll has nowhere to put a disk and returns `503`, so
register at least one server. The command upserts the pool row keyed on
`--data-addr`; re-run it to update the ops address, capacity, or status.

| Flag            | Meaning                                                                          | Default          |
| --------------- | -------------------------------------------------------------------------------- | ---------------- |
| `--data-addr`   | address agents dial for the data plane; must match the server's cert SAN (`tls.fqdn`) | `localhost:8443` |
| `--ops-addr`    | address the control plane dials for the server's ops API over mTLS               | `localhost:7878` |
| `--total-bytes` | pool capacity that agent allocations are placed against                          | 10 GiB           |
| `--status`      | pool status; only `available` servers are picked for placement                   | `available`      |

On a single local node both addresses use the same host, so one self-provisioned
cert covers both connections. Re-registering resets free capacity to total, which
is correct for a single node with no concurrent reservations to preserve; a
multi-node operator manages capacity out of band.

### Issue an agent enroll token

```sh
orlop-control token issue --agent demo --control-plane https://control.orlop.example
```

This is the agent enrollment entry point. It provisions the agent's disk
allocation idempotently and mints a single-use, agent-scoped enroll token
(`purpose = 'agent_enroll'`) that is short-lived (~10 minutes), then prints a
ready-to-mount env block:

```sh
export ORLOP_AGENT_ID=demo
export ORLOP_MOUNT_POINT=./agent-disk
export ORLOP_CONTROL_PLANE=https://control.orlop.example
export ORLOP_ENROLL_TOKEN=<token>
orlop mount --from-env
```

The mount client trades `ORLOP_ENROLL_TOKEN` at `/agent/enroll` for a 1h agent
leaf. Optional flags: `--owner UUID` (the owning account), `--size BYTES` (initial
disk grant, default 1 GiB), and `--mount-point PATH`. For the full end-to-end
flow (database, control plane, `server register`, the data-plane server, mount,
and a durability check), follow [`standalone-quickstart.md`](./standalone-quickstart.md).

### Suspend a user

```sh
orlop-control user suspend --email alice@acme.example
```

This stamps `users.suspended_at`. The bearer middleware joins through that column,
so the user's access and refresh tokens stop validating on their next use, and
`/agent/enroll` refuses to mint new leaves for them. An agent leaf already minted
for that user (up to 1h old) keeps authenticating to orlop-server until it
expires, because the data plane does not call back to the control plane on each
request. To drop an outstanding leaf before its hour is up, get its serial onto
the deny-list (see [Revocation](#revocation)); a leaf serial lands there when its
mount lease is released.

## Rotation

### Tenant intermediate (yearly, no incident)

1. `ca init --tenant <id>` is not the rotation command. It is idempotent and will
   not overwrite. To rotate, first remove the existing intermediate from
   `$ORLOP_SECRETS_DIR/ca/tenant/<id>/` (and from the secret store), then re-run
   `ca init --tenant <id>`.
2. Push the new `cert.pem` to the tenant's orlop-server VM and roll the process.
   Until both the new and old intermediates are trusted on the server, agents
   holding outstanding leaves issued by the old intermediate are denied.
3. Outstanding agent leaves expire within 1h, so the rollout window is
   self-healing and needs no client-side action.

### Org root (emergency only)

A root rotation invalidates every intermediate and every agent leaf across all
tenants. There is no online procedure: distribute a new root to every server VM
and re-bootstrap every tenant intermediate against the new root. Plan a
maintenance window and announce it.

## Revocation

There is no CRL or OCSP, so cert expiry plus a per-serial **deny-list kill
switch** is how a single leaf is revoked mid-life. Releasing a mount lease records
the bound agent leaf's serial in the `cert_revocations` table. A reconcile loop on
the control plane fans the active set out to the data-plane servers:

```
lease release ──> cert_revocations (control-plane DB)
                        │
                        │  control-plane reconcile loop (~60s), outbound client
                        ▼
   PUT /control/cert-revocations ──> each data-plane server (hosts this route)
                        │
                        ▼
   server drops a matching leaf at session start; entries age out at cert expiry
```

The direction matters: `PUT /control/cert-revocations` is served by orlop-server
(the data plane). The control plane is the outbound client that pushes the active
serial set to every registered server's ops address on each ~60s tick (and once
immediately at startup), repopulating any server that restarted with an empty
in-memory list. Propagation is bounded by that interval, and entries age out
automatically at the cert's own expiry. This kills a single leaked or released
leaf without a tenant-wide rotation.

For a broader cut-off, rotation is the blunt instrument. To cut a single tenant
off immediately:

1. Rotate that tenant's intermediate following the rotation procedure above.
2. Push the new `cert.pem` only to the tenant's orlop-server VM and restart it.
   Do not include the old intermediate in the server's client-CA trust.
3. All outstanding leaves for that tenant fail the TLS handshake from this point.
   Agents that re-enroll get leaves signed by the new intermediate; the leaves
   they already hold (up to 1h old) become useless.

To cut a single user off, use `orlop-control user suspend` (see above).

## Blast radius

| Compromise                   | Blast radius                                                                                                   | Recovery                                                                                                  |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Agent leaf                   | One user, up to 1h.                                                                                            | None needed; the cert expires. Cut it short via the deny-list.                                           |
| Tenant intermediate          | All agents in that tenant for as long as the intermediate is trusted by the server.                           | Rotate the intermediate. Up to 1h until all outstanding leaves expire.                                   |
| Org root                     | All tenants and all environments using that root. The attacker can mint intermediates that pass verification. | Emergency root rotation. Re-bootstrap every server VM and every tenant intermediate against the new root.|
| Control-plane process memory | Equivalent to a tenant intermediate compromise per tenant whose intermediate was loaded at the time.          | Rotate every loaded intermediate.                                                                        |
