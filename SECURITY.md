# Security

This subsystem gives untrusted AI agents a durable, per-agent POSIX disk. Its
whole reason to exist is the **isolation boundary**: an agent runs arbitrary
code, yet must only ever reach its own data and never the credentials of the
storage underneath. This document is the operator-facing summary of that model,
what you must configure, what is hardened, and what is not. The deep design is
in [`docs/design-auth.md`](docs/design-auth.md) and
[`docs/design-data-plane.md`](docs/design-data-plane.md).

## Model in one paragraph

Each agent receives a short-lived mTLS client certificate whose SPIFFE SAN
encodes its tenant and agent id. The data-plane server is the trust boundary: it
binds every connection to that certificate, confines all operations to the
agent's own path prefix (canonicalized, traversal-proof), and never reads a
tenant or path from the request body. Storage credentials (object store, Redis,
JuiceFS) live behind the data plane and are never handed to the agent.

## What is guaranteed

- **Tenant isolation.** Agent A cannot read, write, stat, list, rename, or
  symlink-escape into agent B's data. Path traversal is blocked by a
  canonicalization gate; the tenant is taken from the verified certificate, not
  the request; a leaf is rejected if its SAN tenant does not match the tenant of
  the intermediate that signed it.
- **Credential confinement.** The agent only ever holds its own short-lived,
  path-scoped client certificate. It never holds an intermediate key or the
  storage backend credentials.

## What the operator must do

These are not optional for a production deployment:

- **Encrypt the CA at rest.** With `ORLOP_SECRETS_BACKEND=postgres`, set
  `ORLOP_SECRETS_ENC_KEY` (a hex-encoded 32-byte AES key). The control plane
  refuses to boot otherwise (or set `ORLOP_SECRETS_ALLOW_PLAINTEXT=1` to
  consciously accept plaintext, which is not recommended).
- **Enforce a per-tenant disk quota.** Run with `quota.enforce: true` and an
  ext4 project quota or a JuiceFS directory quota. With enforcement off there is
  **no** per-tenant disk cap and one agent can fill the host disk for all
  tenants; the server logs a loud warning at boot in that state.
- **Protect the service token.** `ORLOP_CONTROL_PLANE_TOKEN` gates provisioning,
  server-cert signing, and enroll-token minting. Treat it as a high-value
  secret.
- **Front the control plane with a trusted proxy.** Rate limiters key on the
  client IP via `X-Forwarded-For`; only expose the control plane behind a proxy
  that sets that header. Never expose its port directly.
- **Consider an API-token TTL.** Set `ORLOP_API_TOKEN_TTL` (e.g. `2160h`) so
  `orlop_` tokens expire; the default is no expiry.
- **Lock down lazy tenant bootstrap.** By default the control plane will
  bootstrap a CA intermediate for any server-derived `u_`/`a_` tenant. Set
  `ORLOP_CA_TENANT_ALLOWLIST` (and optionally `ORLOP_CA_ALLOW_DYNAMIC_TENANTS=false`)
  to restrict which tenants may self-onboard (issue #8).

## Hardening in place

The data plane bounds untrusted input and load: msgpack decoding is guarded
against pre-allocation bombs, each request handler is panic-isolated (one bad
request can't crash the server), and concurrent connections, in-flight requests,
and per-chunk size are all capped. On the identity side: per-pod agent-enroll
tokens are single-use (issue #6); a released or leaked agent leaf is revoked
onto a data-plane serial deny-list checked at session start (issue #5); the
cross-tenant cert-forgery check fails closed (issue #7); API tokens can expire;
and cert issuance derives every SAN server-side and pins client/server usage.

## Known limitations

Honest gaps a deployment should account for:

- **Rate limiters are per-process and in-memory.** They reset on restart and are
  not shared across replicas. Running more than one control-plane replica, or a
  crash loop, weakens every rate-limit-dependent control (device-code, enroll).
  Use a shared store (Redis is already in the stack) for multi-replica.
- **Disk accounting when quota enforcement is off.** There is no in-process
  per-tenant byte accountant; the per-tenant cap depends entirely on the
  filesystem/JuiceFS quota (see "what the operator must do").
- **Intermediate-key blast radius.** Tenant intermediates carry a
  `PermittedURIDomains` name constraint pinning them to the deployment trust
  domain, but that is host-scoped and cannot isolate tenants (which differ only
  by SPIFFE URI *path*). The data-plane `checkTenantBinding` cross-check — now
  fail-closed — is the gate that rejects a leaked intermediate key minting
  another tenant's SAN; the control plane must still guard intermediate keys
  carefully.
- **Device user_code entropy.** The device-flow user code is short; approval
  requires an authenticated admin session, but widening it is a tracked
  hardening item.

## Reporting a vulnerability

Please report security issues privately by opening a private security advisory
on the repository rather than a public issue. Include a description, affected
component (control plane / data plane / mount client), and a reproduction if you
have one. Do not include live secrets in the report.
