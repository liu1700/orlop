# Host Identity: Verifying an External IdP

orlop is an embeddable storage layer for agent sandboxes, not a standalone
product. The host platform owns the human account lifecycle; orlop owns only the
**tenant subject**: the authorization unit that a path prefix, a disk
allocation, and an agent's certificate all hang off of.

This path lets your own identity provider (IdP) decide which tenant an agent
acts as. orlop verifies a host-issued, audience-pinned signed JWT and maps an
allowlisted claim onto the tenant subject. It is implemented today in
`cmd/orlop-control/internal/identity/` and exercised end to end by
`GET /v1/whoami`.

## When to use this

Most deployments do not need an IdP. The shipped, working agent path mints a
single-use enroll token (`orlop-control token issue`) and hands it to the mount
client. See [`control-plane.md`](control-plane.md). Reach for host identity
when you **already run an IdP** and want it, rather than an operator-issued
token, to be the source of truth for tenant assignment.

| Path | External dependency | Best when |
| --- | --- | --- |
| Enroll token (default) | none (needs no external IdP) | self-hosting; one or a few tenants |
| Host JWT (this doc) | your IdP signs short-lived JWTs | you already operate an IdP and want it to own tenant assignment |

### Why an id from the request is not enough

A passed id is authentication only *inside* a trust boundary already established
by a real credential. Across a trust boundary, a bare id is an
attacker-controllable string. orlop has two integration points with very
different threat models, and "just pass a tenant id" is valid for only one.

| Integration point | Caller | Threat model | Acceptable identity |
| --- | --- | --- | --- |
| **host → orlop-control** (control plane) | the host platform | host is *trusted*; orlop is a subsystem behind it | A signed token verified against a pinned key. A plain id is acceptable only if the host authenticated with a real credential first **and** orlop strips any caller-supplied tenant (default-deny). |
| **agent → orlop-server** (data plane) | the AI agent | **agent is hostile**, orlop's whole premise | **Never** a plain id. Only the mTLS certificate: proof-of-possession, CA-rooted, tenant scope baked into the SAN, serial revocable. |

The rule that follows: **never accept a tenant id from request parameters; derive
it only from a validated token's claims.** That is exactly what the verifier below
does — the tenant comes from a signed, allowlisted claim, never from the request
body.

The data-plane certificate model is covered in [`design-auth.md`](design-auth.md);
this document is only about the host → control-plane integration point.

## Trust flow

```
  human ──auth──▶ host platform          (orlop is not involved)
                      │
                      ▼  signs a short-lived JWT
              ┌───────────────────────────────┐
              │ aud = orlop                    │
              │ tenant = u_acme  (a claim)     │
              │ exp = now + a few minutes      │
              └───────────────────────────────┘
                      │  presented as a bearer token
                      ▼
                 orlop-control
                      │  1. signature vs the configured public key
                      │  2. iss / aud exact match, exp + skew
                      │  3. tenant claim must be on the allowlist
                      ▼
              tenant subject  (u_acme)   ── echoed by GET /v1/whoami
```

1. The host platform authenticates the human. orlop never sees this step.
2. The host IdP signs a short-lived JWT carrying `aud=orlop`, a tenant claim,
   and an `exp`.
3. The token is presented to orlop-control as a bearer token. Today the verifier
   is wired to `GET /v1/whoami`; enrollment is gated by a single-use enroll token.
4. orlop-control checks the signature against the configured public key, checks
   `iss`/`aud`/`exp`, and maps the tenant claim onto the tenant subject, but only
   if that claim value is on the operator allowlist.
5. `/v1/whoami` echoes the verified tenant subject — the durable authorization
   unit the rest of orlop hangs off (a disk allocation, an agent leaf cert whose
   SANs are `spiffe://<trust-domain>/tenant/<id>` and `.../agent/<agentID>`).
   Today the verifier gates only `/v1/whoami`; agent enrollment still rides the
   enroll-token path above.

## Configure the trusted issuer

The verifier is off until you set an audience. When `ORLOP_IDENTITY_AUDIENCE` is
set, orlop-control builds the JWT verifier, applies the other `ORLOP_IDENTITY_*`
knobs, and mounts `GET /v1/whoami`.

| Env var | Required | Meaning |
| --- | --- | --- |
| `ORLOP_IDENTITY_AUDIENCE` | yes (enables the path) | The value the token `aud` must contain. Pinning `aud` stops a token minted for some other service from being replayed here. |
| `ORLOP_IDENTITY_PUBLIC_KEY_FILE` | yes when audience set | Path to a PKIX/SPKI PEM public key. The token signature is checked against this key. |
| `ORLOP_IDENTITY_ISSUER` | optional | When set, the token `iss` must equal it exactly. |
| `ORLOP_IDENTITY_TENANT_CLAIM` | optional | The claim whose string value becomes the tenant subject. Default `tenant`. |
| `ORLOP_IDENTITY_TENANT_ALLOWLIST` | yes when audience set | Comma-separated, fail-closed list of tenant ids that may be accepted. |

The verifier trusts exactly one static PKIX public key — there is no JWKS
endpoint or multi-key trust. Rotating the signing key means swapping the file and
restarting.

## JWT verification rules

orlop-control validates the token in this order; any failure rejects it.

| Check | Rule |
| --- | --- |
| Algorithm | The `alg` header must match the configured key type. The verifier never picks the algorithm from the attacker-controlled header. That is the defense against the JWS algorithm-confusion attack. |
| Signature | Verified against `ORLOP_IDENTITY_PUBLIC_KEY_FILE`. |
| `iss` | If `ORLOP_IDENTITY_ISSUER` is set, must match exactly. |
| `aud` | Must contain `ORLOP_IDENTITY_AUDIENCE` (string or array form, per RFC 7519). |
| `exp` | Required. A token with no expiry is rejected. Compared with a 60-second clock-skew allowance. |
| `nbf` | If present, must not be in the future (same 60-second allowance). |
| tenant claim | Must be a non-empty string **and** on the allowlist (see below). |

Accepted signing algorithms are bound to the key type:

| Key type | Accepted `alg` |
| --- | --- |
| RSA | `RS256` |
| ECDSA P-256 | `ES256` |
| Ed25519 | `EdDSA` |

Rejections do not tell the client which check failed; orlop logs the reason for
the operator (`host_identity_rejected`) and returns a generic `401`. A
well-signed token whose tenant is not allowlisted is a `403` (see next section).

## Claim → tenant mapping and the allowlist

The mapping is one step: the value of the configured claim *becomes* the tenant
id. The `sub` claim is also captured, for audit only: it is the host's
principal id, not an orlop account.

| Token claim | Maps to | Notes |
| --- | --- | --- |
| `ORLOP_IDENTITY_TENANT_CLAIM` (default `tenant`) | `Identity.TenantID` | Must be a non-empty string and on the allowlist. |
| `sub` | `Identity.Subject` | Recorded for audit; not an authorization input. |

The allowlist is **default-deny and fail-closed**:

- An empty allowlist is a configuration error: the verifier refuses to start,
  so a misconfiguration cannot quietly accept every tenant.
- A verified token whose tenant claim is **not** on the allowlist is rejected
  with `403 access_denied` / `tenant_not_allowed`. A valid signature from your
  IdP is necessary but not sufficient; the operator still decides which tenants
  may exist.

This is the same rule the rest of the control plane enforces: a
verified-but-attacker-influenced claim cannot self-onboard a new tenant or its
CA material.

## Worked example

With the verifier configured, present a host-signed JWT to `GET /v1/whoami`. It
echoes the verified tenant subject, a dependency-free check that a host token is
accepted end to end (also mounted at `/api/v1/whoami`).

```bash
curl -fsS https://control.orlop.example/v1/whoami \
  -H "Authorization: Bearer $HOST_JWT"
# → {"tenant_id":"u_acme","subject":"host-user-42"}
```

Responses:

| Situation | Status | Body |
| --- | --- | --- |
| Valid token, allowlisted tenant | `200` | `{"tenant_id":"u_acme","subject":"host-user-42"}` |
| Missing/malformed/bad-signature/expired token | `401` | `invalid_token` |
| Valid token, tenant not on allowlist | `403` | `access_denied` / `tenant_not_allowed` |

## Hardening notes

The verifier is built to fail closed; the load-bearing properties are:

- **Pin the audience.** `aud` is required and must match exactly, so a token
  minted for another service cannot be replayed against orlop.
- **Keep the allowlist tight.** It is default-deny; only listed tenant ids are
  accepted. An empty list refuses to start.
- **Tenant comes from the claim, never the request.** The handler derives the
  tenant from the verified token; nothing in the request body can influence it.
- **Algorithm is bound to the key.** The accepted `alg` is fixed by the
  configured key type, closing the JWS algorithm-confusion attack.
- **Short expiries.** `exp` is mandatory; issue host JWTs with a short lifetime
  so a leaked token ages out quickly (60-second skew allowance).

For the data-plane certificate model (the agent leaf, tenant binding, and
revocation that protect agent → orlop-server), see
[`design-auth.md`](design-auth.md).
