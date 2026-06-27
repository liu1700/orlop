# Auth: Certificates & Tenant Isolation

orlop has one shape: a Rust mount client on a user's machine opens a long-lived,
mutually-authenticated TLS connection to a per-tenant Go server in a cloud
region. This doc explains how that connection is authenticated, how each side
knows who it is talking to, and how one tenant's credential is kept from ever
reaching another tenant's data.

The transport is plain mTLS over the public internet. Everything below is built
from short-lived X.509 certificates issued by a private CA that orlop runs
itself.

Related docs: [control-plane.md](control-plane.md) (the enrollment HTTP API),
[design-identity.md](design-identity.md) (how a bearer credential is obtained),
[design-data-plane.md](design-data-plane.md) (the wire protocol the connection
carries), [control-plane-runbook.md](control-plane-runbook.md) (operator CA
workflow).

## What is and isn't trusted

The mount client is **untrusted**. It runs on a user's machine, can be patched
or replaced, and the requests it sends can claim anything. The network between
client and server is untrusted too. So:

- **The server never reads tenant or agent identity from a request.** It derives
  both from the verified client certificate presented during the TLS handshake.
  A field in a request body cannot widen access.
- **Neither side consults the system / public PKI trust store.** Each side trusts
  exactly the CA material orlop delivers it; nothing a public CA signs is
  accepted.

Three properties have to hold on every connection:

1. **Encrypted in transit**: TLS 1.3, modern suites only.
2. **Mutually authenticated**: the server learns which tenant and which agent
   the client is; the client confirms it reached the right server.
3. **Tenant-isolated**: tenant A's credential must never grant access to tenant
   B's server, even if A's signing key leaks.

### Threat model

| Threat | Mitigation |
|--------|-----------|
| Agent cert leaked | 1h leaf TTL bounds the window. Releasing the mount lease puts the leaf's serial on a data-plane deny-list; the server drops it mid-TTL within the reconcile window (~60s). Rotating the tenant intermediate is the backstop. |
| Tenant A forges a leaf bearing tenant B's SAN | The TLS handshake completes (the forged leaf chains to the shared org root), but the data-plane tenant-binding check fails closed and the connection is dropped before any frame is served. |
| Stolen/forged bearer token at `/agent/enroll` | Opaque tokens carry ≥128 bits of entropy; only hashes are stored; unknown, expired, revoked, consumed, suspended-user and suspended-tenant tokens are rejected. Enroll tokens are single-use, spent the moment a cert is minted. |
| Replay of an old cert | Leaf TTL is 1h; the server tolerates ±5 min of clock skew. |
| Server impersonation | The client trusts **only** the org root delivered in `ca.pem` at enroll. The server's leaf is signed by that org root, so a public-PKI or self-signed cert is rejected; the client never falls back to a system trust store. |
| MITM on the wire | TLS 1.3 only, mutual cert auth on every connection. |
| Compromised control plane | Worst case: the attacker can mint arbitrary tenant certs. Mitigations: the CA signing key is encrypted at rest in the secret store and decrypted into memory only on boot; every signing event is audited; enroll is rate-limited per token. |

## What a certificate asserts

Tenant and agent identity live in the leaf's **URI Subject Alternative Names**,
encoded as [SPIFFE](https://spiffe.io) IDs, a URI of the form
`spiffe://<trust-domain>/<path>`. The trust domain defaults to `orlop.example`
(`ORLOP_TRUST_DOMAIN`).

An agent leaf carries **two** SPIFFE URI SANs:

```
spiffe://orlop.example/tenant/<tenantID>   ← which tenant (and so which server)
spiffe://orlop.example/agent/<agentID>     ← which agent disk, within that tenant
```

The `tenant/<id>` SAN selects the tenant. The `agent/<id>` SAN is the per-agent
isolation point on the data plane: a connection may operate only on paths under
its own `agentID`. A leaf without an agent SAN is rejected at the door; every
connection is scoped to a single agent.

The control plane gives itself a third identity, `spiffe://<td>/control`, signed
directly by the org root; it is what authenticates control-plane calls to the
server's `/control/*` endpoints. It is not a tenant identity.

## CA hierarchy

Three tiers, each signing only the tier below it. All keys are ed25519.

```
org root CA                      10 years   offline; key never on a server VM
  │  CN "<ORG> Root CA", IsCA, MaxPathLen 1
  │
  ├── tenant intermediate (A)     1 year    one per tenant; in the control-plane
  │     │  OU "tenant=A"                     secret store; PermittedURIDomains =
  │     │  IsCA, MaxPathLen 0                [trust-domain]
  │     │
  │     ├── agent leaf            1 hour     minted on every /agent/enroll
  │     │     SANs: tenant/A, agent/<id>
  │     └── server leaf*          ~90d       (servers self-provision, see below)
  │
  └── tenant intermediate (B)     1 year     ...
        └── agent leaf            1 hour     SANs: tenant/B, agent/<id>
```

\* The **server's** TLS cert is the one exception to the tier rule: it is signed
**directly by the org root**, not by a tenant intermediate, so that every
tenant's agent, each of which trusts the org root via the chain it received at
enroll, trusts the one shared server. The server self-provisions it through the
control plane (`POST /control/sign-server-cert`): it generates its own key, sends
a CSR, and gets back an org-root-signed server-auth leaf (default 90-day TTL,
re-signed in place before expiry). The private key never leaves the server pod.

### Certificate contents

| | Signed by | Subject | URI SANs | DNS SAN | Key usage | Validity |
|---|---|---|---|---|---|---|
| **Org root** | self | CN `<ORG> Root CA` | none | none | CertSign, CRLSign (IsCA) | 10y |
| **Tenant intermediate** | org root | CN `<ORG> Tenant <id> Intermediate`, OU `tenant=<id>` | none | none | CertSign, CRLSign (IsCA); `PermittedURIDomains=[td]` | 1y |
| **Agent leaf** | tenant intermediate | CN `<userID>`, OU `tenant=<id>` | `tenant/<id>`, `agent/<agentID>` | none | DigitalSignature, ExtKeyUsage ClientAuth | 1h |
| **Server leaf** | org root | CN `<fqdn>` | none | `<fqdn>` | DigitalSignature, KeyEncipherment, ExtKeyUsage ServerAuth | ~90d |
| **Control-plane** | org root | CN `orlop-control` | `control` | none | DigitalSignature, ExtKeyUsage ClientAuth | (short) |

The agent's user id rides in the leaf Subject CN (for the audit trail); the
tenant id is duplicated into the OU as `tenant=<id>`; that OU is what the
data-plane binding check reads back. `NotBefore` is set 5 minutes early to absorb
clock skew.

## Issuance and handshake

**Enrollment** (`POST /agent/enroll`, over the control plane's HTTPS API):

```
agent box                         control plane
─────────                         ─────────────
  bearer credential ───────────►  POST /agent/enroll  (Authorization: Bearer …)
  (single-use enroll token)          │
                                      ├─ verify token; derive tenant_id + user_id +
                                      │  agent_id from the bound allocation (never the body)
                                      ├─ reject if tenant suspended
                                      ├─ ensure tenant intermediate exists
                                      │  (lazy bootstrap, operator-allowlisted)
                                      ├─ mint ed25519 agent leaf (1h), signed by
                                      │  that tenant's intermediate, SANs tenant/<id>
                                      │  + agent/<id>
                                      ├─ consume the enroll token (single-use)
   { client_cert_pem,                │
     client_key_pem,    ◄────────────┘  record serial + not-after for audit
     ca_chain_pem,
     server_addr, expires_at } }
  write cert.pem / key.pem / ca.pem (0600), then dial server_addr
```

`ca_chain_pem` is `intermediate || root`. The client uses it two ways: as the
**only** trust anchor for verifying the server, and (concatenated with its leaf)
as the chain it presents to the server.

The bearer credential itself comes from one of the enrollment paths in
[design-identity.md](design-identity.md); the shipped agent path is
`orlop-control token issue` → `ORLOP_ENROLL_TOKEN` → `orlop mount --from-env`.

**Handshake** (data plane: a long-lived mTLS connection over TCP, the default,
or QUIC, carrying binary frames):

1. The client dials `server_addr` and starts a TLS 1.3 handshake.
2. The server presents its org-root-signed leaf. The client verifies it against
   `ca.pem` alone (org root in the chain), not the system trust store.
3. The client presents `leaf || tenant intermediate`. The server verifies that
   chain against `ClientCAs`, which is the **org root alone**
   (`RequireAndVerifyClientCert`), so the handshake cannot complete unless the
   client supplied its intermediate.
4. The server runs the verifier checks below before serving any frame.

## Verifier checks (server side)

At session start, before the first frame, the server requires **all** of these.
Any failure drops the connection silently; it fails closed.

| Check | Rejects |
|---|---|
| Chain verifies to the org root (TLS layer, `ClientCAs` = org root) | any cert not issued under the org root |
| Leaf has a `tenant/<id>` SAN in the configured trust domain | malformed / foreign-domain / tenant-less certs |
| Leaf has an `agent/<id>` SAN | tenant-only certs (no tenant-wide access) |
| Leaf serial is **not** on the revocation deny-list | leaked / lease-released certs mid-TTL |
| `checkTenantBinding`: the intermediate that signed the leaf has OU `tenant=<id>` **equal** to the leaf's SPIFFE tenant | cross-tenant forgeries (see below) |

`checkTenantBinding` is the enforcing gate, not a nicety. URI name constraints on
the intermediate (`PermittedURIDomains`) stop a leaked intermediate key from
minting a leaf in a *different* trust domain, but they cannot separate tenants:
every tenant's SPIFFE SAN shares the same host and differs only by the URI
*path*, which X.509 path validation does not constrain. So the only thing
standing between a leaked tenant-A key and a forged tenant-B leaf is this check.

## Cross-tenant rejection, worked

Suppose tenant A's intermediate key leaks and an attacker mints a leaf that
*claims* to be tenant B:

```
forged leaf:    SAN spiffe://orlop.example/tenant/B   ← lie
signed by:      tenant A intermediate, Subject OU "tenant=A"
```

What happens on connect:

1. TLS handshake **succeeds**: the leaf chains `leaf → A-intermediate → org
   root`, and the server trusts the org root.
2. The server reads the leaf SAN: tenant = `B`.
3. `checkTenantBinding` walks the verified chain, finds the signing intermediate,
   reads its OU: `tenant=A`.
4. `A != B` → **rejected**, connection dropped before any frame.

The attacker can only ever mint leaves that bind to tenant A, because that is the
tenant their intermediate's OU says. A leaked signing key is contained to its own
tenant.

## Rotation and revocation

orlop uses no CRL or OCSP. Two mechanisms cover the gap:

**Expiry is the floor.**

| Cert | TTL | Rotation |
|---|---|---|
| Agent leaf | 1h | re-minted on the next `/agent/enroll` |
| Server leaf | ~90d | server self-re-signs in place (~⅔ of remaining life); new connections pick it up with no restart |
| Tenant intermediate | 1y | rotated by the operator; rotating it invalidates **every** outstanding leaf for that tenant, the blunt, tenant-wide instrument |
| Org root | 10y | offline; the deployment-wide anchor |

**A per-serial deny-list is the kill switch.** It cuts a single leaked cert
mid-TTL without a CA rotation:

```
release mount lease ─► record leaf serial in `cert_revocations` (durable)
                            │
control-plane reconcile loop (~60s)
                            │  PUT /control/cert-revocations  (control-cert gated)
                            ▼
each server merges the active set into an in-memory deny-list
                            │
next session presenting that serial ─► dropped at the door
```

The reconcile loop also re-pushes the full active set on every tick, so a server
that restarts repopulates its deny-list within one interval. Entries age out once
the underlying cert would have expired anyway.
