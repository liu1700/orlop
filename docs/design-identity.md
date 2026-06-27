# Identity & Data-Isolation Design

Status: design (2026-06-27). Basis for issue #4 ("Hide the Postgres with storage
interface" → broadened into "how should orlop's identity mechanism be designed").

## Thesis

orlop is an **embeddable file-plane component**, not a standalone product. The
host platform owns the human/account lifecycle; orlop owns only the
**authorization subject** (tenant → path prefix, allocation, agent enrollment)
and the **mTLS credential** it mints for each agent. orlop verifies a
host-supplied, cryptographically-verifiable identity assertion and maps it onto
that subject. It does **not** ship signup, email login, or password recovery.

## 1. Two layers that must be reasoned about separately

**(A) The authorization SUBJECT — KEEP.** Zero-trust isolation requires a
durable owner for every byte: `tenants` → path prefix, `disk_allocations`
(`bound_agent_id`, lease), `agent_enrollments` (cert serial/expiry). The data
plane (`orlop-server`) confines each connection to the SPIFFE SAN's prefix
(`certTenantID` / `certScopedAgentID` in `cmd/orlop-server/identity.go`). This
subject, and the SAN-in-credential shape, is the isolation boundary and is the
correct design.

**(B) The human/account LIFECYCLE — DELETE from orlop.** Who the human is, how
they sign up, how an account is recovered — email-OTP, the Resend mailer,
first-login auto-provision of a tenant+user, the seeded admin-session URL. This
is not orlop's job.

The survey is unanimous: **no infra storage/data component bakes in human
signup.** MinIO, Garage, SeaweedFS, Ceph, FoundationDB, CockroachDB, Temporal,
NATS, etcd, and Ory all either (a) verify a token from an external IdP and map a
claim → authorization, or (b) expose an operator/host provisioning verb. Ory
exists precisely to be the thing identity is delegated *to*.

## 2. "Passing an id at the API layer is authentication" — half right

A passed id is authentication **only inside a trust boundary already
established by a real credential**. Across a trust boundary, a bare id is an
attacker-controllable string. orlop has two seams with different threat models,
and the "just pass an id" idea is valid for only one of them.

| Seam | Caller | Threat model | Acceptable identity |
| --- | --- | --- | --- |
| **host → orlop-control** (API/SDK control plane) | the host platform | host is *trusted*; orlop is a trusted subsystem behind it | Plain id is OK **iff** the host authenticated with a real credential (mTLS / platform key) **and orlop strips any caller-supplied tenant** (default-deny). Better: a signed token. |
| **agent → orlop-server** (data plane) | the AI agent | **agent is hostile** (orlop's whole premise) | **Never** a plain id. Must be the mTLS SPIFFE cert: proof-of-possession, CA-rooted, scope-in-SAN, serial revocable. |

Prior art for "plain id safe only inside a trust boundary": Postgres RLS
(`current_setting('app.tenant')` is safe only because the connecting role lacks
`BYPASSRLS` and the app is the sole writer of the GUC); Stripe Connect (the
`Stripe-Account: acct_…` header is safe only because the platform's secret API
key is authenticated first — the id is explicitly *not* the boundary); Envoy
ext_authz (must *strip* any client-supplied identity header at the trust edge).
The AWS multi-tenant cardinal rule states it bluntly: **never accept `tenantId`
from request parameters; derive it only from a validated token's claims.**

Across a trust boundary you need one of:

- a **signed JWT** verified against an issuer's JWKS — MinIO
  `AssumeRoleWithWebIdentity`, FoundationDB authorization tokens, Kubernetes
  projected ServiceAccount tokens, AWS `AssumeRoleWithWebIdentity`, SPIFFE
  JWT-SVID;
- an **mTLS X.509 identity** verified against a CA (ideally with name
  constraints) — MinIO `AssumeRoleWithCertificate`, CockroachDB (tenant in URI
  SAN), etcd `--client-cert-auth`, **and orlop's own SPIFFE SAN**;
- a **capability token** that self-verifies against a published public key —
  Biscuit (Ed25519 chain), NATS (operator/account/user nkey chain), macaroons.

**Consequence:** plain-id injection is acceptable host→control, never
agent→data. The seams must not be collapsed.

## 3. Deployment modes

All four keep orlop's data-plane shape identical (SPIFFE mTLS cert minted by the
tenant CA). They differ only in **how the host asserts identity to
orlop-control to authorize a mint.**

### Mode A — Embedded / trusted-subsystem (plain id inside a credentialed channel)

- **Trust boundary:** host process and orlop-control share a
  mutually-authenticated channel (host mTLS, or private network + platform key).
- **Identity stripping (default-deny):** each platform token in `api_tokens`
  carries an explicit `tenant_scope`. The handler computes the effective tenant
  from the token's scope, **never from the request body**. A body naming a
  tenant outside scope → 403.
- **Shape:**
  ```http
  POST /v1/entities
  Authorization: Bearer <ORLOP_PLATFORM_KEY>
  { "owner_id": "host-user-42", "tenant": "u_host-user-42", "size_bytes": 10737418240 }
  ```
- **Pros:** simplest, no new crypto. **Cons:** the platform key is a bearer
  secret; mitigate with per-tenant scoped, expirable tokens (reuse `api_tokens`).
- **Prior art:** Trusted Subsystem pattern, Stripe Connect, Postgres RLS, Garage
  scoped admin tokens.

### Mode B — Trusted-issuer / BYO-IdP (verify a signed JWT) — RECOMMENDED DEFAULT

- **Trust boundary:** the host's IdP signing key, via OIDC discovery. Works over
  an untrusted network; no channel assumption.
- **Verify:** orlop-control as an OIDC relying party checks signature against
  JWKS, `iss`, `exp`, and pins `aud=orlop`. Maps a configured claim
  (`tenant`/`org_id`/`sub`) → orlop subject **through an operator allowlist**
  (never lazy auto-bootstrap).
- **Shape:**
  ```http
  POST /agent/enroll
  Authorization: Bearer <host-signed JWT, aud=orlop, claim tenant=u_acme>
  DPoP: <proof over POST + URL + jti, signed by agent ephemeral key>
  ```
  ```yaml
  identity:
    issuer:    https://idp.host.example/
    jwks_uri:  https://idp.host.example/.well-known/jwks.json   # or static_pubkey
    audience:  orlop
    tenant_claim: tenant
    tenant_allowlist: [u_acme, u_globex]   # FAIL-CLOSED: only these may be provisioned
    sender_constraint: dpop                # dpop | mtls | none
  ```
- **Pros:** strongest practical posture for an OSS component; host owns all human
  lifecycle; no shared secret; offline verification after JWKS cache. **Cons:**
  host must run an OIDC issuer (most platforms already do; K8s gives it free);
  operators maintain the tenant allowlist.
- **Prior art:** MinIO WebIdentity STS, FoundationDB tokens, K8s OIDC discovery +
  IRSA, SPIFFE JWT-SVID, aws-jwt-verify.

### Mode C — Admin-API / token-exchange (host owns users; orlop mints on request)

- **Trust boundary:** host admin credential + an RFC 8693 verified
  `subject_token`.
- **Verify:** orlop verifies *both* the admin credential and the subject_token
  signature, maps the subject claim through the allowlist, issues a
  sender-constrained, single-use enroll token. Records an `act`-claim audit row
  (actor distinct from subject).
- **Shape:**
  ```http
  POST /v1/token-exchange
  Authorization: Bearer <ORLOP_ADMIN_KEY>
  { "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "<host-signed JWT>", "subject_token_type": "urn:...:jwt",
    "requested": "agent_enroll", "tenant": "u_acme" }
  → { "enroll_token": "...", "expires_in": 300, "cnf": { "jkt": "<agent-key-thumbprint>" } }
  ```
  Reuses the existing `IssueAgentEnrollToken` / `PurposeAgentEnroll` /
  `RequireEnrollBearer` plumbing — but re-sources authorization from a verified
  host assertion, binds the token to the agent key, and consumes it on use.
- **Prior art:** AWS STS token vending, RFC 8693, `ceph auth get-or-create`.

### Mode D — Decentralized / capability (no user DB anywhere; advanced)

- **Trust boundary:** one root public key. The host signs a self-describing
  capability (tenant + path-prefix + `exp` as caveats); orlop-server verifies
  offline against the root public key and never holds minting power.
- **Cons:** a second token system on top of mTLS for little new property —
  orlop's SPIFFE cert already gives asymmetric mint/verify and
  proof-of-possession. File under "if you ever need sub-cert, per-request
  capabilities." Avoid symmetric-HMAC macaroons (every tenant server would need
  the shared root secret — the exact over-broad-credential anti-pattern orlop
  rejects for storage creds).
- **Prior art:** NATS (operator key), Biscuit (root keypair).

## 4. Recommendation

**Default to Mode B (verify a host-issued, audience-pinned signed JWT), expose a
pluggable verifier, and ship Mode A (per-tenant-scoped platform token with
default-deny identity stripping) as the batteries-included fallback** for
self-hosters who don't run an IdP.

Rationale:

1. Mode B is the unanimous infra-OSS pattern; it deletes the entire
   mailer/OTP/signup surface without touching the isolation core.
2. Mode A keeps tiny self-hosts viable (Garage's lesson: an infra component can
   ship with no human-identity system, just a scoped operator token).
3. Modes compose behind one seam. Steal Temporal's design: a pluggable
   `ClaimMapper` / `Authorizer` where `AuthInfo` carries both a JWT and mTLS
   material. One Go interface; the built-in default verifies a JWT (Mode B) or a
   scoped platform token (Mode A); a host can drop in its own.

The composition contract, fail-closed: **the injected identity MUST be a signed
token verified against a pinned issuer/JWKS (with `aud=orlop`), an mTLS client
cert validated against a CA, or genuine workload attestation — and that
verification IS the trust boundary.** A `ClaimMapper` that trusts a header is
acceptable only behind a host edge that authenticates and strips
client-supplied identity (the wired default-deny of Mode A).

### Getting identity into the agent pod

The injection mechanism is a solved problem; mirror it rather than ship a static
secret: Kubernetes TokenRequest API / projected ServiceAccount tokens (bound,
audience-scoped, time-limited, auto-rotated); AWS IRSA / EKS Pod Identity
webhook; SPIFFE/SPIRE Workload API (attested SVID over a local socket, auto
rotation). orlop already emits SPIFFE SANs, so consuming an `aud`-scoped
JWT-SVID is the natural fit.

## 5. Map to the existing code

### DELETE — the human-lifecycle surface (none of it touches isolation)

| What | Where |
| --- | --- |
| Email-OTP start/verify + auto-provision | `internal/devauth/devauth.go` `StartEmailOTP`, `VerifyEmailOTP`, `createHostedUser`; handlers `handleOTPStart`/`handleOTPVerify` in `devauth_handlers.go` |
| Mailer / Resend | `mailer.go` (`resendMailer`, `resend-go` dep), `logMailer`, `mailer_otp_log_test.go` |
| OTP storage | migration `0009_email_otp_attempts.sql` (+ the `email_otps` table from `0001`), `queries/email_otps.sql`, `sqlcdb/email_otps.sql.go`, `email_otp_lockout_test.go`, OTP rate limiters |
| Seeded admin-session URL | the `?session=TOK` cookie path in `devauth_handlers.go`, the `user seed` URL printing in `user_cmd.go` |

### ADD — the pluggable identity seam (Temporal/Envoy shaped)

1. A `Verifier` interface in orlop-control (`internal/identity`). `AuthInfo`
   carries a JWT *and* mTLS subject so both paths share one mapping seam.
   **Implemented.**
2. A built-in JWT verifier (Mode B default): config `{issuer, public key,
   audience, tenant_claim, tenant_allowlist}`; offline verify. Maps a verified +
   allowlisted claim → tenant subject, replacing `createHostedUser`.
   **Implemented** (`internal/identity/jwt.go`, RS256/ES256/EdDSA against a
   static PKIX public key; wired via `ORLOP_IDENTITY_*` and exercised by
   `GET /v1/whoami`). *Follow-ups:* `jwks_uri` with rotation; sender-constraint
   (DPoP/mTLS) on the enroll seam; re-sourcing `/agent/enroll` authorization
   from the verifier with allowlisted tenant bootstrap (issue #8).
3. A built-in platform-token verifier (Mode A fallback): per-tenant scoped,
   expirable token via `api_tokens`, with default-deny stripping of
   caller-supplied tenant. *Not yet implemented.*

### KEEP — the isolation core

`tenants`, `disk_allocations`, `agent_enrollments`; `ca.MintAgentCert` and the
tenant CA; the SPIFFE SAN as data-plane identity (`cmd/orlop-server/identity.go`);
the `POST /agent/enroll` token-for-cert shape (the credential-broker pattern).

## 6. Data-plane hardening (verified against the code, tracked separately)

These are independent of the identity refactor but load-bearing for the
zero-trust claim. Severity is calibrated to the current code, not worst case.

1. **No revocation on the data plane.** `orlop-server` records the leaf serial in
   audit logs but never checks `agent_enrollments.cert_serial` against a
   deny-list at handshake (the data plane is stateless and cannot read the
   table). A leaked 1h leaf is valid for the full hour. *Fix:* a serial deny-list
   pushed from the control plane, checked at connect; lease release adds the
   serial. **(Real gap.)**
2. **Enroll token is not single-use / replayable.** `authenticateRaw`
   (`internal/devauth/devauth.go:695`) validates the token but never consumes the
   row, so it is reusable until its 10-minute expiry. *Fix:* sender-constrain
   (DPoP RFC 9449 / mTLS RFC 8705) + consume-on-use. **(Real hardening gap.)**
3. **`checkTenantBinding` fails open + intermediates have no NameConstraints.**
   `cert_tenant_binding.go:30,35` returns `true` on an unrecognized chain shape;
   `generateIntermediate` (`internal/ca/ca.go`) emits no `PermittedURIDomains`.
   *Fix:* add NameConstraints so RFC 5280 path validation rejects cross-tenant
   SANs in `crypto/x509` itself, and make the binding check fail closed. **(Real,
   but defense-in-depth: not exploitable today since agents never hold an
   intermediate key; primary isolation is `checkAgentPath`.)**
4. **Lazy tenant bootstrap.** `agent_enroll_handlers.go:177` bootstraps a tenant
   intermediate the first time a tenant id is seen. *Fix:* gate on the operator
   allowlist so a verified-but-attacker-influenced claim cannot self-onboard.
   **(Mainly a prerequisite for the Mode B/C designs above.)**

## 7. Comparison table

| Project | Isolation unit | Identity asserted as | Who issues | Embeddable pattern |
| --- | --- | --- | --- | --- |
| MinIO (WebIdentity) | bucket/prefix + IAM policy | signed OIDC JWT vs JWKS | external IdP | RP verifies token, maps claim → policy, mints STS creds |
| MinIO (Certificate) | policy = cert CN | mTLS X.509 vs trusted CA | your PKI | cert CN → pre-existing policy; creds ≤ cert lifetime |
| Garage | bucket (per-key grant) | S3 secret / scoped admin token | operator/host | host mints scoped key per tenant; no users, no OIDC |
| Ceph/RADOS | pool + namespace cap | cephx shared secret (not sent on wire) | cluster monitors | `ceph auth get-or-create` mints capped keyring |
| FoundationDB | tenant key-prefix | signed JWT (`tenants` claim) vs JWKS | external issuer | data plane verifies pubkey; no user DB |
| CockroachDB | TenantID prefix | mTLS, tenant in URI SAN | control plane | KV re-checks tenant per RPC, fail-closed |
| K8s SA / IRSA | namespace+SA (`sub`) | projected JWT, `aud`-bound, rotated | cluster OIDC issuer | RP verifies via OIDC discovery; injected projected volume |
| SPIFFE/SPIRE | trust-domain path | X.509-SVID / JWT-SVID | SPIRE server (attestation) | Workload API hands attested SVID to workload |
| Postgres RLS | row predicate | plain GUC string | trusted middle tier | safe only: non-BYPASSRLS role + `SET LOCAL` |
| Stripe Connect | connected account | plain `acct_` id + secret key | platform (secret key auth) | id is not the boundary; the secret key is |
| Temporal | namespace | signed JWT *or* mTLS (pluggable) | host IdP via `ClaimMapper` | ships interfaces, not signup |
| NATS | account | signed JWT + nkey nonce proof | operator key | server trusts one root key, no user DB |
| Biscuit | Datalog caveats | Ed25519 capability | root keypair holder | offline verify vs root pubkey; attenuate-not-escalate |
| Ory | app-enforced | signed OAuth2/OIDC token | delegated login app | *don't build identity — delegate it* |
| **orlop (target)** | tenant + agent path prefix | mTLS SPIFFE SAN; host-injected verified JWT/cert | host-injected; tenant CA | host injects verified, allowlisted, audience-pinned identity; orlop mints constrained cert |

## 8. Sources

- MinIO STS (TLS / WebIdentity): https://github.com/minio/minio/blob/master/docs/sts/tls.md , https://github.com/minio/minio/blob/master/docs/sts/web-identity.md
- FoundationDB authorization: https://apple.github.io/foundationdb/authorization.html
- CockroachDB tenant-in-SAN auth: https://github.com/cockroachdb/cockroach/blob/master/pkg/security/auth.go
- RFC 5280 §4.2.1.10 Name Constraints: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10
- SPIFFE X.509-SVID / JWT-SVID: https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md , https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md
- SPIRE Workload API: https://spiffe.io/docs/latest/spire-about/spire-concepts/
- Kubernetes TokenRequest: https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/
- AWS IRSA: https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
- OAuth2 DPoP (RFC 9449): https://www.rfc-editor.org/rfc/rfc9449.html
- OAuth2 mTLS-bound tokens (RFC 8705): https://www.rfc-editor.org/rfc/rfc8705.html
- AWS AssumeRoleWithWebIdentity: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
- Temporal Authorizer/ClaimMapper: https://pkg.go.dev/go.temporal.io/server/common/authorization
- RFC 8693 Token Exchange: https://www.rfc-editor.org/rfc/rfc8693.html
- Postgres RLS: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- Stripe Connect auth: https://docs.stripe.com/connect/authentication
- Garage admin/key model: https://garagehq.deuxfleurs.fr/documentation/reference-manual/admin-api/
