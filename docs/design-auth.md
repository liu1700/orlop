# Hosted Auth: mTLS over public HTTPS

Status: design (2026-04-29). Supersedes an earlier Tailscale-based architecture.

## Problem

orlop has one shape: a Rust agent CLI on a user's box dials a per-tenant
Go server VM in a cloud region. The connection must be:

1. Encrypted in transit.
2. Mutually authenticated — the server must learn which tenant the agent
   belongs to, and the agent must verify it's talking to the right server.
3. Tenant-isolated — tenant A's credential must never grant access to
   tenant B's server.

The agent dials out from arbitrary networks (often behind NAT). The server
runs on a cloud VM with a public IP.

## Why not a mesh VPN (Tailscale, Headscale, NetBird)

A mesh VPN solves NAT traversal, peer discovery, and identity enforcement at
the network layer. We have none of those problems:

- **NAT traversal**: not needed — only the agent dials out, and only the
  server needs to be reachable. A public HTTPS endpoint suffices.
- **Peer discovery**: not needed — there is one server FQDN per tenant,
  resolved by public DNS.
- **Network-layer identity**: replaceable — TLS already pins identity to a
  certificate. Layer-7 tenant routing on the server is a five-line check.

The cost of a mesh VPN for our use case:

- An external SaaS dependency (Tailscale) or a self-hosted coordinator
  (Headscale) — neither is free of operational burden.
- A separate identity system (tags) that has to stay in sync with the
  control-plane database (`tenant_id`).
- An ACL DSL (`hujson`) and a push runbook for changes.
- An extra hop for every request through `tailscaled` and DERP relays under
  failure modes.

We get nothing in return that public HTTPS + mTLS doesn't already give us.

## Architecture

```
agent box                    control plane (staging VM)    server VM (per tenant)
─────────                    ──────────────────────        ──────────────────────
orlop login    ── device flow ──►   /auth/device/{code,token}
                                  /device approval page
                                  └── opaque token ────┐
                                                       │
orlop mount    ── POST /agent/enroll (Bearer token) ─►   │
                                  ├── verify token     │
                                  ├── resolve tenant_id
                                  ├── lookup tenant.fqdn
                                  ├── mint x509 cert(SAN: tenant=<id>, exp=1h)
                                  │   signed by tenant's intermediate CA
                                  └── return { cert, key, ca_chain, server_fqdn }
             ◄──────────────────────────────────────────
             write to ~/.config/orlop/{cert.pem, key.pem, ca.pem} (0600)

orlop FUSE → HTTPS request ─────────────────────────────►  orlop-server (Go, stdlib)
             TLS client cert (+ intermediate)             tls.Config.ClientAuth = RequireAndVerifyClientCert
             server_fqdn in TLS SNI                       ClientCAs = org root (client sends its intermediate)
                                                          On accept: drop if leaf serial revoked;
                                                                     tenant SAN must match the signing
                                                                     intermediate's tenant OU; else drop
```

Key properties:

- The server VM's public HTTPS endpoint is the only ingress. No tailnet, no
  bastion, no Tailscale agent on the server.
- Server presents a normal Let's Encrypt cert for the tenant FQDN
  (`tenant-acme.orlop.example.com`). Agent verifies it via the public PKI.
- Agent presents a client cert minted by the control plane's CA, together with
  the tenant intermediate it received at enroll. The server verifies the chain
  against the shared org root (its `ClientCAs`), then confirms — fail-closed —
  that the intermediate which signed the leaf is scoped to the same tenant as
  the leaf's SAN, so a leaked tenant-intermediate key can't forge a cross-tenant
  cert (`cmd/orlop-server/cert_tenant_binding.go`).
- Tenant identity is encoded in the client cert's URI SAN as
  `spiffe://<trust-domain>/tenant/<id>` (resolved 2026-04-29; see "open
  questions").

## Threat model

| Threat | Mitigation |
|--------|-----------|
| Agent cert leaked | 1h TTL bounds blast radius. Releasing the mount lease revokes the leaf's serial onto a data-plane deny-list (issue #5), killing a leaked copy mid-TTL within the reconcile window; rotating the tenant CA stays a backstop. |
| Tenant A agent dials tenant B server | TLS handshake completes (cert is valid against the org root) but the data-plane tenant-binding check fails closed and the connection is dropped. |
| Forged/stolen bearer token at `/agent/enroll` | Opaque tokens have ≥128 bits of entropy; only hashes are stored; unknown, expired, revoked, consumed, suspended-user, and suspended-tenant tokens are rejected. Per-pod agent-enroll tokens are single-use — spent once a cert is minted — so a captured token cannot be replayed (issue #6). |
| Replay of old cert | Cert TTL 1h; server clock-skew tolerance ±5min. |
| Server impersonation | Agent verifies server cert against public PKI + pinned tenant FQDN. |
| MITM on the wire | TLS 1.3, modern cipher suites only. |
| Compromised control plane | Worst case: attacker mints arbitrary tenant certs. Same blast radius as a compromised Tailscale OAuth client would have been. Mitigations: HSM-backed CA key (post-MVP), audit log of every signing event, rate limits per `access_token`. |

## Cert lifecycle

- **Org root CA**: long-lived (10y), private key offline. Signs tenant
  intermediates only. One per environment (dev, prod).
- **Tenant intermediate CA**: per-tenant, rotated yearly. Signs agent certs
  for that tenant. Lives in the control plane's secret store.
- **Agent client cert**: 1h TTL, minted on every `/agent/enroll`. Not
  persisted in the control plane DB beyond an audit row (serial + issued_at +
  user_id).
- **Server cert**: standard Let's Encrypt for the tenant FQDN, renewed by
  certbot or equivalent on the VM. Independent of the agent CA chain.

Revocation has two levels. Expiry is the floor (1h TTL — no CRL, no OCSP). On
top of it sits a per-serial **deny-list kill switch** (issue #5): releasing a
mount lease records the bound leaf's serial in `cert_revocations`, a
control-plane reconcile loop pushes the active set to each server
(`PUT /control/cert-revocations`), and the server refuses a matching leaf at
session start — so a single leaked cert dies mid-TTL without a CA rotation.
Rotating the tenant intermediate (invalidating every outstanding cert for that
tenant) remains the blunt, tenant-wide instrument.

## What this collapses vs. the Tailscale design

| Concern | Tailscale design | mTLS design |
|---------|-----------------|------------|
| Network-layer policy | hujson ACL + `acl-test` CI + manual push runbook | gone — server-side tenant check is 5 lines of Go |
| Identity injection | tsnet WhoIs | `tls.ConnectionState().PeerCertificates[0]` |
| Authkey minting | Tailscale OAuth client + rotation runbook | local CA + Go signing — no SaaS |
| Agent join | `tailscale up --authkey` shell-out | write 3 PEM files |
| Server runtime | tsnet (links libtailscale) | net/http stdlib |
| Cross-tenant denial | ACL test fixtures | unit test on the tenant-check middleware |
| External dependencies | Tailscale (SaaS), `tailscaled` on every box | none for MVP auth beyond the deploy platform |

## Open questions

1. ~~**Cert identity encoding.** SPIFFE URI vs custom X.509 extension.~~
   **Resolved 2026-04-29 in #39:** SPIFFE URI SAN
   (`spiffe://<trust-domain>/tenant/<id>`). Rationale: a custom OID
   would need an IANA-issued Private Enterprise Number we don't own,
   and the SPIFFE URI scheme itself is trivial — SPIRE adoption is not
   a prerequisite. The URI is encoded via Go's stdlib
   `x509.Certificate.URIs`; both control-plane minting and server-side
   verification work today with no extra dependencies.
2. **CA key storage.** MVP: encrypted at rest in the secret store, decrypted
   into memory on control-plane boot. Post-MVP: HSM (AWS KMS, GCP Cloud KMS,
   or Cloud HSM) so the key never appears in process memory.
3. **Per-entity ACL** (was filed as out-of-scope under Tailscale grants v2).
   With mTLS, this is just an extra claim in the cert, checked server-side.
   Strictly easier than the Tailscale equivalent.
4. **Server cert provisioning automation.** Out of MVP scope. MVP is manual
   certbot per server VM at provision time.

## Migration status

The earlier tailnet sketch has been replaced by the mTLS design in the current
hosted MVP:

1. `cmd/orlop-server` uses the stdlib TLS listener with
   `tls.RequireAndVerifyClientCert`.
2. Tenant isolation is enforced by the SPIFFE tenant identity in the client
   cert plus the data-plane fail-closed tenant-binding check; the server trusts
   the shared org root as its client CA, and the agent supplies its tenant
   intermediate in the chain it presents.
3. `cmd/orlop-control` owns tenant CA operations, first-party device flow,
   refresh-token backed sessions, and `/agent/enroll`.
4. `orlop login` and hosted `orlop mount` use the control-plane and mTLS flow
   documented in `docs/control-plane.md` and `docs/control-plane-runbook.md`.
