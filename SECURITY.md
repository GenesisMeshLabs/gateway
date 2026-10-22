# Security Policy

The Genesis Mesh gateway verifies join certificates against operator policy,
synchronizes signed revocation lists from Network Authorities and forwards a
fixed catalog of authority operations. This page says how to report a
vulnerability in the gateway, what the gateway defends against and what it
leaves to other components.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security report.** Use the private
disclosure channel instead.

- Open a draft advisory at
  [github.com/GenesisMeshLabs/gateway/security/advisories/new](https://github.com/GenesisMeshLabs/gateway/security/advisories/new).
  A finding in the Network Authority, the protocol or an SDK goes to
  [the core's advisories](https://github.com/GenesisMeshLabs/genesismesh/security/advisories/new);
  when you are not sure which component is at fault, report it to either.
- Include: a description, reproduction steps, the version
  (`genesis-mesh-gateway --version`, or the container image tag and digest),
  the relevant part of the policy with tokens and keys removed, and any logs
  or proof-of-concept code.
- You should receive acknowledgement within **5 business days**.
- Expect a remediation plan within **30 days** for confirmed issues, longer for
  cryptographic findings that require a redesign.

Coordinated disclosure is preferred. If you publish before a fix exists,
please give the project a reasonable window first.

## Supported Versions

The gateway ships with each Genesis Mesh release and has the same version.
Only the latest minor release receives security fixes.

| Version | Status |
|---|---|
| `1.7.x` | Supported |
| `< 1.7` | Unsupported: upgrade to 1.7 |

## In Scope

- **Operator policy.** Pinned authority keys, required roles, CRL sequence
  floors, client scopes (networks, service groups, `authority_admin`,
  `metrics`) and the startup checks on demo clients. A request that gains a
  scope its client does not have is in scope.
- **Certificate verification.** `POST /verify` and `POST /verify/batch`: a
  forged, revoked, expired or wrongly scoped certificate reported as
  `trusted`, or a caller overriding the pinned anchors or CRL.
- **Revocation synchronization.** CRL refresh, rollback and same-sequence
  checks, and fail-closed readiness when a snapshot expires.
- **Durable state.** The SQLite CRL checkpoints and audit store
  (`GATEWAY_STATE_FILE`): restoring an older sequence, losing audit rows
  without a fail-closed error, or filling the store without a credential.
- **Forwarding.** The authority service route: reaching an operation outside
  the catalog, a path or query the catalog does not allow, another origin
  than the pinned `authority_url`, or relaying a response beyond its limit.
- **Authentication adapters.** Bearer tokens, OIDC subject bindings, native
  mutual TLS and shared Redis quotas.
- **The console's browser signing.** Operator signatures made in the
  browser: a seed leaving the page or persisting in browser storage, or a
  signature valid for another request, route or authority.
- **The released artifacts.** The container image and the native ZIPs, and
  their Sigstore signatures.

## Out of Scope

- **The Network Authority and the protocol.** Issuance, operator-signature
  checks, operator tiers, key succession and the evidence store are the
  authority's. Report them to the core.
- **Authority key succession.** The gateway pins authority keys and does not
  read the key history. After a succession takes effect the gateway cannot
  accept that authority's CRLs or the certificates its new key signs; the
  network goes not ready. This is a known limitation, documented in
  [key succession](docs/key-succession.md), not a vulnerability.
- **Proof of possession.** A trusted certificate is a public document. It
  does not prove that the caller holds the node's private key. Bind it to a
  session or challenge in the relying service.
- **A gateway you do not operate.** The console trusts the gateway that
  serves it for the authority key and the forwarded path. Sign with an SDK,
  from metadata you verified yourself, when the gateway is not yours.
- **Ingress and network attacks.** The gateway expects an organization's TLS
  ingress in front of it, with connection limits and abuse controls. Floods
  that bypass the per-client quotas are the ingress's to stop.
- **Insider abuse.** An operator with write access to the policy file, the
  state volume or the secrets manager can change what the gateway trusts.
  Protect them with access control and protected backups.
- **The deployment's own settings.** A policy that pins the wrong key,
  grants a broad scope or enables development mode does what it says.
  `GATEWAY_DEVELOPMENT=true` is for local use only.
- **The public demo.** The demo token at `GET /v1/demo` is public by design;
  the startup checks limit what it can do.

## Hardening Resources

- [Operations](docs/operations.md): the deployment boundary, credentials and
  policy.
- [Platform controls](docs/platform.md): durable state, audit, OIDC, mutual
  TLS and shared quotas.
- [Distribution](docs/distribution.md): verifying the signed image and ZIPs.
- [The core's security policy](https://github.com/GenesisMeshLabs/genesismesh/blob/main/SECURITY.md).
