# 0001: Retain scoped bearer authentication for the current deployment

Date: 2026-09-07

Status: Accepted for the current self-hosted deployment. This is not a default
approval for other organizations or a workforce identity design.

## Decision

Keep the existing scoped bearer authentication enabled. Leave OIDC disabled
until an organization supplies an approved issuer, audience, JWKS endpoint and
subject-to-client mappings. An available adapter does not establish an identity
provider's ownership or authorize its subjects.

The present deployment has two distinct identities: a privileged gateway
operator and a restricted revocation relay. The relay has no authority-admin
or metrics permission and only its configured network/service scopes. Authority
mutations additionally require an independently registered operator signature.
Public mesh reads do not require a credential.

This choice preserves working unattended service access without inventing an
organizational identity boundary. Human use of the operator credential remains
limited to the trusted operator console. It identifies the service credential,
not an individual person; do not distribute it as a shared workforce login.

## Operating requirements

- Issue a separate high-entropy credential for each workload and environment.
  Store only its SHA-256 digest in gateway policy and the token in protected
  caller storage. Do not reuse the operator credential for a new integration.
- Grant only required networks, service groups and metrics access. Review
  authority-admin permission separately; it does not replace operator signing.
- Send credentials only to the approved HTTPS public origin or its controlled
  local transport. The existing Cloudflare origin connection is private HTTP;
  this decision does not claim end-to-end mTLS.
- Assign credential ownership and a rotation schedule in the deployment's
  operational inventory. Bearer tokens currently have no automatic expiry.
  The 2026-09-07 rotation and role-based schedule are recorded in ../acceptance-2026-09-07.md; named organizational handover remains.
- Rotate through a short overlap: add a replacement client ID with minimal
  equivalent scope, deploy to every replica, switch the caller, then remove the
  old ID and deploy again. Distinct IDs have separate Redis allowances during
  overlap; bound the overlap and account for that temporary capacity.
- After removal, confirm the old credential receives 401 at every replica and
  the replacement retains intended access and scope denials. Policy is loaded
  at startup; changing the file alone does not revoke a running credential.
- For compromise, remove the affected identity and apply it to every replica
  promptly, preserve audit evidence and review its actions. Authority-key
  compromise requires separate authority revocation and recovery procedures.

## Revisit this decision when

Activate organization identity before introducing multi-user operator access
that requires individual attribution, workforce offboarding, MFA or centrally
managed session policy. Those controls belong to the approved identity provider
and its application integration; accepting JWTs alone does not establish them.

For workload OIDC, approve exact issuer/audience and subject bindings to the
existing least-privilege clients. Test valid tokens, invalid signatures, expiry,
wrong issuer/audience, unknown subjects, key rotation and provider unavailability.
Decide explicitly which bearer clients remain during migration; enabling OIDC
does not automatically disable their tokens.

Native mTLS is a separate transport control. Activate it where approved PKI,
client-certificate lifecycle and compatible ingress/probes exist. It still
requires bearer/OIDC application authorization. See [platform controls](../platform.md).

## Evidence and remaining gates

On 2026-09-07, the published gateway reported OIDC disabled and shared quotas,
durable audit and durable CRL state enabled. An unauthenticated protected-network
request returned 401; the relay credential was denied metrics access with 403.
These read-only checks verify the existing access boundary, not token rotation
or organizational offboarding.

The authentication choice is now explicit. Credential lifecycle acceptance,
P0 canary/revocation/restart recovery, external secrets-provider activation and
independent security assessment remain separate gates in the
[improvement plan](../improvement-plan.md).

## 2026-09-07 acceptance update

The replacement-identity rotation, retired-token 401 checks on every existing replica, canary revocation/restart and offline backup restore have now passed. See [acceptance evidence](../acceptance-2026-09-07.md), which supersedes the earlier unexecuted lifecycle/recovery status above. Organization offboarding and external identity activation remain outside this evidence.
