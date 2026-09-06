# Gateway improvement plan

Implemented against the existing Rust gateway, September 2026. These are
engineering controls, not claims of certification or universal production readiness.

| Improvement | Delivery | Evidence |
| --- | --- | --- |
| Secure defaults | Implemented | Mandatory production policy and client authentication; remote key generation/signing absent in production |
| Scoped service identities | Implemented | Individual hashed credentials, exact network scopes, separate metrics permission |
| Operator-owned trust | Implemented | Pinned authority keys, required roles and signed revocation snapshots |
| Native Genesis Mesh integration | Implemented | Rust fetches `/crl` from configured authorities every 60 seconds; verifies signatures, issuer, freshness and sequence before atomic replacement |
| Fail-closed revocation | Implemented | Stale data denies trust and fails readiness; failed fetch retains only the previous verified snapshot |
| Bounded execution | Implemented | Body/batch limits, client quotas, deadlines and cancellation-safe crypto permits |
| Operational visibility | Implemented | JSON audit events, request IDs, scoped Prometheus metrics, liveness and readiness |
| API discoverability | Implemented | OpenAPI 3.1 description and an embedded responsive explorer with live responses |
| Privacy in the console | Implemented | No browser credential persistence, same-origin requests, restrictive CSP, network data behind authorization |
| Safer containers | Implemented | Non-root, read-only filesystem, dropped capabilities, process/memory/CPU limits and bounded log files |
| Reproducible validation | Implemented | Locked dependencies, Python interoperability fixtures, security regression tests and Windows/Linux CI |
| Public deployment | Implemented and verified | Existing Cloudflare tunnel to `mesh.genesismesh.org`; retain previous image for rollback |

## Why these priorities

- [CISA secure-by-design guidance](https://www.cisa.gov/securebydesign) informs
  removing insecure default behavior and making authentication mandatory.
- [NIST SP 800-207](https://www.nist.gov/publications/zero-trust-architecture-0)
  informs explicit policy-based trust and least-privilege access. This gateway
  is one component of that architecture, not a complete zero-trust system.
- [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.0) provides a standard,
  machine-readable API contract alongside the human-facing explorer.

## Next rollout gates

1. Persist CRL high-water marks across restarts, with controlled bootstrap
   recovery and signed policy distribution. Current refresh prevents rollback
   within a process; the configured sequence floor is the restart baseline.
2. Integrate organization identity (OIDC or mTLS), tenant lifecycle and external
   secrets management. Current authentication uses scoped service tokens.
3. Connect a durable, integrity-protected audit sink with explicit delivery
   guarantees and retention policy.
4. Establish SLOs using deployment-specific load/soak tests, distributed quotas,
   multi-instance rollout and failover drills.
5. Add SBOM/provenance and signed image publication to the organization's
   release pipeline; run independent penetration and conformance reviews.
6. Extend issuer/CRL aggregation for multi-authority federation only after
   defining its revocation semantics and interoperability fixtures.

Avoid adding speculative post-quantum algorithms to the wire format: the
Genesis Mesh protocol authority must define algorithm negotiation and migration
before this gateway changes signature semantics.
