# Gateway improvement plan

Reviewed against gateway v0.57.0; authentication decision updated on 2026-09-07. These are
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
| Durable CRL high-water marks | Implemented; enabled in published deployment | Gateway-owned SQLite checkpoints, verified restore before serving, explicit first-time initialization and exclusive replica ownership |
| Multiple CRL issuers | Implemented | Independently pinned and refreshed issuer snapshots; issuer-specific verification and parent network role requirements |
| Required network roles | Enabled in published deployment | All four configured networks require `role:client`; this does not change federation membership or treaty semantics |
| Durable audit | Implemented; local sink enabled | SQLite intent/completion records, decision context, backlog/storage metrics; optional explicitly acknowledged HTTPS export |
| Shared quotas | Implemented; enabled in published deployment | Atomic Redis admission across replicas, persistent local Redis, backend failures deny admission rather than granting a local allowance |
| Deployment authentication | Scoped bearers deliberately retained; OIDC/mTLS adapters available | [Authentication decision](adr/0001-deployment-authentication.md) records scope, lifecycle requirements and triggers for organization identity activation |
| Secrets integration | Mounted-file support implemented; provider deployment pending | Read-only credentials and TLS files; CSI fragment requires an organization's provider, workload identity and access policy |
| Signed distribution | Published and verified | v0.57.0 Windows/Linux ZIPs and AMD64/ARM64 OCI archive have verified Sigstore bundles and checksums; OCI includes SPDX SBOM and SLSA provenance |

Implementation and activation details are in [platform controls](platform.md).
The [v0.57.0 release](https://github.com/GenesisMeshLabs/gateway/releases/tag/v0.57.0)
contains nine files: three archives and their checksums/signature bundles. These
are signatures over archive bytes; publication into an organization's registry
and its image-admission policy remain separate tasks.

## Why these priorities

- [CISA secure-by-design guidance](https://www.cisa.gov/securebydesign) informs
  removing insecure default behavior and making authentication mandatory.
- [NIST SP 800-207](https://www.nist.gov/publications/zero-trust-architecture-0)
  informs explicit policy-based trust and least-privilege access. This gateway
  is one component of that architecture, not a complete zero-trust system.
- [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.0) provides a standard,
  machine-readable API contract alongside the human-facing explorer.

## Next rollout gates

| Priority | Remaining work | Acceptance evidence |
| --- | --- | --- |
| P0 | Complete credential lifecycle acceptance | Scoped bearers selected for this deployment in ADR 0001; assign credential owners/rotation schedules and verify replacement/old-token rejection on every replica. Organization OIDC/PKI activation applies when the ADR's migration conditions arise |
| P0 | Complete operational recovery acceptance | Revoke a dedicated canary, observe denial, restart the relevant gateway/consumers, confirm retained floors and continued denial; distinguish gateway JoinCRLs from authority membership feeds |
| P0 | Protect and recover persistent storage | Consistent backups, tested restore, protected external sequence records and issuer-key rotation procedure; never reinitialize lost state to regain readiness |
| P0 | Define audit retention and integrity requirements | Size/alert on the local sink; if required, activate an independently controlled collector, verify durable acknowledgements, retries and retention; local SQLite is not WORM storage |
| P1 | Activate an organization secrets provider | Real provider configuration, least-privilege workload identity, mounted secrets and controlled rotation; a CSI fragment alone is not a vault deployment |
| P1 | Sign off deployment-specific availability and capacity | Load/soak tests, mixed verification and authority traffic, replica/backend failure drills, Redis HA loss semantics and measured recovery objectives; local Redis remains a single availability dependency |
| P1 | Adopt release artifacts in the organization | Verify archive signatures and SBOMs, scan/import images, enforce approved digests and registry/admission policy |
| External | Independent review and accreditation | Penetration/conformance findings and remediation, privacy review and the organization's accreditation decision |
| Phase 2 | External operator adoption | Independent implementations, governance, protocol/runbook stability and real application memberships; public demo records do not prove adoption |

## Recovery evidence boundaries

Automated gateway tests cover restoring a persisted revoked certificate against
an older bootstrap policy, rejecting forged or regressing CRLs, corrupt state,
concurrent ownership and audit recovery. Run the focused existing tests with:

```text
cargo test --locked --test production durable_
```

These tests reopen the store in the test process. They are not a live
kill/restart, disk-loss, or power-failure drill. The deployment restart retained
its CRL floors and audit records, and a separate two-replica local read workload
passed 100 requests at concurrency four with p99 42.74 ms. Neither establishes
a production SLO or proves survival of backend failover.

The isolated replica stop/start drill was blocked by automatic approval review
and remains unverified. The complete membership revoke/propagate/restart
checklist is in [federation operations](federation.md); its consumer restart
acceptance must not be inferred from matching feed sequence numbers.

Avoid adding speculative post-quantum algorithms to the wire format: the
Genesis Mesh protocol authority must define algorithm negotiation and migration
before this gateway changes signature semantics.
