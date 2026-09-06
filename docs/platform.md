# Gateway platform controls

Version 0.57.0 adds gateway-owned durable CRL checkpoints and audit, pinned OIDC,
native mutual TLS, coordinated Redis quotas, and multiple CRL issuers per network.
These are configurable controls, not an accreditation or a claim that every
deployment enables them. `/api.security_capabilities` reports enabled adapters.

## Durable state and recovery

Mount one persistent directory per replica, owned by UID 10001 in the container.
Set `GATEWAY_STATE_FILE=/var/lib/gateway/state.db`. Before its first startup run
the **same image, policy and mounts** with `--init-state`. This verifies bootstrap
CRLs and refuses to overwrite a file. Ordinary startup never creates missing
state. Do not put automatic initialization in a restart or init-container loop.
`--check-config` needs exclusive access to that database; validate a stopped
replica or a consistent backup, not the live database.

SQLite WAL with FULL synchronous commits persists each issuer snapshot before
publishing it to requests. Startup authenticates saved snapshots using current
approved keys and restores the higher sequence before opening a listener.
Lower sequences, earlier issuance, conflicting equal-sequence revocations,
corruption and concurrent writers fail closed. An authentic but expired saved
CRL cannot grant trust. Refresh can recover it from its pinned source.

Use storage with reliable fsync and local filesystem locking. Do not share a
SQLite file between replicas or use an NFS/SMB mount. Replicas still refresh
independently; this is not linearizable revocation. New replicas must bootstrap
from independently verified current floors. Restore consistent SQLite backups
(including WAL through SQLite's backup API), never just copy an active main DB.
An administrator rolling back the entire disk can roll back history; prevent
that through protected backups, independent sequence records and access control.
Issuer-key rotation needs an explicit reviewed checkpoint migration.

## Audit

Durable state stores request intent before execution and completion before the
response, including policy/client identifiers and verification decisions.
Health/readiness probes bypass audit. Raw credentials, request bodies, node
keys, URL queries and certificate contents are excluded. Operator-selected
client IDs must not contain personal data. An intent without completion means
an uncertain outcome; inspect authority state before retrying a mutation.
Storage write failure latches not-ready and denies protected requests.

The database is capped at 262144 SQLite pages (1 GiB with its default 4 KiB
pages); reserve additional capacity for WAL, backups and filesystem overhead.
Audit is retained locally, including acknowledged rows. `/metrics` exposes `gateway_audit_pending` and `gateway_state_bytes`. Monitor volume use and
archive through a controlled SQLite backup before capacity exhaustion. This
release does not automatically delete audit history. The limit causes fail-closed
write errors, not silent event loss. Size storage and retention for real traffic.

Optional `GATEWAY_AUDIT_URL` is a pinned HTTPS collector; optional
`GATEWAY_AUDIT_TOKEN_FILE` contains its bearer secret. Every five seconds the
gateway posts up to 100 `{"events":[{"id":"...","event":{...}}]}` records.
The collector must durably commit and deduplicate stable IDs before returning
`{"acknowledged_ids":["..."]}`. HTTP 200 alone is insufficient. Only IDs in
that batch are acknowledged; failures and partial acknowledgements retry.
Delivery is at least once. A disconnected collector accumulates local events;
the local durable sink remains authoritative. Use an independently controlled,
immutable collector for tamper resistance; SQLite is not WORM storage.

## Organization identity and mounted secrets

`GATEWAY_OIDC_FILE` contains the schema below. JWT subjects map to existing
policy clients, retaining their network, service-group, operator and metrics
scopes and quota. The gateway never grants scopes directly from arbitrary claims.

```json
{"issuer":"https://identity.example.org/tenant","audience":"mesh-gateway",
 "jwks_url":"https://identity.example.org/tenant/keys",
 "bindings":[{"subject":"workload-subject","client_id":"agency-service",
              "required_claims":{"department":"operations"}}]}
```

RS256, ES256 and EdDSA signatures require a unique pinned JWKS key ID, matching
key usage/algorithm, issuer, audience, expiration and subject. Not-before is
checked with 30 seconds skew. JWKS responses are capped at 1 MiB/64 keys and
cached for five minutes; publish replacement keys before issuing tokens with
them. Expired key-cache refresh failure denies OIDC authentication. Static bearer
clients continue to work. Removing a binding/client requires a restart.

For native mutual TLS set all three of `GATEWAY_TLS_CERT_FILE`,
`GATEWAY_TLS_KEY_FILE`, `GATEWAY_TLS_CLIENT_CA_FILE`. The listener at
`GATEWAY_ADDR` then requires a certificate chaining to the approved client CA.
An approved certificate does not replace bearer/OIDC application authorization.
Use short-lived client certificates and roll trust roots for emergency removal;
client-certificate CRL/OCSP checking is not provided. Restart loads rotated files.
This changes the listener to HTTPS: update ingress and probes to present approved
client certificates. Do not enable this blindly behind an HTTP-only tunnel.

Mount policy, Redis URL, OIDC settings, audit token and TLS keys read-only using
your secrets manager. `deploy/secrets-store-csi.yaml` is a provider-neutral
Kubernetes volume fragment. Supply your organization's SecretProviderClass,
workload identity and access policy. Mounted-file support is implemented; no
external vault or organizational IdP is provisioned by this repository.
See [CSI usage](https://secrets-store-csi-driver.sigs.k8s.io/getting-started/usage.html).

## Multiple issuers and roles

Each network can declare `additional_issuers`, a map keyed by issuer ID. Each
value contains `anchors`, `crl`, `minimum_crl_sequence`, optional `crl_url`, and
explicit `allow_http` for private HTTP. It uses the same signed CRL schema as
the primary network. Nesting, duplicate primary IDs, authority proxy URLs and
child roles/publication are rejected; maximum eight additional issuers.
Parent `required_roles` applies to every issuer. Set explicit all-of roles from
your authority's actual JoinCertificate policy, rather than inventing roles.

The gateway refreshes and persists each issuer independently and verifies a
certificate only against its declared issuer's anchors and revocations. It does
not forge a merged signed CRL or treat federation membership feeds as JoinCRLs.
Any stale configured issuer removes network readiness. Membership revocation
consumers beside authorities still serve a different protocol purpose.

## Shared quotas and availability

`GATEWAY_REDIS_URL_FILE` is a secret containing `redis://` or `rediss://` URL.
Use `rediss://` with a publicly trusted server certificate across host boundaries.
`GATEWAY_QUOTA_NAMESPACE` must be identical across replicas in one quota domain.
Atomic Lua admission enforces each client ID's first-request 60-second window.
All replicas must have the same policy limits. Backend errors return 503 and
remove readiness; there is no fresh local allowance fallback. Without Redis,
quotas remain local to a process. Do not change namespaces during rolling updates.

The local Compose Redis uses a mounted secret configuration, AOF with fsync on
every write, no eviction, persistent storage and no published port. It is a
single backend and therefore a single availability dependency. Deploy a managed
HA endpoint for a multi-host service; test failover loss semantics before claiming
strict quota durability. Never reuse an unrelated application's Redis.

## Acceptance and external assessment

Run `cargo test --locked` and the real Redis test:
`GATEWAY_TEST_REDIS_URL=redis://127.0.0.1:6379/ cargo test --locked --lib two_independent_replicas_share_one_atomic_allowance -- --ignored`.
Use an isolated Redis only. Tests cover gateway restart rollback protection,
audit recovery, multiple issuer decisions, forged OIDC credentials, mTLS client
rejection and shared quota admission. `tools/check_slo.mjs` measures authenticated
network reads and checks readiness of each configured replica without changing
authorities. Compare the same workload before/during/after an isolated replica
failure and preserve the output; a localhost benchmark is not a production SLO.

An independent penetration test remains external work. Supply the tester the
image digest/signature, policy schema, OpenAPI, federation runbook and test logs.
Scope issuer confusion, JWT rotation, quotas during backend failure, ingress
bypass, signed-operation replay, audit exhaustion, storage recovery and private
mesh data isolation. Record findings and remediation before accreditation.
