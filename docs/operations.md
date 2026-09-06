# Operating the Rust trust gateway

This service evaluates Genesis Mesh join certificates using the portable Rust
trust core and Python-compatible canonical signatures. It does not implement the
full Network Authority, forward arbitrary application traffic, or issue sovereign
credentials in production. Authorities remain responsible for issuance and CRLs.

## Deployment boundary

Run behind an organization-controlled TLS ingress on a private network. The
gateway listener is HTTP; do not expose it directly to the internet. Ingress must
enforce TLS, connection/header timeouts, connection limits and aggregate abuse
controls. An external tunnel provider is optional and requires your own hosting
and data residency approval. The gateway does not trust forwarded identity or IP
headers. Each service authenticates using its own random bearer credential.

Use at least 32 random bytes encoded as hex or base64 for each credential. Store
the token in the calling service's secret manager; put only its lowercase SHA-256
digest in gateway policy. Token digests are suitable for random service secrets,
not human passwords. Restrict policy-file write access to the deployment identity.
Separate metrics credentials from application credentials.

## Policy format

Set `GATEWAY_POLICY_FILE` to an operator-managed JSON file:

```json
{
  "revision": "agency-policy-2026-09-06-01",
  "clients": [{
    "id": "records-service",
    "token_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_DIGITS",
    "networks": ["agency-network"],
    "metrics": false,
    "requests_per_minute": 120
  }],
  "networks": {
    "agency-network": {
      "anchors": {"agency-authority": "BASE64_ED25519_PUBLIC_KEY"},
      "required_roles": ["reader"],
      "minimum_crl_sequence": 42,
      "crl_url": "https://authority.example.org/crl",
      "allow_http": false,
      "crl": {
        "crl_id": "authority-snapshot-42",
        "sequence": 42,
        "issued_at": "2026-09-06T00:00:00Z",
        "next_update": "2026-09-07T00:00:00Z",
        "issuer": "agency-authority",
        "revoked_certificates": [],
        "signatures": [{"key_id": "agency-authority", "sig": "AUTHORITY_SIGNATURE"}]
      }
    }
  }
}
```

This is a schema example, not usable trust material. Obtain the actual signed
CRL and approved keys from your Genesis Mesh authority. Startup validates the
signature, sequence floor and freshness. Never edit a signed CRL's fields.
Networks support independently pinned additional CRL issuers. Required roles are all-of conditions; see [platform controls](platform.md).

Apply updates through an access-controlled configuration pipeline: retrieve and
validate authority material, retain a durable highest-seen sequence, advance
`minimum_crl_sequence`, replace the entire file atomically, then roll instances.
The process loads operator configuration at startup and refreshes configured
`crl_url` endpoints every sixty seconds. Rustls validates HTTPS; redirects and
proxy discovery are disabled. Private HTTP needs explicit `allow_http: true`.
Responses are bounded to 16 MiB and ten seconds. Each candidate must verify
under the pinned issuer, be fresh, and not regress sequence or issuance time.
Same-sequence updates cannot alter revocations. A failure retains the last
verified snapshot, which stops granting trust at expiry. Updates replace the
in-memory snapshot atomically. Operator configuration is not hot-reloaded, and
sequence history persists when GATEWAY_STATE_FILE is configured. Restart restores verified durable checkpoints before using the policy-file snapshot and floor. With a configured CRL URL, an authentic expired
bootstrap snapshot may start in not-ready state and recover after a successful
refresh. Without a URL, expired startup snapshots are rejected. Keep the durable
sequence floor current in the configuration pipeline. Rolling back the file and its
sequence floor can reintroduce revoked state, so prevent this in the pipeline.

Rotate client tokens by deploying an additional client ID with the same minimal
scope, switching the caller, then removing the old client and rolling all
instances. Restart is also required for emergency client revocation.

## API and decisions

`POST /verify` accepts `{"certificate": <JoinCertificate>}`.
`POST /verify/batch` accepts `{"certificates": [<JoinCertificate>, ...]}`.
Both require `Authorization: Bearer <service-token>`. Caller-provided nonempty
anchors or CRLs are rejected in production. Unknown request and signed-document
fields are rejected to prevent silent changes to signed content.

A successful HTTP response does not mean trust was granted. Check `trusted` on
every result; `false` includes reason strings. Trust does not authorize an
arbitrary application action and does not prove possession of the node's private
key. A relying service must bind the identity to an authenticated session or
challenge and apply its own resource/action authorization. Certificates alone
are replayable public documents.

`401` means authentication failed; `403` means the network or metrics scope was
denied; `429` means the per-client quota is exhausted; `503` means capacity or
readiness is unavailable. Framework JSON errors use `400`/`422`, oversized bodies
use `413`, and request deadlines use `408`. Framework rejections may have plain
text or empty bodies; application errors have `error` and `code` fields.
`429` and application `503` include a conservative `Retry-After: 60`.

`GET /health` is liveness; `GET /ready` returns `503` when any configured network's
CRL expires. Stale networks deny verification immediately even before a load
balancer observes readiness. `GET /metrics` requires an authenticated client with
`metrics: true`. All routes return server-generated `x-request-id`, `no-store`
and `nosniff` headers.

## Resource controls

| Variable | Default | Valid range |
| --- | --- | --- |
| `GATEWAY_ADDR` | `127.0.0.1:8080` | Socket address |
| `GATEWAY_TIMEOUT_MS` | `15000` | 1–300000 |
| `GATEWAY_MAX_BODY_BYTES` | `1048576` | 1–16777216 |
| `GATEWAY_MAX_INFLIGHT` | `512` | 1–4096 |
| `GATEWAY_MAX_BATCH` | `1024` | 1–4096 |

An independent worker semaphore stays held until computation actually finishes,
even if the HTTP future times out or disconnects. Batch processing is sequential
within each worker; independent requests execute concurrently. Set concurrency
and batch sizes using load tests on your actual CPU allocation. Quotas count
requests, not certificates, over sixty-second windows. Configure Redis for a shared allowance across replicas; otherwise quotas remain process-local.

CPU tasks cannot be interrupted once started. SIGTERM and Ctrl-C stop accepting
new connections and allow requests to drain. Enforce a bounded container stop
grace externally. Live probes bypass HTTP admission; CPU isolation keeps crypto work off the async scheduler.

## Observability and incident response

JSON stdout logs include request ID, admitted client ID, policy revision, status,
latency and completed trust decisions. Request spans correlate admitted clients
with decisions. Raw URLs, query strings, headers, credentials and request bodies
are excluded. Operator-supplied client names are logged; do not use personal data
for these identifiers. `/metrics` exposes aggregate requests, server failures,
authentication denials and active crypto workers without client labels.

Forward stdout to an access-controlled collector with retention, integrity and
delivery monitoring. The bounded background stdout writer applies backpressure rather than dropping events. Local stdout is neither durable nor tamper-evident, and the
gateway does not fail closed on collector failure. Set those controls at the
platform boundary according to your audit requirements. Monitor readiness,
snapshot deadlines, 401/403/429/503 rates and worker saturation. For compromise,
revoke through the authority, distribute its new CRL, roll gateways, verify
denial, and preserve relevant collector records.

## Evidence required before government production use

The repository is an engineering implementation, not a certification. Complete
an independent security assessment, protocol conformance review, dependency and
image scans, workload capacity/soak tests, disaster recovery and rotation drills,
ingress review and your organization's privacy/accreditation process. No claim
of FIPS validation, NIS2/GDPR compliance or suitability for classified systems is
made. HSM-backed issuance belongs in the authority; this production gateway
does not accept or hold authority signing keys. OIDC, native mTLS, durable audit delivery, durable CRL history and Redis quotas are implemented as configurable adapters. See [platform controls](platform.md) for activation and recovery boundaries.

Replica packaging, CPU/batch budgets, field limits and quota semantics are
documented in [distribution](distribution.md).
