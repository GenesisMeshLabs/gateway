# Authority services

The console exposes 82 explicitly allowed authority operations in addition to
eight gateway operations. The catalog at `/v1/services` and the OpenAPI document
describe each HTTP method, resource parameter, query field and request example.

| Area | Available workflows |
| --- | --- |
| Agreement | Offer, counter, accept and verify |
| Attestations | Issue, list, inspect, verify, revoke and recognition policy |
| Boundary | Decide and verify |
| Boundary policy (`boundary_policy`) | Validate, publish, list, activate, deactivate, history and verify policies; policy-aware evaluation |
| Evidence store (`evidence_store`) | Submit executor-signed evidence, search, status, verify, resource heads and histories, vendor histories, JSON Lines export, executor keys, retention and signed store anchors (list, anchor now) |
| Disclosure | Commitment, membership proof, nullifier and verification |
| Consensus | Vote, assemble proof and verify against explicit validator keys |
| Data usage | Create/read license policy, issue intent and verify |
| Evidence | Build and verify signed trust evidence |
| Enrollment | Invite, join, heartbeat, renew and certificate revocation |
| Discovery | Signed agent registration, lookup, listing and deregistration |
| Treaties | Issue, inspect, verify, revoke, import feeds and inspect trust paths |
| Network | Genesis, policy, CRL, health, dashboard, atlas and node roster |
| Administration | Policy versions, rollback and operator-key revocation |

## Using the console

1. Enter your service token and click **Connect**.
2. Select your authority network, then search or filter the service list.
3. Fill resource/query fields and replace request-example placeholders with real
   records. Examples are starting points, not pre-authorized production requests.
4. For operator operations, open **Operator authorization**, enter your registered
   key ID and base64 Ed25519 seed, or paste SDK-generated `X-Admin-*` headers.
   Signatures are generated in the browser. Keys never reach the gateway and are
   not saved to browser storage. Clear the session when finished. A signature
   (version 2, Genesis Mesh 1.0.2) covers the HTTP method, the authority path the
   gateway forwards to, the forwarded query parameters, the authority's
   public key and the body, so it is valid only for that one request at that
   one authority. The console reads the public key through the network's
   `public-sovereign-metadata` operation; SDK-generated headers must be signed
   for the authority path, not the gateway path.
5. Send the request and inspect both the HTTP status and protocol result
   (`accepted`, `valid`, `trusted`, or denial reason). A 200 is not a trust grant.

Use **Insert last response** to put a successful result into a field of the next
request, such as `offer`, `agreement`, `commitment` or `attestation`. Original
SDK headers must be regenerated if their body changes or their nonce is consumed.
Browser signing supports safe-integer JSON values; use SDK-generated headers for
fractional or larger numeric values. Enrollment and discovery retain their
node proof-of-possession and signed-record requirements.

## Demo access and the guided tour (v0.65)

A client marked `demo: true` is a public demonstration identity. Its token is
stored in the policy as `demo_token` (it must hash to `token_sha256`) and
published at `GET /v1/demo`; the console's **Try the demo** button uses it.
Publishing is safe because the gateway refuses to start unless every demo
client:

- has no `authority_admin` and no `metrics`;
- allows at most 120 requests per minute;
- uses only read and verify groups: `agreement`, `attestations`, `boundary`,
  `boundary_policy`, `consensus`, `data_usage`, `disclosure`, `evidence`,
  `network`, `treaties` (their non-operator operations are reads and
  verifications; enrollment, discovery, evidence submission and
  administration are excluded).

A demo client can never forward an operator-signed request, even with signed
headers. Non-demo clients may not carry `demo_token`.

The **Guided tour** runs four scenarios with whatever token is connected:
explore the mesh, verify a treaty from another sovereign (and a tampered copy),
recognize and revoke a membership across sovereigns, and verify a governed
secret's evidence chain in the browser. The last three read signed records a
deployment publishes at `/demo-data/` (see `genesismesh/infrastructure/mesh-demo`).

A network may also set `public_external_treaties: true` (with `public_mesh`)
to show its treaties to sovereigns outside the gateway as external nodes in
the live mesh. It is off by default. With `mesh_reader` (see
[mesh operations](mesh.md#members)) the live mesh also shows the network's
published members. A demo client's own *List attestations* call still returns
only the count: the authority lists attestations to operators.

## Operator configuration

Each network may have an `authority_url` containing only its pinned HTTPS origin.
Private HTTP requires the existing explicit `allow_http` option. URLs cannot
contain credentials, query strings, fragments or path prefixes.

Each client adds exact `service_groups` and an optional `authority_admin` flag:

```json
{
  "service_groups": ["network", "attestations", "agreement", "boundary"],
  "authority_admin": false
}
```

These extend the existing client policy; token digest, quota and allowed networks
are still required. An empty group set disables authority service access.
`authority_admin: true` permits forwarding signed operator operations; it does
not replace the authority's signature, nonce, key revocation or operator-tier
checks. Because the signature binds the method, path, query and target
authority's key, a captured signed request cannot be replayed to another
route, target or authority. The console itself trusts the gateway that serves
it: it reads the authority key and the forwarded path through that gateway, so
sign with an SDK, from metadata you verified yourself, when the gateway is not
under your control. The node roster is treated as an operator operation.

The gateway forwards only allowlisted methods/paths and the four operator
signature headers. It never forwards gateway bearer tokens, cookies or client
forwarding headers. Redirects are refused, requests time out after ten seconds,
and responses are limited to 2 MiB (the evidence export, forwarded as
`application/x-ndjson` JSON Lines, to 8 MiB; page it with `since_sequence` and
`limit`). Automatic retries are intentionally absent
because mutations and consumed nonces cannot safely be replayed.

Resource identifiers are protocol text: `resource_id` may span path segments
(`kv:vault/secret`) and `resource_id` and `vendor_id` may contain non-ASCII
characters. Each segment is encoded once; empty and dot segments, `%`, `\\` and
control characters are refused before any authority request. Other identifiers
keep the ASCII rule (letters, digits, `-_.:@`).

The catalog is generated from the core's route source by
`tests/reference/build_service_catalog.py`; CI runs it with `--check` against core
`main`, so an authority route the gateway has not reviewed fails the build.

Service readiness and policy freshness are distinct. An authority may return
`no_policy`, `recognition_policy_not_configured` or a record-not-found result
until its operator provisions the relevant data. Those responses are displayed
without fabricating records or treating missing state as successful trust.

## Persistence and validation

Multi-worker authorities require durable active data-license policy storage.
The accompanying reference-authority fix adds migration
`010_data_license_policies.sql` and database-backed policy reads/writes. Older
authority builds used process-local policy memory and can lose or disagree on
active policy state; the gateway cannot repair that by retrying requests.

Local validation covers 56 Rust tests and Python-compatible browser signatures.
Live workflows exercised all seven SDK areas, node enrollment/heartbeat/renewal,
and signed agent registration/lookup/deregistration. Temporary attestation,
treaty and node credentials were revoked after testing. An explicitly named,
short-lived demonstration data-source policy was initialized on authority-a;
it survived a real authority restart. No existing recognition policy was replaced.

The authority persistence fix passed 209 authority tests. This is not proof of
multi-host availability, native ARM hardware support or government accreditation.
