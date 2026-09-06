# Authority services

The console exposes 59 explicitly allowed authority operations in addition to
eight gateway operations. The catalog at `/v1/services` and the OpenAPI document
describe each HTTP method, resource parameter, query field and request example.

| Area | Available workflows |
| --- | --- |
| Agreement | Offer, counter, accept and verify |
| Attestations | Issue, list, inspect, verify, revoke and recognition policy |
| Boundary | Decide and verify |
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
   not saved to browser storage. Clear the session when finished.
5. Send the request and inspect both the HTTP status and protocol result
   (`accepted`, `valid`, `trusted`, or denial reason). A 200 is not a trust grant.

Use **Insert last response** to put a successful result into a field of the next
request, such as `offer`, `agreement`, `commitment` or `attestation`. Original
SDK headers must be regenerated if their body changes or their nonce is consumed.
Browser signing supports safe-integer JSON values; use SDK-generated headers for
fractional or larger numeric values. Enrollment and discovery retain their
node proof-of-possession and signed-record requirements.

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
checks. The node roster is treated as an operator operation.

The gateway forwards only allowlisted methods/paths and the four operator
signature headers. It never forwards gateway bearer tokens, cookies or client
forwarding headers. Redirects are refused, requests time out after ten seconds,
and responses are limited to 2 MiB. Automatic retries are intentionally absent
because mutations and consumed nonces cannot safely be replayed.

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
