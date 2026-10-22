# Authority services

The console exposes 110 explicitly allowed authority operations in addition to
nine gateway operations. The catalog at `/v1/services` and the OpenAPI document
describe each HTTP method, resource parameter, query field and request example.

| Area | Available workflows |
| --- | --- |
| Agreement | Offer, counter, accept and verify |
| Attestations | Issue, list, inspect, verify, revoke and recognition policy |
| Boundary | Decide and verify |
| Boundary policy (`boundary_policy`) | Validate, publish, list, activate, deactivate, history and verify policies; policy-aware evaluation |
| Evidence store (`evidence_store`) | Submit executor-signed evidence, search, status, verify, resource heads and histories, vendor histories, JSON Lines export, executor keys, retention and signed store anchors (list, anchor now); remediation records, the due queue, notices and reviews (Genesis Mesh 1.4.0, see [below](#remediation-reviews-and-notification)); archives (list, record) and retention through an archived position (1.5.0, see [below](#key-history-archives-and-audit-packs)); pre-issued grants (issue, list, read, a grant's use chain, revoke), a holder's time tokens and grant uses, and a search for a grant's uses and revocation (1.6.0, see [below](#pre-issued-grants)) |
| Changes outside the controlled path (`out_of_band`) | Submit observations (one or a batch) and break-glass records, judge them, a resource's changes with how each was governed and its state (shown as a table; paged with `after_sequence` and `limit` from 1.4.0), operator key holders and holder changes (Genesis Mesh 1.3.0) |
| Disclosure | Commitment, membership proof, nullifier and verification |
| Consensus | Vote, assemble proof and verify against explicit validator keys |
| Data usage | Create/read license policy, issue intent and verify |
| Evidence | Build and verify signed trust evidence |
| Enrollment | Join, heartbeat and renew |
| Discovery | Signed agent registration, lookup, listing and deregistration |
| Treaties | Issue, inspect, verify, revoke, import feeds and inspect trust paths |
| Network | Genesis, policy, CRL, health, dashboard, atlas, node roster, the NA key history (1.5.0) and edge nodes (1.7.0, see [below](#edge-nodes-genesis-mesh-170)) |
| Administration | Invites, certificate revocation, policy versions, rollback, operator-key revocation and NA key succession (1.5.0) |

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

Some answers are also shown as tables above the JSON: a resource's changes,
the due queue, one subject's remediation state and the evidence store status
(see [below](#remediation-reviews-and-notification)), the NA key history
(see [below](#key-history-archives-and-audit-packs)), and grants, grant uses,
resource heads and judgements (see [below](#pre-issued-grants)), and edge
nodes and an edge node's revocation (see [below](#edge-nodes-genesis-mesh-170)).
The tables hold text only; the authority's values are never read as markup.

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

The **Guided tour** runs five scenarios with whatever token is connected:
explore the mesh, verify a treaty from another sovereign (and a tampered copy),
recognize and revoke a membership across sovereigns, verify a governed
secret's evidence chain in the browser, and see how changes are governed after
the fact (1.4.0). The middle three read signed records a deployment publishes
at `/demo-data/`. The gateway does not serve `/demo-data/`: route it at your
ingress to a directory with `network.json`, `attestations.json`,
`evidence.ndjson`, `executor-keys.json` and `status.json`, as
`genesismesh/infrastructure/mesh-demo` does. Without it, only *The mesh*
and *Changes governed after the fact* run. The last reads
the demo authority's published evidence store status for its remediation
counts (or that the records are off) and checks that this gateway forwards
the seven remediation and review operations; demo access cannot call them,
since they are operator and controller operations.

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
`limit`). The due queue, one subject's remediation state and a resource's
changes may also be up to 8 MiB (1.4.0; page the changes with
`after_sequence` and `limit`). The audit pack is not forwarded at all
(1.5.0; see [why](#the-audit-pack-is-not-forwarded)). Automatic retries are intentionally absent
because mutations and consumed nonces cannot safely be replayed.

The authority's answers are relayed with their status and JSON body, with
these exceptions. A redirect, and a server error other than `503`, becomes the
gateway's `502`, and its body is not read. A `503` is relayed with its JSON
object (at most 16 KiB) so its code reaches the client: an SDK must tell an
authority's `evidence_store_unavailable`, on which it never breaks the glass,
from a gateway or network failure (1.3.1; before, it was a `502`). A `503`
whose body is not a JSON object is a `502` as before.

### Observation submission rate

The authority limits observation and break-glass submissions per client
address (`NA_RATE_LIMIT_OBSERVATIONS_PER_MINUTE`, 120 a minute by default),
and counts each observation in a batch. Every request the gateway forwards
comes from the gateway's own address, and the gateway does not forward client
addresses. So all of its clients share one bucket: one observer's backlog can
use up the minute for every other client of the same authority. Size
`NA_RATE_LIMIT_OBSERVATIONS_PER_MINUTE` for everything sent through the
gateway, or connect observers and controllers that submit many records
directly to the authority. The SDKs halve their batches after a `429` and wait
as long as its `Retry-After` asks.

Resource identifiers are protocol text: `resource_id` may span path segments
(`kv:vault/secret`) and `resource_id` and `vendor_id` may contain non-ASCII
characters. Each segment is encoded once; empty and dot segments, `%`, `\\` and
control characters are refused before any authority request. Other identifiers
keep the ASCII rule (letters, digits, `-_.:@`).

The catalog is generated from the core's route source by
`tests/reference/build_service_catalog.py`; CI runs it with `--check` against the
core branch of the same name when there is one (a coordinated change), the
core's tag for a release tag, and core `main` otherwise, so an authority route
the gateway has not reviewed fails the build.

Service readiness and policy freshness are distinct. An authority may return
`no_policy`, `recognition_policy_not_configured` or a record-not-found result
until its operator provisions the relevant data. Those responses are displayed
without fabricating records or treating missing state as successful trust.

## Remediation, reviews and notification

*Genesis Mesh 1.4.0. The authority's routes are stable from 1.5.0.*

With `EVIDENCE_REMEDIATION=on` at the authority, a change judged after the
fact becomes due for remediation, is reviewed by a second holder, or is
waived. The seven operations are in the `evidence_store` group, so a client
scoped to the evidence store reaches them; until the switch is on they
answer `404 remediation_disabled`.

| Operation | Authority route | Who |
| --- | --- | --- |
| Submit remediation | `POST /evidence/remediations` | A controller: the record's executor signature, no operator headers |
| Due queue | `GET /admin/evidence/remediations` (`state`, `limit` 1 to 500, `after`) | Operator, read tier |
| Get remediation | `GET /admin/evidence/remediations/{subject_id}` | Operator, read tier |
| Record notice | `POST /admin/evidence/remediations/{subject_id}/notified` | Operator, standard tier |
| Request review | `POST /admin/evidence/reviews` | Operator, standard tier |
| Get review | `GET /admin/evidence/reviews/{review_id}` | Operator, read tier |
| Decide review | `POST /admin/evidence/reviews/{review_id}/decide` | Operator, privileged tier, of another holder |

The gateway's `authority_admin` flag only lets a client forward signed
operator requests; the authority checks each key's tier and, for a decision,
that its holder is neither the requester nor the actor. A review record
embeds the decider's signed request, which verifies offline: the gateway
forwards the body byte for byte and no query, so sign exactly what is sent.

### In the console

- **Due queue**: send *Due queue* without `state` for the open items, one
  table per state: remediation due (due time, plan as mode, steps and fallback,
  actor and holder, resource, when the actor was notified), overdue
  (`overdue_since`) and waived (`waived_until`); items in other states that
  have a pending review come together in one more table. The `state` field
  suggests each value.
- **Pending reviews**: a pending review is a flag beside a state, not a state:
  an overdue change can be under review, and its due time keeps running. Each
  table shows the flag in its *Review* column (`pending` and what opened the
  review, or the latest decided review). The default queue then lists every
  pending review again with its request: what opened it, the requester and
  holder, the justification and when an emergency change's lifetime ends.
  `state=review_pending` shows only that table, whatever the items' states.
- **Paging**: when a page is full, the note under the table gives the
  `next_after` value; send it as `after` for the next page.
- **One subject**: *Get remediation*, *Record notice*, *Request review* and
  *Decide review* show the subject's state as a table (and its pending review);
  its reviews and records stay in the JSON. *Get remediation* returns the
  newest 100 of each; the note says when older ones are left out
  (`reviews_truncated`, `records_truncated`).
- **Changes**: the changes table of *Resource changes* shows each change's
  Stage 3 state and its remediation (plan, due time, pending review, waiver,
  the remediation record, the notice). The changes come a page at a time
  (`limit`, 1 to 10,000, default 1,000); when there are more, the note gives
  `next_after_sequence`; send it as `after_sequence` for the next page.
- **Status**: *Status* (evidence store) shows the number of remediation
  states by state and of pending reviews (an item under review is counted
  under both), or that the records are off.

### Limits

- A page of the due queue holds up to 500 states, each with its pending
  review; the gateway forwards up to 8 MiB. A page of mostly non-ASCII text
  can still exceed it: send a smaller `limit`.
- *Get remediation* returns a subject's newest 100 reviews and 100 stored
  records, also up to 8 MiB.
- A page of a resource's changes (1,000 by default) is forwarded up to 8 MiB:
  with a remediation object on each change, a default page can pass 2 MiB.
  For larger `limit` values, page with `after_sequence`.
- Remediation records count against the authority's evidence submission
  limit (`NA_RATE_LIMIT_EVIDENCE_PER_MINUTE`), which is per client address:
  all of the gateway's clients share it, as they share the observation limit
  (see [Observation submission rate](#observation-submission-rate)).

## Key history, archives and audit packs

*Genesis Mesh 1.5.0. The authority's new routes are beta.*

Since 1.5.0 the Network Authority's signing key can be replaced by a key
succession that its root key signs, and the evidence store is archived as
NA-signed audit packs before retention removes anything. The gateway forwards
four new operations, and *Apply retention* gains `through_sequence`. The
audit pack itself is not forwarded.

| Operation | Authority route | Group | Who |
| --- | --- | --- | --- |
| Key history | `GET /na/key-history` | `network` | Anyone with the group, demo access included; no operator headers |
| Succession | `POST /admin/na/succession` | `administration` | Operator, privileged tier |
| List archives | `GET /admin/evidence/archives` | `evidence_store` | Operator, read tier |
| Record archive | `POST /admin/evidence/archives` | `evidence_store` | Operator, privileged tier |
| Apply retention | `POST /admin/evidence/retention/apply` (`through_sequence`, `older_than_days`) | `evidence_store` | Operator, privileged tier |

The key history file is public on the authority, so the gateway reads it
as it reads the genesis block. Recording a succession replaces the key the
authority signs with, so it sits in `administration`, not `network`: a
client needs that group and `authority_admin` to forward it, and the
authority still checks the privileged tier and the record's signatures.

The gateway forwards a succession but does not follow it: it pins the keys
in each network's `anchors` and does not read the key history. After the
succession takes effect the network goes not ready. See
[key succession](key-succession.md) before an authority you serve records
one.

The record must reach the authority with two signatures already on it:
the root key's, made offline (`genesis-mesh na succession sign`), and the
new key's proof of possession, made where the new key lives (`genesis-mesh
na succession prove`). The authority adds the outgoing key's
countersignature, so the record it returns has three. The request example
`{"succession": {}}` is only a placeholder: paste the record the two
commands produced.

### Read tier for evidence reads

Every evidence store read accepts a `read` operator key from 1.5.0:
search, status, verify, resource and vendor histories, resource heads, the
export, the executor keys and the archive list. An auditor's gateway
client can hold a read key. It still needs `authority_admin` and the
`evidence_store` group, since the gateway forwards any signed request only
for such a client. The tier is the authority's check, not the gateway's:
what changes the store or its keys answers `403 insufficient_operator_tier`
to a read key.

### Retention through an archive

- `through_sequence` stops retention at a store position: give it, with or
  without `older_than_days`. The request example holds a placeholder that the
  authority refuses until you replace it with a number.
- With `NA_RETENTION_REQUIRE_ARCHIVE` on (the default) the authority removes
  nothing past what an unbroken run of archive records covers. It then
  answers `held_back` with `"reason": "not_archived"`. *List archives* gives
  `archived_through_sequence`, the position to send.
- A store upgraded to 1.5.0 has no archive, so retention removes nothing
  until the first archive is recorded.

### The audit pack is not forwarded

`POST /admin/evidence/audit-pack` is not in the gateway's catalog, and
`evidence_store-audit-pack` answers `404`. Run `genesis-mesh audit pack`
against the authority itself, with a read-tier key. Then `genesis-mesh audit
archive` writes the pack to immutable storage and records the archive.
Recording an archive through the gateway, as above, is for a pack already
written and read back. The authority records only a pack it built itself
(`409 archive_pack_unknown`) and whose own checks passed (`409
archive_pack_unverified`).

Why the pack is left out:

- **Size.** A pack is one unpaged answer: up to 50,000 store entries with
  every record they cite, the key history, the trust material and a report.
  At about 1.6 KB per entry, that can pass 80 MB before JSON escaping. The
  gateway reads a whole answer into memory, parses it and writes it again,
  so one request would hold several times that.
- **Time.** The authority builds the pack and verifies all of it before it
  answers. The gateway gives an authority ten seconds; the CLI waits two
  minutes.
- **Load.** The gateway's quotas count requests, not bytes. Through the
  gateway, any read-tier client could start full-range exports and
  verifications. The authority allows a number of packs an hour per client
  address (`NA_RATE_LIMIT_AUDIT_PACKS_PER_HOUR`, 12 by default) and answers
  `429` beyond it. Every request the gateway forwards comes from the
  gateway's address, so its clients would share that one allowance, as they
  share the [observation limit](#observation-submission-rate).
- **Little to gain.** The pack's manifest is signed by the NA and checked
  offline from the root key, so a pack is no more trustworthy for passing
  through the gateway. The paged JSON Lines export stays available for SIEM
  pipelines.

### In the console

- *Key history* shows a table of the NA's keys: the key ID, public key, valid
  from (the genesis key from the start of the network), when it was succeeded
  and its declared end. The genesis key's end is marked *not enforced*.
  Another column says where each key stands: the key that signs now, a
  succeeded key, or one that takes effect later, and the instance that
  answered.
- The successions, if any, come in a second table: the key each replaced,
  when it takes effect, when it was issued and who signed it. The signatures
  are listed by key ID: the root key, the new key and the outgoing key.
- *Succession* shows the same tables for the history it returns.
- The console shows the history and does not check it. A verifier checks it
  from the root key it already holds: keys named in the history prove nothing
  alone.

### Refusals

The gateway relays the authority's refusals with their status and code. These
are new in 1.5.0:

| Area | Codes |
| --- | --- |
| NA key (`503`, relayed with `Retry-After`) | `na_key_succeeded`, `na_key_not_yet_effective`, `na_key_expired` |
| Succession (`400`, `409`, `422`) | `invalid_succession`, `succession_after_expiry`, `succession_backdated`, `succession_chain_break`, `succession_invalid_new_key_signature`, `succession_invalid_root_signature`, `succession_key_reused`, `succession_not_increasing`, `succession_pending`, `succession_sovereign_mismatch`, `succession_times_invalid` |
| Archive (`400`, `409`, `422`) | `invalid_archive`, `archive_anchor_mismatch`, `archive_conflict`, `archive_manifest_invalid`, `archive_not_contiguous`, `archive_pack_unknown`, `archive_pack_unverified` |
| Retention | `held_back` with `"reason": "not_archived"` (a `200`, not an error) |

The audit pack's codes (`audit_pack_not_anchored`, `audit_pack_too_large`,
`invalid_audit_pack`, `evidence_store_incomplete`) and its hourly `429`
reach only clients of the authority itself.

### Authority readiness

The authority's own readiness is the `health-readyz` operation (`GET
/readyz`, `network` group); the gateway's `GET /ready` covers only the
gateway's revocation data. From 1.5.0 the authority's answer includes
`na_key.state`:

- `signing`: this instance's key signs now.
- `pending`: the instance was started with a new key before its succession
  takes effect (`signs_from` says when).
- `stopped`: its key was succeeded or has expired.

Only `signing` is ready. Otherwise the authority answers `503
service_not_ready`, and the gateway relays it with its checks under
`error.details` (`na_key` among them), as it relays every `503` that is a
JSON object.

### Response limits

Each limit stays the default 2 MiB. The archive list is not paged: at about
1 KB per archive record it holds some 2,000 archives. Past that, read it from
the authority directly.

## Pre-issued grants

*Genesis Mesh 1.6.0. The authority's grant routes are beta; the records'
signed forms are stable.*

A grant is an authorisation the authority signs in advance, so that a device
or controller can make a bounded change while it cannot reach the authority.
When it issues the grant, the authority checks that every policy that applies
allows every request the grant's parameter envelope permits. The holder then
acts within the grant offline and uploads each use later. Grants are off
until the authority runs with `EVIDENCE_GRANTS=on` (which needs
`EVIDENCE_OUT_OF_BAND=on`). Until then every grant operation answers
`404 grants_disabled`, and the console says so.

### Operations

The seven operations are in the `evidence_store` group. A grant, its uses and
its revocation are evidence store records, a grant's bearer is a registered
executor key, and holders submit their uses there as controllers submit
execution evidence.

| Operation | Authority route | Who |
| --- | --- | --- |
| Issue grant | `POST /admin/grants` | Operator, privileged tier |
| List grants | `GET /admin/grants` (`status`, `bearer_key_id`, `limit` 1 to 500, `before`) | Operator, read tier |
| Get grant | `GET /admin/grants/{grant_id}` | Operator, read tier |
| List grant uses | `GET /admin/grants/{grant_id}/uses` (`limit` 1 to 500, `before`) | Operator, read tier |
| Revoke grant | `POST /admin/grants/{grant_id}/revoke` | Operator, privileged tier |
| Time token | `POST /grants/time-tokens` | The holder: a request its bearer key signs, no operator headers |
| Submit grant execution | `POST /evidence/grant-executions` | The holder: a use its bearer key signs, no operator headers |

*Search* (evidence store) also takes `grant_id` from 1.6.0: a grant's uses
and its revocation.

The gateway's `authority_admin` flag only lets a client forward signed
operator requests; the authority checks each key's tier. A holder's request
and use are checked by their signatures, so a client without
`authority_admin` can forward them, and operator headers sent with them go
no further. The gateway forwards every body byte for byte: a use is checked
in its exact serialized form, so a number written `1.0` reaches the
authority as `1.0`.

The request examples hold placeholders that the authority refuses unedited:
the bearer's executor key ID and the attestation the grant rests on
(`attestation_id`, or an `agreement` instead). *Issue grant* fills
`valid_from` with a minute ago and `valid_until` with an hour from now; a
grant lasts at most 24 hours. The `reason` sent to *Revoke grant* is free
text, stored as the revocation's `detail`; the revocation's own `reason` is
`operator`.

### In the console

- **Grants**: *List grants* shows one row per grant, newest first: its
  status (`active`, `scheduled`, `exhausted`, `expired` or `revoked`), bearer
  key, capabilities, basis, validity, uses of its budget, who issued it and
  when it was revoked and why. The `status` field suggests `active`,
  `expired` and `revoked`; `active` also lists the grants that say
  `scheduled` or `exhausted`. Grants come newest first by issue time, then
  ID. When a page is full, the note gives `next_before`, the ID of the
  page's last grant; send it as `before` for the next page.
- **One grant**: *Get grant* shows the uses admitted of its budget, the
  remaining budget, the length of its use chain (admitted and quarantined
  uses; the budget counts admitted uses only), the uses allowed per time
  token, the policy versions it was checked against, its parameter envelope
  (each parameter, whether it is required, and its allowed values or range)
  and its revocation, if any.
- **Uses**: *List grant uses* shows the use chain, newest first: each use's
  position, ID and state (`admitted`, or `quarantined` with the code it was
  refused with: a refused use that still continued the chain), when it was
  executed and recorded, its resource and the position the authority gave
  it there, and its outcome. When a page is full, the note gives
  `next_before`, a use's position; send it as `before`.
- **Preparing**: a grant offers *Prepare the list of its uses* and, unless
  it is revoked, *Prepare revocation of this grant*. Each selects the
  operation with the grant's ID filled in and sends nothing: review it,
  then sign and send it. *Revoke grant*
  shows the signed revocation. Uses executed from its time on are refused,
  and holders stop using the grant once their revocation feed lists it.
- **Issuing**: *Issue grant* shows the signed grant, its envelope and the
  first time token the holder keeps with it.
- **A holder's requests**: *Time token* shows the token and the uses before
  it. *Submit grant execution* shows the use and the position the authority
  gave it in its resource's chain: a use with a resource becomes the
  resource's head, which the next execution evidence links to.
- **Resource heads and changes**: *Resource head* shows the position and
  digest the next record links to, and from 1.6.0 what that record is:
  execution evidence, a grant use or the latest retention checkpoint, with
  its record ID. In
  *Resource changes*, a use is a change of kind `grant_execution`, governed by
  `grant`, with its grant and use number in the details. An observation that
  matched a use says so, and a refused use kept in quarantine is marked as a
  grant use.
- **Judgements**: *Judge observation* and *Judge break glass* show the
  judgement, with how the change was governed: by a prior decision, by a
  grant (with the use it matched; the change is not judged again) or
  judged after the fact.
- **Status**: *Status* (evidence store) adds the grants issued, active and
  revoked and the uses admitted, or says that grants are off.

The console names each revocation reason in words: by an operator, or by the
authority because the grant's attestation was revoked, a policy it was
checked against was deactivated, a policy activated since may deny it, its
bearer key was retired, or (`agreement_untrusted`) a treaty revocation left
its agreement untrusted. It shows grants and does not verify them: the SDKs
and verifiers check a grant's signature against the authority's key history.

### Refusals

The gateway relays the authority's refusals with their status, code and
details. These are new in 1.6.0:

| Area | Codes |
| --- | --- |
| Every grant operation | `404 grants_disabled` while grants are off |
| Issuing (`400`) | `unexpected_field`, `ambiguous_basis`, `invalid_grant_validity`, `invalid_grant_request`, `grant_limit_exceeded`, `invalid_grant_envelope`, `invalid_agreement` |
| Issuing (`422`) | `grant_bearer_key_unknown`, `grant_bearer_key_not_executor`, `grant_bearer_key_retired`, `agreement_untrusted`; then the first issuance refusal, from `grant_basis_invalid` to `grant_gate_may_deny`, with every problem in `error.details.problems` |
| Issuing (`409`) | `grant_issuance_conflict`: what the grant rests on changed while it was issued; send it again |
| Reading and revoking | `400 invalid_grant_filter`, `400 invalid_page` (also a `before` that names no grant, or is not a use's position), `400 invalid_grant_revocation`, `404 grant_not_found`, `409 grant_already_revoked` |
| Time tokens | `400 invalid_time_token_request`; `422 time_token_request_malformed`, `time_token_request_invalid_signature`, `time_token_request_stale`; `409 grant_bearer_key_retired`, `grant_revoked`, `grant_expired`, `grant_budget_exhausted`, `time_token_request_behind`, `time_token_request_mismatch` |
| Uses | `400 invalid_grant_use`; the use rejections from `grant_use_malformed` to `grant_revoked` (`422`, and `409 grant_use_conflict`), among them `422 grant_use_out_of_scope` (the bearer key's role or resource prefix does not cover the use's resource), with `error.details.quarantine_id` when the authority keeps the use in quarantine |
| Store | `503 evidence_store_unavailable`; `503 grant_store_integrity_failed` from any grant operation, when a grant the authority holds no longer verifies under its signature. Both are relayed with `Retry-After` |

The rules behind each code are on the core's *Pre-Issued Grants* operations
page.

### Limits

- *List grants*, *Get grant* and *Issue grant* are forwarded up to 8 MiB: a
  page holds up to 500 summaries of up to 16 capabilities each, and a grant's
  envelope up to 64 parameters of up to 256 values each. The other grant
  operations keep the default 2 MiB; a page of uses holds at most 500.
- A holder's time tokens and uses count against the authority's evidence
  submission limit (`NA_RATE_LIMIT_EVIDENCE_PER_MINUTE`), which is per client
  address: all of the gateway's clients share it, as they share the
  [observation limit](#observation-submission-rate). A holder with many uses
  to upload after reconnecting can send them to the authority directly.

## Edge nodes (Genesis Mesh 1.7.0)

*The edge node list is beta.*

An edge node is a device that runs the Genesis Mesh edge agent. It enrols
with an edge invite, holds its own node and executor keys, and keeps acting
under the grants it holds while it cannot reach its authority. Operators
list edge nodes and revoke them through the gateway; the agent itself talks
to its authority directly.

### Operations

| Operation | Authority route | Who |
| --- | --- | --- |
| List edge nodes | `GET /admin/edge-nodes` (`status`, `node_sovereign_id`, `limit` 1 to 500, `before`) | Operator, read tier |

*List edge nodes* is in the `network` group, like the node roster (*List
nodes*). Edge invites and edge revocation extend existing operations:

- *Create invite* takes `node_sovereign_id` and `executor_resource_prefix`
  together (for example `edge:site7-17/`). An edge invite needs the
  privileged tier, and an authority with `EVIDENCE_STORE=on` and
  `EVIDENCE_OUT_OF_BAND=on`.
- *Revoke certificate*, given a certificate of an edge node, revokes the
  node: every certificate it holds in one CRL, its executor key, and the
  grants that key bears (reason `bearer_key_retired`). The answer adds an
  `edge_node` block.

The three routes an edge agent signs with its node key are not forwarded:
`POST /node/boundary/evaluate`, `POST /node/state` and
`POST /node/evidence/resource-head`. Each request is bound to its purpose
and to one authority, and the agent calls its authority directly. They are
not in the catalog or the OpenAPI document.

### In the console

- **Edge nodes**: *List edge nodes* shows one row per node, newest
  enrolment first: its node public key, sovereign ID, executor key and
  resource prefix; its status (`online` while its newest heartbeat is
  under five minutes old, `offline`, or `revoked` with when and why); its
  newest certificate and when it expires; its last heartbeat and
  address; what its agent last reported (the age of its trust snapshot,
  uploads pending with any dead letters, and its version); the usable
  grants its executor key bears and their admitted uses; and its
  break-glass records since it enrolled, with the latest. The `status`
  field suggests `online`, `offline` and `revoked`. A node whose newest
  certificate has expired shows `certificate expired` rather than
  `offline`: the authority refuses its heartbeats and renewals until it
  enrols again, while its agent still acts under the grants it holds (the
  authority lists such a node as `offline`). A cell is empty when
  the authority has nothing to report: no heartbeat from the agent yet,
  grants off (`EVIDENCE_GRANTS`), or the evidence store off. When a page is
  full, the note gives `next_before`, the node public key of the page's
  last node; send it as `before`.
- **Revocation**: *Revoke certificate* of an edge node's certificate shows
  the CRL sequence, the certificates revoked, the executor key and whether
  it was retired, and the number of grants revoked with it. Revoking the
  node again changes nothing. If the authority could not retire the key,
  the certificates stay revoked and the authority retires the key when it
  next starts; the note says so. Any other certificate's revocation shows
  no table, as before.

Edge nodes are operator data: the public [mesh view](mesh.md) does not show
them.

### Refusals

The gateway relays the authority's refusals with their status and code.
These are new in 1.7.0:

| Area | Codes |
| --- | --- |
| Edge invites (*Create invite*) | `400 invalid_edge_invite` (one of the two fields without the other), `400 invalid_node_sovereign_id`, `400 invalid_resource_prefix` (1 to 256 characters, no control characters, ending with `/` or `:`), `403 insufficient_operator_tier`, `409 edge_requires_evidence_store`, `409 node_sovereign_in_use` (the ID belongs to an active edge node, an outstanding edge invite, another executor key or the subject of an attestation the authority issued), `409 resource_prefix_overlap` (the prefix starts with, or is the start of, an active executor key's or an outstanding edge invite's) |
| *List edge nodes* | `400 invalid_edge_status`, `400 invalid_page` (also a `before` that names no edge node) |
| *Renew certificate*, *Heartbeat* | `403 edge_node_retired`: the edge node was revoked, whatever certificate it presents |
| *Retire executor key* | `409 executor_key_is_edge_node`: an active edge node's key; revoke the node with *Revoke certificate* instead |

The rules behind each code are on the core's operations page *The Edge Agent*.

## Persistence (v0.56.1 record)

At v0.56.1, multi-worker authorities require durable active data-license policy storage.
The accompanying reference-authority fix adds migration
`010_data_license_policies.sql` and database-backed policy reads/writes. Older
authority builds used process-local policy memory and can lose or disagree on
active policy state; the gateway cannot repair that by retrying requests.

At v0.56.1, local validation covered 56 Rust tests and Python-compatible
browser signatures. Live workflows exercised all seven SDK areas, node enrollment/heartbeat/renewal,
and signed agent registration/lookup/deregistration. Temporary attestation,
treaty and node credentials were revoked after testing. An explicitly named,
short-lived demonstration data-source policy was initialized on authority-a;
it survived a real authority restart. No existing recognition policy was replaced.

The authority persistence fix passed 209 authority tests. This is not proof of
multi-host availability, native ARM hardware support or government accreditation.
