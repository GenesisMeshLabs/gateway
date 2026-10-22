# When an authority's NA key is succeeded

Since Genesis Mesh 1.5.0 a Network Authority replaces its signing key by a
**key succession**: a record its offline root key signs, which names the next
NA key and when it takes effect (`effective_at`). The core's operations page
*Key Succession and the Root Key* describes the authority's side. This page
describes what happens to a gateway that serves that authority, and what its
operator does.

**The gateway pins keys; it does not read the key history.** It verifies a
network's CRL and certificates only against the keys in that network's
`anchors`, by key ID. It forwards the *Key history* and *Succession*
operations (see [authority services](services.md#key-history-archives-and-audit-packs)),
but it does not use them for its own checks. Support for the key history is
a known gap; until it exists, a gateway cannot keep serving a network across
a succession.

## What happens

| When | What the gateway does |
| --- | --- |
| Before `effective_at` | Nothing changes. The outgoing key still signs the authority's CRLs and certificates. |
| From `effective_at` | Certificates the new key signs (`issued_by` is the new key ID) are refused with `NetworkPolicyRejected`; that includes renewals. Each CRL refresh fails and logs `authority refresh failed; retaining verified snapshot`. The gateway keeps the last CRL the outgoing key signed, so revocations the authority records after `effective_at` do not reach it. Certificates the outgoing key signed keep verifying against that CRL. |
| When that CRL expires | The network denies every certificate and `GET /ready` answers `503` for the whole gateway, not only for that network. A load balancer that follows readiness stops sending the replica any traffic. |

The authority signs a CRL for 24 hours and signs a new one when less than 12
remain, and the gateway reads it every minute. So the last CRL the outgoing
key signed expires between 12 and 24 hours after `effective_at`. A
revocation just before `effective_at` makes it close to 24 hours. Read the
exact time from `GET /v1/networks`: `revocation.next_update` of that network.

## Why re-pinning does not help

After a succession the authority keeps the genesis key's ID as the CRL's
`issuer` and signs the CRL with the new key, under the new key's ID. The
gateway accepts a CRL only when it carries a signature under the key ID
named by `issuer` that verifies with `anchors[issuer]`. No change to
`anchors` makes both true:

- Adding the new key ID and key to `anchors` leaves the CRL's `issuer`
  pointing at the genesis key ID, under which the CRL has no signature.
- Replacing the public key of the genesis key ID with the new key does not
  match either: the signature names the new key ID. With durable state on,
  startup also refuses the change: `stored CRL no longer authenticates under
  the configured issuer; explicit rotation migration required`.

A certificate the new key signs names the new key ID as `issued_by`. The
gateway looks up that ID as the network's CRL issuer or as one of its
`additional_issuers`. An additional issuer needs its own CRL with the new
key ID as `issuer`, and the authority does not publish one.

## What to do

Plan this with the authority's operator before they submit the succession.
Ask for `effective_at`, and decide which of the two outcomes you want.

**Keep the network until its CRL expires.** Nothing to change. Tell the
network's clients that certificates the new key signs are refused from
`effective_at`, and that revocations after `effective_at` are not applied
here. Then remove the network, below, before `revocation.next_update`.

**Remove the network before `effective_at`.** Choose this when revocations
must stay current, or when the gateway must not go not ready at all.

To remove the network:

1. Delete the network from `networks` in the policy, and its name from every
   client's `networks`. `--check-config` refuses a client that names a
   network the policy does not have.
2. Give the policy a new `revision`, then run the check against it:

   ```sh
   GATEWAY_POLICY_FILE=/path/to/new-policy.json genesis-mesh-gateway --check-config
   ```

   With durable state on, run the check against a stopped replica or a
   consistent backup of its state, not the live database.
3. Roll the new policy to every replica (a new versioned Secret on
   Kubernetes; see [distribution](distribution.md#multiple-replicas)). The
   gateway reads policy only at startup.
4. Check each replica:

   ```sh
   curl -fsS https://gateway.example.org/ready
   curl -fsS -H "Authorization: Bearer $TOKEN" https://gateway.example.org/v1/networks
   ```

   `/ready` answers `{"status":"ready"}`, and `/v1/networks` no longer lists
   the network. The durable store keeps the removed network's checkpoint; it
   is not used.

Do not run `--init-state` to recover readiness, and do not edit a signed CRL.

## Watching for a succession

- The *Key history* operation (`network` group) lists the authority's keys
  and any succession waiting to take effect, with its `effective_at`. The
  console shows it as a table. Check it from the root key you hold; the
  console does not check it.
- The *Readyz* operation (`health-readyz`) reports the authority's
  `na_key.state`: `pending` on an instance that holds the new key before
  `effective_at`.
- `GET /v1/networks` gives each network's `revocation.next_update`, and the
  log line `authority refresh failed; retaining verified snapshot` repeats
  every minute while a refresh fails.

A compromised NA key cannot sign its own succession. The authority then
needs a new genesis block, which is a new identity: onboard it as a new
network ([federation](federation.md#onboard-an-authority)).
