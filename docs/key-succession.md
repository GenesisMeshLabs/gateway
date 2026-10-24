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
but it does not use them for its own checks. So the gateway does not follow a
succession on its own: its operator re-pins the network to the new key once
the succession takes effect.

Re-pinning needs an authority on **Genesis Mesh 1.8.0 or later**. From 1.8.0
the CRL names the key that signed it as its `issuer`, so after a succession
it names the new key. Before 1.8.0 the CRL kept the genesis key's ID as its
`issuer` while the new key signed it, and no `anchors` matched it: with such
an authority, the only choice is to remove the network
([below](#remove-the-network)). Ask the authority's operator to upgrade
before they record the succession.

## What happens

| When | What the gateway does |
| --- | --- |
| Before `effective_at` | Nothing changes. The outgoing key still signs the authority's CRLs and certificates. |
| From `effective_at` | The authority signs its CRL again with the new key, under the new key's ID. The gateway refuses it, because its `issuer` is not the network's: each refresh fails and logs `authority refresh failed; retaining verified snapshot`. The gateway keeps the last CRL the outgoing key signed, so revocations the authority records after `effective_at` do not reach it. Certificates the outgoing key signed keep verifying against that CRL. Certificates the new key signs (`issued_by` is the new key ID) are refused with `NetworkPolicyRejected`; that includes renewals. |
| When that CRL expires | The network denies every certificate and `GET /ready` answers `503` for the whole gateway, not only for that network. A load balancer that follows readiness stops sending the replica any traffic. |

The authority signs a CRL for 24 hours and signs a new one when less than 12
remain, and the gateway reads it every minute. So the last CRL the outgoing
key signed expires between 12 and 24 hours after `effective_at`. A
revocation just before `effective_at` makes it close to 24 hours. Read the
exact time from `GET /v1/networks`: `revocation.next_update` of that network.

Re-pinning the network ends this at once. Do it after `effective_at` and
before `revocation.next_update`.

## Why it waits for `effective_at`

The gateway changes a network's keys only when it reads its policy, at
startup, and it accepts a refreshed CRL only from the network's configured
`issuer`. Before `effective_at` there is no CRL under the new key to start
from, and after it the authority no longer refreshes one under the outgoing
key. So the switch is one step, made after `effective_at`:

- Adding the new key to `anchors` beforehand changes nothing: the refreshed
  CRL is still refused, because its `issuer` changed.
- Keeping the outgoing key as an `additional_issuers` entry after the switch
  needs a CRL under that key's ID, which the authority no longer refreshes.
  When it expires the gateway goes not ready.

## What to do

Plan this with the authority's operator before they submit the succession.
Ask for `effective_at`, the new key's ID and public key, and confirm that the
authority runs 1.8.0 or later. Confirm the key through an independent
channel, as when you onboarded the authority, and check that the *Key
history* operation lists it with that `effective_at`.

### Re-pin the network

Wait until the succession has taken effect and the authority's holders have
renewed their certificates. Mesh nodes from 1.8.0 renew a certificate the
outgoing key signed on their own, within 10 minutes of `effective_at`. Ask
the authority's operator about other holders.

1. Read the authority's CRL (`GET /crl` on the authority; the network's
   `crl_url`). Check that its `issuer` is the new key's ID, that
   `next_update` is in the future, and that its `sequence` is not below the
   one in `GET /v1/networks`.
2. Change the network in the policy:
   - `anchors`: only the new key, `{"NEW_KEY_ID": "NEW_PUBLIC_KEY"}`;
   - `crl`: that CRL, unchanged;
   - `minimum_crl_sequence`: its `sequence`.

   Leave the rest of the network as it is. `genesis-mesh-operator` does not
   build this fragment: its preflight checks the key against the genesis
   block, which names the genesis key.
3. Give the policy a new `revision`, then run the check against it:

   ```sh
   GATEWAY_POLICY_FILE=/path/to/new-policy.json genesis-mesh-gateway --check-config
   ```

   With durable state on, run the check against a stopped replica or a
   consistent backup of its state, not the live database.
4. Roll the new policy to every replica (a new versioned Secret on
   Kubernetes; see [distribution](distribution.md#multiple-replicas)). The
   gateway reads policy only at startup.
5. Check each replica:

   ```sh
   curl -fsS https://gateway.example.org/ready
   curl -fsS -H "Authorization: Bearer $TOKEN" https://gateway.example.org/v1/networks
   ```

   `/ready` answers `{"status":"ready"}`, and the network's `revocation`
   names the new key as `issuer`. The log shows `authority snapshot
   synchronized` for the network again.

From then on the gateway refuses certificates the outgoing key signed, as
the authority's nodes do once that key's vouching horizon passes. With
durable state on, the gateway keeps the CRL checkpoint of each issuer
separately: it starts from the new CRL, and the outgoing key's checkpoint
stays in the store, unused.

### Remove the network

Choose this when the authority runs a release before 1.8.0, or when you stop
serving it. Remove it before `effective_at` when revocations must stay
current, or when the gateway must not go not ready at all. Otherwise remove
it before `revocation.next_update`, and tell the network's clients that
certificates the new key signs are refused from `effective_at`.

1. Delete the network from `networks` in the policy, and its name from every
   client's `networks`. `--check-config` refuses a client that names a
   network the policy does not have.
2. Give the policy a new `revision`, check it and roll it out as in steps
   3 and 4 above.
3. Check each replica: `/ready` answers `{"status":"ready"}`, and
   `/v1/networks` no longer lists the network. The durable store keeps the
   removed network's checkpoint; it is not used.

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
