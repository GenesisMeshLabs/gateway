# Federation operations

Each operator controls their own authority, keys and recognition policy. Gateway
access does not create recognition. Treaties are directed and scoped; the reverse
relationship requires a separate decision by the other operator.

## Onboard an authority

Build the native tool with `cargo build --locked --release --bin genesis-mesh-operator`.
Confirm the sovereign name and authority public key through an independent channel:

```text
genesis-mesh-operator --origin https://na.example.org --network example --authority-key BASE64_PUBLIC_KEY --report preflight.json --policy-fragment network.json
```

The tool checks signed genesis self-consistency, the pinned authority key, CRL
freshness, membership revocation feed identity/signature/freshness, delegation
expiry and catalog shape. Redirects are rejected, reads have an eight-second
timeout and a 2 MiB limit. Private HTTP requires `--allow-http`.
Failed checks produce a nonzero exit and no policy fragment. Root ownership still
requires out-of-band confirmation. This is limited wire compatibility evidence,
not full RFC conformance or proof of an independent authority implementation.

Review the fragment before adding it to gateway policy. Publication defaults off.
Run the gateway configuration check before reloading. Never replace an existing
CRL high-water mark with an older sequence. Expired authority delegation must be
renewed and signed by that sovereign's operator; the gateway does not renew it.

## Recognize and monitor

Connect with your service token, then use the federation form to prepare a scoped
recognition request. Review the destination, peer key, roles and validity in the
API explorer. Submit using your registered operator signature. The form does not
automatically create reciprocal recognition or grant every role.

The public synchronization table compares a verified publisher feed sequence with
the consumer authority's reported imported sequence. `current` means those numbers
match; it is not proof of consumer liveness or end-to-end rejection. Missing or
unverified data is shown explicitly. The snapshot refreshes every 30 seconds and
the gateway caches it for up to 20 seconds.

Continuous revocation consumption belongs beside each authority. The Python
reference adapter lives in `genesismesh/scripts/authority_ops`, outside the Rust
gateway. It requires pinned peers, an active locally signed treaty and monotonic
feed sequences, and writes an audit event on import. Other implementations need
their own protocol-compatible consumer. No gateway signing key is required.

## Acceptance and recovery runbook

1. Issue a short-lived test membership and verify acceptance by each intended peer.
2. Revoke it at its issuer. Wait for the configured propagation interval, then
   verify rejection at every peer without manually importing a feed.
3. Restart consumers and confirm retained sequence high-water marks and rejection.
4. Alert on unavailable consumers, stale/unverified publishers and sequence lag.
   Investigate source rollback or same-sequence changes; never reset the store to
   make synchronization appear healthy.
5. For key rotation, coordinate signed identity renewal, explicit key pin changes
   and treaty renewal with both operators; preserve revocation history and backups.

The public mesh is a view of opted-in records. Demo memberships are sample trust
records, not deployed applications. External adoption, governance and independent
implementation evidence remain separate Phase 2 milestones.
