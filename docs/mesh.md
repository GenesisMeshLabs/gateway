# Live mesh overview

The console loads `/v1/mesh` without a bearer token. It renders approved trust
domains, directed active recognition treaties and explicitly published signed
memberships. Gateway routes, treaties and memberships have different line styles.
Select a domain, membership or treaty to inspect its current record details.

## Publication controls

Set `public_mesh: true` on each network you intend to publish in the gateway
security policy. The default is false. Only treaties between published domains
appear. A membership also needs `claims.public_mesh: true`; private subjects,
arbitrary claims, keys, origins and credentials are excluded from this projection.
The diagram is an authority-reported read model, not a replacement for signature
verification or a guarantee that a member operates a reachable application.

### Members

Network Authorities from Genesis Mesh 1.0.2 list attestations to operators
only and give everyone else the count. To show a network's members, give the
gateway a `read`-tier operator key for that authority: the tier opens the
attestation list and the node roster and nothing else.

```json
"mesh_reader": {"key_id": "mesh-reader", "seed_file": "/run/gateway/mesh-reader.key"}
```

The seed file holds the key's base64 Ed25519 seed (lines starting with `#`
are skipped, so a key written by `genesis-mesh keygen node` works). The
gateway reads it at start and fails to start if it cannot. Each member read
carries a version 2 admin signature for `GET /attestations?status=active`
with the authority's public key from `anchors` (the CRL issuer's key) as its
audience. On the authority, add the public key to `OPERATOR_PUBLIC_KEYS_JSON`
and `"mesh-reader": "read"` to `OPERATOR_KEY_TIERS_JSON`. `mesh_reader`
requires `public_mesh` and `authority_url`. Without it the network shows no
members; a refused key is logged as `authority refused the mesh reader key`.

The endpoint coalesces concurrent refreshes and caches for 20 seconds. Each
authority read has a four-second deadline and a 2 MiB response bound. It exposes
up to 16 domains, 256 active treaties and 64 public memberships per domain. The
diagram draws six memberships per domain; the counts include the full bounded
projection. Expired, revoked and not-yet-valid records are excluded. Unavailable
authorities and stale browser snapshots are shown explicitly.

## Demonstration records

`../sandbox/tests/gateway-mesh/bootstrap_demo_mesh.py` creates real operator-authorized `role:client`
treaties and three signed demo memberships per supplied network. It imports
signed revocation feeds and verifies every demo membership across each treaty.
It reuses compatible active records and does not replace recognition policy.
Records expire after 30 days; rerun to reuse or renew expiring demo records.

```powershell
python ../sandbox/tests/gateway-mesh/bootstrap_demo_mesh.py --token-file /private/service.token `
  --authority network-a=/private/network-a/operator.key `
  --authority network-b=/private/network-b/operator.key
```

Requires Python with `cryptography`. Operator seeds remain local. Demo subjects
are illustrative participants, not deployed public-sector applications.

For reference authorities that do not renew inactive CRLs automatically,
`../genesismesh/scripts/authority_ops/refresh_authority_crl.py` can run hourly in the authority's Python
environment. It retains existing revocations, advances sequence numbers and
signs with the authority's existing key under a SQLite write transaction.
Never extend a CRL's timestamps without re-signing it on its authority host.

## Latency branch review

Reviewed `connectorzzz26/gateway` branch
`cursor/gateway-latency-throughput-c2a4` at `8b3c87e` for this release.

Cached parsed keys, prepared revocation indexes, direct certificate signing
serialization, TCP_NODELAY, runtime sizing and the nondeprecated timeout layer
were already present in this gateway. The remaining general canonical-JSON
capacity reservation and sorted-map iteration optimization were adapted here.
The sorted-map path retains a fallback when downstream dependency feature
unification enables `serde_json/preserve_order`.

The branch's inline CPU execution and global Rayon batch pool were not imported:
this gateway keeps CPU work bounded separately from HTTP admission, with permits
owned by running jobs even after cancellation. The branch's weaker issuer and
revocation handling is also superseded by current production security checks.
No new latency percentage is claimed without a comparable benchmark.
