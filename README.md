# Genesis Mesh Rust Gateway

A Rust trust-verification gateway built on Genesis Mesh portable trust. It serves
an embedded API explorer, validates signed join certificates against operator
policy, and synchronizes signed revocation snapshots from Genesis Mesh authorities.

**Live console:** https://mesh.genesismesh.org/

Production mode requires individually scoped service credentials and approved
trust policy. It accepts no authority signing keys. The Python Genesis Mesh
implementation remains the protocol authority; interoperability fixtures pin
canonical JSON and signature compatibility.

## Included

- Per-client network authorization and request quotas.
- Pinned Ed25519 authority keys, required roles, fresh signed CRLs and sequence checks.
- Native Rust CRL refresh from configured authority endpoints every sixty seconds.
- Cancellation-safe worker limits, bounded bodies/batches, request deadlines.
- JSON audit logs, request correlation, Prometheus metrics and readiness probes.
- Responsive endpoint explorer, scoped network data and OpenAPI 3.1.
- 59 scoped Network Authority operations across all seven SDK service areas,
  enrollment, discovery, treaties and administration, with browser-side operator signing.
- Non-root container with read-only filesystem and constrained resources.

## API

| Method | Path | Access |
| --- | --- | --- |
| GET | `/` | Public console |
| GET | `/api` | Public service metadata |
| GET | `/openapi.json` | Public API specification |
| GET | `/health` | Public liveness |
| GET | `/ready` | Public trust readiness |
| GET | `/v1/networks` | Client-authorized networks only |
| GET | `/v1/services` | Public operation catalog and request examples |
| GET/POST/DELETE | `/v1/networks/{network}/services/{operation}` | Network and service-group scope; operator signatures for admin operations |
| GET | `/metrics` | Bearer token with metrics permission |
| POST | `/verify` | Bearer token with certificate network permission |
| POST | `/verify/batch` | Bearer token with every certificate network permission |

Production verification bodies contain `certificate` or `certificates`; callers
cannot override operator anchors or revocation data. Check `trusted` in each
response, even when HTTP status is 200. Certificate verification does not prove
private-key possession or authorize arbitrary application actions.

## Run

Provision the policy and credentials described in [operations](docs/operations.md).
For Compose, place policy at `.local/policy.json`, which is excluded from Git
and container build context. Then:

```sh
docker compose up --build -d gateway
```

The existing named tunnel configuration serves the same Rust process over HTTPS.
To operate outside Docker, set `GATEWAY_POLICY_FILE` and run
`cargo run --locked --bin genesis-mesh-gateway`. Default bind is loopback.

Local crypto utility mode requires `GATEWAY_DEVELOPMENT=true` and a
`GATEWAY_TOKEN` of at least 32 bytes. Only this explicit mode enables `/keygen`
and `/issue`; never use it for a public production service. The standalone
`genesis-mesh` CLI remains available for local signing and interoperability work.

## Verify

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release --bin genesis-mesh-gateway
```

See [the implemented improvement plan](docs/improvement-plan.md) and
[deployment, security boundaries and remaining rollout gates](docs/operations.md).
This implementation is not a government accreditation, compliance certification,
or complete Genesis Mesh Network Authority.

## Distribution and replicas

See [distribution](docs/distribution.md) for portable images, checksummed binary
bundles, configuration validation and Kubernetes rolling deployments. The
`--check-config` command validates operator policy without starting the server.

See [authority services](docs/services.md) for the full service catalog, browser
workflow, per-client permissions and authority persistence requirements.
