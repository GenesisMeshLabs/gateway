# Genesis Mesh Rust Gateway

A Rust trust-verification gateway built on Genesis Mesh portable trust. It serves
an embedded API explorer, validates signed join certificates against operator
policy, and synchronizes signed revocation snapshots from Genesis Mesh authorities.

**Live console:** https://mesh.genesismesh.org/

Production mode requires individually scoped service credentials and approved
trust policy. It holds no Network Authority signing key. With `mesh_reader`, it
holds one read-tier operator key per published network, which can read the
attestation list and node roster and nothing else. The Python Genesis Mesh
implementation remains the protocol authority; interoperability fixtures pin
canonical JSON and signature compatibility.

## Included

- Per-client network authorization and request quotas.
- Optional pinned OIDC identity, native mutual TLS and Redis quotas shared by replicas.
- Durable per-issuer CRL checkpoints and a SQLite audit outbox with acknowledged HTTPS delivery.
- Pinned Ed25519 authority keys, required roles, fresh signed CRLs and sequence checks.
- Native Rust CRL refresh from configured authority endpoints every sixty seconds.
- Cancellation-safe worker limits, bounded bodies/batches, request deadlines.
- JSON audit logs, request correlation, Prometheus metrics and readiness probes.
- Responsive endpoint explorer, scoped network data and OpenAPI 3.1.
- Public demo access (`GET /v1/demo`, read and verify only, enforced at startup)
  and a guided tour of portable trust in the console.
- 110 scoped Network Authority operations: every SDK service area, boundary
  policies, the execution evidence store, changes outside the controlled path,
  remediation and reviews, the NA key history and key succession, archives,
  pre-issued grants, edge nodes, enrollment, discovery, treaties and administration, with browser-side
  operator signing. Audit packs are built against the authority, not through
  the gateway (see [authority services](docs/services.md#the-audit-pack-is-not-forwarded)).
- Non-root container with read-only filesystem and constrained resources.

See [platform controls](docs/platform.md) for activation, persistent-volume bootstrap,
secrets-manager mounts, recovery tests and external production acceptance gates.

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
| GET | `/v1/mesh` | Public opt-in mesh view |
| GET | `/v1/demo` | Public demo token, when a demo client is configured |
| GET/POST/DELETE | `/v1/networks/{network}/services/{operation}` | Network and service-group scope; operator signatures for admin operations |
| GET | `/metrics` | Bearer token with metrics permission |
| POST | `/verify` | Bearer token with certificate network permission |
| POST | `/verify/batch` | Bearer token with every certificate network permission |

Production verification bodies contain `certificate` or `certificates`; callers
cannot override operator anchors or revocation data. Check `trusted` in each
response, even when HTTP status is 200. Certificate verification does not prove
private-key possession or authorize arbitrary application actions.

## Run

Each release publishes a signed image, `ghcr.io/genesismeshlabs/genesis-mesh-gateway`,
for `linux/amd64` and `linux/arm64`; verify it and deploy by digest (see
[distribution](docs/distribution.md)).

For a first production-mode gateway in front of a local authority, follow the
[quickstart](docs/quickstart.md). Provision the policy and credentials described
in [operations](docs/operations.md).

To build and run from this checkout with Compose, put three files in `.local/`,
which is excluded from Git and the container build context:

- `.local/policy.json`: the gateway policy;
- `.local/redis.url`: the URL of the `quota` service, such as
  `redis://:PASSWORD@quota:6379/`;
- `.local/redis.conf`: that service's Redis configuration, with the password
  the URL uses (`requirepass`); see
  [platform controls](docs/platform.md#shared-quotas-and-availability) for
  the persistence and eviction settings it needs.

The gateway keeps durable state, so initialize it once, then start it:

```sh
docker compose -f deploy/docker-compose.yml build gateway
docker compose -f deploy/docker-compose.yml run --rm gateway --init-state
docker compose -f deploy/docker-compose.yml up -d gateway
```

See [platform controls](docs/platform.md#durable-state-and-recovery) for what
`--init-state` checks. The public console at mesh.genesismesh.org runs the
released image behind Caddy; its stack is `infrastructure/mesh-demo` in the
`genesismesh` repository.
To operate outside Docker, set `GATEWAY_POLICY_FILE` and run
`cargo run --locked --bin genesis-mesh-gateway`. Default bind is loopback.
Every setting is in the [configuration reference](docs/configuration.md).

Local crypto utility mode requires `GATEWAY_DEVELOPMENT=true` and a
`GATEWAY_TOKEN` of at least 32 bytes. Only this explicit mode enables `/keygen`
and `/issue`; never use it for a public production service. `smoke.sh` checks a
development-mode gateway end to end. The standalone `genesis-mesh` CLI remains
available for local signing and interoperability work; see [the CLIs](docs/cli.md).

## Verify

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
node --test tools/test_ui_*.mjs
cargo build --locked --release --bin genesis-mesh-gateway
```

See [the architecture](docs/architecture.md) for the module map, the layers and
where a change goes, and [CONTRIBUTING](CONTRIBUTING.md) for pull request rules.

See [deployment, security boundaries and remaining rollout gates](docs/operations.md).
This implementation is not a government accreditation, compliance certification,
or complete Genesis Mesh Network Authority.

## Distribution and replicas

See [distribution](docs/distribution.md) for the signed release image, signed
binary bundles, configuration validation and Kubernetes rolling deployments. The
`--check-config` command validates operator policy without starting the server.

See [authority services](docs/services.md) for the full service catalog, browser
workflow, per-client permissions and authority persistence requirements.

### Live mesh

The console includes an opt-in public mesh visualization of live authorities, directed recognition treaties and explicitly published signed memberships. See [mesh operations](docs/mesh.md) for publication controls, demo setup and the latency branch review.

## Documentation

**Run it**

- [Quickstart](docs/quickstart.md): a production-mode gateway in front of a
  local authority.
- [Operations](docs/operations.md): the deployment boundary, policy, responses
  and metrics.
- [Configuration reference](docs/configuration.md): every setting.
- [Platform controls](docs/platform.md): durable state, audit, OIDC, mutual
  TLS and shared quotas.
- [Distribution](docs/distribution.md): the signed image, ZIPs and replicas.
- [Key succession](docs/key-succession.md): when an authority replaces its
  NA key.

**Use it**

- [Authority services](docs/services.md): the catalog and the console.
- [Live mesh](docs/mesh.md) and [federation](docs/federation.md).
- [The CLIs](docs/cli.md): `genesis-mesh-gateway`, `genesis-mesh-operator`
  and `genesis-mesh`.

**Develop**

- [Architecture](docs/architecture.md) and [CONTRIBUTING](CONTRIBUTING.md).
- [Security policy](SECURITY.md).

**Records** (dated; not updated)

- [Deployment record, 2026-09-06](docs/deployment-record-2026-09-06.md) and
  [acceptance, 2026-09-07](docs/acceptance-2026-09-07.md).
- [Security assurance plan](docs/security-assurance-plan.md) and
  [security findings, 2026-09-07](docs/security-findings-2026-09-07.md).
- [The improvement plan (2026-09, v0.57.2)](docs/improvement-plan.md) and
  [ADR 0001](docs/adr/0001-deployment-authentication.md).
- [Native Windows services (2026-09-11)](docs/windows-services.md).
