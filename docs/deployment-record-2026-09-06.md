# Deployment record

Date: 2026-09-06. Application version: 0.56.1.

The Rust gateway is deployed at https://mesh.genesismesh.org/ using the existing
Cloudflare Tunnel and Docker Compose on the operator's host. Availability depends
on that host, Docker and the tunnel remaining online. This is a single-host
deployment, not a multi-region or highly available government installation.

## Verified

- Public HTTPS console renders and its endpoint explorer completes live requests.
- `/health`, `/ready`, `/api` and `/openapi.json` return HTTP 200.
- Authenticated `/v1/networks` returns both configured networks as ready.
- Authenticated `/metrics` returns Prometheus output.
- Unauthenticated protected requests return 401; authenticated requests to the
  removed production signing/key-generation routes return 404.
- Both pinned Genesis Mesh authorities synchronize signed CRLs through the native
  Rust refresh task; synchronization events appear in JSON audit logs.
- 50 Rust tests pass, including Python interoperability, security boundaries,
  cancellation-safe workers, and CRL refresh progress/rollback/forgery checks.
- Formatting and Clippy with warnings denied pass; Linux release container builds.

Policy and credentials are excluded from Git and Docker build context. The
operator credential is preserved locally in `.local/service.token` for use in
the console. Do not publish this file or distribute it to untrusted clients.
Provision narrower per-service credentials for production integrations.

The previous container image is retained as
`genesis-mesh-gateway:pre-enterprise`. Rolling back also requires restoring the
previous Compose environment because the old service uses a different auth model.
Do not roll back the trust policy's revocation sequence without incident review.

The version 0.2.0 image is also retained locally as
`genesis-mesh-gateway:pre-distribution` for this update. The 0.3.0 candidate passed
readiness and authenticated network/metrics checks before replacing the public
container. Both local replicas served ready snapshots and distinct request IDs.
After replacement, public HTTPS checks passed for the console, API version,
readiness, OpenAPI, authenticated networks and latency metrics. The browser
console reports Rust v0.3.0, Operational and Ready.

The Windows release ZIP passed archive integrity, version, manifest and SHA-256
checks. Distribution files contain no operational credentials or policy.
Compose and Kubernetes distribution templates parse successfully; Kubernetes
client validation could not complete because the configured cluster requires
credentials. No Kubernetes deployment or multi-host availability is claimed.
See [distribution](distribution.md) for deployment and consistency boundaries.

The final Docker build cross-compiles on the builder's native CPU for Linux
AMD64 and ARM64. Both binaries report version 0.3.0. ARM64 additionally passed
configuration validation and HTTP readiness, API, authenticated network and
metrics checks under local emulation. Native ARM hardware is not yet validated.
The exported Docker archive's OCI index, configuration blobs and layer presence
were checked for both architectures, and a SHA-256 sidecar was generated.
The final AMD64 image was deployed and all public checks repeated successfully.

CI workflows are added but have not been executed by a remote CI service in this
change. Dependency audit and image security scans remain release gates. See
[operations](operations.md) for trust boundaries and
[the improvement plan](improvement-plan.md) for subsequent rollout work.

## Service expansion, v0.56.1

The published console now offers 67 operations, including 59 scoped authority
operations. Local and public HTTPS verification covered signed attestation
issuance/revocation, agreements, boundary decisions, disclosure and evidence.
Local checks also covered data usage, consensus, node lifecycle and signed
discovery. Browser-side operator signing completed a real authority request.

56 gateway tests, Python-compatible browser signing tests and 209 reference
authority tests passed. The two local authorities now use durable data-license
policy storage, with a database backup retained before the additive migration.
The active demonstration data policy survived an actual authority restart.

The local gateway-operator identity retains its original token and is authorized
for the service catalog on both networks. Operator operations additionally
require independently signed X-Admin headers. No authority signing key was added
to the gateway. The pre-services image and policy backup are retained locally;
rolling back to 0.56.0 requires restoring both because it predates service scopes.
