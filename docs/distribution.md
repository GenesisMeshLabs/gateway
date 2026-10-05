# Distributing and scaling the gateway

Use immutable builds with externally supplied policy. A gateway replica needs no
authority private key, session store or sticky client routing. The embedded UI
ships inside the same binary and always calls its own origin.

## Available distribution paths

1. **Published image:** every release tag publishes
   `ghcr.io/genesismeshlabs/genesis-mesh-gateway` for `linux/amd64` and
   `linux/arm64` with SBOM and provenance, signed keylessly by this
   repository's `distribution.yml` (see *Signed release artifacts* below).
   Tags follow the Genesis Mesh rules: `X.Y.Z` is never moved; `X.Y` and
   `latest` follow the newest release. Verify the signature, then deploy by
   digest; mirror it into your approved registry if you need one.
   To build it yourself instead, build `Dockerfile` for either platform. No
   `target-cpu=native` or x86-specific flags are embedded in the portable
   build.
2. **Native binary:** build with `cargo build --locked --release --bin
   genesis-mesh-gateway --bin genesis-mesh-operator`, then run `pwsh tools/package.ps1 -Binary
   target/release/genesis-mesh-gateway -Platform linux-amd64`. Windows uses the
   `.exe` binary and platform `windows-amd64`. The packager checks the version,
   bundles an explicit allowlist, and emits a SHA-256 sidecar plus binary manifest.
3. **Release artifacts:** a release tag runs `distribution.yml`, which builds
   Windows/Linux binary ZIPs and a multi-platform OCI archive of the published
   image (the workflow checks that the archive and the pushed image have the
   same digest), signs them, and attaches them to the GitHub release. A manual
   dispatch, even on a release tag, builds and tests the same artifacts as
   workflow artifacts and publishes nothing: it only reads the registry to
   report whether the version is already published. Ubuntu 24.04 native
   binaries require a compatible glibc (the artifact label records 2.39); the
   Debian-based container avoids that host dependency.

The Docker build runs the Rust compiler on the builder's native CPU and
cross-compiles with explicit GNU linkers for AMD64 and ARM64. Build caches are
separate for each target. This avoids expensive emulated Rust compilation;
emulation may still prepare the small runtime image and run local ARM64 checks.
Use native ARM64 runners for hardware validation and workload benchmarks.
See [Docker's build strategies](https://docs.docker.com/build/building/multi-platform/)
and [Cargo's target linker configuration](https://doc.rust-lang.org/cargo/reference/config.html#targettriplelinker).

Never ship `.local`, `.env`, tunnel credentials, client tokens or operational
policy in the image or archive. The packaging script excludes them by allowlist.
Checksums detect corruption; they are not publisher signatures. The release
signatures below are; verify them before deploying.

For an offline transfer of a locally built multi-platform Docker image:

```sh
docker save -o genesis-mesh-gateway-0.56.1-images.tar genesis-mesh-gateway:0.56.1
# Transfer the archive and its SHA-256 sidecar through your approved channel.
docker load -i genesis-mesh-gateway-0.56.1-images.tar
docker run --rm genesis-mesh-gateway:0.56.1 --version
```

Compare the archive checksum before loading (`sha256sum` on Linux or
`Get-FileHash -Algorithm SHA256` in PowerShell). The local Docker image archive
is separate from the CI-produced OCI archive; import the latter using your
registry's OCI tooling. Keep the original archive for rollback. Policy remains
separate and must be provisioned for the destination authorities and clients.

## Validate configuration before rollout

Set `GATEWAY_POLICY_FILE` to the local policy file, then run:

```sh
genesis-mesh-gateway --version
genesis-mesh-gateway --check-config
```

The check validates policy and signatures without opening a listener or printing
credentials. An authentic expired bootstrap CRL with a configured source URL is
allowed to start but remains not ready until refresh succeeds. A configuration
check alone is therefore not proof of readiness.

Use `deploy/compose.yml` with `GATEWAY_IMAGE` set to a verified image digest and
`GATEWAY_POLICY_FILE` set to an absolute file path. The generic distribution has
no Cloudflare account or developer-host dependency. TLS ingress is operated
separately; Compose publishes only to host loopback.

## Multiple replicas

`deploy/kubernetes.yaml` provides a ClusterIP service, two replicas, zero
unavailable pods during updates, a disruption budget, and scheduling across at
least two eligible nodes. Replace its image digest placeholder with the digest
you verified, create the
`gateway-policy` Secret with the key `policy.json`, then apply it in your intended
namespace. Use reachable HTTPS authority URLs; `host.docker.internal` is specific
to the local Docker deployment and must not be copied to another environment.

Put your authenticated TLS ingress in front of the service. Restrict ingress and
egress using cluster network policy appropriate to your actual ingress, DNS and
authority destinations. This template deliberately does not invent those
addresses or install a new public load balancer.

Create a **new versioned policy Secret** for each rollout, update the Deployment's
Secret reference, and wait for readiness before retiring old pods. Updating a
mounted Secret in place does not reload process configuration. Coordinate urgent
credential revocation across every replica; old pods otherwise retain old client
credentials until stopped. Keep the previous image and policy revision for
rollback, but never roll back revocation sequence floors.

## Runtime limits per replica

| Setting | Default | Purpose |
| --- | --- | --- |
| `GATEWAY_MAX_INFLIGHT` | 32 | HTTP admission, with health/readiness exempt |
| `GATEWAY_CPU_WORKERS` | 2 | Concurrent blocking crypto jobs |
| `GATEWAY_MAX_BATCH_JOBS` | 1 | Batch subset of CPU jobs |
| `GATEWAY_MAX_BATCH` | 128 | Certificates per batch |
| `TOKIO_WORKER_THREADS` | 2 | Async scheduler threads |
| `TOKIO_MAX_BLOCKING_THREADS` | 16 | Explicitly applied runtime pool cap |

For CPU capacity greater than one, the batch cap must be smaller than CPU
capacity. This reserves admission capacity for single requests during batch
load. On a one-worker deployment, no such reservation is possible. Blocking
capacity also serves DNS and bounded background CRL preparation; do not reduce
it below the combined workload without measuring. CPU jobs retain admission
permits after client disconnects or HTTP timeout.

Certificate limits are eight signatures, 32 roles, 256-byte identifiers,
128-byte roles, and the fixed encoded key/signature lengths. These are gateway
admission limits, not changes to the canonical Genesis Mesh wire format.

## Consistency and observability

Every replica independently verifies snapshots from its pinned authorities.
Snapshots are immutable during each verification/batch. Replicas can briefly
observe different valid CRL sequences during refresh or outages. This is not
linearizable distributed authorization. A stale snapshot stops granting trust.
Enable GATEWAY_STATE_FILE on a persistent per-replica volume to preserve verified high-water marks across restarts. Configure the Redis adapter and shared namespace for coordinated client quotas. See [platform controls](platform.md) for initialization, fail-closed recovery and backend availability requirements.

Request IDs contain a random boot ID and local sequence, avoiding collisions
between replicas. Audit stdout uses a bounded 8192-line background writer with
backpressure instead of silent dropping. The separate SQLite audit sink is durable when GATEWAY_STATE_FILE is set; optional acknowledged HTTPS delivery is available.
Collect logs centrally and monitor collector health. Prometheus exposes an
aggregate request-duration histogram in seconds, with sub-millisecond buckets.
It covers all HTTP requests, including health checks; add workload-specific
measurements for capacity decisions.

Validate a rollout with public readiness, authenticated network snapshots,
signature acceptance/rejection, and mixed single/batch load. Compare p99 and
accepted certificates per second at the same CPU quota before making performance
claims. Kubernetes templates and CI workflows require execution in your own
cluster/CI before treating them as verified deployments.

## Signed release artifacts

Tagged releases sign and immediately verify the registry image, each native ZIP
and the multiarchitecture OCI archive with Sigstore. Verify the image by digest:

```sh
IMAGE=ghcr.io/genesismeshlabs/genesis-mesh-gateway
DIGEST="$(docker buildx imagetools inspect "$IMAGE:1.1.0" --format '{{json .Manifest.Digest}}' | tr -d '"')"
cosign verify "$IMAGE@$DIGEST" \
  --certificate-identity https://github.com/GenesisMeshLabs/gateway/.github/workflows/distribution.yml@refs/tags/v1.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Use cosign 3 or later: the release workflow signs with cosign 3's bundle
format, which cosign 2 reports as `no signatures found`. The GitHub release
notes list the image digest.

For the archive and ZIPs, download the matching `.sigstore.json` bundle and
verify each file before extracting or importing it:

```sh
cosign verify-blob gateway-oci.tar --bundle gateway-oci.tar.sigstore.json \
  --certificate-identity https://github.com/GenesisMeshLabs/gateway/.github/workflows/distribution.yml@refs/tags/v0.57.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The OCI archive contains BuildKit SBOM and provenance attestations for both
architectures. The signature covers the archive bytes, including the
attestations. Verify native ZIPs with the same command and their matching
bundle. See [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/).

Import the archive with an OCI-aware registry tool such as skopeo; it is not a
Docker `save` archive. Its index names the image
`ghcr.io/genesismeshlabs/genesis-mesh-gateway:latest` whatever the release, so
name it when you import it, and deploy it by the digest the release notes list:

```sh
skopeo copy --all --preserve-digests oci-archive:gateway-oci.tar \
  docker://registry.example.com/genesis-mesh-gateway:1.1.0
```
