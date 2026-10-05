# Deploying the gateway

| File | What |
| --- | --- |
| `compose.yml` | The released image, by digest, published to host loopback; TLS ingress is yours. See `docs/distribution.md` |
| `kubernetes.yaml` | Two replicas, a ClusterIP service, a disruption budget and spread scheduling; see `docs/distribution.md` |
| `secrets-store-csi.yaml` | A provider-neutral volume fragment for mounting the policy and secrets from your secrets manager; see `docs/platform.md` |
| `docker-compose.yml` | The gateway built from this checkout with a shared quota store and a Cloudflare tunnel; run from the repository root with `docker compose -f deploy/docker-compose.yml up -d` |
| `docker-compose.quick.yml` | Overlay for an ephemeral Cloudflare quick tunnel |
| `cloudflared/` | The tunnel configuration and `finish-setup.sh` |

The image itself (`Dockerfile`) stays at the repository root, because each
release builds it from its own tag. Deployment files for the Network
Authority are in the `genesismesh` repository's `deploy/` folder.
