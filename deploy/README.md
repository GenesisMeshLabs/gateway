# Deploying the gateway

| File | What |
| --- | --- |
| `compose.yml` | The released image, by digest, published to host loopback; TLS ingress is yours. Set `GATEWAY_IMAGE`, `GATEWAY_POLICY_FILE`, `GATEWAY_REDIS_URL_FILE` (a `redis://` or `rediss://` URL you operate) and `GATEWAY_QUOTA_NAMESPACE`, and run the service once with `--init-state` before the first start. See `docs/distribution.md` |
| `kubernetes.yaml` | Two replicas, a ClusterIP service, a disruption budget and spread scheduling; see `docs/distribution.md` |
| `secrets-store-csi.yaml` | A provider-neutral volume fragment for mounting the policy and secrets from your secrets manager; see `docs/platform.md` |
| `docker-compose.yml` | The gateway built from this checkout with a shared quota store and a Cloudflare tunnel. It needs `.local/policy.json`, `.local/redis.url` and `.local/redis.conf`, and `--init-state` once; see the README's *Run* section |
| `docker-compose.quick.yml` | Overlay for an ephemeral Cloudflare quick tunnel |
| `cloudflared/` | An example tunnel configuration and `finish-setup.sh`. Its hostname is that of the former 2026-09 deployment; the public console no longer runs through it. Replace the tunnel ID and hostname with your own |

The image itself (`Dockerfile`) stays at the repository root, because each
release builds it from its own tag. Deployment files for the Network
Authority are in the `genesismesh` repository's `deploy/` folder.
