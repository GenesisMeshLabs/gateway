# Genesis Mesh Gateway

A concurrent HTTP gateway for **Genesis Mesh portable trust**, implemented in
Rust. It embeds the trust core — Ed25519 identities, canonical JSON, signed join
certificates, revocation, trust evaluation — and exposes it as a small JSON API
that runs in a container behind a Cloudflare tunnel.

| Layer | What it is |
|---|---|
| `src/crypto`, `src/canonical`, `src/models`, `src/trust` | the portable-trust core — the bytes every participant must agree on |
| `src/gateway` | the HTTP surface: router, middleware, handlers |
| `src/main.rs` | the `genesis-mesh-gateway` binary |
| `src/bin/genesis_mesh.rs` | the dependency-free `genesis-mesh` CLI, kept for shell use |

It is **stateless** and holds no keys: `/issue` signs with the seed in the
request body, exactly as `genesis-mesh issue --seed …` does.

## API

| Method | Path | Auth | Body → Result |
|--------|------|------|---------------|
| GET | `/` | – | endpoint listing |
| GET | `/health` | – | `{ "status": "ok" }` |
| POST | `/keygen` | ✔ | – → `{ seed_b64, public_key_b64 }` |
| POST | `/issue` | ✔ | `{ seed_b64, key_id, node_public_key, network_name, roles?, days? }` → the signed `JoinCertificate` |
| POST | `/verify` | ✔ | `{ certificate, anchors: {key_id: pubkey_b64}, crl? }` → `{ trusted, reasons[] }` |
| POST | `/verify/batch` | ✔ | `{ certificates[], anchors, crl? }` → `{ results[] }` — Rayon-parallel |

Auth is `Authorization: Bearer <GATEWAY_TOKEN>` on every route except `/` and
`/health`, active only while `GATEWAY_TOKEN` is set.

### Concurrency model

A sized multi-thread Tokio runtime (one worker per core, blocking pool capped
by `GATEWAY_MAX_BATCH_INFLIGHT`) runs the server. Single-certificate routes
(`/keygen`, `/issue`, `/verify`) run inline — one Ed25519 op is cheaper than a
`spawn_blocking` handoff. `/verify/batch` decodes anchors and verifies the CRL
once, then fans batches of 16+ across Rayon from a blocking worker. A `tower`
stack adds a per-request timeout, a request-body cap, TCP_NODELAY, and inflight
limits that shed with `503`. `/health` is excluded from the inflight cap.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `GATEWAY_ADDR` | `0.0.0.0:8080` | bind address |
| `GATEWAY_TOKEN` | *(unset)* | bearer token; unset ⇒ no auth |
| `GATEWAY_TIMEOUT_MS` | `15000` | per-request timeout |
| `GATEWAY_MAX_BODY_BYTES` | `1048576` | max request body |
| `GATEWAY_MAX_INFLIGHT` | `512` | concurrent authenticated requests before `503` |
| `GATEWAY_MAX_BATCH` | `1024` | max certs per `/verify/batch` |
| `GATEWAY_MAX_BATCH_INFLIGHT` | `4` | concurrent `/verify/batch` requests before `503` |
| `RUST_LOG` | `info,tower_http=warn` | tracing filter |

## Run

```bash
cargo test
cargo run --bin genesis-mesh-gateway        # http://localhost:8080

# or in Docker
docker compose up --build -d gateway
BASE=http://localhost:8080 TOKEN=$(grep -oP '(?<=GATEWAY_TOKEN=).*' .env) bash smoke.sh
```

## Expose through a named Cloudflare tunnel

One-time, on the host (needs a Cloudflare account with a zone):

```bash
cloudflared tunnel login
cloudflared tunnel create genesis-mesh-gateway
cloudflared tunnel route dns genesis-mesh-gateway mesh.example.com
bash cloudflared/finish-setup.sh mesh.example.com
```

`finish-setup.sh` stages the tunnel credentials into `cloudflared/`, renders
`cloudflared/config.yml`, and runs `docker compose up -d` — starting the
`cloudflared` connector alongside the gateway on one Docker network, serving
`https://mesh.example.com` → `http://gateway:8080`. The gateway's own port is
published only on `127.0.0.1`; the tunnel is the sole public path.

For a throwaway public URL with no account, use the quick-tunnel overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.quick.yml up -d gateway cloudflared-quick
docker compose -f docker-compose.yml -f docker-compose.quick.yml logs cloudflared-quick   # the *.trycloudflare.com URL
```

## Interoperability

The Python implementation in `../genesismesh/` is the wire authority. Two details
silently break every signature if wrong, and `src/canonical.rs` handles both:

- **Canonical JSON escapes non-ASCII** as `\uXXXX` (Python's `ensure_ascii=True`),
  with UTF-16 surrogate pairs above the BMP. `serde_json` emits raw UTF-8.
- **Timestamps** render with either no fractional seconds
  (`2026-01-01T12:00:00Z`) or exactly six digits
  (`2026-01-08T12:30:45.500000Z`). Always `Z`.

`tests/interop.rs` pins both against vectors from `tools/gen_vectors.py`.
Regenerate them whenever the Python canonical form changes:

```bash
python tools/gen_vectors.py
```

## Next steps

- Prometheus `/metrics`
- per-token rate limiting + audit events (mirroring the Python Network Authority)
- `POST /issue-crl` — sign a revocation list, not just join certificates
- `criterion` throughput bench for `/verify/batch`
