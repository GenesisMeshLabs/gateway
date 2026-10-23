# Configuration reference

The gateway reads its settings from the environment once, at startup.
Changing one needs a restart. Policy, credentials and trust material are in
the policy file (`GATEWAY_POLICY_FILE`); its format is in
[operations](operations.md#policy-format).

**Checked** says what validates a setting before the server starts:

- *check-config*: `genesis-mesh-gateway --check-config` reads and checks it,
  as does a normal start.
- *start*: only a normal start reads it. `--check-config` does not, so an
  invalid value fails at startup instead. These settings are read in
  `gateway/tls.rs`, `gateway/audit_delivery.rs` and `main.rs`.

## Mode, policy and state

| Setting | Default | Valid values | Checked | Details |
| --- | --- | --- | --- | --- |
| `GATEWAY_ADDR` | `127.0.0.1:8080`; the image sets `0.0.0.0:8080` | A socket address | check-config | [Operations](operations.md#deployment-boundary) |
| `GATEWAY_DEVELOPMENT` | `false` | `true` or `false` | check-config | Local utility mode with `/keygen` and `/issue`; never in production. Refuses a policy file. |
| `GATEWAY_TOKEN` | unset | 32 to 1024 bytes | check-config | Development mode only; production refuses it. |
| `GATEWAY_POLICY_FILE` | unset; required in production | A JSON file of at most 16 MiB | check-config | [Operations](operations.md#policy-format) |
| `GATEWAY_STATE_FILE` | unset (no durable state) | A SQLite file, created once with `--init-state` | check-config | [Platform controls](platform.md#durable-state-and-recovery) |

## Identity and quotas

| Setting | Default | Valid values | Checked | Details |
| --- | --- | --- | --- | --- |
| `GATEWAY_OIDC_FILE` | unset (bearer tokens only) | A JSON file | check-config | [Platform controls](platform.md#organization-identity-and-mounted-secrets) |
| `GATEWAY_REDIS_URL_FILE` | unset (process-local quotas) | A file holding a `redis://` or `rediss://` URL | check-config | [Platform controls](platform.md#shared-quotas-and-availability) |
| `GATEWAY_QUOTA_NAMESPACE` | unset; required with `GATEWAY_REDIS_URL_FILE` | The same string on every replica of one quota domain | check-config | [Platform controls](platform.md#shared-quotas-and-availability) |
| `GATEWAY_TLS_CERT_FILE`, `GATEWAY_TLS_KEY_FILE`, `GATEWAY_TLS_CLIENT_CA_FILE` | unset (plain HTTP listener) | PEM files; set all three or none | start | [Platform controls](platform.md#organization-identity-and-mounted-secrets) |

## Resource limits

| Setting | Default | Valid values | Checked | Details |
| --- | --- | --- | --- | --- |
| `GATEWAY_TIMEOUT_MS` | `15000` | 1 to 300000 | check-config | Request deadline; `408` when it passes |
| `GATEWAY_MAX_BODY_BYTES` | `1048576` | 1 to 16777216 | check-config | `413` above it |
| `GATEWAY_MAX_INFLIGHT` | `32` | 1 to 4096 | check-config | [Distribution](distribution.md#runtime-limits-per-replica) |
| `GATEWAY_MAX_BATCH` | `128` | 1 to 4096 | check-config | Certificates per `POST /verify/batch` |
| `GATEWAY_CPU_WORKERS` | `2` | 1 to 256 | check-config | [Distribution](distribution.md#runtime-limits-per-replica) |
| `GATEWAY_MAX_BATCH_JOBS` | `1` | 1 to `GATEWAY_CPU_WORKERS`, and below it when there is more than one worker | check-config | [Distribution](distribution.md#runtime-limits-per-replica) |
| `TOKIO_WORKER_THREADS` | `2` | 1 to 256 | start | Async scheduler threads |
| `TOKIO_MAX_BLOCKING_THREADS` | `16` | 1 to 512 | start | Blocking pool cap |

## Audit and logs

| Setting | Default | Valid values | Checked | Details |
| --- | --- | --- | --- | --- |
| `GATEWAY_AUDIT_RETENTION_DAYS` (1.8.0) | `7` | 0 to 3650; 0 keeps every row | check-config | [Platform controls](platform.md#audit) |
| `GATEWAY_AUDIT_URL` | unset (no collector) | An HTTPS URL | start | [Platform controls](platform.md#audit) |
| `GATEWAY_AUDIT_TOKEN_FILE` | unset | A file holding the collector's bearer token | start | [Platform controls](platform.md#audit) |
| `RUST_LOG` | `info,tower_http=info` | A `tracing` filter, such as `info` or `warn,genesis_mesh=info` | start | JSON logs on stdout; [operations](operations.md#observability-and-incident-response) |

`deploy/compose.yml`, `deploy/docker-compose.yml` and
`deploy/kubernetes.yaml` set the resource limits to these defaults
explicitly. `deploy/docker-compose.yml` takes `RUST_LOG` from
`GATEWAY_LOG_FILTER`.
