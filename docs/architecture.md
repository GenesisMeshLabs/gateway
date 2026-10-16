# Gateway architecture

One crate, `genesis_mesh`, holds two things: a small **trust library**
(canonical JSON, Ed25519, signed documents, trust evaluation) and the **HTTP
gateway** built on it (`src/gateway/`). The binaries are `genesis-mesh-gateway`
(`src/main.rs`) and two command-line tools in `src/bin/`. The console in `ui/`
is embedded in the binary with `include_str!`.

## Modules

| Module | What it does |
| --- | --- |
| `error` | The trust library's error and `Result` types. |
| `time` | Timestamps in the Python reference's exact text form. |
| `canonical` | Canonical JSON, byte-compatible with the Python reference. |
| `crypto` | Ed25519 key pairs, signatures, public key validation. |
| `models` | Join certificates, service manifests, revocation lists, and how each is signed. |
| `admin_auth` | Operator-signed authority request headers. |
| `federation` | Authority origins and signed authority documents fetched from them. |
| `trust` | Evaluates a certificate against anchors and revocations into a `Decision`. |
| `gateway` (`mod.rs`) | `AppState`, the router (open and guarded routes), `run`. |
| `gateway::error` | `ApiError`: the gateway's JSON error responses. |
| `gateway::security` | The operator policy: networks, anchors, clients, scopes, demo clients. |
| `gateway::oidc` | Optional pinned OIDC identity for clients. |
| `gateway::tls` | Native TLS and mutual TLS settings. |
| `gateway::durable` | The SQLite state file: CRL checkpoints, the audit outbox, its migrations. |
| `gateway::quota` | Client quotas shared by replicas through Redis. |
| `gateway::config` | Settings from the environment; opens the state file, OIDC and Redis. |
| `gateway::sync` | Refreshes signed CRLs from the authorities every minute. |
| `gateway::audit_delivery` | Delivers the audit outbox to a collector, and prunes it. |
| `gateway::runtime` | Request observation, metrics, quotas, durable audit events, readiness. |
| `gateway::handlers` | Authentication (`auth`), the in-flight limit, `/api`, `/health`, `/verify`. |
| `gateway::services` | Forwards the authority catalog (`ui/services.json`) with scope checks. |
| `gateway::ui` | The console page, its scripts, the demo token and `/openapi.json`. |
| `gateway::mesh` | The opt-in public mesh view. |

## Layers

A module may use modules in its own layer or a lower one. `tests/architecture.rs`
enforces this table, so a change to it changes that test.

| # | Layer | Modules |
| --- | --- | --- |
| 1 | foundation | `error`, `time` |
| 2 | primitives | `canonical`, `crypto` |
| 3 | documents | `models`, `admin_auth`, `federation` |
| 4 | evaluation | `trust` |
| 5 | gateway policy | `gateway::error`, `gateway::security`, `gateway::oidc`, `gateway::tls` |
| 6 | gateway storage | `gateway::durable`, `gateway::quota` |
| 7 | gateway composition | `gateway::config` |
| 8 | gateway background | `gateway::sync`, `gateway::audit_delivery` |
| 9 | shared state | `gateway::AppState` (defined in `gateway/mod.rs`) |
| 10 | request pipeline | `gateway::runtime` |
| 11 | handlers | `gateway::handlers`, `gateway::services`, `gateway::ui`, `gateway::mesh` |
| 12 | router | `gateway` (`gateway/mod.rs`) |

The crate root (`lib.rs`), `main.rs` and `src/bin/` may use anything. Three
more rules:

- The trust library (layers 1 to 4) never uses `gateway`, and uses none of the
  gateway's frameworks (`axum`, `tower`, `tokio`, `reqwest`, `rusqlite`,
  `redis`, `jsonwebtoken`, `rustls`). Allowed today: `federation` uses
  `reqwest` to fetch authority documents.
- Storage (layer 6) uses no HTTP framework (`axum`, `tower`, `reqwest`).
- Handlers (layer 11) do not reach storage (`durable`, `quota`, or the
  `cfg.durable` and `cfg.distributed_quota` handles); the request pipeline does.
  Allowed today: `handlers` reads the state file's health in `auth` and
  `/api`, and admits clients against the shared quota in `auth`.

The allowed exceptions are listed in `tests/architecture.rs`. The test fails
when a new one appears and when a listed one is gone, so the list only
shrinks.

## A request

Layers run outermost first:

1. `runtime::observe`: request ID, the route template from the router
   (`MatchedPath`), metrics, the audit record, and the completed audit event.
2. The body size limit (`GATEWAY_MAX_BODY_BYTES`) and the request timeout.
3. `handlers::limit_inflight`: sheds with 503 when every permit is taken.
4. Guarded routes only, `handlers::auth`: the bearer token or OIDC identity,
   the started audit event (not for demo clients), then the client's quota.
5. The handler. `services::execute` checks the client's network, service group
   and operator tier, builds the authority URL one encoded segment at a time,
   forwards operator signature headers for admin operations, and relays a
   size-limited JSON (or JSON Lines) answer.

Open routes (console, `/api`, `/openapi.json`, `/health`, `/ready`,
`/v1/services`, `/v1/mesh`, `/v1/demo`) are never written to the durable audit
store. Registering a route in `guarded_routes()` in `gateway/mod.rs` is what
makes it authenticated and audited.

Background tasks: `sync` refreshes CRLs into the policy (`ArcSwap`) and the
state file; `audit_delivery` sends the outbox to `GATEWAY_AUDIT_URL` and prunes
delivered rows.

## Generated and copied files

- `ui/services.json` and the service paths of `ui/openapi.json` are generated
  by `tests/reference/build_service_catalog.py` from a core checkout. The
  gateway's own paths in `ui/openapi.json` are edited by hand.
- `tests/reference/admin_auth.json` is the core's console signing vectors; CI
  compares it byte for byte.
- `tests/vectors.json` comes from `tests/reference/gen_vectors.py`;
  `tests/reference/python-evidence-vectors.json` is a copy of core vectors.

These are marked `linguist-generated` in `.gitattributes`, so pull request
diffs show the code first.

## Where a change goes

### Forward a new core route

The core merges first. Use a branch with the same name in both repositories.

1. `tests/reference/build_service_catalog.py`: a new core routes file needs a
   `GROUPS` entry; add `PATH_GROUPS`, `SERVICE_QUERY` (query parameters the
   core reads in its service layer), `RESPONSE_LIMITS`, `RESPONSE_FORMATS`,
   `NOT_FORWARDED` or an example body as needed.
2. Run `python tests/reference/build_service_catalog.py --core ../genesismesh`
   and commit `ui/services.json` and `ui/openapi.json`.
3. `tests/catalog.rs`: add the operation to `DEMO_ALLOWED_OPERATIONS` only if
   it lands in a demo group and is a read or a verification.
4. Tests in `tests/production.rs`: scope, path and query, error relay.
5. `docs/services.md` and the operation count in `README.md`.

What fails when a step is missed:

- The CI check "Authority catalog and signing vectors match the core"
  (`build_service_catalog.py --check`) when the catalog was not regenerated.
- `catalog::the_demo_token_reaches_only_the_allowed_read_and_verify_operations`
  when a demo group gained an operation, and
  `catalog::every_admin_path_is_an_operator_operation` for an `/admin/` path.
- The "Operation IDs" check when a released operation ID disappears or
  changes incompatibly (it needs the `breaking` label and an `### Upgrading`
  note).

### Add a console view

1. `ui/<area>.js` with the view functions.
2. `tools/test_ui_<area>.mjs`. CI runs every `tools/test_ui_*.mjs`.
3. `gateway/ui.rs`: a handler that serves the script; `gateway/mod.rs`: its
   `/assets/<area>.js` entry in `open_routes()`.
4. `ui/app.js`: the import, and the `VIEWS` and `CHOICES` entries keyed by
   operation ID.
5. A `the_console_serves_its_<area>_views` test in `tests/production.rs`.

What fails: `tools/test_ui_catalog.mjs` when a `VIEWS` or `CHOICES` key is not
a catalog operation; the `the_console_serves_…` test when the script is not
served.

### Add a gateway endpoint

1. The handler in `gateway/handlers.rs`, `gateway/ui.rs` or `gateway/mesh.rs`.
2. One entry in `open_routes()` or `guarded_routes()` in `gateway/mod.rs`.
   Metrics labels and the audit class follow from the router.
3. The path in `ui/openapi.json` (by hand), in `handlers::index`
   (`endpoints`) and in the API table of `README.md`.
4. A test in `tests/production.rs`.

What fails: `gateway::tests::every_guarded_route_writes_started_and_completed_audit_events`
and `a_route_is_either_open_or_guarded` for a guarded route that is not
audited; `tests/architecture.rs` when the handler reaches storage directly.

### Add a setting

1. `gateway/config.rs`: the `Config` field, its parsing in `from_env_inner`
   and its bounds in `validate`.
2. The settings table in `docs/platform.md` or `docs/operations.md`, and
   `deploy/` when it needs a value there.
3. A test of the accepted and refused values.

TLS, audit delivery and Tokio settings are read in `gateway/tls.rs`,
`gateway/audit_delivery.rs` and `main.rs` instead, so `--check-config` does
not check them. Nothing fails today when the docs table is missed.

### Change the durable state schema

Append a migration to `MIGRATIONS` in `gateway/durable.rs`; never edit a
released one. `durable::tests::migration_versions_are_unique_consecutive_and_follow_the_base_schema`
and `a_new_store_has_every_migration` fail when the ladder is wrong. The
durable store is a flagged path: the Maintainer merges it.

### Explain a new authority error in the console

Add the code to `explainFailure` in `ui/errors.js` and a case to
`tools/test_ui_errors.mjs`. Nothing checks yet that the code exists in the
core.

### Change canonical JSON, signing or trust evaluation

Change the core first; regenerate `tests/vectors.json` with
`tests/reference/gen_vectors.py`. `tests/interop.rs` fails when the Rust bytes
or signatures differ from Python's; the property tests in
`tests/properties.rs` fail when canonical form loses a round trip, sorted keys
or ASCII escaping.
