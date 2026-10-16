//! The HTTP gateway: shared state, router assembly, and the server entrypoint.
//!
//! Everything the binary needs lives here so integration tests can build the
//! [`router`] and drive it in-process without binding a socket.
//!
//! CPU work runs under separate HTTP, CPU and batch budgets. Worker permits
//! remain owned by running jobs after request cancellation.

mod audit_delivery;
mod config;
pub mod durable;
mod error;
mod handlers;
mod mesh;
pub mod oidc;
pub mod quota;
mod runtime;
pub mod security;
mod services;
mod sync;
mod tls;
mod ui;

use std::sync::Arc;

use axum::routing::{get, post, MethodRouter};
use axum::serve::ListenerExt;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

pub use config::Config;
pub use error::ApiError;

/// Shared, cheaply-cloneable state handed to middleware and handlers.
#[derive(Clone)]
pub struct AppState {
    /// Parsed configuration.
    pub cfg: Arc<Config>,
    /// Permits for the in-flight-request limit; exhaustion sheds with 503.
    pub inflight: Arc<Semaphore>,
    security: Arc<arc_swap::ArcSwapOption<security::SecurityPolicy>>,
    workers: Arc<Semaphore>,
    batches: Arc<Semaphore>,
    instance_id: Arc<str>,
    metrics: Arc<runtime::Metrics>,
    quotas: Arc<Vec<runtime::Window>>,
    audit_workers: Arc<Semaphore>,
    dev_token_digest: Option<[u8; 32]>,
    authority_http: reqwest::Client,
    mesh_cache: Arc<tokio::sync::Mutex<Option<(std::time::Instant, serde_json::Value)>>>,
}

/// Build the gateway router. Exposed for in-process testing.
pub fn router(cfg: Config) -> Router {
    build_router(cfg).0
}

fn build_router(cfg: Config) -> (Router, AppState) {
    let mut cfg = cfg;
    cfg.prepare().expect("invalid gateway configuration");
    let quotas = (0..cfg.security.as_ref().map_or(0, |s| s.clients.len()))
        .map(|_| runtime::Window::new())
        .collect();
    let dev_token_digest = cfg.token.as_ref().map(|token| {
        use sha2::{Digest, Sha256};
        Sha256::digest(token.as_bytes()).into()
    });
    let state = AppState {
        mesh_cache: Arc::default(),
        authority_http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("authority HTTP client"),
        security: Arc::new(arc_swap::ArcSwapOption::from(
            cfg.security.clone().map(Arc::new),
        )),
        workers: Arc::new(Semaphore::new(cfg.cpu_workers)),
        batches: Arc::new(Semaphore::new(cfg.max_batch_jobs)),
        instance_id: uuid::Uuid::new_v4().simple().to_string().into(),
        metrics: Arc::default(),
        quotas: Arc::new(quotas),
        audit_workers: Arc::new(Semaphore::new(cfg.max_inflight)),
        inflight: Arc::new(Semaphore::new(cfg.max_inflight)),
        cfg: Arc::new(cfg),
        dev_token_digest,
    };

    let open = open_routes()
        .into_iter()
        .fold(Router::new(), |router, (path, route)| {
            router.route(path, route)
        });
    let guarded = guarded_routes(state.cfg.development)
        .into_iter()
        .fold(Router::new(), |router, (path, route)| {
            router.route(path, route)
        })
        // `route_layer`: unknown paths reach the merged fallback (404) without
        // authentication, and are neither audited nor charged to a quota.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            handlers::auth,
        ));

    let app = open
        .merge(guarded)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            handlers::limit_inflight,
        ))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            state.cfg.timeout,
        ))
        .layer(RequestBodyLimitLayer::new(state.cfg.max_body_bytes))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            runtime::observe,
        ))
        .with_state(state.clone());
    (app, state)
}

/// Routes that need no credential. They are never written to the durable
/// audit store, so anonymous traffic cannot fill it.
fn open_routes() -> Vec<(&'static str, MethodRouter<AppState>)> {
    vec![
        ("/", get(ui::page)),
        ("/assets/app.js", get(ui::script)),
        ("/assets/signing.js", get(ui::signing_script)),
        ("/assets/errors.js", get(ui::errors_script)),
        ("/assets/mesh.js", get(mesh::script)),
        ("/assets/tour.js", get(ui::tour_script)),
        ("/assets/remediation.js", get(ui::remediation_script)),
        ("/assets/keys.js", get(ui::keys_script)),
        ("/assets/grants.js", get(ui::grants_script)),
        ("/assets/edge.js", get(ui::edge_script)),
        ("/assets/style.css", get(ui::style)),
        ("/api", get(handlers::index)),
        ("/v1/services", get(services::catalog)),
        ("/v1/mesh", get(mesh::overview)),
        ("/v1/demo", get(ui::demo)),
        ("/openapi.json", get(ui::specification)),
        ("/health", get(handlers::health)),
        ("/ready", get(runtime::ready)),
    ]
}

/// Routes behind client authentication (`handlers::auth`). Every request to
/// one of them is written to the durable audit store when it is configured;
/// registering a route here is what makes it audited.
fn guarded_routes(development: bool) -> Vec<(&'static str, MethodRouter<AppState>)> {
    let mut routes = Vec::new();
    if development {
        routes.push(("/keygen", post(handlers::keygen)));
        routes.push(("/issue", post(handlers::issue)));
    }
    routes.extend([
        (
            "/v1/networks/{network}/services/{operation}",
            axum::routing::any(services::execute),
        ),
        ("/metrics", get(runtime::metrics)),
        ("/v1/networks", get(ui::networks)),
        ("/verify", post(handlers::verify)),
        ("/verify/batch", post(handlers::verify_batch)),
    ]);
    routes
}

/// Parse configuration from the environment, bind, and serve until Ctrl-C.
pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _audit_guard = init_tracing();

    let cfg = Config::from_env().map_err(|e| format!("configuration: {e}"))?;
    tracing::info!(config = ?cfg, "starting genesis-mesh gateway");
    if cfg.development {
        tracing::warn!("development utility endpoints enabled");
    }

    let addr = cfg.addr;
    let tls = tls::from_env()?;
    let (app, state) = build_router(cfg);
    let refresh = sync::start(state.security.clone(), state.cfg.durable.clone());
    let audit_delivery =
        audit_delivery::start(state.cfg.durable.clone(), state.cfg.audit_retention())?;

    if let Some(tls) = tls {
        let handle = axum_server::Handle::new();
        let shutdown = handle.clone();
        let signal = tokio::spawn(async move {
            shutdown_signal().await;
            shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        });
        let result = axum_server::bind_rustls(addr, tls)
            .handle(handle)
            .serve(app.into_make_service())
            .await;
        signal.abort();
        if let Some(delivery) = audit_delivery {
            delivery.abort();
        }
        refresh.abort();
        result?;
        return Ok(());
    }
    let listener = TcpListener::bind(addr).await?.tap_io(|tcp| {
        if let Err(error) = tcp.set_nodelay(true) {
            tracing::trace!(%error, "could not set TCP_NODELAY");
        }
    });
    tracing::info!(%addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    refresh.abort();
    if let Some(delivery) = audit_delivery {
        delivery.abort();
    }
    Ok(())
}

fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .buffered_lines_limit(8192)
        .lossy(false)
        .finish(std::io::stdout());
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info"));
    // `try_init` so repeated calls in tests are harmless.
    let _ = tracing_subscriber::fmt()
        .json()
        .with_writer(writer)
        .with_env_filter(filter)
        .try_init();
    guard
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    const TOKEN: &str = "development-token-at-least-32-bytes";

    /// A development router with durable state, so every route is registered.
    fn audited_router() -> (Router, Arc<durable::DurableState>, std::path::PathBuf) {
        let folder = std::env::temp_dir().join(format!("gateway-routes-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&folder).unwrap();
        let path = folder.join("state.db");
        durable::DurableState::initialize(&path).unwrap();
        let store = Arc::new(durable::DurableState::open(&path).unwrap());
        let cfg = Config {
            durable: Some(store.clone()),
            oidc: None,
            distributed_quota: None,
            development: true,
            security: None,
            addr: "127.0.0.1:0".parse().unwrap(),
            token: Some(TOKEN.into()),
            timeout: std::time::Duration::from_secs(5),
            max_body_bytes: 65536,
            max_inflight: 8,
            max_batch: 8,
            cpu_workers: 2,
            max_batch_jobs: 1,
            audit_retention_days: 7,
        };
        (router(cfg), store, folder)
    }

    fn concrete(template: &str) -> String {
        template
            .replace("{network}", "public-agency")
            .replace("{operation}", "health-health")
    }

    async fn send(app: &Router, method: &str, path: &str, token: Option<&str>) -> StatusCode {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        response.status()
    }

    /// Every route registered behind authentication writes its started and
    /// completed events for an authenticated request, labelled with the route
    /// template; a request without a valid credential writes nothing and is
    /// counted by route; no open route writes anything.
    #[tokio::test]
    async fn every_guarded_route_writes_started_and_completed_audit_events() {
        let (app, store, folder) = audited_router();
        let guarded = guarded_routes(true);
        assert!(guarded.len() >= 7, "guarded routes went missing");
        for (template, _) in &guarded {
            let method = if template.starts_with("/v1/networks/")
                || *template == "/metrics"
                || *template == "/v1/networks"
            {
                "GET"
            } else {
                "POST"
            };
            let status = send(&app, method, &concrete(template), None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{template}");
            assert!(
                store.pending_audit().unwrap().is_empty(),
                "{template}: an unauthenticated request was stored"
            );
            let status = send(&app, method, &concrete(template), Some(TOKEN)).await;
            let events = store.pending_audit().unwrap();
            assert_eq!(events.len(), 2, "{template}");
            let (started, completed) = (&events[0], &events[1]);
            assert_eq!(started["event"]["phase"], "started", "{template}");
            assert_eq!(started["event"]["route"], *template);
            assert_eq!(started["event"]["method"], method);
            assert_eq!(completed["event"]["phase"], "completed", "{template}");
            assert_eq!(completed["event"]["status"], status.as_u16());
            assert_eq!(
                started["event"]["request_id"],
                completed["event"]["request_id"]
            );
            let ids: Vec<String> = events
                .iter()
                .map(|e| e["id"].as_str().unwrap().to_owned())
                .collect();
            store.acknowledge(&ids).unwrap();
        }
        let metrics = axum::body::to_bytes(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/metrics")
                        .header("authorization", format!("Bearer {TOKEN}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .into_body(),
            1 << 20,
        )
        .await
        .unwrap();
        let metrics = String::from_utf8(metrics.to_vec()).unwrap();
        for (template, _) in &guarded {
            assert!(
                metrics.contains(&format!(
                    "gateway_unauthenticated_requests_total{{route=\"{template}\"}} 1\n"
                )),
                "{template}: {metrics}"
            );
        }
        let ids: Vec<String> = store
            .pending_audit()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_owned())
            .collect();
        store.acknowledge(&ids).unwrap();
        for (path, _) in open_routes() {
            send(&app, "GET", path, None).await;
            send(&app, "GET", path, Some(TOKEN)).await;
            assert!(store.pending_audit().unwrap().is_empty(), "{path}");
        }
        assert_eq!(
            send(&app, "POST", "/no/such/route", Some(TOKEN)).await,
            StatusCode::NOT_FOUND
        );
        assert!(store.pending_audit().unwrap().is_empty());
        drop(app);
        drop(store);
        std::fs::remove_dir_all(folder).ok();
    }

    /// Open and guarded routes are disjoint, so each route has exactly one
    /// audit class.
    #[test]
    fn a_route_is_either_open_or_guarded() {
        let open: Vec<_> = open_routes().into_iter().map(|(p, _)| p).collect();
        for (path, _) in guarded_routes(true) {
            assert!(!open.contains(&path), "{path} is both open and guarded");
        }
    }
}
