//! The HTTP gateway: shared state, router assembly, and the server entrypoint.
//!
//! Everything the binary needs lives here so integration tests can build the
//! [`router`] and drive it in-process without binding a socket.
//!
//! CPU work runs under separate HTTP, CPU and batch budgets. Worker permits
//! remain owned by running jobs after request cancellation.

mod config;
mod error;
mod handlers;
mod runtime;
pub mod security;
mod services;
mod sync;
mod ui;

use std::sync::Arc;

use axum::routing::{get, post};
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
    dev_token_digest: Option<[u8; 32]>,
    authority_http: reqwest::Client,
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
        inflight: Arc::new(Semaphore::new(cfg.max_inflight)),
        cfg: Arc::new(cfg),
        dev_token_digest,
    };

    let open = Router::new()
        .route("/", get(ui::page))
        .route("/assets/app.js", get(ui::script))
        .route("/assets/signing.js", get(ui::signing_script))
        .route("/assets/style.css", get(ui::style))
        .route("/api", get(handlers::index))
        .route("/v1/services", get(services::catalog))
        .route("/openapi.json", get(ui::specification))
        .route("/health", get(handlers::health))
        .route("/ready", get(runtime::ready));

    let mut guarded = Router::new();
    if state.cfg.development {
        guarded = guarded
            .route("/keygen", post(handlers::keygen))
            .route("/issue", post(handlers::issue));
    }
    let guarded = guarded
        .route(
            "/v1/networks/:network/services/:operation",
            axum::routing::any(services::execute),
        )
        .route("/metrics", get(runtime::metrics))
        .route("/v1/networks", get(ui::networks))
        .route("/verify", post(handlers::verify))
        .route("/verify/batch", post(handlers::verify_batch))
        .layer(axum::middleware::from_fn_with_state(
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

/// Parse configuration from the environment, bind, and serve until Ctrl-C.
pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _audit_guard = init_tracing();

    let cfg = Config::from_env().map_err(|e| format!("configuration: {e}"))?;
    tracing::info!(config = ?cfg, "starting genesis-mesh gateway");
    if cfg.development {
        tracing::warn!("development utility endpoints enabled");
    }

    let addr = cfg.addr;
    let (app, state) = build_router(cfg);
    let refresh = sync::start(state.security.clone());

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");

    axum::serve(listener, app)
        .tcp_nodelay(true)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    refresh.abort();
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
