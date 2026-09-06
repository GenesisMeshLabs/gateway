//! The HTTP gateway: shared state, router assembly, and the server entrypoint.
//!
//! Everything the binary needs lives here so integration tests can build the
//! [`router`] and drive it in-process without binding a socket.
//!
//! Single-certificate routes (`/keygen`, `/issue`, `/verify`) run inline on
//! the Tokio worker: one Ed25519 operation is cheaper than a `spawn_blocking`
//! handoff. `POST /verify/batch` prepares anchors and the CRL once, then fans
//! large batches across the Rayon pool from a blocking worker.

mod config;
mod error;
mod handlers;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub use config::Config;
pub use error::ApiError;

/// Shared, cheaply-cloneable state handed to middleware and handlers.
#[derive(Clone)]
pub struct AppState {
    /// Parsed configuration.
    pub cfg: Arc<Config>,
    /// Permits for the in-flight-request limit; exhaustion sheds with 503.
    /// Applied only to authenticated routes so `/health` stays reachable.
    pub inflight: Arc<Semaphore>,
    /// Separate cap for `/verify/batch` so one fat batch cannot starve singles.
    pub batch_inflight: Arc<Semaphore>,
}

/// Build the gateway router. Exposed for in-process testing.
pub fn router(cfg: Config) -> Router {
    let state = AppState {
        inflight: Arc::new(Semaphore::new(cfg.max_inflight)),
        batch_inflight: Arc::new(Semaphore::new(cfg.max_batch_inflight)),
        cfg: Arc::new(cfg),
    };

    let open = Router::new()
        .route("/", get(handlers::index))
        .route("/health", get(handlers::health));

    let guarded = Router::new()
        .route("/keygen", post(handlers::keygen))
        .route("/issue", post(handlers::issue))
        .route("/verify", post(handlers::verify))
        .route("/verify/batch", post(handlers::verify_batch))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            handlers::auth,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            handlers::limit_inflight,
        ));

    open.merge(guarded)
        .layer(TimeoutLayer::new(state.cfg.timeout))
        .layer(RequestBodyLimitLayer::new(state.cfg.max_body_bytes))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Parse configuration from the environment, bind, and serve until Ctrl-C.
pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tracing();

    let cfg = Config::from_env().map_err(|e| format!("configuration: {e}"))?;
    tracing::info!(config = ?cfg, "starting genesis-mesh gateway");
    if cfg.token.is_none() {
        tracing::warn!("GATEWAY_TOKEN not set — every endpoint except /health is unauthenticated");
    }

    let addr = cfg.addr;
    let app = router(cfg);

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");

    axum::serve(listener, app)
        .tcp_nodelay(true)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=warn"));
    // `try_init` so repeated calls in tests are harmless.
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
