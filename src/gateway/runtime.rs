//! Bounded workers, per-client admission, and low-cardinality telemetry.
use super::{ApiError, AppState};
use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use tracing::Instrument;

#[derive(Clone)]
pub(super) struct Principal(pub Option<usize>);

pub(super) struct Window(Mutex<(Instant, u32)>);

impl Window {
    pub(super) fn new() -> Self {
        Self(Mutex::new((Instant::now(), 0)))
    }
}

/// Serialize only requests sharing one client; reset and admission are indivisible.
pub(super) fn admit(window: &Window, limit: u32) -> bool {
    let Ok(mut state) = window.0.lock() else {
        return false;
    };
    if state.0.elapsed() >= std::time::Duration::from_secs(60) {
        *state = (Instant::now(), 0);
    }
    if state.1 >= limit {
        return false;
    }
    state.1 += 1;
    true
}

#[derive(Default)]
pub(super) struct Metrics {
    pub requests: AtomicU64,
    pub failures: AtomicU64,
    pub denied: AtomicU64,
    latency_us: AtomicU64,
    completed: AtomicU64,
    buckets: [AtomicU64; 8],
}

impl AppState {
    /// Acquire a crypto-worker permit or shed immediately with 503.
    pub(super) fn try_worker(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
        self.workers.clone().try_acquire_owned().map_err(|_| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "crypto capacity exhausted".into(),
            )
        })
    }

    /// Permit belongs to the actual worker, including after HTTP cancellation.
    pub(super) async fn compute<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, ApiError> {
        let permit = self.try_worker()?;
        let span = tracing::Span::current();
        Ok(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            span.in_scope(work)
        })
        .await?)
    }
}

fn route_label(path: &str) -> &'static str {
    match path {
        "/" => "/",
        "/api" => "/api",
        "/v1/networks" => "/v1/networks",
        "/openapi.json" => "/openapi.json",
        "/assets/app.js" => "/assets/app.js",
        "/assets/style.css" => "/assets/style.css",
        "/health" => "/health",
        "/ready" => "/ready",
        "/metrics" => "/metrics",
        "/verify" => "/verify",
        "/verify/batch" => "/verify/batch",
        "/keygen" => "/keygen",
        "/issue" => "/issue",
        _ => "unmatched",
    }
}

pub(super) async fn observe(State(state): State<AppState>, req: Request, next: Next) -> Response {
    static REQUEST_IDS: AtomicU64 = AtomicU64::new(1);
    let id = format!(
        "{}-{:016x}",
        state.instance_id,
        REQUEST_IDS.fetch_add(1, Ordering::Relaxed)
    );
    let started = Instant::now();
    let method = req.method().clone();
    // Never log raw URI, query, headers or bodies, which can contain secrets.
    let route = route_label(req.uri().path());
    state.metrics.requests.fetch_add(1, Ordering::Relaxed);
    let mut response = next
        .run(req)
        .instrument(tracing::info_span!("request", request_id = %id))
        .await;
    let elapsed = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
    state
        .metrics
        .latency_us
        .fetch_add(elapsed, Ordering::Relaxed);
    state.metrics.completed.fetch_add(1, Ordering::Relaxed);
    for (bucket, ceiling) in state
        .metrics
        .buckets
        .iter()
        .zip([100, 500, 1000, 5000, 10000, 50000, 100000, 1000000])
    {
        if elapsed <= ceiling {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
    }
    if response.status().is_server_error() {
        state.metrics.failures.fetch_add(1, Ordering::Relaxed);
    }
    tracing::info!(target: "audit", request_id = %id, %method, route, status = response.status().as_u16(), elapsed_us = started.elapsed().as_micros() as u64, "request completed");
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&id).expect("request id"),
    );
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert("content-security-policy", HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

pub(super) async fn ready(State(state): State<AppState>) -> Response {
    let ready = state
        .security
        .load_full()
        .as_ref()
        .is_none_or(|p| p.networks.values().all(|n| n.ready(chrono::Utc::now())));
    if ready {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({"status":"ready"})),
        )
            .into_response()
    } else {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "trust policy unavailable".into(),
        )
        .into_response()
    }
}

pub(super) async fn metrics(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let (Some(policy), Some(i)) = (state.security.load_full(), principal.0) {
        if !policy.clients[i].metrics {
            return ApiError(StatusCode::FORBIDDEN, "metrics scope required".into())
                .into_response();
        }
    }
    let m: &Arc<Metrics> = &state.metrics;
    let mut output = format!(
        "# TYPE gateway_requests_total counter\ngateway_requests_total {}\n# TYPE gateway_failures_total counter\ngateway_failures_total {}\n# TYPE gateway_denied_total counter\ngateway_denied_total {}\n# TYPE gateway_crypto_active gauge\ngateway_crypto_active {}\n",
        m.requests.load(Ordering::Relaxed), m.failures.load(Ordering::Relaxed), m.denied.load(Ordering::Relaxed), state.cfg.cpu_workers - state.workers.available_permits()
    );
    output.push_str("# TYPE gateway_request_duration_seconds histogram\n");
    for (bucket, ceiling) in m.buckets.iter().zip([
        "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.05", "0.1", "1",
    ]) {
        output.push_str(&format!(
            "gateway_request_duration_seconds_bucket{{le=\"{ceiling}\"}} {}\n",
            bucket.load(Ordering::Relaxed)
        ));
    }
    let count = m.completed.load(Ordering::Relaxed);
    output.push_str(&format!("gateway_request_duration_seconds_bucket{{le=\"+Inf\"}} {count}\ngateway_request_duration_seconds_count {count}\ngateway_request_duration_seconds_sum {}\n", m.latency_us.load(Ordering::Relaxed) as f64 / 1_000_000.0));
    ([("content-type", "text/plain; version=0.0.4")], output).into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn concurrent_quota_admission_never_exceeds_limit_even_after_reset() {
        let window = super::Window::new();
        for _ in 0..2 {
            let accepted = std::sync::atomic::AtomicU32::new(0);
            std::thread::scope(|scope| {
                for _ in 0..16 {
                    scope.spawn(|| {
                        for _ in 0..20 {
                            if super::admit(&window, 50) {
                                accepted.fetch_add(1, super::Ordering::Relaxed);
                            }
                        }
                    });
                }
            });
            assert_eq!(accepted.load(super::Ordering::Relaxed), 50);
            window.0.lock().unwrap().0 =
                std::time::Instant::now() - std::time::Duration::from_secs(61);
        }
    }

    #[tokio::test]
    async fn cancelled_request_keeps_worker_capacity_reserved() {
        let cfg = crate::gateway::Config {
            development: true,
            security: None,
            addr: "127.0.0.1:0".parse().unwrap(),
            token: Some("development-token-at-least-32-bytes".into()),
            timeout: std::time::Duration::from_secs(1),
            max_body_bytes: 1024,
            max_inflight: 1,
            max_batch: 1,
            cpu_workers: 1,
            max_batch_jobs: 1,
        };
        let (_, state) = crate::gateway::build_router(cfg);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_state = state.clone();
        let request = tokio::spawn(async move {
            worker_state
                .compute(move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
                .await
        });
        started_rx.await.unwrap();
        request.abort();
        let _ = request.await;
        assert!(state.compute(|| 1).await.is_err());
        release_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while state.workers.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state.compute(|| 42).await.unwrap(), 42);
    }
}
