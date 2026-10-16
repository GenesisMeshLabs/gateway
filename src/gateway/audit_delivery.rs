//! At-least-once durable audit delivery with explicit collector acknowledgements.
use super::durable::{DurableState, AUDIT_BATCH};
use std::{sync::Arc, time::Duration};

/// Pause between delivery rounds once the backlog is drained.
const DELIVERY_INTERVAL: Duration = Duration::from_secs(5);

/// The configured audit collector.
struct Collector {
    client: reqwest::Client,
    url: String,
    token: Option<String>,
}

/// Pause between retention passes over delivered rows.
const PRUNE_INTERVAL: Duration = Duration::from_secs(600);

/// Deliver pending audit events to `GATEWAY_AUDIT_URL`, if it is set, and
/// delete delivered rows older than `retention` (`None` keeps them).
pub(super) fn start(
    store: Option<Arc<DurableState>>,
    retention: Option<Duration>,
) -> Result<Option<tokio::task::JoinHandle<()>>, String> {
    let Ok(url) = std::env::var("GATEWAY_AUDIT_URL") else {
        return Ok(None);
    };
    let parsed = reqwest::Url::parse(&url).map_err(|_| "invalid audit collector URL")?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err("audit collector requires HTTPS without URL credentials".into());
    }
    let store = store.ok_or("audit delivery requires durable state")?;
    let token = std::env::var("GATEWAY_AUDIT_TOKEN_FILE")
        .ok()
        .map(|path| {
            std::fs::read_to_string(path)
                .map(|s| s.trim().to_owned())
                .map_err(|_| "cannot read audit collector credential")
        })
        .transpose()?;
    let collector = Collector {
        client: client()?,
        url,
        token,
    };
    Ok(Some(tokio::spawn(async move {
        let mut pruned: Option<std::time::Instant> = None;
        loop {
            drain(&store, &collector).await;
            if let Some(retention) = retention {
                if pruned.is_none_or(|at| at.elapsed() >= PRUNE_INTERVAL) {
                    prune(&store, retention).await;
                    pruned = Some(std::time::Instant::now());
                }
            }
            tokio::time::sleep(DELIVERY_INTERVAL).await;
        }
    })))
}

/// Delete delivered rows past retention. A failure is logged and retried at
/// the next pass; it never touches undelivered rows or readiness.
async fn prune(store: &Arc<DurableState>, retention: Duration) {
    let store = store.clone();
    match tokio::task::spawn_blocking(move || store.prune_delivered(retention, chrono::Utc::now()))
        .await
    {
        Ok(Ok(0)) => {}
        Ok(Ok(deleted)) => tracing::info!(deleted, "delivered audit rows past retention deleted"),
        _ => tracing::warn!("delivered audit retention failed; retrying at the next pass"),
    }
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| "audit HTTP client failed".into())
}

/// Deliver batches back to back while they come back full and the collector
/// acknowledges some of each, so a backlog drains at the collector's pace
/// rather than one batch per interval. Returns the events acknowledged.
async fn drain(store: &Arc<DurableState>, collector: &Collector) -> usize {
    let mut acknowledged = 0;
    loop {
        let Some((sent, confirmed)) = deliver_batch(store, collector).await else {
            return acknowledged;
        };
        acknowledged += confirmed;
        if sent < AUDIT_BATCH || confirmed == 0 {
            return acknowledged;
        }
    }
}

/// Post one batch of pending events and record the acknowledged ones.
/// Returns the events sent and acknowledged, or `None` on any failure.
async fn deliver_batch(store: &Arc<DurableState>, collector: &Collector) -> Option<(usize, usize)> {
    let reader = store.clone();
    let events = tokio::task::spawn_blocking(move || reader.pending_audit())
        .await
        .ok()?
        .ok()?;
    if events.is_empty() {
        return Some((0, 0));
    }
    let mut request = collector
        .client
        .post(&collector.url)
        .json(&serde_json::json!({"events":events}));
    if let Some(token) = &collector.token {
        request = request.bearer_auth(token);
    }
    let mut response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len() + chunk.len() > 65536 {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    let value = serde_json::from_slice::<serde_json::Value>(&bytes).ok()?;
    let ids: Vec<_> = value["acknowledged_ids"]
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|id| events.iter().any(|e| e["id"] == *id))
        .map(str::to_owned)
        .collect();
    let confirmed = ids.len();
    let writer = store.clone();
    if !matches!(
        tokio::task::spawn_blocking(move || writer.acknowledge(&ids)).await,
        Ok(Ok(()))
    ) {
        tracing::error!("audit acknowledgement failed; events will be redelivered");
        return None;
    }
    Some((events.len(), confirmed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn store_with(events: usize) -> (Arc<DurableState>, std::path::PathBuf) {
        let folder =
            std::env::temp_dir().join(format!("gateway-delivery-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&folder).unwrap();
        let path = folder.join("state.db");
        DurableState::initialize(&path).unwrap();
        let store = Arc::new(DurableState::open(&path).unwrap());
        for i in 0..events {
            store
                .audit(&format!("event-{i:04}"), &json!({"n": i}))
                .unwrap();
        }
        (store, folder)
    }

    /// A collector that acknowledges every event (or none) and counts posts.
    async fn collector(acknowledge: bool) -> (Collector, Arc<AtomicUsize>) {
        let posts = Arc::new(AtomicUsize::new(0));
        let counter = posts.clone();
        let app = Router::new().route(
            "/audit",
            post(move |Json(body): Json<Value>| {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let ids: Vec<Value> = if acknowledge {
                        body["events"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|e| e["id"].clone())
                            .collect()
                    } else {
                        vec![]
                    };
                    Json(json!({"acknowledged_ids": ids}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (
            Collector {
                client: client().unwrap(),
                url: format!("http://{address}/audit"),
                token: None,
            },
            posts,
        )
    }

    #[tokio::test]
    async fn a_backlog_drains_in_one_round_of_full_batches() {
        let (store, folder) = store_with(2 * AUDIT_BATCH + 50);
        let (collector, posts) = collector(true).await;
        assert_eq!(drain(&store, &collector).await, 2 * AUDIT_BATCH + 50);
        assert_eq!(posts.load(Ordering::SeqCst), 3);
        assert_eq!(store.stats().unwrap().0, 0);
        // Nothing pending: one read, no post.
        assert_eq!(drain(&store, &collector).await, 0);
        assert_eq!(posts.load(Ordering::SeqCst), 3);
        std::fs::remove_dir_all(folder).ok();
    }

    #[tokio::test]
    async fn a_collector_that_acknowledges_nothing_gets_one_batch_per_round() {
        let (store, folder) = store_with(2 * AUDIT_BATCH);
        let (collector, posts) = collector(false).await;
        assert_eq!(drain(&store, &collector).await, 0);
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert_eq!(store.stats().unwrap().0, 2 * AUDIT_BATCH as u64);
        std::fs::remove_dir_all(folder).ok();
    }
}
