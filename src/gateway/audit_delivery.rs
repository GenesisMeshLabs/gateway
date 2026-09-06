//! At-least-once durable audit delivery with explicit collector acknowledgements.
use super::durable::DurableState;
use std::{sync::Arc, time::Duration};

pub(super) fn start(
    store: Option<Arc<DurableState>>,
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
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| "audit HTTP client failed")?;
    Ok(Some(tokio::spawn(async move {
        loop {
            let reader = store.clone();
            if let Ok(Ok(events)) =
                tokio::task::spawn_blocking(move || reader.pending_audit()).await
            {
                if !events.is_empty() {
                    let mut request = client
                        .post(&url)
                        .json(&serde_json::json!({"events":events}));
                    if let Some(token) = &token {
                        request = request.bearer_auth(token);
                    }
                    if let Ok(mut response) = request.send().await {
                        if response.status().is_success() {
                            let mut bytes = Vec::new();
                            loop {
                                let chunk = match response.chunk().await {
                                    Ok(Some(chunk)) => chunk,
                                    Ok(None) => break,
                                    Err(_) => {
                                        bytes.clear();
                                        break;
                                    }
                                };
                                if bytes.len() + chunk.len() > 65536 {
                                    bytes.clear();
                                    break;
                                }
                                bytes.extend_from_slice(&chunk);
                            }
                            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                                if let Some(ack) = value["acknowledged_ids"].as_array() {
                                    let ids: Vec<_> = ack
                                        .iter()
                                        .filter_map(|v| v.as_str())
                                        .filter(|id| events.iter().any(|e| e["id"] == *id))
                                        .map(str::to_owned)
                                        .collect();
                                    let writer = store.clone();
                                    if !matches!(
                                        tokio::task::spawn_blocking(
                                            move || writer.acknowledge(&ids)
                                        )
                                        .await,
                                        Ok(Ok(()))
                                    ) {
                                        tracing::error!("audit acknowledgement failed; events will be redelivered");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    })))
}
