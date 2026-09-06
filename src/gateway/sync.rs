//! Fetch signed Genesis Mesh revocation snapshots from pinned authority URLs.
use super::security::SecurityPolicy;
use arc_swap::ArcSwapOption;
use std::{sync::Arc, time::Duration};

async fn fetch_snapshot(
    client: &reqwest::Client,
    url: &str,
    network: super::security::NetworkPolicy,
) -> Result<super::security::NetworkPolicy, String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "authority transport failed".to_string())?
        .error_for_status()
        .map_err(|_| "authority HTTP failure".to_string())?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "authority body failure".to_string())?
    {
        if bytes.len() + chunk.len() > 16 * 1024 * 1024 {
            return Err("snapshot exceeds size limit".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }
    tokio::task::spawn_blocking(move || prepare_snapshot(bytes, network))
        .await
        .map_err(|_| "snapshot worker failed".to_string())?
}

fn prepare_snapshot(
    bytes: Vec<u8>,
    network: super::security::NetworkPolicy,
) -> Result<super::security::NetworkPolicy, String> {
    let crl: crate::models::CertificateRevocationList =
        serde_json::from_slice(&bytes).map_err(|_| "invalid CRL JSON".to_string())?;
    if crl.issuer != network.crl.issuer
        || crl.sequence < network.crl.sequence
        || crl.issued_at < network.crl.issued_at
        || (crl.sequence == network.crl.sequence
            && crl.revoked_certificates != network.crl.revoked_certificates)
    {
        return Err("snapshot rollback or conflicting sequence".into());
    }
    let mut candidate = network;
    candidate.crl = crl;
    if !candidate.ready(chrono::Utc::now()) || !candidate.authentic() {
        return Err("untrusted snapshot".into());
    }
    candidate.rebuild_crypto_cache();
    Ok(candidate)
}

pub(super) async fn refresh(store: &ArcSwapOption<SecurityPolicy>, client: &reqwest::Client) {
    let Some(current) = store.load_full() else {
        return;
    };
    // At most two fetch/prepare jobs per replica. No task per configured network.
    let mut sources = current.networks.iter().filter_map(|(name, network)| {
        network
            .crl_url
            .as_ref()
            .map(|url| (name.clone(), url.clone(), network.clone()))
    });
    let mut jobs = tokio::task::JoinSet::new();
    let mut updated = (*current).clone();
    let mut changed = false;
    loop {
        while jobs.len() < 2 {
            let Some((name, url, network)) = sources.next() else {
                break;
            };
            let client = client.clone();
            jobs.spawn(async move { (name, fetch_snapshot(&client, &url, network).await) });
        }
        let Some(result) = jobs.join_next().await else {
            break;
        };
        match result {
            Ok((name, Ok(candidate))) => {
                tracing::info!(target:"audit", network = %name, sequence = candidate.crl.sequence, "authority snapshot synchronized");
                updated.networks.insert(name, candidate);
                changed = true;
            }
            _ => {
                tracing::warn!(target:"audit", "authority refresh failed; retaining verified snapshot")
            }
        }
    }
    if changed {
        store.store(Some(Arc::new(updated)));
    }
}

pub(super) fn start(store: Arc<ArcSwapOption<SecurityPolicy>>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .tcp_nodelay(true)
            .pool_max_idle_per_host(4)
            .build()
            .expect("Rustls HTTP client");
        loop {
            refresh(&store, &client).await;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gateway::security::NetworkPolicy,
        models::{CertificateRevocationList, Signed},
        KeyPair,
    };

    #[tokio::test]
    async fn refresh_accepts_signed_progress_and_retains_snapshot_on_rollback_or_forgery() {
        let key = KeyPair::generate().unwrap();
        let now =
            chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros()).unwrap();
        let mut crl = CertificateRevocationList {
            crl_id: "snapshot".into(),
            sequence: 1,
            issued_at: now - chrono::Duration::minutes(1),
            next_update: now + chrono::Duration::hours(1),
            issuer: "authority".into(),
            revoked_certificates: vec![],
            signatures: vec![],
        };
        crl.sign(&key, "authority").unwrap();
        let response = Arc::new(std::sync::RwLock::new(crl.clone()));
        let http_state = response.clone();
        let app = axum::Router::new().route(
            "/crl",
            axum::routing::get(move || {
                let body = http_state.read().unwrap().clone();
                async move { axum::Json(body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let policy = SecurityPolicy {
            revision: "test".into(),
            clients: vec![],
            token_index: Default::default(),
            networks: [(
                "mesh".into(),
                NetworkPolicy {
                    public_mesh: false,
                    authority_url: None,
                    anchors: [("authority".into(), key.public_key_b64())].into(),
                    crl: crl.clone(),
                    minimum_crl_sequence: 1,
                    required_roles: Default::default(),
                    crl_url: Some(format!("http://{address}/crl")),
                    allow_http: true,
                    verifying_keys: Default::default(),
                    revoked_index: Default::default(),
                },
            )]
            .into(),
        };
        let store = ArcSwapOption::from(Some(Arc::new(policy)));
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        crl.sequence = 2;
        crl.signatures.clear();
        crl.sign(&key, "authority").unwrap();
        *response.write().unwrap() = crl.clone();
        refresh(&store, &client).await;
        assert_eq!(store.load_full().unwrap().networks["mesh"].crl.sequence, 2);
        crl.sequence = 1;
        crl.signatures.clear();
        crl.sign(&key, "authority").unwrap();
        *response.write().unwrap() = crl.clone();
        refresh(&store, &client).await;
        assert_eq!(store.load_full().unwrap().networks["mesh"].crl.sequence, 2);
        crl.sequence = 3;
        crl.signatures.clear();
        crl.sign(&KeyPair::generate().unwrap(), "authority")
            .unwrap();
        *response.write().unwrap() = crl;
        refresh(&store, &client).await;
        assert_eq!(store.load_full().unwrap().networks["mesh"].crl.sequence, 2);
        server.abort();
    }
}
