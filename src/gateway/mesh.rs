//! Opt-in, bounded public topology. Never forwards credentials or private records.
use super::AppState;
use axum::{extract::State, response::IntoResponse, Json};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

pub(super) async fn script() -> impl IntoResponse {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        include_str!("../../ui/mesh.js"),
    )
}

async fn read(client: &reqwest::Client, origin: &str, path: &str) -> Result<Value, ()> {
    let mut response = client
        .get(format!("{}{path}", origin.trim_end_matches('/')))
        .timeout(Duration::from_secs(4))
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > 2_097_152) {
        return Err(());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if bytes.len() + chunk.len() > 2_097_152 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn current(record: &Value) -> bool {
    let now = Utc::now();
    record["status"] == "active"
        && record["valid_from"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .is_some_and(|t| t <= now)
        && record["expires_at"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .is_some_and(|t| t > now)
}

fn project(
    name: &str,
    visible: &BTreeSet<String>,
    treaties: &Value,
    attestations: &Value,
) -> (Vec<Value>, Vec<Value>) {
    let mut edges = Vec::new();
    for row in treaties["recognition_treaties"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let t = &row["treaty"];
        if row["status"] != "active" || !current(t) || t["issuer_sovereign_id"] != name {
            continue;
        }
        if !t["subject_sovereign_id"]
            .as_str()
            .is_some_and(|s| visible.contains(s))
        {
            continue;
        }
        edges.push(json!({"id":t["treaty_id"],"from":name,"to":t["subject_sovereign_id"],"roles":t["scope"]["allowed_roles"],"expires_at":t["expires_at"],"issued_at":t["issued_at"]}));
        if edges.len() == 256 {
            break;
        }
    }
    let mut members = Vec::new();
    for row in attestations["attestations"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let a = &row["attestation"];
        if row["status"] != "active"
            || !current(a)
            || a["issuer_sovereign_id"] != name
            || a["claims"]["public_mesh"] != true
        {
            continue;
        }
        members.push(json!({"id":a["attestation_id"],"network":name,"subject":a["subject_id"],"roles":a["roles"],"expires_at":a["expires_at"],"issued_at":a["issued_at"],"demo":a["claims"]["demo"] == true}));
        if members.len() == 64 {
            break;
        }
    }
    (edges, members)
}

pub(super) async fn overview(State(state): State<AppState>) -> Json<Value> {
    // Single-flight refresh prevents anonymous traffic multiplying authority requests.
    let mut cache = state.mesh_cache.lock().await;
    if let Some((at, data)) = cache.as_ref() {
        if at.elapsed() < Duration::from_secs(20) {
            return Json(data.clone());
        }
    }
    let policy = state.security.load_full();
    let visible: BTreeSet<String> = policy
        .as_ref()
        .map(|p| {
            p.networks
                .iter()
                .filter(|(_, n)| n.public_mesh && n.authority_url.is_some())
                .take(16)
                .map(|(name, _)| name.clone())
                .collect()
        })
        .unwrap_or_default();
    let mut tasks = tokio::task::JoinSet::new();
    if let Some(policy) = policy.as_ref() {
        for name in &visible {
            let network = &policy.networks[name];
            let name = name.clone();
            let origin = network.authority_url.clone().expect("selected origin");
            let ready = network.ready(Utc::now());
            let sequence = network.crl.sequence;
            let client = state.authority_http.clone();
            let visible = visible.clone();
            tasks.spawn(async move {
                let (treaties, attestations) = tokio::join!(read(&client, &origin, "/recognition-treaties?status=active"), read(&client, &origin, "/attestations?status=active"));
                let available = treaties.is_ok() && attestations.is_ok();
                // Partial failures never retain old links or present stale counts as live.
                let (edges, members) = project(&name, &visible, &treaties.unwrap_or(Value::Null), &attestations.unwrap_or(Value::Null));
                (json!({"id":name,"available":available,"trust_ready":ready,"crl_sequence":sequence}), edges, members)
            });
        }
    }
    let (mut networks, mut edges, mut members) = (Vec::new(), Vec::new(), Vec::new());
    while let Some(result) = tasks.join_next().await {
        if let Ok((network, e, m)) = result {
            networks.push(network);
            edges.extend(e);
            members.extend(m);
        }
    }
    for name in &visible {
        if !networks.iter().any(|n| n["id"] == name.as_str()) {
            networks
                .push(json!({"id":name,"available":false,"trust_ready":false,"crl_sequence":null}));
        }
    }
    networks.sort_by_key(|n| n["id"].as_str().unwrap_or_default().to_owned());
    edges.sort_by_key(|n| n["id"].as_str().unwrap_or_default().to_owned());
    members.sort_by_key(|n| n["subject"].as_str().unwrap_or_default().to_owned());
    let data = json!({"observed_at":Utc::now(),"refresh_seconds":20,"networks":networks,"links":edges,"members":members,"network_limit":16,"member_limit_per_network":64,"link_limit_per_network":256});
    *cache = Some((Instant::now(), data.clone()));
    Json(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_excludes_private_revoked_expired_and_foreign_records() {
        let valid = json!({"status":"active","valid_from":Utc::now()-chrono::Duration::hours(1),"expires_at":Utc::now()+chrono::Duration::hours(1),"issuer_sovereign_id":"a"});
        let mut treaty = valid.clone();
        treaty["subject_sovereign_id"] = json!("b");
        treaty["treaty_id"] = json!("t1");
        let mut hidden = treaty.clone();
        hidden["subject_sovereign_id"] = json!("private");
        let mut member = valid;
        member["claims"] = json!({"public_mesh":true,"demo":true,"private_secret":"never expose"});
        member["subject_id"] = json!("demo");
        let mut private = member.clone();
        private["claims"]["public_mesh"] = json!(false);
        let mut expired = member.clone();
        expired["expires_at"] = json!(Utc::now() - chrono::Duration::seconds(1));
        let (edges, members) = project(
            "a",
            &["a".into(), "b".into()].into(),
            &json!({"recognition_treaties":[{"status":"active","treaty":treaty},{"status":"active","treaty":hidden},{"status":"revoked","treaty":treaty}]}),
            &json!({"attestations":[{"status":"active","attestation":member},{"status":"revoked","attestation":member},{"status":"active","attestation":private},{"status":"active","attestation":expired}]}),
        );
        assert_eq!(edges.len(), 1);
        assert_eq!(members.len(), 1);
        assert!(!json!(members).to_string().contains("never expose"));
    }
}
