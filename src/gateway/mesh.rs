//! Opt-in, bounded public topology. Never forwards credentials or private records.
use super::AppState;
use crate::{
    admin_auth::{self, AdminRequest},
    crypto::KeyPair,
};
use axum::{extract::State, response::IntoResponse, Json};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};

pub(super) async fn script() -> impl IntoResponse {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        include_str!("../../ui/mesh.js"),
    )
}

/// A network's mesh reader: an operator key and the authority it signs for.
struct Reader {
    key_id: String,
    key: Arc<KeyPair>,
    /// The authority's public key, which version 2 signatures name (v1.0.2).
    audience: String,
}

impl Reader {
    /// Operator headers for one `GET` of `url`, signed as the authority checks them.
    fn headers(&self, url: &reqwest::Url) -> [(&'static str, String); 4] {
        let mut query: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, value) in url.query_pairs() {
            query
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        let request = AdminRequest {
            method: "GET",
            path: url.path(),
            query: &query,
            audience: &self.audience,
            body: &json!({}),
        };
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false);
        let nonce = uuid::Uuid::new_v4().to_string();
        admin_auth::sign(&self.key, &self.key_id, &request, &timestamp, &nonce)
    }
}

async fn read(
    client: &reqwest::Client,
    origin: &str,
    path: &str,
    reader: Option<&Reader>,
) -> Result<Value, ()> {
    let url =
        reqwest::Url::parse(&format!("{}{path}", origin.trim_end_matches('/'))).map_err(|_| ())?;
    let mut request = client.get(url.clone()).timeout(Duration::from_secs(4));
    if let Some(reader) = reader {
        for (name, value) in reader.headers(&url) {
            request = request.header(name, value);
        }
    }
    let mut response = request.send().await.map_err(|_| ())?;
    if reader.is_some() && matches!(response.status().as_u16(), 401 | 403) {
        // The key is unknown to the authority, revoked or not of the read tier.
        tracing::warn!(target: "audit", status = response.status().as_u16(), "authority refused the mesh reader key");
    }
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

/// External sovereign names come from authority data; render only plain IDs.
fn valid_sovereign_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.'
        })
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

fn verified_feed(
    name: &str,
    feed: &Value,
    keys: &std::collections::HashMap<String, crate::crypto::CachedPublicKey>,
) -> Option<Value> {
    let issuer = feed["issued_by"].as_str()?;
    let key = keys.get(issuer)?;
    let issued = DateTime::parse_from_rfc3339(feed["issued_at"].as_str()?).ok()?;
    let now = Utc::now();
    if feed["issuer_sovereign_id"] != name
        || issued > now + chrono::Duration::minutes(5)
        || issued < now - chrono::Duration::hours(24)
    {
        return None;
    }
    let sequence = feed["sequence"].as_u64()?;
    let payload = crate::canonical::to_canonical_json_excluding(feed, &["signatures"]).ok()?;
    let valid = feed["signatures"].as_array()?.iter().any(|s| {
        s["key_id"] == issuer
            && s["sig"]
                .as_str()
                .is_some_and(|sig| key.verify(payload.as_bytes(), sig).unwrap_or(false))
    });
    valid.then(
        || json!({"sequence":sequence,"issued_at":feed["issued_at"],"signature_verified":true}),
    )
}

/// Treaty rows from a live NA (`recognition_treaties`, row status) or a public
/// reference (`treaties` and `external_treaties`, treaty status; v0.65).
fn treaty_rows(treaties: &Value) -> impl Iterator<Item = (&Value, &Value)> {
    ["recognition_treaties", "treaties", "external_treaties"]
        .into_iter()
        .flat_map(move |key| treaties[key].as_array().into_iter().flatten())
        .map(|row| {
            let status = if row["status"].is_string() {
                &row["status"]
            } else {
                &row["treaty"]["status"]
            };
            (row, status)
        })
}

fn project(
    name: &str,
    visible: &BTreeSet<String>,
    show_external: bool,
    treaties: &Value,
    attestations: &Value,
) -> (Vec<Value>, Vec<Value>) {
    let mut edges = Vec::new();
    for (row, status) in treaty_rows(treaties) {
        let t = &row["treaty"];
        if status != "active" || !current(t) || t["issuer_sovereign_id"] != name {
            continue;
        }
        let Some(subject) = t["subject_sovereign_id"].as_str() else {
            continue;
        };
        // Sovereigns outside this gateway appear only when the operator opts in (v0.65).
        let external = !visible.contains(subject);
        if external && !(show_external && valid_sovereign_id(subject)) {
            continue;
        }
        edges.push(json!({"id":t["treaty_id"],"from":name,"to":subject,"roles":t["scope"]["allowed_roles"],"expires_at":t["expires_at"],"issued_at":t["issued_at"],"external":external}));
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
            let keys = network.verifying_keys.clone();
            let visible = visible.clone();
            let show_external = network.public_external_treaties;
            // Authorities list attestations to operators only (v1.0.2); without
            // a reader the view gets a count and shows no members.
            let reader = network.mesh_reader.as_ref().and_then(|r| {
                Some(Reader {
                    key_id: r.key_id.clone(),
                    key: r.key.clone()?,
                    audience: network.anchors.get(&network.crl.issuer)?.clone(),
                })
            });
            tasks.spawn(async move {
                let (treaties, attestations, dashboard, feed) = tokio::join!(read(&client, &origin, "/recognition-treaties?status=active", None), read(&client, &origin, "/attestations?status=active", reader.as_ref()), read(&client, &origin, "/dashboard.json", None), read(&client, &origin, "/sovereign-revocation-feed", None));
                // A public reference publishes no attestation listing; treaties decide availability.
                let available = treaties.is_ok();
                // Partial failures never retain old links or present stale counts as live.
                let (edges, members) = project(&name, &visible, show_external, &treaties.unwrap_or(Value::Null), &attestations.unwrap_or(Value::Null));
                let source_feed = verified_feed(&name, &feed.unwrap_or(Value::Null), &keys);
                let dashboard_available = dashboard.is_ok();
                let dashboard = dashboard.unwrap_or(Value::Null);
                let imports: Vec<Value> = dashboard["revocation_feeds"].as_array().into_iter().flatten().filter(|f| f["issuer_sovereign_id"].as_str().is_some_and(|s| visible.contains(s))).map(|f|json!({"issuer":f["issuer_sovereign_id"],"sequence":f["sequence"],"imported_at":f["imported_at"]})).collect();
                (json!({"id":name,"available":available,"trust_ready":ready,"crl_sequence":sequence,"source_feed":source_feed,"imports_available":dashboard_available,"imports":imports}), edges, members)
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
    let pairs: BTreeSet<_> = edges
        .iter()
        .filter(|e| e["external"] != true)
        .filter_map(|e| Some((e["from"].as_str()?, e["to"].as_str()?)))
        .collect();
    let mut external: Vec<Value> = Vec::new();
    for edge in edges.iter().filter(|e| e["external"] == true) {
        let id = edge["to"].clone();
        if let Some(x) = external.iter_mut().find(|x| x["id"] == id) {
            if let Some(list) = x["recognized_by"].as_array_mut() {
                list.push(edge["from"].clone());
            }
        } else if external.len() < 32 {
            external.push(json!({"id": id, "recognized_by": [edge["from"].clone()]}));
        }
    }
    let synchronization: Vec<_> = pairs.into_iter().map(|(consumer, publisher)| {
        let source = networks.iter().find(|n| n["id"] == publisher);
        let target = networks.iter().find(|n| n["id"] == consumer);
        let published = source.and_then(|s|s["source_feed"]["sequence"].as_u64());
        let imported = target.and_then(|t|t["imports"].as_array()).and_then(|items|items.iter().find(|i|i["issuer"]==publisher));
        let sequence = imported.and_then(|i|i["sequence"].as_u64());
        let status = if !target.is_some_and(|t| t["imports_available"] == true) { "consumer_unavailable" }
            else if published.is_none() { "source_unverified" }
            else if sequence.is_none() { "not_imported" }
            else if sequence == published { "current" }
            else if sequence < published { "behind" } else { "source_rollback" };
        json!({"consumer":consumer,"publisher":publisher,"status":status,"published_sequence":published,"imported_sequence":sequence,"last_imported_at":imported.map(|i|&i["imported_at"])})
    }).collect();
    let data = json!({"observed_at":Utc::now(),"refresh_seconds":20,"networks":networks,"links":edges,"external_sovereigns":external,"members":members,"synchronization":synchronization,"network_limit":16,"member_limit_per_network":64,"link_limit_per_network":256});
    *cache = Some((Instant::now(), data.clone()));
    Json(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn feed_health_requires_fresh_pinned_issuer_signature() {
        let key = crate::KeyPair::generate().unwrap();
        let keys = [(
            "na".to_string(),
            crate::crypto::CachedPublicKey::parse(&key.public_key_b64()).unwrap(),
        )]
        .into();
        let mut feed = json!({"issuer_sovereign_id":"a","issued_by":"na","sequence":3,"issued_at":Utc::now(),"signatures":[]});
        let sign = |f: &mut Value| {
            let body = crate::canonical::to_canonical_json_excluding(f, &["signatures"]).unwrap();
            f["signatures"] = json!([{"key_id":"na","sig":key.sign_b64(body.as_bytes())}]);
        };
        sign(&mut feed);
        assert_eq!(verified_feed("a", &feed, &keys).unwrap()["sequence"], 3);
        assert!(verified_feed("other", &feed, &keys).is_none());
        feed["sequence"] = json!(4);
        assert!(verified_feed("a", &feed, &keys).is_none());
        for issued in [
            Utc::now() - chrono::Duration::hours(25),
            Utc::now() + chrono::Duration::minutes(6),
        ] {
            feed["issued_at"] = json!(issued);
            sign(&mut feed);
            assert!(verified_feed("a", &feed, &keys).is_none());
        }
    }
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
            false,
            &json!({"recognition_treaties":[{"status":"active","treaty":treaty},{"status":"active","treaty":hidden},{"status":"revoked","treaty":treaty}]}),
            &json!({"attestations":[{"status":"active","attestation":member},{"status":"revoked","attestation":member},{"status":"active","attestation":private},{"status":"active","attestation":expired}]}),
        );
        assert_eq!(edges.len(), 1);
        assert_eq!(members.len(), 1);
        assert!(!json!(members).to_string().contains("never expose"));
    }

    #[test]
    fn reference_treaties_and_opted_in_external_sovereigns_are_projected() {
        let window = json!({"status":"active","valid_from":Utc::now()-chrono::Duration::hours(1),"expires_at":Utc::now()+chrono::Duration::hours(1),"issuer_sovereign_id":"ref","scope":{"allowed_roles":["role:demo"]}});
        let treaty = |id: &str, subject: &str| {
            let mut t = window.clone();
            t["treaty_id"] = json!(id);
            t["subject_sovereign_id"] = json!(subject);
            json!({"treaty": t, "expected_active": true})
        };
        let mut retired = treaty("t4", "gm-demo-gamma-na");
        retired["treaty"]["status"] = json!("revoked");
        let reference = json!({
            "treaties": [treaty("t1", "gm-demo-alpha-na"), treaty("t2", "<script>"), retired],
            "external_treaties": [treaty("t3", "genesis-mesh")],
        });
        let visible: BTreeSet<String> = ["ref".into(), "genesis-mesh".into()].into();
        let (edges, members) = project("ref", &visible, true, &reference, &Value::Null);
        let summary: Vec<(String, bool)> = edges
            .iter()
            .map(|e| (e["to"].as_str().unwrap().to_owned(), e["external"] == true))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("gm-demo-alpha-na".into(), true),
                ("genesis-mesh".into(), false)
            ]
        );
        assert!(members.is_empty());
        let (hidden, _) = project("ref", &visible, false, &reference, &Value::Null);
        assert_eq!(hidden.len(), 1);
    }
}
