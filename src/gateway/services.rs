//! Scoped forwarding of a fixed, reviewed Genesis Mesh authority API catalog.
use super::{runtime::Principal, ApiError, AppState};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Deserialize)]
struct Operation {
    id: String,
    group: String,
    method: String,
    upstream_path: String,
    admin: bool,
    parameters: Vec<String>,
    query: Vec<String>,
}

fn operations() -> &'static Vec<Operation> {
    static OPS: OnceLock<Vec<Operation>> = OnceLock::new();
    OPS.get_or_init(|| {
        serde_json::from_str(include_str!("../../ui/services.json")).expect("service catalog")
    })
}

pub(super) async fn catalog() -> Json<Value> {
    Json(
        json!({"operations": serde_json::from_str::<Value>(include_str!("../../ui/services.json")).expect("catalog"),
        "route_template": "/v1/networks/{network}/services/{operation}"}),
    )
}

pub(super) async fn execute(
    State(state): State<AppState>,
    (Extension(principal), Extension(facts)): (
        Extension<Principal>,
        Extension<super::runtime::AuditFacts>,
    ),
    Path((network, operation)): Path<(String, String)>,
    Query(query): Query<BTreeMap<String, String>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let security = state.security.load_full();
    let policy = security.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority policy required".into(),
        )
    })?;
    let client = &policy.clients[principal.0.ok_or_else(ApiError::unauthorized)?];
    // Authorize before disclosing whether a network exists or contacting it.
    if !client.networks.contains(&network) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "network not authorized".into(),
        ));
    }
    let op = operations()
        .iter()
        .find(|o| o.id == operation)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "unknown service operation".into()))?;
    if let Ok(mut context) = facts.0.lock() {
        context.insert("network".into(), json!(network));
        context.insert("operation".into(), json!(op.id));
    }
    if method.as_str() != op.method {
        return Err(ApiError(
            StatusCode::METHOD_NOT_ALLOWED,
            "method does not match service operation".into(),
        ));
    }
    if !client.service_groups.contains(&op.group) || (op.admin && !client.authority_admin) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "service operation not authorized".into(),
        ));
    }
    let upstream = policy.networks[&network]
        .authority_url
        .as_ref()
        .ok_or_else(|| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "authority not configured".into(),
            )
        })?;
    let mut url = reqwest::Url::parse(upstream).map_err(|_| ApiError::internal("authority URL"))?;
    if query.len() > 24
        || query
            .iter()
            .any(|(k, v)| v.len() > 2048 || (!op.parameters.contains(k) && !op.query.contains(k)))
    {
        return Err(ApiError::bad_request(
            "unsupported or oversized query parameter",
        ));
    }
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| ApiError::internal("authority path"))?;
        segments.clear();
        for segment in op.upstream_path.trim_start_matches('/').split('/') {
            if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                let value = query
                    .get(name)
                    .filter(|s| !s.is_empty() && s.as_str() != "." && s.as_str() != "..")
                    .ok_or_else(|| ApiError::bad_request(format!("missing or invalid {name}")))?;
                let valid = if name == "node_public_key" {
                    crate::crypto::validate_public_key(value).unwrap_or(false)
                } else {
                    value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.:@".contains(&b))
                };
                if !valid {
                    return Err(ApiError::bad_request("invalid resource identifier"));
                }
                // Encoded once as one segment; never interpolate untrusted paths.
                segments.push(value);
            } else {
                segments.push(segment);
            }
        }
    }
    for (key, value) in &query {
        if op.query.contains(key) {
            url.query_pairs_mut().append_pair(key, value);
        }
    }
    let mut request = state.authority_http.request(method.clone(), url);
    if method == Method::GET {
        if !body.is_empty() {
            return Err(ApiError::bad_request("GET does not accept a body"));
        }
    } else {
        let parsed: Value = serde_json::from_slice(&body)
            .map_err(|_| ApiError::bad_request("JSON object required"))?;
        if !parsed.is_object() {
            return Err(ApiError::bad_request("JSON object required"));
        }
        request = request
            .header("content-type", "application/json")
            .body(body);
    }
    if op.admin {
        for name in [
            "x-admin-key-id",
            "x-admin-timestamp",
            "x-admin-nonce",
            "x-admin-signature",
        ] {
            let value = headers
                .get(name)
                .filter(|h| !h.is_empty() && h.len() <= 512)
                .ok_or_else(|| {
                    ApiError(
                        StatusCode::UNAUTHORIZED,
                        "operator-signed headers required for this operation".into(),
                    )
                })?;
            request = request.header(name, value);
        }
    }
    // No gateway bearer token, cookie, forwarding header or client URL reaches the authority.
    let mut upstream = request
        .send()
        .await
        .map_err(|_| ApiError(StatusCode::BAD_GATEWAY, "authority unavailable".into()))?;
    let status = upstream.status();
    if status.is_redirection() || status.is_server_error() {
        return Err(ApiError(
            StatusCode::BAD_GATEWAY,
            "authority request failed".into(),
        ));
    }
    const MAX_RESPONSE: usize = 2 * 1024 * 1024;
    if upstream
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE as u64)
    {
        return Err(ApiError(
            StatusCode::BAD_GATEWAY,
            "authority response too large".into(),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = upstream
        .chunk()
        .await
        .map_err(|_| ApiError(StatusCode::BAD_GATEWAY, "authority response failed".into()))?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE {
            return Err(ApiError(
                StatusCode::BAD_GATEWAY,
                "authority response too large".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let payload: Value = serde_json::from_slice(&bytes).map_err(|_| {
        ApiError(
            StatusCode::BAD_GATEWAY,
            "authority returned invalid JSON".into(),
        )
    })?;
    tracing::info!(target: "audit", client_id = %client.id, network = %network, operation = %op.id, status = status.as_u16(), "authority operation completed");
    Ok((status, Json(payload)).into_response())
}
