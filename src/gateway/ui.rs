//! Embedded, same-origin API explorer; no CDN dependencies or stored credentials.
use super::{runtime::Principal, ApiError, AppState};
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    Extension, Json,
};
use serde_json::{json, Value};

pub(super) async fn page() -> Html<&'static str> {
    Html(include_str!("../../ui/index.html"))
}
pub(super) async fn script() -> impl IntoResponse {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        include_str!("../../ui/app.js"),
    )
}
pub(super) async fn signing_script() -> impl IntoResponse {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        include_str!("../../ui/signing.js"),
    )
}
pub(super) async fn errors_script() -> impl IntoResponse {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        include_str!("../../ui/errors.js"),
    )
}
pub(super) async fn tour_script() -> impl IntoResponse {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        include_str!("../../ui/tour.js"),
    )
}
pub(super) async fn style() -> impl IntoResponse {
    (
        [("content-type", "text/css; charset=utf-8")],
        include_str!("../../ui/style.css"),
    )
}
pub(super) async fn specification() -> Json<Value> {
    static SPEC: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    Json(
        SPEC.get_or_init(|| {
            let mut spec: Value = serde_json::from_str(include_str!("../../ui/openapi.json"))
                .expect("embedded OpenAPI");
            // The document describes this build, whatever the file says.
            spec["info"]["version"] = Value::from(env!("CARGO_PKG_VERSION"));
            spec
        })
        .clone(),
    )
}

/// Published demo credentials (v0.65). Demo clients are validated at startup
/// to read and verify operations only, so publishing their tokens is safe.
pub(super) async fn demo(State(state): State<AppState>) -> Json<Value> {
    let security = state.security.load_full();
    let clients: Vec<Value> = security
        .as_ref()
        .map(|policy| {
            policy
                .clients
                .iter()
                .filter(|c| c.demo)
                .filter_map(|c| {
                    Some(json!({"client_id": c.id, "token": c.demo_token.as_ref()?,
                        "networks": c.networks, "service_groups": c.service_groups,
                        "requests_per_minute": c.requests_per_minute}))
                })
                .collect()
        })
        .unwrap_or_default();
    Json(json!({"available": !clients.is_empty(), "clients": clients,
        "notice": "Demo access is public and limited to reading and verifying. It cannot change any authority."}))
}

pub(super) async fn networks(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>, ApiError> {
    let security = state.security.load_full();
    let Some(policy) = &security else {
        return Ok(Json(json!({"mode":"development", "networks":[]})));
    };
    let client = &policy.clients[principal.0.ok_or_else(ApiError::unauthorized)?];
    let networks: Vec<Value> = policy.networks.iter().filter(|(name, _)| client.networks.contains(*name)).map(|(name, network)| json!({
        "name": name, "ready": network.ready(chrono::Utc::now()), "anchors": network.anchors,
        "services_configured": network.authority_url.is_some(),
        "required_roles": network.required_roles, "revocation": {"issuer":network.crl.issuer, "sequence":network.crl.sequence, "issued_at":network.crl.issued_at, "next_update":network.crl.next_update, "revoked_count":network.crl.revoked_certificates.len()},
        "additional_issuers":network.additional_issuers.values().map(|n| json!({"issuer":n.crl.issuer,"sequence":n.crl.sequence,"next_update":n.crl.next_update,"ready":n.primary_ready(chrono::Utc::now()),"revoked_count":n.crl.revoked_certificates.len()})).collect::<Vec<_>>()
    })).collect();
    Ok(Json(
        json!({"policy_revision":policy.revision,"client_id":client.id,"networks":networks,
            "service_groups":client.service_groups,"authority_admin":client.authority_admin}),
    ))
}
