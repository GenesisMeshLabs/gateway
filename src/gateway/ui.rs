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
            serde_json::from_str(include_str!("../../ui/openapi.json")).expect("embedded OpenAPI")
        })
        .clone(),
    )
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
        "required_roles": network.required_roles, "revocation": {"issuer":network.crl.issuer, "sequence":network.crl.sequence, "issued_at":network.crl.issued_at, "next_update":network.crl.next_update, "revoked_count":network.crl.revoked_certificates.len()}
    })).collect();
    Ok(Json(
        json!({"policy_revision":policy.revision,"client_id":client.id,"networks":networks}),
    ))
}
