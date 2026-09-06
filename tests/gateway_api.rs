//! In-process tests for the gateway router — no socket, no Docker.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use genesis_mesh::gateway::{router, Config};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // `oneshot`

const TOKEN: &str = "test-token";

fn test_config() -> Config {
    Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        token: Some(TOKEN.to_string()),
        timeout: Duration::from_secs(10),
        max_body_bytes: 1 << 20,
        max_inflight: 64,
        max_batch: 128,
        max_batch_inflight: 8,
    }
}

fn app() -> axum::Router {
    router(test_config())
}

fn app_with(cfg: Config) -> axum::Router {
    router(cfg)
}

async fn call_on(
    app: axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let request = match body {
        Some(v) => builder
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

async fn call(
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    call_on(app(), method, path, token, body).await
}

/// keygen + issue a cert signed by `na-001`; returns (authority_pub, cert).
async fn issue_cert() -> (String, Value) {
    let (_, authority) = call("POST", "/keygen", Some(TOKEN), None).await;
    let (_, node) = call("POST", "/keygen", Some(TOKEN), None).await;
    let auth_seed = authority["seed_b64"].as_str().unwrap().to_string();
    let auth_pub = authority["public_key_b64"].as_str().unwrap().to_string();
    let node_pub = node["public_key_b64"].as_str().unwrap().to_string();

    let (status, cert) = call(
        "POST",
        "/issue",
        Some(TOKEN),
        Some(json!({
            "seed_b64": auth_seed,
            "key_id": "na-001",
            "node_public_key": node_pub,
            "network_name": "mesh-alpha",
            "roles": ["role:anchor"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cert}");
    (auth_pub, cert)
}

#[tokio::test]
async fn health_needs_no_auth() {
    let (status, body) = call("GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn keygen_requires_token() {
    let (status, _) = call("POST", "/keygen", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = call("POST", "/keygen", Some("wrong"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = call("POST", "/keygen", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["seed_b64"].as_str().unwrap().len() > 20);
    assert!(body["public_key_b64"].as_str().is_some());
}

#[tokio::test]
async fn issue_then_verify_trusted() {
    let (auth_pub, cert) = issue_cert().await;

    let (status, body) = call(
        "POST",
        "/verify",
        Some(TOKEN),
        Some(json!({ "certificate": cert, "anchors": { "na-001": auth_pub } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["trusted"], true, "{body}");
    assert_eq!(body["reasons"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn verify_wrong_anchor_is_untrusted() {
    let (_auth_pub, cert) = issue_cert().await;
    let (_, other) = call("POST", "/keygen", Some(TOKEN), None).await;
    let other_pub = other["public_key_b64"].as_str().unwrap();

    let (status, body) = call(
        "POST",
        "/verify",
        Some(TOKEN),
        Some(json!({ "certificate": cert, "anchors": { "na-001": other_pub } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["trusted"], false);
    let reasons = body["reasons"].as_array().unwrap();
    assert!(reasons
        .iter()
        .any(|r| r.as_str().unwrap().contains("BadSignature")));
}

#[tokio::test]
async fn verify_missing_anchors_is_bad_request() {
    let (_auth_pub, cert) = issue_cert().await;
    let (status, _) = call(
        "POST",
        "/verify",
        Some(TOKEN),
        Some(json!({ "certificate": cert, "anchors": {} })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_batch_evaluates_each() {
    let (auth_pub, cert) = issue_cert().await;
    let (_, other) = call("POST", "/keygen", Some(TOKEN), None).await;
    let other_pub = other["public_key_b64"].as_str().unwrap();

    // Same cert, three times; anchor is correct -> all trusted.
    let (status, body) = call(
        "POST",
        "/verify/batch",
        Some(TOKEN),
        Some(json!({
            "certificates": [cert, cert, cert],
            "anchors": { "na-001": auth_pub },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|r| r["trusted"] == true));

    // Wrong anchor -> none trusted.
    let (status, body) = call(
        "POST",
        "/verify/batch",
        Some(TOKEN),
        Some(json!({
            "certificates": [cert],
            "anchors": { "na-001": other_pub },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["results"][0]["trusted"], false);
}

#[tokio::test]
async fn unknown_route_is_404() {
    let (status, _) = call("GET", "/nope", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_stays_up_when_inflight_is_zero() {
    let mut cfg = test_config();
    cfg.max_inflight = 0;
    let (status, body) = call_on(app_with(cfg), "GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn verify_is_shed_when_inflight_is_zero() {
    let mut cfg = test_config();
    cfg.max_inflight = 0;
    let (status, body) = call_on(
        app_with(cfg),
        "POST",
        "/verify",
        Some(TOKEN),
        Some(json!({
            "certificate": {"cert_id": "x"},
            "anchors": {"na-001": "x"},
        })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server overloaded");
}

#[tokio::test]
async fn verify_batch_is_shed_when_batch_inflight_is_zero() {
    let (auth_pub, cert) = issue_cert().await;
    let mut cfg = test_config();
    cfg.max_batch_inflight = 0;
    let (status, body) = call_on(
        app_with(cfg),
        "POST",
        "/verify/batch",
        Some(TOKEN),
        Some(json!({
            "certificates": [cert],
            "anchors": { "na-001": auth_pub },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server overloaded");
}

#[tokio::test]
async fn verify_batch_parallel_path_matches_sequential() {
    let (auth_pub, cert) = issue_cert().await;
    // 20 certs is above VERIFY_BATCH_PARALLEL_THRESHOLD (16).
    let certificates = vec![cert; 20];
    let (status, body) = call(
        "POST",
        "/verify/batch",
        Some(TOKEN),
        Some(json!({
            "certificates": certificates,
            "anchors": { "na-001": auth_pub },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 20);
    assert!(results.iter().all(|r| r["trusted"] == true));
}

#[tokio::test]
async fn index_is_valid_json() {
    let (status, body) = call("GET", "/", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["service"], "genesis-mesh-gateway");
    assert!(body["endpoints"]["GET /health"].is_string());
}
