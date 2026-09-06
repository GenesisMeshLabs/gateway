//! Security boundary regression tests using real Genesis Mesh signatures.
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use chrono::Utc;
use genesis_mesh::{
    gateway::{
        router,
        security::{Client, NetworkPolicy, SecurityPolicy},
        Config,
    },
    models::{CertificateRevocationList, JoinCertificate, RevokedCertificate, Signed},
    KeyPair,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Duration};
use tower::ServiceExt;

const TOKEN: &str = "test-production-service-token-32-bytes-minimum";

#[tokio::test]
async fn durable_gateway_restart_restores_revocations_and_audit_without_upstream() {
    use genesis_mesh::gateway::durable::DurableState;
    let folder = std::env::temp_dir().join(format!("gateway-state-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&folder).unwrap();
    let path = folder.join("state.db");
    assert!(DurableState::open(&path).is_err());
    DurableState::initialize(&path).unwrap();
    let (mut cfg, cert, key) = fixture();
    let old_policy = cfg.security.clone().unwrap();
    let durable = DurableState::open(&path).unwrap();
    assert!(
        DurableState::open(&path).is_err(),
        "second writer must be rejected"
    );
    durable.restore(cfg.security.as_mut().unwrap()).unwrap();
    let n = cfg
        .security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap();
    n.crl.sequence += 1;
    n.crl.revoked_certificates.push(RevokedCertificate {
        certificate_id: cert.cert_id.clone(),
        revoked_at: Utc::now(),
        reason: "key_compromise".into(),
        issuer: "authority".into(),
    });
    n.crl.signatures.clear();
    n.crl.sign(&key, "authority").unwrap();
    durable.checkpoint("public-agency", n).unwrap();
    durable
        .audit("test-audit", &json!({"event":"checkpoint-test"}))
        .unwrap();
    drop(durable);
    let durable = std::sync::Arc::new(DurableState::open(&path).unwrap());
    cfg.security = Some(old_policy);
    durable.restore(cfg.security.as_mut().unwrap()).unwrap();
    assert_eq!(
        cfg.security.as_ref().unwrap().networks["public-agency"]
            .crl
            .sequence,
        6
    );
    assert_eq!(durable.pending_audit().unwrap()[0]["id"], "test-audit");
    durable.acknowledge(&["test-audit".into()]).unwrap();
    cfg.durable = Some(durable.clone());
    let app = router(cfg);
    let (status, result) = call(
        &app,
        "/verify",
        Some(json!({"certificate":cert})),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["trusted"], false);
    assert!(result["reasons"].to_string().contains("Revoked"));
    let pending = durable.pending_audit().unwrap();
    assert!(pending.len() >= 2);
    let completed = pending
        .iter()
        .find(|e| e["event"]["phase"] == "completed")
        .unwrap();
    assert_eq!(
        completed["event"]["context"]["trust_decision"]["trusted"],
        false
    );
    assert_eq!(
        durable.pending_audit().unwrap(),
        pending,
        "unacknowledged delivery retries retain stable IDs"
    );
    durable.acknowledge(&["foreign-id".into()]).unwrap();
    assert_eq!(durable.pending_audit().unwrap(), pending);
    let (count, bytes) = durable.stats().unwrap();
    assert_eq!(count, pending.len() as u64);
    assert!(bytes > 0);
    drop(app);
    drop(durable);
    std::fs::remove_dir_all(folder).unwrap();
}

#[test]
fn durable_state_rejects_corruption_conflicts_and_forged_progress() {
    use genesis_mesh::gateway::durable::DurableState;
    let folder = std::env::temp_dir().join(format!("gateway-state-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&folder).unwrap();
    let path = folder.join("state.db");
    DurableState::initialize(&path).unwrap();
    let (mut cfg, _, key) = fixture();
    let durable = DurableState::open(&path).unwrap();
    durable.restore(cfg.security.as_mut().unwrap()).unwrap();
    let mut altered = cfg
        .security
        .unwrap()
        .networks
        .remove("public-agency")
        .unwrap();
    altered.crl.sequence += 1;
    altered.crl.signatures.clear();
    altered
        .crl
        .sign(&KeyPair::generate().unwrap(), "authority")
        .unwrap();
    assert!(durable.checkpoint("public-agency", &altered).is_err());
    altered.crl.sequence = 4;
    altered.crl.signatures.clear();
    altered.crl.sign(&key, "authority").unwrap();
    assert!(durable.checkpoint("public-agency", &altered).is_err());
    assert!(!durable.healthy());
    drop(durable);
    std::fs::write(&path, b"corrupted").unwrap();
    assert!(DurableState::open(&path).is_err());
    std::fs::remove_dir_all(folder).unwrap();
}

#[tokio::test]
async fn multiple_issuers_use_their_own_signed_revocations_and_parent_roles() {
    let (mut cfg, mut cert, _) = fixture();
    let other_key = KeyPair::generate().unwrap();
    let parent = cfg
        .security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap();
    let mut other = parent.clone();
    other.required_roles.clear();
    other.anchors = [("other".into(), other_key.public_key_b64())].into();
    other.crl.issuer = "other".into();
    other.crl.signatures.clear();
    other.crl.sign(&other_key, "other").unwrap();
    parent
        .additional_issuers
        .insert("other".into(), Box::new(other));
    cfg.prepare().unwrap();
    cert.issued_by = "other".into();
    cert.signatures.clear();
    cert.sign(&other_key, "other").unwrap();
    let (status, value) = call(
        &router(cfg.clone()),
        "/verify",
        Some(json!({"certificate":cert})),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["trusted"], true);
    let other = cfg
        .security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap()
        .additional_issuers
        .get_mut("other")
        .unwrap();
    other.crl.revoked_certificates.push(RevokedCertificate {
        certificate_id: cert.cert_id.clone(),
        revoked_at: Utc::now(),
        reason: "key_compromise".into(),
        issuer: "other".into(),
    });
    other.crl.signatures.clear();
    other.crl.sign(&other_key, "other").unwrap();
    let (_, value) = call(
        &router(cfg),
        "/verify",
        Some(json!({"certificate":cert})),
        Some(TOKEN),
    )
    .await;
    assert_eq!(value["trusted"], false);
    assert!(value["reasons"].to_string().contains("Revoked"));
}

fn fixture() -> (Config, JoinCertificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let now = Utc::now();
    let mut cert = JoinCertificate {
        cert_id: "certificate-1".into(),
        node_public_key: KeyPair::generate().unwrap().public_key_b64(),
        network_name: "public-agency".into(),
        roles: vec!["reader".into()],
        issued_at: now - chrono::Duration::minutes(1),
        expires_at: now + chrono::Duration::days(1),
        issued_by: "authority".into(),
        signatures: vec![],
    };
    cert.sign(&key, "authority").unwrap();
    let mut crl = CertificateRevocationList {
        crl_id: "snapshot-1".into(),
        sequence: 5,
        issued_at: now - chrono::Duration::minutes(1),
        next_update: now + chrono::Duration::hours(1),
        issuer: "authority".into(),
        revoked_certificates: vec![],
        signatures: vec![],
    };
    crl.sign(&key, "authority").unwrap();
    let network = NetworkPolicy {
        additional_issuers: Default::default(),
        public_mesh: false,
        authority_url: None,
        crl_url: None,
        allow_http: false,
        anchors: [("authority".into(), key.public_key_b64())].into(),
        crl,
        minimum_crl_sequence: 5,
        required_roles: ["reader".into()].into(),
        verifying_keys: Default::default(),
        revoked_index: Default::default(),
    };
    let client = Client {
        service_groups: Default::default(),
        authority_admin: false,
        id: "agency-service".into(),
        token_sha256: format!("{:x}", Sha256::digest(TOKEN.as_bytes())),
        networks: ["public-agency".into()].into(),
        metrics: false,
        requests_per_minute: 100,
        token_digest: [0; 32],
    };
    (
        Config {
            durable: None,
            oidc: None,
            distributed_quota: None,
            development: false,
            security: Some(SecurityPolicy {
                revision: "test-1".into(),
                networks: [("public-agency".into(), network)].into(),
                clients: vec![client],
                token_index: Default::default(),
            }),
            addr: "127.0.0.1:0".parse().unwrap(),
            token: None,
            timeout: Duration::from_secs(5),
            max_body_bytes: 65536,
            max_inflight: 4,
            max_batch: 8,
            cpu_workers: 1,
            max_batch_jobs: 1,
        },
        cert,
        key,
    )
}

async fn call(
    app: &Router,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(if body.is_some() { "POST" } else { "GET" })
        .uri(path);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(
            req.header("content-type", "application/json")
                .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.headers().contains_key("x-request-id"));
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn production_uses_operator_policy_and_removes_signing_routes() {
    let (cfg, cert, _) = fixture();
    let app = router(cfg);
    let (status, result) = call(
        &app,
        "/verify",
        Some(json!({"certificate":cert})),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["trusted"], true);
    for path in ["/issue", "/keygen"] {
        assert_eq!(
            call(&app, path, Some(json!({})), Some(TOKEN)).await.0,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        call(
            &app,
            "/verify",
            Some(json!({"certificate":cert,"anchors":{"attacker":"key"}})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&app, "/verify", Some(json!({"certificate":cert})), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(call(&app, "/ready", None, None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn client_cannot_cross_network_or_scrape_metrics() {
    let (cfg, mut cert, key) = fixture();
    let app = router(cfg);
    cert.network_name = "another-agency".into();
    cert.signatures.clear();
    cert.sign(&key, "authority").unwrap();
    assert_eq!(
        call(
            &app,
            "/verify",
            Some(json!({"certificate":cert})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "/verify/batch",
            Some(json!({"certificates":[cert]})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, "/metrics", None, Some(TOKEN)).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn network_data_requires_auth_and_never_exposes_client_credentials() {
    let (cfg, _, _) = fixture();
    let app = router(cfg);
    assert_eq!(
        call(&app, "/v1/networks", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, body) = call(&app, "/v1/networks", None, Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["networks"][0]["name"], "public-agency");
    assert!(!body.to_string().contains("token_sha256"));
    let (status, spec) = call(&app, "/openapi.json", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(spec["openapi"], "3.1.0");
}

#[tokio::test]
async fn revoked_and_missing_role_certificates_are_denied() {
    let (mut cfg, mut cert, key) = fixture();
    let crl = &mut cfg
        .security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap()
        .crl;
    crl.revoked_certificates.push(RevokedCertificate {
        certificate_id: cert.cert_id.clone(),
        revoked_at: Utc::now(),
        reason: "key_compromise".into(),
        issuer: "authority".into(),
    });
    crl.signatures.clear();
    crl.sign(&key, "authority").unwrap();
    let app = router(cfg);
    assert_eq!(
        call(
            &app,
            "/verify",
            Some(json!({"certificate":cert})),
            Some(TOKEN)
        )
        .await
        .1["trusted"],
        false
    );
    cert.roles.clear();
    cert.signatures.clear();
    cert.sign(&key, "authority").unwrap();
    assert_eq!(
        call(
            &app,
            "/verify",
            Some(json!({"certificate":cert})),
            Some(TOKEN)
        )
        .await
        .1["reasons"][0],
        "NetworkPolicyRejected"
    );
}

#[tokio::test]
async fn quota_is_shared_across_requests_and_metrics_require_scope() {
    let (mut cfg, cert, _) = fixture();
    cfg.security.as_mut().unwrap().clients[0].requests_per_minute = 1;
    let app = router(cfg);
    assert_eq!(
        call(
            &app,
            "/verify",
            Some(json!({"certificate":cert})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "/verify",
            Some(json!({"certificate":cert})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let (mut cfg, _, _) = fixture();
    cfg.security.as_mut().unwrap().clients[0].metrics = true;
    assert_eq!(
        call(&router(cfg), "/metrics", None, Some(TOKEN)).await.0,
        StatusCode::OK
    );
}

#[test]
fn invalid_security_configuration_fails_closed() {
    let (base, _, _) = fixture();
    assert!(base.validate().is_ok());
    let mut cfg = base.clone();
    cfg.security = None;
    assert!(cfg.validate().is_err());
    let mut cfg = base.clone();
    cfg.max_inflight = 0;
    assert!(cfg.validate().is_err());
    let mut cfg = base.clone();
    cfg.security.as_mut().unwrap().clients[0].networks = BTreeSet::new();
    assert!(cfg.validate().is_err());
    for mode in 0..4 {
        let mut cfg = base.clone();
        let n = cfg
            .security
            .as_mut()
            .unwrap()
            .networks
            .get_mut("public-agency")
            .unwrap();
        match mode {
            0 => n.crl.signatures.clear(),
            1 => n.crl.next_update = Utc::now() - chrono::Duration::seconds(1),
            2 => n.minimum_crl_sequence = 6,
            _ => n.crl.issued_at = Utc::now() + chrono::Duration::hours(1),
        }
        assert!(cfg.validate().is_err());
    }
}

#[tokio::test]
async fn malformed_oversized_and_excessive_batches_are_rejected() {
    let (mut cfg, cert, _) = fixture();
    cfg.max_body_bytes = 4096;
    cfg.max_batch = 1;
    let app = router(cfg);
    assert_eq!(
        call(
            &app,
            "/verify/batch",
            Some(json!({"certificates":[cert,cert]})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &app,
            "/verify/batch",
            Some(json!({"certificates":[]})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &app,
            "/verify",
            Some(json!({"certificate":cert,"unexpected":true})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        call(
            &app,
            "/verify",
            Some(json!({"padding":"x".repeat(5000)})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[test]
fn snapshot_expiry_and_issuer_binding_are_enforced_at_evaluation_time() {
    let (cfg, mut cert, key) = fixture();
    let n = &cfg.security.as_ref().unwrap().networks["public-agency"];
    assert!(!n.accepts(&cert, n.crl.next_update));
    cert.issued_by = "impostor".into();
    cert.signatures.clear();
    cert.sign(&key, "authority").unwrap();
    assert!(!n.accepts(&cert, Utc::now()));
}

#[tokio::test]
async fn another_trusted_anchor_cannot_impersonate_the_claimed_issuer() {
    let (mut cfg, mut cert, _) = fixture();
    let other = KeyPair::generate().unwrap();
    cfg.security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap()
        .anchors
        .insert("other-authority".into(), other.public_key_b64());
    cert.signatures.clear();
    cert.sign(&other, "other-authority").unwrap();
    let app = router(cfg);
    let (_, result) = call(
        &app,
        "/verify",
        Some(json!({"certificate": cert})),
        Some(TOKEN),
    )
    .await;
    assert_eq!(result["trusted"], false);
    assert!(result["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "IssuerSignatureMissing"));
}

#[tokio::test]
async fn indexed_revocations_preserve_the_first_duplicate_entry() {
    let (mut cfg, cert, key) = fixture();
    let crl = &mut cfg
        .security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap()
        .crl;
    for reason in ["first-reason", "second-reason"] {
        crl.revoked_certificates.push(RevokedCertificate {
            certificate_id: cert.cert_id.clone(),
            revoked_at: Utc::now(),
            reason: reason.into(),
            issuer: "authority".into(),
        });
    }
    crl.signatures.clear();
    crl.sign(&key, "authority").unwrap();
    let (_, result) = call(
        &router(cfg),
        "/verify",
        Some(json!({"certificate":cert})),
        Some(TOKEN),
    )
    .await;
    assert_eq!(result["trusted"], false);
    assert!(result["reasons"].to_string().contains("first-reason"));
    assert!(!result["reasons"].to_string().contains("second-reason"));
}

#[tokio::test]
async fn excessive_signatures_are_rejected_before_crypto() {
    let (cfg, mut cert, _) = fixture();
    cert.signatures = vec![cert.signatures[0].clone(); 9];
    assert_eq!(
        call(
            &router(cfg),
            "/verify",
            Some(json!({"certificate":cert})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn replica_request_identifiers_do_not_collide() {
    let (cfg, _, _) = fixture();
    let first = router(cfg.clone())
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let second = router(cfg)
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        first.headers()["x-request-id"],
        second.headers()["x-request-id"]
    );
}

fn service_fixture(origin: &str) -> Config {
    let (mut cfg, _, _) = fixture();
    let policy = cfg.security.as_mut().unwrap();
    let network = policy.networks.get_mut("public-agency").unwrap();
    network.authority_url = Some(origin.into());
    network.allow_http = true;
    policy.clients[0].service_groups = ["network".into(), "attestations".into()].into();
    cfg
}

#[tokio::test]
async fn authority_services_enforce_network_group_and_operator_scope() {
    let cfg = service_fixture("http://127.0.0.1:9");
    let app = router(cfg.clone());
    assert_eq!(
        call(
            &app,
            "/v1/networks/other/services/public-get-genesis",
            None,
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "/v1/networks/public-agency/services/admin-create-invite",
            Some(json!({})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "/v1/networks/public-agency/services/attestations-issue-attestation",
            Some(json!({})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let mut cfg = cfg;
    cfg.security.as_mut().unwrap().clients[0].authority_admin = true;
    let app = router(cfg);
    let (status, body) = call(
        &app,
        "/v1/networks/public-agency/services/attestations-issue-attestation",
        Some(json!({})),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().unwrap().contains("operator-signed"));
}

async fn mock_authority(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (origin, task)
}

#[tokio::test]
async fn authority_forwarding_preserves_signed_body_but_never_gateway_credentials() {
    async fn receive(
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> (StatusCode, axum::Json<Value>) {
        assert!(!headers.contains_key("authorization"));
        assert!(!headers.contains_key("cookie"));
        assert!(!headers.contains_key("x-forwarded-host"));
        assert_eq!(headers["x-admin-key-id"], "operator-test");
        assert_eq!(
            body.as_ref(),
            b"{ \"subject_id\": \"subject\", \"roles\": [\"member\"] }"
        );
        (
            StatusCode::CREATED,
            axum::Json(json!({"attestation_id":"created"})),
        )
    }
    let (origin, task) =
        mock_authority(Router::new().route("/admin/attestations", axum::routing::post(receive)))
            .await;
    let mut cfg = service_fixture(&origin);
    cfg.security.as_mut().unwrap().clients[0].authority_admin = true;
    let app = router(cfg);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/networks/public-agency/services/attestations-issue-attestation")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("cookie", "session=must-not-forward")
                .header("x-forwarded-host", "attacker.invalid")
                .header("x-admin-key-id", "operator-test")
                .header("x-admin-timestamp", "2026-09-06T00:00:00Z")
                .header("x-admin-nonce", "unique-nonce")
                .header("x-admin-signature", "signed-request")
                .body(Body::from(
                    "{ \"subject_id\": \"subject\", \"roles\": [\"member\"] }",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    task.abort();
}

#[tokio::test]
async fn authority_rejects_path_injection_unknown_queries_and_wrong_methods() {
    let app = router(service_fixture("http://127.0.0.1:9"));
    for path in [
        "/v1/networks/public-agency/services/attestations-get-attestation?attestation_id=..%2Fadmin",
        "/v1/networks/public-agency/services/attestations-get-attestation?attestation_id=%252e%252e",
        "/v1/networks/public-agency/services/public-get-genesis?url=http://attacker.invalid",
    ] { assert_eq!(call(&app,path,None,Some(TOKEN)).await.0,StatusCode::BAD_REQUEST,"{path}"); }
    assert_eq!(
        call(
            &app,
            "/v1/networks/public-agency/services/public-get-genesis",
            Some(json!({})),
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        call(
            &app,
            "/v1/networks/public-agency/services/not-a-service",
            None,
            Some(TOKEN)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn authority_redirects_and_non_json_responses_fail_closed() {
    for response in [
        axum::response::Response::builder()
            .status(302)
            .header("location", "http://127.0.0.1:9/private")
            .body(Body::empty())
            .unwrap(),
        axum::response::Response::builder()
            .status(200)
            .body(Body::from("<html>private failure detail</html>"))
            .unwrap(),
        axum::response::Response::builder()
            .status(500)
            .body(Body::from("private failure detail"))
            .unwrap(),
        axum::response::Response::builder()
            .status(200)
            .body(Body::from("x".repeat(2 * 1024 * 1024 + 1)))
            .unwrap(),
    ] {
        let saved = std::sync::Arc::new(tokio::sync::Mutex::new(Some(response)));
        let (origin, task) = mock_authority(Router::new().route(
            "/genesis",
            axum::routing::get(move || {
                let saved = saved.clone();
                async move { saved.lock().await.take().unwrap() }
            }),
        ))
        .await;
        let app = router(service_fixture(&origin));
        let (status, body) = call(
            &app,
            "/v1/networks/public-agency/services/public-get-genesis",
            None,
            Some(TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(!body.to_string().contains("private failure detail"));
        task.abort();
    }
}

#[test]
fn authority_origins_reject_credentials_paths_queries_and_implicit_http() {
    for origin in [
        "http://name:password@localhost",
        "http://localhost/path",
        "http://localhost?url=other",
        "file:///tmp/a",
    ] {
        assert!(service_fixture(origin).prepare().is_err());
    }
    let mut cfg = service_fixture("http://localhost");
    cfg.security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap()
        .allow_http = false;
    assert!(cfg.prepare().is_err());
}

#[tokio::test]
async fn every_catalog_operation_is_documented_in_openapi() {
    let app = router(fixture().0);
    let (_, catalog) = call(&app, "/v1/services", None, None).await;
    let (_, spec) = call(&app, "/openapi.json", None, None).await;
    let operations = catalog["operations"].as_array().unwrap();
    assert!(operations.len() >= 59);
    for op in operations {
        let path = format!(
            "/v1/networks/{{network}}/services/{}",
            op["id"].as_str().unwrap()
        );
        assert!(spec["paths"].get(path).is_some());
    }
}

#[tokio::test]
async fn public_mesh_is_opt_in_and_never_exposes_private_policy() {
    let (status, body) = call(&router(fixture().0), "/v1/mesh", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["networks"], json!([]));
    assert!(!body.to_string().contains("public-agency"));
    assert!(!body.to_string().contains(TOKEN));
}

#[tokio::test]
async fn public_mesh_marks_failed_upstreams_and_coalesces_refreshes() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let (origin, task) = mock_authority(Router::new().fallback(move || {
        let observed = observed.clone();
        async move {
            observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (StatusCode::INTERNAL_SERVER_ERROR, "private diagnostics")
        }
    }))
    .await;
    let mut cfg = service_fixture(&origin);
    cfg.security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap()
        .public_mesh = true;
    let app = router(cfg);
    let (status, body) = call(&app, "/v1/mesh", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["networks"][0]["available"], false);
    assert_eq!(body["links"], json!([]));
    assert!(!body.to_string().contains("private diagnostics"));
    assert!(!body.to_string().contains(&origin));
    assert!(!body.to_string().contains("anchors"));
    let (_, again) = call(&app, "/v1/mesh", None, None).await;
    assert_eq!(body, again);
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 4);
    task.abort();
}
