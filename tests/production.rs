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

/// Lowercase hex SHA-256, the `token_sha256` form of a client policy.
fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

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
        public_external_treaties: false,
        mesh_reader: None,
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
        token_sha256: sha256_hex(TOKEN.as_bytes()),
        networks: ["public-agency".into()].into(),
        metrics: false,
        requests_per_minute: 100,
        demo: false,
        demo_token: None,
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
    assert_eq!(spec["info"]["version"], env!("CARGO_PKG_VERSION"));
}

/// Anonymous traffic to public pages and unknown paths writes nothing to the
/// durable audit store, which fails closed when full (v1.1.0).
#[tokio::test]
async fn public_pages_and_unknown_paths_do_not_fill_the_durable_audit() {
    use genesis_mesh::gateway::durable::DurableState;
    let folder = std::env::temp_dir().join(format!("gateway-audit-scope-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&folder).unwrap();
    let path = folder.join("state.db");
    DurableState::initialize(&path).unwrap();
    let durable = std::sync::Arc::new(DurableState::open(&path).unwrap());
    let (mut cfg, _, _) = fixture();
    durable.restore(cfg.security.as_mut().unwrap()).unwrap();
    cfg.durable = Some(durable.clone());
    let app = router(cfg);

    for path in [
        "/",
        "/api",
        "/assets/app.js",
        "/assets/errors.js",
        "/openapi.json",
        "/no/such/path",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
    }
    assert!(durable.pending_audit().unwrap().is_empty());

    assert_eq!(
        call(&app, "/v1/networks", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let pending = durable.pending_audit().unwrap();
    let phases: Vec<_> = pending
        .iter()
        .map(|e| e["event"]["phase"].clone())
        .collect();
    assert_eq!(phases, vec![json!("started"), json!("completed")]);
    assert_eq!(pending[0]["event"]["route"], "/v1/networks");
    std::fs::remove_dir_all(folder).ok();
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
    // Retry-After is when the client's quota window resets, not a fixed minute.
    let refused = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"certificate":cert}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    let wait: u64 = refused.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&wait), "{wait}");
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

fn evidence_fixture(origin: &str) -> Config {
    let mut cfg = service_fixture(origin);
    let client = &mut cfg.security.as_mut().unwrap().clients[0];
    client.service_groups = ["evidence_store".into(), "boundary_policy".into()].into();
    client.authority_admin = true;
    cfg
}

async fn signed_get(app: &Router, path: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("x-admin-key-id", "operator-test")
                .header("x-admin-timestamp", "2026-10-03T00:00:00Z")
                .header("x-admin-nonce", "unique-nonce")
                .header("x-admin-signature", "signed-request")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn resource_ids_span_segments_and_carry_unicode_encoded_once() {
    let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
    let record = seen.clone();
    let (origin, task) = mock_authority(Router::new().fallback(move |uri: axum::http::Uri| {
        let record = record.clone();
        async move {
            record.lock().await.push(uri.to_string());
            axum::Json(json!({"resource_sequence": 3, "record_digest": "d"}))
        }
    }))
    .await;
    let app = router(evidence_fixture(&origin));
    for (path, upstream) in [
        (
            "/v1/networks/public-agency/services/evidence_store-resource-head?resource_id=kv%3Apilot-vault%2Fvendor-zo%C3%AB-api",
            "/admin/evidence/resource-heads/kv:pilot-vault/vendor-zo%C3%AB-api",
        ),
        (
            "/v1/networks/public-agency/services/evidence_store-resource-history?resource_id=kv%3Av%2Fs%20one",
            "/admin/evidence/resources/kv:v/s%20one",
        ),
        (
            "/v1/networks/public-agency/services/evidence_store-vendor-history?vendor_id=vendor-zo%C3%AB",
            "/admin/evidence/vendors/vendor-zo%C3%AB",
        ),
        (
            "/v1/networks/public-agency/services/evidence_store-search?vendor_id=v1&entry_kind=execution&after_sequence=5&limit=2",
            "/admin/evidence?after_sequence=5&entry_kind=execution&limit=2&vendor_id=v1",
        ),
    ] {
        let response = signed_get(&app, path).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(seen.lock().await.last().unwrap(), upstream);
    }
    task.abort();
}

#[tokio::test]
async fn evidence_identifiers_refuse_traversal_and_encoded_paths() {
    let app = router(evidence_fixture("http://127.0.0.1:9"));
    for query in [
        "evidence_store-resource-head?resource_id=kv%3Av%2F..%2Fadmin",
        "evidence_store-resource-head?resource_id=kv%3Av%2F%2Fs",
        "evidence_store-resource-head?resource_id=%252e%252e",
        "evidence_store-resource-head?resource_id=kv%3Av%5Cs",
        "evidence_store-resource-head?resource_id=kv%3Av%0As",
        "evidence_store-resource-head?resource_id=",
        "evidence_store-vendor-history?vendor_id=a%2Fb",
        "evidence_store-retire-executor-key?key_id=k%C3%AB",
    ] {
        let path = format!("/v1/networks/public-agency/services/{query}");
        let method_body = query
            .starts_with("evidence_store-retire")
            .then(|| json!({}));
        let response = if method_body.is_some() {
            call(&app, &path, method_body, Some(TOKEN)).await.0
        } else {
            signed_get(&app, &path).await.status()
        };
        assert_eq!(response, StatusCode::BAD_REQUEST, "{query}");
    }
}

#[tokio::test]
async fn new_admin_reads_require_operator_signed_headers() {
    let app = router(evidence_fixture("http://127.0.0.1:9"));
    for op in [
        "evidence_store-search",
        "evidence_store-status",
        "evidence_store-export",
        "boundary_policy-active-policies",
        "evidence_store-resource-head?resource_id=kv%3Av%2Fs",
    ] {
        let (status, body) = call(
            &app,
            &format!("/v1/networks/public-agency/services/{op}"),
            None,
            Some(TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{op}");
        assert!(body["error"].as_str().unwrap().contains("operator-signed"));
    }
    let mut cfg = evidence_fixture("http://127.0.0.1:9");
    cfg.security.as_mut().unwrap().clients[0].service_groups = ["network".into()].into();
    let (status, _) = call(
        &router(cfg),
        "/v1/networks/public-agency/services/evidence_store-status",
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn evidence_export_is_forwarded_as_json_lines_and_fails_closed_otherwise() {
    let lines = "{\"entry\":{\"store_sequence\":1}}\n{\"entry\":{\"store_sequence\":2}}\n";
    for (body, expected) in [
        (lines.to_owned(), StatusCode::OK),
        (
            "{\"entry\":1}\n<html>private failure detail</html>\n".to_owned(),
            StatusCode::BAD_GATEWAY,
        ),
        (
            "{\"x\":\"".to_owned() + &"y".repeat(8 * 1024 * 1024) + "\"}\n",
            StatusCode::BAD_GATEWAY,
        ),
    ] {
        let saved = std::sync::Arc::new(tokio::sync::Mutex::new(Some(body)));
        let (origin, task) = mock_authority(Router::new().route(
            "/admin/evidence/export",
            axum::routing::get(move |uri: axum::http::Uri| {
                let saved = saved.clone();
                async move {
                    assert_eq!(uri.query(), Some("limit=2&since_sequence=0"));
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
                        saved.lock().await.take().unwrap(),
                    )
                }
            }),
        ))
        .await;
        let app = router(evidence_fixture(&origin));
        let response = signed_get(
            &app,
            "/v1/networks/public-agency/services/evidence_store-export?since_sequence=0&limit=2",
        )
        .await;
        assert_eq!(response.status(), expected);
        let content_type = response.headers()["content-type"]
            .to_str()
            .unwrap()
            .to_owned();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        if expected == StatusCode::OK {
            assert_eq!(content_type, "application/x-ndjson");
            assert_eq!(bytes.as_ref(), lines.as_bytes());
        } else {
            assert!(!String::from_utf8_lossy(&bytes).contains("private failure detail"));
        }
        task.abort();
    }
}

#[tokio::test]
async fn authority_errors_on_new_routes_are_forwarded_with_their_code() {
    let (origin, task) = mock_authority(Router::new().fallback(|| async {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": {"code": "resource_not_found", "message": "no head"}})),
        )
    }))
    .await;
    let app = router(evidence_fixture(&origin));
    let response = signed_get(
        &app,
        "/v1/networks/public-agency/services/evidence_store-resource-head?resource_id=kv%3Av%2Fnone",
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"]["code"], "resource_not_found");
    task.abort();
}

#[tokio::test]
async fn the_authoritys_retry_after_and_request_id_are_passed_on() {
    let (origin, task) =
        mock_authority(Router::new().fallback(|uri: axum::http::Uri| async move {
            let (status, retry, id) = match uri.path() {
                "/admin/evidence/status" => (
                    StatusCode::TOO_MANY_REQUESTS,
                    "17",
                    "1f0c2a5e-9d3b-4c1a-8f2e-6b7a9c0d1e2f",
                ),
                "/admin/evidence/verify" => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "30", "upstream-500")
                }
                _ => (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Wed, 21 Oct 2026 07:28:00 GMT",
                    "has spaces in it",
                ),
            };
            (
                status,
                [("retry-after", retry), ("x-request-id", id)],
                axum::Json(
                    json!({"error": {"code": "rate_limit_exceeded", "message": "slow down"}}),
                ),
            )
        }))
        .await;
    let app = router(evidence_fixture(&origin));
    let limited = signed_get(
        &app,
        "/v1/networks/public-agency/services/evidence_store-status",
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers()["retry-after"], "17");
    assert_eq!(
        limited.headers()["x-upstream-request-id"],
        "1f0c2a5e-9d3b-4c1a-8f2e-6b7a9c0d1e2f"
    );
    assert_ne!(
        limited.headers()["x-request-id"],
        limited.headers()["x-upstream-request-id"]
    );
    // A server error is not relayed, but its retry time and request ID are.
    let failed = signed_get(
        &app,
        "/v1/networks/public-agency/services/evidence_store-verify",
    )
    .await;
    assert_eq!(failed.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(failed.headers()["retry-after"], "30");
    assert_eq!(failed.headers()["x-upstream-request-id"], "upstream-500");
    // Values the gateway cannot vouch for are dropped; a relayed 429 still says when to retry.
    let odd = signed_get(
        &app,
        "/v1/networks/public-agency/services/evidence_store-list-executor-keys",
    )
    .await;
    assert_eq!(odd.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(odd.headers()["retry-after"], "60");
    assert!(!odd.headers().contains_key("x-upstream-request-id"));
    task.abort();
}

#[tokio::test]
async fn an_authority_503_keeps_its_code_and_other_server_errors_do_not() {
    // SDKs never break the glass on `evidence_store_unavailable`; a 502 hid
    // the code (1.3.1).
    let unavailable = json!({"error": {
        "code": "evidence_store_unavailable",
        "message": "The evaluation could not be stored",
        "request_id": "upstream-1",
    }});
    let private = "private failure detail";
    for (status, body, expected) in [
        (
            503,
            unavailable.to_string(),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            503,
            format!("<html>{private}</html>"),
            StatusCode::BAD_GATEWAY,
        ),
        (503, json!([private]).to_string(), StatusCode::BAD_GATEWAY),
        (
            503,
            json!({"error": {"code": "x", "message": "y".repeat(16 * 1024)}}).to_string(),
            StatusCode::BAD_GATEWAY,
        ),
        (
            500,
            json!({"error": {"code": "internal_error", "message": private}}).to_string(),
            StatusCode::BAD_GATEWAY,
        ),
        (504, unavailable.to_string(), StatusCode::BAD_GATEWAY),
    ] {
        let reply = body.clone();
        let (origin, task) = mock_authority(Router::new().fallback(move || {
            let reply = reply.clone();
            async move {
                (
                    StatusCode::from_u16(status).unwrap(),
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    reply,
                )
            }
        }))
        .await;
        let app = router(evidence_fixture(&origin));
        let response = signed_get(
            &app,
            "/v1/networks/public-agency/services/evidence_store-status",
        )
        .await;
        assert_eq!(
            response.status(),
            expected,
            "{status} {}",
            &body[..40.min(body.len())]
        );
        // A relayed 503 still says when to retry.
        let retry = response.headers().get("retry-after").cloned();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        if expected == StatusCode::SERVICE_UNAVAILABLE {
            assert_eq!(retry.unwrap(), "60");
            let relayed: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(relayed, unavailable);
        } else {
            assert!(!String::from_utf8_lossy(&bytes).contains(private));
            assert!(!String::from_utf8_lossy(&bytes).contains("evidence_store_unavailable"));
        }
        task.abort();
    }
}

const DEMO_TOKEN: &str = "public-demo-token-for-the-mesh-console-0001";

fn demo_client() -> genesis_mesh::gateway::security::Client {
    let mut client = fixture().0.security.unwrap().clients.remove(0);
    client.id = "mesh-demo".into();
    client.token_sha256 = sha256_hex(DEMO_TOKEN.as_bytes());
    client.demo = true;
    client.demo_token = Some(DEMO_TOKEN.into());
    client.requests_per_minute = 60;
    client.service_groups = ["attestations".into(), "treaties".into(), "network".into()].into();
    client
}

fn with_demo(mut cfg: Config, demo: genesis_mesh::gateway::security::Client) -> Config {
    cfg.security.as_mut().unwrap().clients.push(demo);
    cfg
}

#[tokio::test]
async fn demo_credentials_are_published_and_limited_to_read_and_verify() {
    async fn verify() -> axum::Json<Value> {
        axum::Json(json!({"accepted": true}))
    }
    let (origin, task) =
        mock_authority(Router::new().route("/attestations/verify", axum::routing::post(verify)))
            .await;
    let app = router(with_demo(service_fixture(&origin), demo_client()));
    let (status, demo) = call(&app, "/v1/demo", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(demo["available"], true);
    let published = &demo["clients"][0];
    assert_eq!(published["token"], DEMO_TOKEN);
    assert_eq!(published["networks"], json!(["public-agency"]));
    assert!(
        !demo.to_string().contains(TOKEN),
        "only demo tokens are published"
    );

    let (status, body) = call(
        &app,
        "/v1/networks/public-agency/services/attestations-verify-attestation",
        Some(json!({"attestation": {}})),
        Some(DEMO_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], true);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/networks/public-agency/services/attestations-issue-attestation")
                .header("authorization", format!("Bearer {DEMO_TOKEN}"))
                .header("content-type", "application/json")
                .header("x-admin-key-id", "operator-test")
                .header("x-admin-timestamp", "2026-10-04T00:00:00Z")
                .header("x-admin-nonce", "unique-nonce")
                .header("x-admin-signature", "signed-request")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    task.abort();
}

#[tokio::test]
async fn no_demo_clients_means_no_published_credentials() {
    let (status, demo) = call(
        &router(service_fixture("http://127.0.0.1:9")),
        "/v1/demo",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        demo,
        json!({"available": false, "clients": [], "notice": demo["notice"]})
    );
}

#[test]
fn unsafe_demo_clients_are_refused_at_startup() {
    type Change = fn(&mut genesis_mesh::gateway::security::Client);
    let cases: [(&str, Change); 7] = [
        ("operator forwarding", |c| c.authority_admin = true),
        ("metrics", |c| c.metrics = true),
        ("enrollment group", |c| {
            c.service_groups.insert("enrollment".into());
        }),
        ("evidence submission group", |c| {
            c.service_groups.insert("evidence_store".into());
        }),
        ("high quota", |c| c.requests_per_minute = 1000),
        ("token mismatch", |c| {
            c.demo_token = Some("another-public-demo-token-0000000000".into())
        }),
        ("missing token", |c| c.demo_token = None),
    ];
    for (name, change) in cases {
        let mut client = demo_client();
        change(&mut client);
        assert!(
            with_demo(service_fixture("http://127.0.0.1:9"), client)
                .prepare()
                .is_err(),
            "{name}"
        );
    }
    let mut leaked = fixture().0;
    leaked.security.as_mut().unwrap().clients[0].demo_token = Some(TOKEN.into());
    assert!(
        leaked.prepare().is_err(),
        "only demo clients may publish a token"
    );
    assert!(
        with_demo(service_fixture("http://127.0.0.1:9"), demo_client())
            .prepare()
            .is_ok()
    );
}

#[tokio::test]
async fn every_catalog_operation_is_documented_in_openapi() {
    let app = router(fixture().0);
    let (_, catalog) = call(&app, "/v1/services", None, None).await;
    let (_, spec) = call(&app, "/openapi.json", None, None).await;
    let operations = catalog["operations"].as_array().unwrap();
    assert!(operations.len() >= 80);
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

/// A public mesh network with a mesh reader whose seed sits in a fresh file.
fn mesh_reader_fixture(origin: &str, reader: &KeyPair) -> (Config, std::path::PathBuf) {
    let folder = std::env::temp_dir().join(format!("mesh-reader-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&folder).unwrap();
    let seed_file = folder.join("mesh-reader.key");
    std::fs::write(
        &seed_file,
        format!("# Ed25519 Private Key\n{}\n", reader.seed_b64()),
    )
    .unwrap();
    let mut cfg = service_fixture(origin);
    let network = cfg
        .security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap();
    network.public_mesh = true;
    network.mesh_reader = Some(genesis_mesh::gateway::security::MeshReader {
        key_id: "mesh-reader".into(),
        seed_file: seed_file.to_string_lossy().into_owned(),
        key: None,
    });
    (cfg, folder)
}

#[tokio::test]
async fn public_mesh_reads_members_with_a_read_operator_key() {
    use genesis_mesh::admin_auth::{signing_payload, AdminRequest};
    let reader = KeyPair::generate().unwrap();
    let reader_public = reader.public_key_b64();
    let audience = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let expected_audience = audience.clone();
    let signed_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = signed_reads.clone();
    let window = |subject: &str, public: bool| json!({"status":"active","attestation":{"attestation_id":format!("att-{subject}"),"status":"active","issuer_sovereign_id":"public-agency","subject_id":subject,"roles":["role:client"],"claims":{"public_mesh":public,"demo":true},"issued_at":Utc::now()-chrono::Duration::hours(1),"valid_from":Utc::now()-chrono::Duration::hours(1),"expires_at":Utc::now()+chrono::Duration::hours(1)}});
    let listing = json!({"count":2,"attestations":[window("demo:visitor", true), window("private-member", false)]});
    // The authority's check (genesis_mesh.na_service.auth): a version 2
    // signature over GET /attestations?status=active, body {}, for its key.
    let attestations = move |headers: axum::http::HeaderMap| {
        let audience = expected_audience.lock().unwrap().clone();
        let observed = observed.clone();
        let listing = listing.clone();
        let reader_public = reader_public.clone();
        async move {
            let header = |name: &str| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            };
            if header("x-admin-key-id").is_empty() {
                return axum::Json(json!({"count":2}));
            }
            assert_eq!(header("x-admin-key-id"), "mesh-reader");
            let query = [("status".to_string(), vec!["active".to_string()])].into();
            let payload = signing_payload(
                &AdminRequest {
                    method: "GET",
                    path: "/attestations",
                    query: &query,
                    audience: &audience,
                    body: &json!({}),
                },
                "mesh-reader",
                &header("x-admin-timestamp"),
                &header("x-admin-nonce"),
            );
            assert!(chrono::DateTime::parse_from_rfc3339(&header("x-admin-timestamp")).is_ok());
            assert!(genesis_mesh::crypto::verify_b64(
                payload.as_bytes(),
                &header("x-admin-signature"),
                &reader_public
            )
            .unwrap());
            observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            axum::Json(listing)
        }
    };
    let (origin, task) = mock_authority(
        Router::new()
            .route("/attestations", axum::routing::get(attestations))
            .route(
                "/recognition-treaties",
                axum::routing::get(|| async { axum::Json(json!({"recognition_treaties":[]})) }),
            ),
    )
    .await;
    let (cfg, folder) = mesh_reader_fixture(&origin, &reader);
    *audience.lock().unwrap() =
        cfg.security.as_ref().unwrap().networks["public-agency"].anchors["authority"].clone();
    let (status, body) = call(&router(cfg), "/v1/mesh", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(signed_reads.load(std::sync::atomic::Ordering::Relaxed), 1);
    let subjects: Vec<&str> = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["subject"].as_str().unwrap())
        .collect();
    assert_eq!(subjects, ["demo:visitor"]);
    assert!(!body.to_string().contains(&reader.seed_b64()));
    assert!(!body.to_string().contains("mesh-reader"));
    task.abort();
    std::fs::remove_dir_all(folder).unwrap();
}

#[test]
fn mesh_reader_needs_a_public_network_and_a_readable_seed() {
    let reader = KeyPair::generate().unwrap();
    let (mut cfg, folder) = mesh_reader_fixture("http://127.0.0.1:9", &reader);
    assert!(cfg.prepare().is_ok());
    let network = |cfg: &mut Config| {
        cfg.security
            .as_mut()
            .unwrap()
            .networks
            .get_mut("public-agency")
            .unwrap()
            .clone()
    };
    let mut private = cfg.clone();
    private
        .security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap()
        .public_mesh = false;
    assert!(private
        .prepare()
        .unwrap_err()
        .contains("mesh_reader requires public_mesh"));
    let mut missing = cfg.clone();
    let mut reader_policy = network(&mut missing).mesh_reader.unwrap();
    reader_policy.key = None;
    reader_policy.seed_file = folder.join("absent.key").to_string_lossy().into_owned();
    missing
        .security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap()
        .mesh_reader = Some(reader_policy);
    assert!(missing
        .prepare()
        .unwrap_err()
        .contains("cannot read mesh_reader seed_file"));
    std::fs::write(folder.join("bad.key"), "not a seed\n").unwrap();
    let mut bad = cfg.clone();
    let mut reader_policy = network(&mut bad).mesh_reader.unwrap();
    reader_policy.key = None;
    reader_policy.seed_file = folder.join("bad.key").to_string_lossy().into_owned();
    bad.security
        .as_mut()
        .unwrap()
        .networks
        .get_mut("public-agency")
        .unwrap()
        .mesh_reader = Some(reader_policy);
    assert!(bad.prepare().unwrap_err().contains("base64 Ed25519 seed"));
    std::fs::remove_dir_all(folder).unwrap();
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
