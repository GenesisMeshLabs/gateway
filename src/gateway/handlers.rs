//! Request handlers and middleware.
//!
//! Handlers are thin: validate, move the crypto onto a blocking worker, shape
//! the response. Nothing here holds state between requests.

use super::runtime::Principal;
use axum::extract::{Request, State};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::KeyPair;
use crate::models::{CertificateRevocationList, JoinCertificate, Signed};
use crate::trust::{verify_join_certificate, Policy, TrustAnchors};

use super::{ApiError, AppState};

// ---------------------------------------------------------------------------
// middleware
// ---------------------------------------------------------------------------

/// Authenticate and apply the configured client quota before parsing JSON.
pub(super) async fn auth(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let presented = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let security = state.security.load_full();
    let identity = presented
        .filter(|t| t.len() >= 32 && t.len() <= 1024)
        .and_then(|token| {
            if let Some(policy) = &security {
                policy.authenticate(token).map(|i| Principal(Some(i)))
            } else {
                let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
                state
                    .dev_token_digest
                    .filter(|expected| bool::from(expected.ct_eq(&digest)))
                    .map(|_| Principal(None))
            }
        });
    let Some(principal) = identity else {
        state
            .metrics
            .denied
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(ApiError::unauthorized());
    };
    if let (Some(policy), Some(i)) = (&security, principal.0) {
        if !super::runtime::admit(&state.quotas[i], policy.clients[i].requests_per_minute) {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "client quota exhausted".into(),
            ));
        }
        tracing::info!(target: "audit", client_id = %policy.clients[i].id, policy_revision = %policy.revision, "client admitted");
    }
    let mut req = req;
    req.extensions_mut().insert(principal);
    Ok(next.run(req).await)
}

/// Bound concurrent work: acquire a permit for the request's lifetime, or shed.
pub(super) async fn limit_inflight(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    if matches!(req.uri().path(), "/health" | "/ready") {
        return next.run(req).await;
    }
    match state.inflight.clone().try_acquire_owned() {
        Ok(_permit) => next.run(req).await,
        Err(_) => {
            ApiError(StatusCode::SERVICE_UNAVAILABLE, "server overloaded".into()).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// GET /  and  GET /health
// ---------------------------------------------------------------------------

pub(super) async fn index(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "service": "genesis-mesh-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if state.cfg.development { "development" } else { "production" },
        "endpoints": ["GET /api", "GET /openapi.json", "GET /health", "GET /ready", "GET /v1/networks", "GET /metrics", "POST /verify", "POST /verify/batch"]
    }))
}

pub(super) async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

// ---------------------------------------------------------------------------
// POST /keygen
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(super) struct KeygenResponse {
    seed_b64: String,
    public_key_b64: String,
}

pub(super) async fn keygen(
    State(state): State<AppState>,
) -> Result<Json<KeygenResponse>, ApiError> {
    let out = state
        .compute(|| -> crate::Result<KeygenResponse> {
            let kp = KeyPair::generate()?;
            Ok(KeygenResponse {
                seed_b64: kp.seed_b64(),
                public_key_b64: kp.public_key_b64(),
            })
        })
        .await?
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(out))
}

// ---------------------------------------------------------------------------
// POST /issue
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IssueRequest {
    /// Base64 Ed25519 seed of the issuing authority. Treated as a secret.
    seed_b64: String,
    /// Identifier the signature is attached under; also becomes `issued_by`.
    key_id: String,
    /// Base64 public key of the node the certificate is for.
    node_public_key: String,
    network_name: String,
    #[serde(default)]
    roles: Vec<String>,
    /// Validity window in days. Defaults to 7.
    #[serde(default)]
    days: Option<i64>,
}

pub(super) async fn issue(
    State(state): State<AppState>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<JoinCertificate>, ApiError> {
    let days = req.days.unwrap_or(7);
    if !(1..=365).contains(&days) {
        return Err(ApiError::bad_request("days must be between 1 and 365"));
    }

    if req.key_id.is_empty()
        || req.network_name.is_empty()
        || !crate::crypto::validate_public_key(&req.node_public_key).unwrap_or(false)
    {
        return Err(ApiError::bad_request(
            "valid key_id, network_name and node public key required",
        ));
    }
    let cert = state
        .compute(move || -> Result<JoinCertificate, ApiError> {
            let keypair = KeyPair::from_seed_b64(&req.seed_b64)
                .map_err(|e| ApiError::bad_request(format!("seed_b64: {e}")))?;

            let now = Utc::now();
            let mut cert = JoinCertificate {
                cert_id: format!("cert-{}", uuid::Uuid::new_v4()),
                node_public_key: req.node_public_key,
                network_name: req.network_name,
                roles: req.roles,
                issued_at: now,
                expires_at: now + Duration::days(days),
                issued_by: req.key_id.clone(),
                signatures: vec![],
            };
            cert.sign(&keypair, &req.key_id)
                .map_err(|e| ApiError::internal(e.to_string()))?;
            Ok(cert)
        })
        .await??;

    Ok(Json(cert))
}

// ---------------------------------------------------------------------------
// POST /verify
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerifyRequest {
    certificate: JoinCertificate,
    #[serde(default)]
    anchors: TrustAnchors,
    #[serde(default)]
    crl: Option<CertificateRevocationList>,
}

#[derive(Serialize)]
pub(super) struct VerifyResponse {
    trusted: bool,
    /// Debug rendering of each [`crate::trust::Reason`].
    reasons: Vec<String>,
}

pub(super) async fn verify(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    authorize(
        &state,
        &principal,
        std::slice::from_ref(&req.certificate),
        &req.anchors,
        req.crl.as_ref(),
    )?;

    let security = state.security.load_full();
    let out = state
        .compute(move || {
            evaluate(
                &req.certificate,
                &req.anchors,
                req.crl.as_ref(),
                security.as_deref(),
                Utc::now(),
            )
        })
        .await?;

    Ok(Json(out))
}

// ---------------------------------------------------------------------------
// POST /verify/batch
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerifyBatchRequest {
    certificates: Vec<JoinCertificate>,
    #[serde(default)]
    anchors: TrustAnchors,
    #[serde(default)]
    crl: Option<CertificateRevocationList>,
}

#[derive(Serialize)]
pub(super) struct VerifyBatchResponse {
    results: Vec<VerifyResponse>,
}

pub(super) async fn verify_batch(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(req): Json<VerifyBatchRequest>,
) -> Result<Json<VerifyBatchResponse>, ApiError> {
    let max = state.cfg.max_batch;
    if req.certificates.len() > max {
        return Err(ApiError::bad_request(format!(
            "batch of {} exceeds GATEWAY_MAX_BATCH={max}",
            req.certificates.len()
        )));
    }

    if req.certificates.is_empty() {
        return Err(ApiError::bad_request("batch must not be empty"));
    }
    authorize(
        &state,
        &principal,
        &req.certificates,
        &req.anchors,
        req.crl.as_ref(),
    )?;
    let batch_permit = state.batches.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "batch capacity exhausted".into(),
        )
    })?;
    let security = state.security.load_full();
    let out = state
        .compute(move || {
            let _batch_permit = batch_permit;
            let now = Utc::now();
            // Sequential within each bounded worker avoids nested pool oversubscription.
            VerifyBatchResponse {
                results: req
                    .certificates
                    .iter()
                    .map(|cert| {
                        evaluate(
                            cert,
                            &req.anchors,
                            req.crl.as_ref(),
                            security.as_deref(),
                            now,
                        )
                    })
                    .collect(),
            }
        })
        .await?;

    Ok(Json(out))
}

fn authorize(
    state: &AppState,
    principal: &Principal,
    certs: &[JoinCertificate],
    anchors: &TrustAnchors,
    crl: Option<&CertificateRevocationList>,
) -> Result<(), ApiError> {
    if certs.iter().any(|c| {
        c.signatures.len() > 8
            || c.roles.len() > 32
            || [&c.cert_id, &c.network_name, &c.issued_by]
                .iter()
                .any(|s| s.is_empty() || s.len() > 256)
            || c.node_public_key.len() != 44
            || c.roles.iter().any(|r| r.len() > 128)
            || c.signatures
                .iter()
                .any(|s| s.key_id.len() > 256 || s.sig.len() != 88)
    }) {
        return Err(ApiError::bad_request(
            "certificate exceeds field or signature limits",
        ));
    }
    let security = state.security.load_full();
    if let Some(policy) = &security {
        if !anchors.is_empty() || crl.is_some() {
            return Err(ApiError::bad_request(
                "production trust material is operator controlled",
            ));
        }
        let client = &policy.clients[principal.0.ok_or_else(ApiError::unauthorized)?];
        if certs
            .iter()
            .any(|c| !client.networks.contains(&c.network_name))
        {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "network scope denied".into(),
            ));
        }
    } else if anchors.is_empty() {
        return Err(ApiError::bad_request(
            "at least one trust anchor is required",
        ));
    }
    Ok(())
}

fn evaluate(
    cert: &JoinCertificate,
    anchors: &TrustAnchors,
    crl: Option<&CertificateRevocationList>,
    security: Option<&super::security::SecurityPolicy>,
    now: chrono::DateTime<Utc>,
) -> VerifyResponse {
    let network = security.and_then(|p| p.networks.get(&cert.network_name));
    if security.is_some() && network.is_none_or(|n| !n.accepts(cert, now)) {
        return VerifyResponse {
            trusted: false,
            reasons: vec!["NetworkPolicyRejected".into()],
        };
    }
    let policy = Policy {
        anchors: network.map_or(anchors, |n| &n.anchors),
        now,
        crl: network.map(|n| &n.crl).or(crl),
        crl_preverified: network.is_some(),
        required_issuer: network.map(|_| cert.issued_by.as_str()),
        revoked_index: network.map(|n| &n.revoked_index),
        verifying_keys: network.map(|n| &n.verifying_keys),
    };
    let response = match verify_join_certificate(cert, &policy) {
        Ok(d) => VerifyResponse {
            trusted: d.trusted,
            reasons: d.reasons.iter().map(|r| format!("{r:?}")).collect(),
        },
        Err(_) => VerifyResponse {
            trusted: false,
            reasons: vec!["MalformedCertificate".into()],
        },
    };
    tracing::info!(target: "audit", trusted = response.trusted, "trust evaluation completed");
    response
}
