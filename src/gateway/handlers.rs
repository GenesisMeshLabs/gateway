//! Request handlers and middleware.
//!
//! Handlers are thin: validate, move the crypto onto a blocking worker, shape
//! the response. Nothing here holds state between requests.

use axum::extract::{Request, State};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::crypto::KeyPair;
use crate::models::{CertificateRevocationList, JoinCertificate, Signed};
use crate::trust::{verify_join_certificate, Policy, TrustAnchors};

use super::{ApiError, AppState};

// ---------------------------------------------------------------------------
// middleware
// ---------------------------------------------------------------------------

/// Require `Authorization: Bearer <GATEWAY_TOKEN>` when a token is configured.
pub(super) async fn auth(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let Some(expected) = state.cfg.token.as_deref() else {
        return Ok(next.run(req).await);
    };
    let presented = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(token) if token == expected => Ok(next.run(req).await),
        _ => Err(ApiError::unauthorized()),
    }
}

/// Bound concurrent work: acquire a permit for the request's lifetime, or shed.
pub(super) async fn limit_inflight(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
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

pub(super) async fn index() -> Json<Value> {
    Json(json!({
        "service": "genesis-mesh-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "endpoints": {
            "GET /health": "liveness",
            "POST /keygen": "-> { seed_b64, public_key_b64 }",
            "POST /issue": "{ seed_b64, key_id, node_public_key, network_name, roles?, days? } -> JoinCertificate",
            "POST /verify": "{ certificate, anchors, crl? } -> { trusted, reasons }",
            "POST /verify/batch": "{ certificates[], anchors, crl? } -> { results[] }"
        }
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

pub(super) async fn keygen() -> Result<Json<KeygenResponse>, ApiError> {
    let out = tokio::task::spawn_blocking(|| -> crate::Result<KeygenResponse> {
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
    Json(req): Json<IssueRequest>,
) -> Result<Json<JoinCertificate>, ApiError> {
    let days = req.days.unwrap_or(7);
    if days <= 0 {
        return Err(ApiError::bad_request("days must be a positive whole number"));
    }

    let cert = tokio::task::spawn_blocking(move || -> Result<JoinCertificate, ApiError> {
        let keypair = KeyPair::from_seed_b64(&req.seed_b64)
            .map_err(|e| ApiError::bad_request(format!("seed_b64: {e}")))?;

        let now = Utc::now();
        let mut cert = JoinCertificate {
            cert_id: format!("cert-{}", now.timestamp_millis()),
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
pub(super) struct VerifyRequest {
    certificate: JoinCertificate,
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
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    if req.anchors.is_empty() {
        return Err(ApiError::bad_request("at least one trust anchor is required"));
    }

    let out = tokio::task::spawn_blocking(move || -> Result<VerifyResponse, ApiError> {
        let mut policy = Policy::new(&req.anchors);
        if let Some(ref list) = req.crl {
            policy = policy.with_crl(list);
        }
        let decision = verify_join_certificate(&req.certificate, &policy)
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        Ok(VerifyResponse {
            trusted: decision.trusted,
            reasons: decision.reasons.iter().map(|r| format!("{r:?}")).collect(),
        })
    })
    .await??;

    Ok(Json(out))
}

// ---------------------------------------------------------------------------
// POST /verify/batch
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct VerifyBatchRequest {
    certificates: Vec<JoinCertificate>,
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
    Json(req): Json<VerifyBatchRequest>,
) -> Result<Json<VerifyBatchResponse>, ApiError> {
    if req.anchors.is_empty() {
        return Err(ApiError::bad_request("at least one trust anchor is required"));
    }
    let max = state.cfg.max_batch;
    if req.certificates.len() > max {
        return Err(ApiError::bad_request(format!(
            "batch of {} exceeds GATEWAY_MAX_BATCH={max}",
            req.certificates.len()
        )));
    }

    let out = tokio::task::spawn_blocking(move || {
        use rayon::prelude::*;

        // One instant for the whole batch keeps results consistent.
        let now = Utc::now();
        let crl = req.crl.as_ref();

        let results = req
            .certificates
            .par_iter()
            .map(|cert| {
                let policy = Policy {
                    anchors: &req.anchors,
                    now,
                    crl,
                };
                match verify_join_certificate(cert, &policy) {
                    Ok(d) => VerifyResponse {
                        trusted: d.trusted,
                        reasons: d.reasons.iter().map(|r| format!("{r:?}")).collect(),
                    },
                    Err(e) => VerifyResponse {
                        trusted: false,
                        reasons: vec![format!("error: {e}")],
                    },
                }
            })
            .collect();

        VerifyBatchResponse { results }
    })
    .await?;

    Ok(Json(out))
}
