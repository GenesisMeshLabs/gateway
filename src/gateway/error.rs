//! The gateway's error type and its JSON rendering.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// An error to return to the client: an HTTP status plus a message that becomes
/// `{ "error": "<message>" }`.
#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    /// `400 Bad Request` with a message.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }

    /// `500 Internal Server Error` with a message.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
    }

    /// `401 Unauthorized`.
    pub fn unauthorized() -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            "missing or invalid bearer token".to_string(),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

/// A panicked or cancelled blocking task becomes a 500.
impl From<tokio::task::JoinError> for ApiError {
    fn from(e: tokio::task::JoinError) -> Self {
        ApiError::internal(format!("worker task failed: {e}"))
    }
}
