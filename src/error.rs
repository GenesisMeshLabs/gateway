//! Error type for the Genesis Mesh trust core.

/// Convenience result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong in the trust core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A key, signature, or seed was not valid base64.
    #[error("invalid base64 in {field}: {source}")]
    Base64 {
        /// Input field associated with the failure.
        field: &'static str,
        #[source]
        /// Underlying decoding error.
        source: base64::DecodeError,
    },

    /// Decoded bytes were the wrong length for their purpose.
    #[error("{field} must be {expected} bytes, got {actual}")]
    KeyLength {
        /// Input field associated with the failure.
        field: &'static str,
        /// Required byte length.
        expected: usize,
        /// Observed byte length.
        actual: usize,
    },

    /// An Ed25519 public key was structurally invalid.
    #[error("malformed Ed25519 public key: {0}")]
    MalformedPublicKey(String),

    /// JSON serialisation or parsing failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Canonicalisation was asked to exclude keys from a non-object.
    #[error("canonical form requires a JSON object, found {found}")]
    NotAnObject {
        /// Observed JSON type.
        found: &'static str,
    },

    /// Filesystem access failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The OS random number generator was unavailable.
    #[error("could not read system randomness: {0}")]
    Random(String),
}
