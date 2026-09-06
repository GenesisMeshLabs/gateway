//! Genesis Mesh Gateway — portable trust, implemented in Rust and served as HTTP.
//!
//! Genesis Mesh lets sovereign communities establish, recognise, and revoke
//! trust across organisational boundaries. This crate implements the primitives
//! that every participant must agree on byte for byte, and wraps them in a
//! concurrent HTTP gateway ([`gateway`]).
//!
//! * [`crypto`] — Ed25519 identities, detached signatures.
//! * [`canonical`] — canonical JSON, the exact bytes that get signed.
//! * [`models`] — join certificates, service manifests, revocation lists.
//! * [`trust`] — evaluating a certificate into an actionable [`trust::Decision`].
//! * [`gateway`] — the JSON API: `keygen`, `issue`, `verify`, `verify/batch`.
//!
//! # Interoperability
//!
//! The Python reference implementation is the wire authority. Anything in this
//! crate that touches the wire is verified against vectors generated from it —
//! see `tests/interop.rs` and `tools/gen_vectors.py`. The two subtleties worth
//! knowing, both of which would otherwise silently break signatures:
//!
//! * Canonical JSON escapes non-ASCII as `\uXXXX`; `serde_json` does not.
//! * Timestamps render with either no fractional seconds or exactly six digits.
//!
//! # Example
//!
//! ```no_run
//! use chrono::{Duration, Utc};
//! use genesis_mesh::crypto::KeyPair;
//! use genesis_mesh::models::{JoinCertificate, Signed};
//! use genesis_mesh::trust::{verify_join_certificate, Policy, TrustAnchors};
//!
//! let authority = KeyPair::generate()?;
//! let node = KeyPair::generate()?;
//!
//! let mut cert = JoinCertificate {
//!     cert_id: "cert-001".into(),
//!     node_public_key: node.public_key_b64(),
//!     network_name: "mesh-alpha".into(),
//!     roles: vec!["role:anchor".into()],
//!     issued_at: Utc::now(),
//!     expires_at: Utc::now() + Duration::days(7),
//!     issued_by: "na-001".into(),
//!     signatures: vec![],
//! };
//! cert.sign(&authority, "na-001")?;
//!
//! let mut anchors = TrustAnchors::new();
//! anchors.insert("na-001".into(), authority.public_key_b64());
//!
//! let decision = verify_join_certificate(&cert, &Policy::new(&anchors))?;
//! assert!(decision.trusted);
//! # Ok::<(), genesis_mesh::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod canonical;
pub mod crypto;
pub mod error;
pub mod gateway;
pub mod models;
pub mod time;
pub mod trust;

pub use crypto::{KeyPair, PublicKey};
pub use error::{Error, Result};
pub use models::{
    CertificateRevocationList, JoinCertificate, RevokedCertificate, ServiceManifest, Signature,
    Signed,
};
pub use trust::{verify_join_certificate, Decision, Policy, PreparedPolicy, Reason, TrustAnchors};
