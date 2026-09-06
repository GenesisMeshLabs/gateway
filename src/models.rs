//! Signed documents of the trust core.
//!
//! Field names and ordering-independent canonical form mirror
//! `genesis_mesh/models/`, so a document signed by either implementation
//! verifies in the other. Every signed type excludes its own `signatures`
//! list from the bytes it signs.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::crypto::{self, KeyPair};
use crate::error::Result;

/// Clock skew tolerated on both ends of a validity window.
pub const CLOCK_SKEW_MINUTES: i64 = 5;

/// A signature together with the identifier of the key that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Identifier of the signing key, resolved against a trust anchor set.
    pub key_id: String,
    /// Base64 detached Ed25519 signature.
    pub sig: String,
}

/// Documents that are signed over their canonical form.
pub trait Signed: Serialize {
    /// Access the attached signatures.
    fn signatures(&self) -> &[Signature];
    /// Attach a signature.
    fn push_signature(&mut self, signature: Signature);

    /// The exact bytes that are signed: canonical JSON minus `signatures`.
    fn signing_input(&self) -> Result<String> {
        canonical::to_canonical_json_excluding(self, &["signatures"])
    }

    /// Sign with `keypair` and attach the result under `key_id`.
    fn sign(&mut self, keypair: &KeyPair, key_id: &str) -> Result<()> {
        let payload = self.signing_input()?;
        let sig = keypair.sign_b64(payload.as_bytes());
        self.push_signature(Signature {
            key_id: key_id.to_string(),
            sig,
        });
        Ok(())
    }

    /// Whether any attached signature verifies under `public_key_b64`.
    fn verify_any(&self, public_key_b64: &str) -> Result<bool> {
        let payload = self.signing_input()?;
        for signature in self.signatures() {
            if crypto::verify_b64(payload.as_bytes(), &signature.sig, public_key_b64)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Permits a node to join a named network for a bounded period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinCertificate {
    pub cert_id: String,
    pub node_public_key: String,
    pub network_name: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(with = "crate::time::py_datetime")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::time::py_datetime")]
    pub expires_at: DateTime<Utc>,
    pub issued_by: String,
    #[serde(default)]
    pub signatures: Vec<Signature>,
}

impl JoinCertificate {
    /// Whether `at` falls inside the validity window, allowing clock skew.
    pub fn is_time_valid(&self, at: DateTime<Utc>) -> bool {
        let skew = Duration::minutes(CLOCK_SKEW_MINUTES);
        at >= self.issued_at - skew && at <= self.expires_at + skew
    }
}

impl Signed for JoinCertificate {
    fn signatures(&self) -> &[Signature] {
        &self.signatures
    }
    fn push_signature(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }
}

/// Authenticates a service identity and the endpoints it answers on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceManifest {
    pub service_name: String,
    pub service_key: String,
    pub endpoints: Vec<String>,
    #[serde(with = "crate::time::py_datetime")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::time::py_datetime")]
    pub valid_to: DateTime<Utc>,
    pub issued_by: String,
    #[serde(default)]
    pub signatures: Vec<Signature>,
}

impl Signed for ServiceManifest {
    fn signatures(&self) -> &[Signature] {
        &self.signatures
    }
    fn push_signature(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }
}

/// One entry in a revocation list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedCertificate {
    pub certificate_id: String,
    #[serde(with = "crate::time::py_datetime")]
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
    pub issuer: String,
}

/// A signed, monotonically sequenced set of revocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    pub crl_id: String,
    pub sequence: u64,
    #[serde(with = "crate::time::py_datetime")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::time::py_datetime")]
    pub next_update: DateTime<Utc>,
    pub issuer: String,
    #[serde(default)]
    pub revoked_certificates: Vec<RevokedCertificate>,
    #[serde(default)]
    pub signatures: Vec<Signature>,
}

impl CertificateRevocationList {
    /// Find the revocation entry for `cert_id`, if any.
    pub fn find(&self, cert_id: &str) -> Option<&RevokedCertificate> {
        self.revoked_certificates
            .iter()
            .find(|entry| entry.certificate_id == cert_id)
    }
}

impl Signed for CertificateRevocationList {
    fn signatures(&self) -> &[Signature] {
        &self.signatures
    }
    fn push_signature(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn cert() -> JoinCertificate {
        JoinCertificate {
            cert_id: "cert-001".into(),
            node_public_key: "pk".into(),
            network_name: "mesh-alpha".into(),
            roles: vec!["role:anchor".into()],
            issued_at: Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap(),
            expires_at: Utc.with_ymd_and_hms(2026, 1, 8, 12, 0, 0).unwrap(),
            issued_by: "na-001".into(),
            signatures: vec![],
        }
    }

    #[test]
    fn signing_input_excludes_signatures() {
        let mut c = cert();
        let before = c.signing_input().unwrap();
        c.signatures.push(Signature {
            key_id: "na-001".into(),
            sig: "irrelevant".into(),
        });
        assert_eq!(before, c.signing_input().unwrap());
        assert!(!before.contains("signatures"));
    }

    #[test]
    fn sign_then_verify() {
        let kp = KeyPair::generate().unwrap();
        let mut c = cert();
        c.sign(&kp, "na-001").unwrap();
        assert!(c.verify_any(&kp.public_key_b64()).unwrap());
    }

    #[test]
    fn mutating_a_field_breaks_the_signature() {
        let kp = KeyPair::generate().unwrap();
        let mut c = cert();
        c.sign(&kp, "na-001").unwrap();
        c.roles.push("role:admin".into());
        assert!(!c.verify_any(&kp.public_key_b64()).unwrap());
    }

    #[test]
    fn clock_skew_is_tolerated_at_both_ends() {
        let c = cert();
        assert!(c.is_time_valid(c.issued_at - Duration::minutes(4)));
        assert!(c.is_time_valid(c.expires_at + Duration::minutes(4)));
        assert!(!c.is_time_valid(c.issued_at - Duration::minutes(6)));
        assert!(!c.is_time_valid(c.expires_at + Duration::minutes(6)));
    }
}
