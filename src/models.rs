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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct JoinCertificate {
    /// Unique certificate identifier.
    pub cert_id: String,
    /// Base64 Ed25519 subject public key.
    pub node_public_key: String,
    /// Exact Genesis Mesh network name.
    pub network_name: String,
    #[serde(default)]
    /// Roles granted by the issuer.
    pub roles: Vec<String>,
    #[serde(with = "crate::time::py_datetime")]
    /// Signed issuance timestamp.
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::time::py_datetime")]
    /// Certificate expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Named issuing authority.
    pub issued_by: String,
    #[serde(default)]
    /// Detached signatures over the canonical document.
    pub signatures: Vec<Signature>,
}

impl JoinCertificate {
    /// Whether `at` falls inside the validity window, allowing clock skew.
    pub fn is_time_valid(&self, at: DateTime<Utc>) -> bool {
        let skew = Duration::minutes(CLOCK_SKEW_MINUTES);
        self.issued_at < self.expires_at
            && self
                .issued_at
                .checked_sub_signed(skew)
                .is_some_and(|start| at >= start)
            && self
                .expires_at
                .checked_add_signed(skew)
                .is_some_and(|end| at <= end)
    }
}

impl Signed for JoinCertificate {
    fn signatures(&self) -> &[Signature] {
        &self.signatures
    }
    fn push_signature(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }
    fn signing_input(&self) -> Result<String> {
        Ok(join_certificate_signing_input(self))
    }
}

fn join_certificate_signing_input(cert: &JoinCertificate) -> String {
    let mut out = String::with_capacity(
        96 + cert.cert_id.len()
            + cert.node_public_key.len()
            + cert.network_name.len()
            + cert.issued_by.len()
            + cert.roles.iter().map(|role| role.len() + 3).sum::<usize>(),
    );
    out.push_str("{\"cert_id\":");
    canonical::write_json_string(&cert.cert_id, &mut out);
    out.push_str(",\"expires_at\":");
    canonical::write_json_string(&crate::time::format(&cert.expires_at), &mut out);
    out.push_str(",\"issued_at\":");
    canonical::write_json_string(&crate::time::format(&cert.issued_at), &mut out);
    out.push_str(",\"issued_by\":");
    canonical::write_json_string(&cert.issued_by, &mut out);
    out.push_str(",\"network_name\":");
    canonical::write_json_string(&cert.network_name, &mut out);
    out.push_str(",\"node_public_key\":");
    canonical::write_json_string(&cert.node_public_key, &mut out);
    out.push_str(",\"roles\":[");
    for (i, role) in cert.roles.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        canonical::write_json_string(role, &mut out);
    }
    out.push_str("]}");
    out
}

/// Authenticates a service identity and the endpoints it answers on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceManifest {
    /// Stable service identity.
    pub service_name: String,
    /// Base64 service public key.
    pub service_key: String,
    /// Advertised service endpoints.
    pub endpoints: Vec<String>,
    #[serde(with = "crate::time::py_datetime")]
    /// Signed issuance timestamp.
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::time::py_datetime")]
    /// Manifest expiry timestamp.
    pub valid_to: DateTime<Utc>,
    /// Named issuing authority.
    pub issued_by: String,
    #[serde(default)]
    /// Detached signatures over the canonical document.
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
#[serde(deny_unknown_fields)]
pub struct RevokedCertificate {
    /// Identifier of the revoked certificate.
    pub certificate_id: String,
    #[serde(with = "crate::time::py_datetime")]
    /// Revocation timestamp.
    pub revoked_at: DateTime<Utc>,
    /// Issuer-provided revocation reason.
    pub reason: String,
    /// Named revocation authority.
    pub issuer: String,
}

/// A signed, monotonically sequenced set of revocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateRevocationList {
    /// Unique revocation snapshot identifier.
    pub crl_id: String,
    /// Monotonically increasing snapshot sequence.
    pub sequence: u64,
    #[serde(with = "crate::time::py_datetime")]
    /// Signed issuance timestamp.
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::time::py_datetime")]
    /// Deadline for replacing this snapshot.
    pub next_update: DateTime<Utc>,
    /// Named revocation authority.
    pub issuer: String,
    #[serde(default)]
    /// Revocations covered by this snapshot.
    pub revoked_certificates: Vec<RevokedCertificate>,
    #[serde(default)]
    /// Detached signatures over the canonical document.
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
    fn specialized_signing_input_matches_generic_canonical_form() {
        let mut c = cert();
        c.roles.push("role:z".into());
        let generic = crate::canonical::to_canonical_json_excluding(&c, &["signatures"]).unwrap();
        assert_eq!(c.signing_input().unwrap(), generic);
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
