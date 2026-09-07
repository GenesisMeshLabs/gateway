//! Trust evaluation: deciding whether to accept a certificate.
//!
//! The decision is deliberately **not** a bare `bool`. A verifier that returns
//! only true/false gives an operator nothing to act on, and every reason a
//! certificate is rejected calls for a different response: a bad signature is an
//! attack or a misconfiguration, an expired certificate needs reissuing, a
//! revoked one needs the node removed. So [`Decision`] carries every reason it
//! failed, and all checks run rather than short-circuiting on the first.

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};

use crate::crypto::CachedPublicKey;
use crate::error::Result;
use crate::models::{CertificateRevocationList, JoinCertificate, Signed};

/// Maps a key identifier to its base64 Ed25519 public key.
///
/// This is the set of authorities the verifier is willing to believe. A
/// certificate signed by a key outside this map is untrusted no matter how
/// valid its signature is.
pub type TrustAnchors = BTreeMap<String, String>;

/// Why a certificate was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// Nothing signed the document.
    NoSignatures,
    /// No attached signature came from a key in the anchor set.
    NoTrustedIssuer,
    /// The named key is not a trust anchor for this verifier.
    UnknownIssuer {
        /// Unrecognized signing identity.
        key_id: String,
    },
    /// The key is an anchor, but its signature did not verify.
    BadSignature {
        /// Signing identity whose signature failed.
        key_id: String,
    },
    /// Presented before its validity window opened.
    NotYetValid {
        /// Start of certificate validity.
        issued_at: DateTime<Utc>,
    },
    /// Presented after its validity window closed.
    Expired {
        /// End of certificate validity.
        expires_at: DateTime<Utc>,
    },
    /// Named in a revocation list.
    Revoked {
        /// Signed issuer-provided reason.
        reason: String,
    },
    /// A revocation list was supplied but was not itself trustworthy.
    UntrustedRevocationList,
    /// Revocation information is outside its validity interval.
    StaleRevocationList,
    /// Certificate validity interval is empty or reversed.
    InvalidValidityWindow,
    /// No valid signature from the explicitly required issuer.
    IssuerSignatureMissing,
}

/// The outcome of evaluating a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// True only when `reasons` is empty.
    pub trusted: bool,
    /// Every reason the certificate was rejected, not just the first.
    pub reasons: Vec<Reason>,
}

impl Decision {
    fn from(reasons: Vec<Reason>) -> Self {
        Self {
            trusted: reasons.is_empty(),
            reasons,
        }
    }
}

/// Inputs to a verification other than the certificate itself.
pub struct Policy<'a> {
    /// Authorities this verifier believes.
    pub anchors: &'a TrustAnchors,
    /// Evaluation time; pass an explicit value to keep tests deterministic.
    pub now: DateTime<Utc>,
    /// Optional revocation list to consult.
    pub crl: Option<&'a CertificateRevocationList>,
    /// Skip CRL signature verification when the snapshot was authenticated at ingest.
    pub crl_preverified: bool,
    /// Optional issuer binding enforced during the existing signature pass.
    pub required_issuer: Option<&'a str>,
    /// First-entry index from an authenticated revocation snapshot.
    pub revoked_index: Option<&'a HashMap<String, usize>>,
    /// Pre-parsed authority keys; when set, verification does not re-decode anchors.
    pub verifying_keys: Option<&'a HashMap<String, CachedPublicKey>>,
}

impl<'a> Policy<'a> {
    /// A policy evaluating against the current wall clock.
    pub fn new(anchors: &'a TrustAnchors) -> Self {
        Self {
            anchors,
            now: Utc::now(),
            crl: None,
            crl_preverified: false,
            required_issuer: None,
            revoked_index: None,
            verifying_keys: None,
        }
    }

    /// Evaluate at a fixed instant.
    pub fn at(mut self, now: DateTime<Utc>) -> Self {
        self.now = now;
        self
    }

    /// Consult a revocation list.
    pub fn with_crl(mut self, crl: &'a CertificateRevocationList) -> Self {
        self.crl = Some(crl);
        self
    }
}

/// Evaluate a join certificate against a policy.
///
/// All independent checks run so the caller sees the full picture in one pass.
pub fn verify_join_certificate(cert: &JoinCertificate, policy: &Policy<'_>) -> Result<Decision> {
    let mut reasons = Vec::new();

    let mut issuer_verified = false;
    // --- issuer signature ------------------------------------------------
    if cert.signatures().is_empty() {
        reasons.push(Reason::NoSignatures);
    } else {
        let payload = cert.signing_input()?;
        let mut trusted_signature = false;
        for signature in cert.signatures() {
            match policy.anchors.get(&signature.key_id) {
                None => reasons.push(Reason::UnknownIssuer {
                    key_id: signature.key_id.clone(),
                }),
                Some(public_key) => {
                    let verified = if let Some(key) = policy
                        .verifying_keys
                        .and_then(|keys| keys.get(&signature.key_id))
                    {
                        key.verify(payload.as_bytes(), &signature.sig)?
                    } else {
                        crate::crypto::verify_b64(payload.as_bytes(), &signature.sig, public_key)?
                    };
                    if verified {
                        trusted_signature = true;
                        if policy.required_issuer == Some(signature.key_id.as_str()) {
                            issuer_verified = true;
                        }
                    } else {
                        reasons.push(Reason::BadSignature {
                            key_id: signature.key_id.clone(),
                        });
                    }
                }
            }
        }
        if !trusted_signature {
            reasons.push(Reason::NoTrustedIssuer);
        }
    }

    if policy.required_issuer.is_some() && !issuer_verified {
        reasons.push(Reason::IssuerSignatureMissing);
    }
    // --- validity window --------------------------------------------------
    let skew = chrono::Duration::minutes(crate::models::CLOCK_SKEW_MINUTES);
    if cert.issued_at >= cert.expires_at {
        reasons.push(Reason::InvalidValidityWindow);
    }
    if cert
        .issued_at
        .checked_sub_signed(skew)
        .is_none_or(|start| policy.now < start)
    {
        reasons.push(Reason::NotYetValid {
            issued_at: cert.issued_at,
        });
    }
    if cert
        .expires_at
        .checked_add_signed(skew)
        .is_none_or(|end| policy.now > end)
    {
        reasons.push(Reason::Expired {
            expires_at: cert.expires_at,
        });
    }

    // --- revocation -------------------------------------------------------
    // A revocation list is itself a signed document. An unsigned or
    // untrusted CRL must not be able to revoke anything, or anyone who can
    // hand us a file could evict arbitrary nodes.
    if let Some(crl) = policy.crl {
        if crl.issued_at > policy.now || policy.now >= crl.next_update {
            reasons.push(Reason::StaleRevocationList);
        }
        // A malformed signature on the CRL is not a hard error â€” it just means
        // the list is not trustworthy, exactly like an absent signature.
        // Production snapshots are authenticated at ingest; do not re-canonicalize.
        let crl_trusted = if policy.crl_preverified {
            true
        } else {
            match policy.anchors.get(&crl.issuer) {
                Some(public_key) => crl.verify_any(public_key).unwrap_or(false),
                None => false,
            }
        };
        if !crl_trusted {
            reasons.push(Reason::UntrustedRevocationList);
        } else if let Some(entry) = match policy.revoked_index {
            Some(index) => index
                .get(&cert.cert_id)
                .and_then(|i| crl.revoked_certificates.get(*i)),
            None => crl.find(&cert.cert_id),
        } {
            reasons.push(Reason::Revoked {
                reason: entry.reason.clone(),
            });
        }
    }

    Ok(Decision::from(reasons))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::models::{RevokedCertificate, Signature};
    use chrono::TimeZone;

    fn at(h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 3, h, 0, 0).unwrap()
    }

    fn signed_cert(kp: &KeyPair) -> JoinCertificate {
        let mut cert = JoinCertificate {
            cert_id: "cert-001".into(),
            node_public_key: "pk".into(),
            network_name: "mesh-alpha".into(),
            roles: vec![],
            issued_at: Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap(),
            expires_at: Utc.with_ymd_and_hms(2026, 1, 8, 12, 0, 0).unwrap(),
            issued_by: "na-001".into(),
            signatures: vec![],
        };
        cert.sign(kp, "na-001").unwrap();
        cert
    }

    fn anchors(kp: &KeyPair) -> TrustAnchors {
        let mut a = TrustAnchors::new();
        a.insert("na-001".into(), kp.public_key_b64());
        a
    }

    #[test]
    fn accepts_a_good_certificate() {
        let kp = KeyPair::generate().unwrap();
        let cert = signed_cert(&kp);
        let anchors = anchors(&kp);
        let decision = verify_join_certificate(&cert, &Policy::new(&anchors).at(at(12))).unwrap();
        assert!(decision.trusted, "valid fixture certificate was rejected");
    }

    #[test]
    fn rejects_an_unknown_issuer() {
        let kp = KeyPair::generate().unwrap();
        let cert = signed_cert(&kp);
        let empty = TrustAnchors::new();
        let decision = verify_join_certificate(&cert, &Policy::new(&empty).at(at(12))).unwrap();
        assert!(!decision.trusted);
        assert!(decision.reasons.contains(&Reason::UnknownIssuer {
            key_id: "na-001".into()
        }));
    }

    #[test]
    fn rejects_a_signature_from_the_wrong_key() {
        let real = KeyPair::generate().unwrap();
        let impostor = KeyPair::generate().unwrap();
        let cert = signed_cert(&impostor);
        // The anchor set names na-001, but binds it to the real key.
        let decision =
            verify_join_certificate(&cert, &Policy::new(&anchors(&real)).at(at(12))).unwrap();
        assert!(!decision.trusted);
        assert!(decision.reasons.contains(&Reason::BadSignature {
            key_id: "na-001".into()
        }));
    }

    #[test]
    fn reports_expiry() {
        let kp = KeyPair::generate().unwrap();
        let cert = signed_cert(&kp);
        let anchors = anchors(&kp);
        let later = Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();
        let decision = verify_join_certificate(&cert, &Policy::new(&anchors).at(later)).unwrap();
        assert!(!decision.trusted);
        assert!(decision
            .reasons
            .iter()
            .any(|r| matches!(r, Reason::Expired { .. })));
    }

    #[test]
    fn a_signed_crl_revokes() {
        let kp = KeyPair::generate().unwrap();
        let cert = signed_cert(&kp);
        let anchors = anchors(&kp);
        let mut crl = CertificateRevocationList {
            crl_id: "crl-001".into(),
            sequence: 1,
            issued_at: at(11),
            next_update: at(23),
            issuer: "na-001".into(),
            revoked_certificates: vec![RevokedCertificate {
                certificate_id: "cert-001".into(),
                revoked_at: at(10),
                reason: "key_compromise".into(),
                issuer: "na-001".into(),
            }],
            signatures: vec![],
        };
        crl.sign(&kp, "na-001").unwrap();
        let decision =
            verify_join_certificate(&cert, &Policy::new(&anchors).at(at(12)).with_crl(&crl))
                .unwrap();
        assert!(!decision.trusted);
        assert!(decision.reasons.contains(&Reason::Revoked {
            reason: "key_compromise".into()
        }));
    }

    #[test]
    fn an_unsigned_crl_cannot_revoke() {
        let kp = KeyPair::generate().unwrap();
        let cert = signed_cert(&kp);
        let anchors = anchors(&kp);
        let forged = CertificateRevocationList {
            crl_id: "crl-666".into(),
            sequence: 99,
            issued_at: at(11),
            next_update: at(23),
            issuer: "na-001".into(),
            revoked_certificates: vec![RevokedCertificate {
                certificate_id: "cert-001".into(),
                revoked_at: at(10),
                reason: "forged".into(),
                issuer: "na-001".into(),
            }],
            signatures: vec![Signature {
                key_id: "na-001".into(),
                sig: "AAAA".into(),
            }],
        };
        let decision =
            verify_join_certificate(&cert, &Policy::new(&anchors).at(at(12)).with_crl(&forged))
                .unwrap();
        assert!(!decision.trusted);
        assert!(decision.reasons.contains(&Reason::UntrustedRevocationList));
        // Crucially, it did NOT accept the forged revocation as authoritative.
        assert!(!decision
            .reasons
            .iter()
            .any(|r| matches!(r, Reason::Revoked { .. })));
    }
}
