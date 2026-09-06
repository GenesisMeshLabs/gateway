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

use crate::crypto::PublicKey;
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
    UnknownIssuer { key_id: String },
    /// The key is an anchor, but its signature did not verify.
    BadSignature { key_id: String },
    /// Presented before its validity window opened.
    NotYetValid { issued_at: DateTime<Utc> },
    /// Presented after its validity window closed.
    Expired { expires_at: DateTime<Utc> },
    /// Named in a revocation list.
    Revoked { reason: String },
    /// A revocation list was supplied but was not itself trustworthy.
    UntrustedRevocationList,
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
}

impl<'a> Policy<'a> {
    /// A policy evaluating against the current wall clock.
    pub fn new(anchors: &'a TrustAnchors) -> Self {
        Self {
            anchors,
            now: Utc::now(),
            crl: None,
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

/// Pre-decoded anchors and, when present, a once-verified CRL.
///
/// Build this once per `/verify` or `/verify/batch` request. Subsequent
/// [`PreparedPolicy::verify`] calls reuse the parsed keys and a `HashMap`
/// revocation lookup instead of re-decoding and re-signing the same inputs.
#[derive(Clone)]
pub struct PreparedPolicy {
    anchors: HashMap<String, PublicKey>,
    now: DateTime<Utc>,
    crl: Option<PreparedCrl>,
}

/// A CRL whose signature has already been checked and whose entries are indexed.
#[derive(Clone)]
struct PreparedCrl {
    trusted: bool,
    /// `cert_id` → revocation reason. Empty when `trusted` is false so a
    /// forged list cannot evict anyone.
    revoked: HashMap<String, String>,
}

impl PreparedPolicy {
    /// Decode every anchor and, if a CRL is supplied, verify it once.
    pub fn new(
        anchors: &TrustAnchors,
        now: DateTime<Utc>,
        crl: Option<&CertificateRevocationList>,
    ) -> Result<Self> {
        let mut parsed = HashMap::with_capacity(anchors.len());
        for (key_id, public_key_b64) in anchors {
            parsed.insert(key_id.clone(), PublicKey::from_b64(public_key_b64)?);
        }
        let crl = match crl {
            Some(list) => Some(PreparedCrl::prepare(list, &parsed)?),
            None => None,
        };
        Ok(Self {
            anchors: parsed,
            now,
            crl,
        })
    }

    /// Build from a [`Policy`], decoding keys and the CRL a single time.
    pub fn from_policy(policy: &Policy<'_>) -> Result<Self> {
        Self::new(policy.anchors, policy.now, policy.crl)
    }

    /// Evaluate one certificate against the prepared anchors and CRL.
    ///
    /// All independent checks run so the caller sees the full picture in one pass.
    pub fn verify(&self, cert: &JoinCertificate) -> Result<Decision> {
        let mut reasons = Vec::new();

        // --- issuer signature ------------------------------------------------
        if cert.signatures().is_empty() {
            reasons.push(Reason::NoSignatures);
        } else {
            let payload = cert.signing_input()?;
            let mut trusted_signature = false;
            for signature in cert.signatures() {
                match self.anchors.get(&signature.key_id) {
                    None => reasons.push(Reason::UnknownIssuer {
                        key_id: signature.key_id.clone(),
                    }),
                    Some(public_key) => {
                        if public_key.verify_b64(payload.as_bytes(), &signature.sig)? {
                            trusted_signature = true;
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

        // --- validity window --------------------------------------------------
        let skew = chrono::Duration::minutes(crate::models::CLOCK_SKEW_MINUTES);
        if self.now < cert.issued_at - skew {
            reasons.push(Reason::NotYetValid {
                issued_at: cert.issued_at,
            });
        }
        if self.now > cert.expires_at + skew {
            reasons.push(Reason::Expired {
                expires_at: cert.expires_at,
            });
        }

        // --- revocation -------------------------------------------------------
        // The CRL signature was checked when this policy was prepared. An
        // untrusted list must not be able to revoke anything.
        if let Some(crl) = &self.crl {
            if !crl.trusted {
                reasons.push(Reason::UntrustedRevocationList);
            } else if let Some(reason) = crl.revoked.get(&cert.cert_id) {
                reasons.push(Reason::Revoked {
                    reason: reason.clone(),
                });
            }
        }

        Ok(Decision::from(reasons))
    }
}

impl PreparedCrl {
    fn prepare(
        crl: &CertificateRevocationList,
        anchors: &HashMap<String, PublicKey>,
    ) -> Result<Self> {
        // A malformed signature on the CRL is not a hard error — it just means
        // the list is not trustworthy, exactly like an absent signature.
        let trusted = match anchors.get(&crl.issuer) {
            Some(public_key) => crl.verify_any_key(public_key).unwrap_or(false),
            None => false,
        };
        let revoked = if trusted {
            let mut map = HashMap::with_capacity(crl.revoked_certificates.len());
            for entry in &crl.revoked_certificates {
                map.insert(entry.certificate_id.clone(), entry.reason.clone());
            }
            map
        } else {
            HashMap::new()
        };
        Ok(Self { trusted, revoked })
    }
}

/// Evaluate a join certificate against a policy.
///
/// All independent checks run so the caller sees the full picture in one pass.
/// For many certificates against the same anchors, build a [`PreparedPolicy`]
/// once and call [`PreparedPolicy::verify`] instead.
pub fn verify_join_certificate(cert: &JoinCertificate, policy: &Policy<'_>) -> Result<Decision> {
    PreparedPolicy::from_policy(policy)?.verify(cert)
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
        assert!(decision.trusted, "{:?}", decision.reasons);
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

    #[test]
    fn prepared_policy_matches_one_shot_verify() {
        let kp = KeyPair::generate().unwrap();
        let cert = signed_cert(&kp);
        let anchors = anchors(&kp);
        let policy = Policy::new(&anchors).at(at(12));
        let one_shot = verify_join_certificate(&cert, &policy).unwrap();
        let prepared = PreparedPolicy::from_policy(&policy).unwrap();
        assert_eq!(prepared.verify(&cert).unwrap(), one_shot);
    }

    #[test]
    fn prepared_crl_is_applied_to_every_certificate() {
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

        let prepared = PreparedPolicy::new(&anchors, at(12), Some(&crl)).unwrap();
        for _ in 0..32 {
            let decision = prepared.verify(&cert).unwrap();
            assert!(!decision.trusted);
            assert!(decision.reasons.contains(&Reason::Revoked {
                reason: "key_compromise".into()
            }));
        }

        let mut other = cert.clone();
        other.cert_id = "cert-002".into();
        other.signatures.clear();
        other.sign(&kp, "na-001").unwrap();
        let decision = prepared.verify(&other).unwrap();
        assert!(decision.trusted, "{:?}", decision.reasons);
    }
}
