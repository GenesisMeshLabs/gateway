//! Correctness of the prepared-policy path at batch sizes that exercise
//! both the sequential and Rayon thresholds used by `/verify/batch`.

use chrono::{TimeZone, Utc};
use genesis_mesh::crypto::KeyPair;
use genesis_mesh::models::{
    CertificateRevocationList, JoinCertificate, RevokedCertificate, Signed,
};
use genesis_mesh::trust::{verify_join_certificate, Policy, PreparedPolicy, TrustAnchors};

fn at(h: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 3, h, 0, 0).unwrap()
}

fn signed_cert(kp: &KeyPair, cert_id: &str) -> JoinCertificate {
    let mut cert = JoinCertificate {
        cert_id: cert_id.into(),
        node_public_key: "pk".into(),
        network_name: "mesh-tëst-\u{1F510}".into(),
        roles: vec!["role:anchor".into(), "role:client".into()],
        issued_at: Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap(),
        expires_at: Utc.with_ymd_and_hms(2026, 1, 8, 12, 0, 0).unwrap(),
        issued_by: "na-001".into(),
        signatures: vec![],
    };
    cert.sign(kp, "na-001").unwrap();
    cert
}

#[test]
fn prepared_batch_matches_naive_policy_with_crl() {
    let kp = KeyPair::generate().unwrap();
    let mut anchors = TrustAnchors::new();
    anchors.insert("na-001".into(), kp.public_key_b64());

    let mut crl = CertificateRevocationList {
        crl_id: "crl-001".into(),
        sequence: 1,
        issued_at: at(11),
        next_update: at(23),
        issuer: "na-001".into(),
        revoked_certificates: vec![RevokedCertificate {
            certificate_id: "cert-000".into(),
            revoked_at: at(10),
            reason: "key_compromise".into(),
            issuer: "na-001".into(),
        }],
        signatures: vec![],
    };
    crl.sign(&kp, "na-001").unwrap();

    // 32 covers the sequential path (n < 16) and the parallel path (n >= 16)
    // when the same fixtures are sliced.
    let certs: Vec<JoinCertificate> = (0..32)
        .map(|i| signed_cert(&kp, &format!("cert-{i:03}")))
        .collect();

    let policy = Policy::new(&anchors).at(at(12)).with_crl(&crl);
    let prepared = PreparedPolicy::new(&anchors, at(12), Some(&crl)).unwrap();

    for n in [1usize, 8, 16, 32] {
        let slice = &certs[..n];
        let naive: Vec<_> = slice
            .iter()
            .map(|c| verify_join_certificate(c, &policy).unwrap())
            .collect();
        let fast: Vec<_> = slice.iter().map(|c| prepared.verify(c).unwrap()).collect();
        assert_eq!(naive, fast, "prepared decisions diverged at batch size {n}");
        assert!(!fast[0].trusted, "cert-000 should be revoked");
        assert!(
            fast.iter().skip(1).all(|d| d.trusted),
            "non-revoked certs should verify at batch size {n}"
        );
    }
}
