//! Operator admin signatures, version 2 (Genesis Mesh v1.0.2).
//!
//! Byte-compatible with `genesis_mesh.crypto.admin_auth` in the Python
//! implementation: an operator signs the canonical JSON of the HTTP method,
//! path, query, the target Network Authority's public key (the audience),
//! the body, key ID, timestamp and nonce. The shared reference vectors are in
//! `tests/reference/admin_auth.json`.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::canonical::canonicalize;
use crate::crypto::KeyPair;

/// Signature version carried in every signed payload.
pub const ADMIN_SIGNATURE_VERSION: u64 = 2;

/// One admin request, as the Network Authority receives it.
pub struct AdminRequest<'a> {
    /// HTTP method; signed in upper case.
    pub method: &'a str,
    /// Decoded request path, without the query.
    pub path: &'a str,
    /// Query parameters, each name with its values in order.
    pub query: &'a BTreeMap<String, Vec<String>>,
    /// The target Network Authority's public key (base64).
    pub audience: &'a str,
    /// The JSON body; `{}` for a request without one.
    pub body: &'a Value,
}

/// The canonical text an operator signs for `request`.
pub fn signing_payload(
    request: &AdminRequest<'_>,
    key_id: &str,
    timestamp: &str,
    nonce: &str,
) -> String {
    canonicalize(&json!({
        "v": ADMIN_SIGNATURE_VERSION,
        "method": request.method.to_ascii_uppercase(),
        "path": request.path,
        "query": request.query,
        "audience": request.audience,
        "body": request.body,
        "key_id": key_id,
        "timestamp": timestamp,
        "nonce": nonce,
    }))
}

/// The four `X-Admin-*` headers that authenticate `request` with `key`.
pub fn sign(
    key: &KeyPair,
    key_id: &str,
    request: &AdminRequest<'_>,
    timestamp: &str,
    nonce: &str,
) -> [(&'static str, String); 4] {
    let signature = key.sign_b64(signing_payload(request, key_id, timestamp, nonce).as_bytes());
    [
        ("X-Admin-Key-Id", key_id.to_owned()),
        ("X-Admin-Timestamp", timestamp.to_owned()),
        ("X-Admin-Nonce", nonce.to_owned()),
        ("X-Admin-Signature", signature),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    #[test]
    fn matches_the_shared_reference_vectors() {
        let suite: Value =
            serde_json::from_str(include_str!("../tests/reference/admin_auth.json")).unwrap();
        assert_eq!(suite["suite"], "admin_auth");
        // The vectors are signed with the seed 0x00, 0x01, ..., 0x1f.
        let seed: Vec<u8> = (0u8..32).collect();
        let key = KeyPair::from_seed_b64(&STANDARD.encode(seed)).unwrap();
        let vectors = suite["vectors"].as_array().unwrap();
        assert!(!vectors.is_empty());
        for vector in vectors {
            let input = &vector["input"];
            assert_eq!(
                key.public_key_b64(),
                input["public_key_b64"].as_str().unwrap()
            );
            let query: BTreeMap<String, Vec<String>> =
                serde_json::from_value(input["query"].clone()).unwrap();
            let request = AdminRequest {
                method: input["method"].as_str().unwrap(),
                path: input["path"].as_str().unwrap(),
                query: &query,
                audience: input["audience"].as_str().unwrap(),
                body: &input["body"],
            };
            let key_id = input["key_id"].as_str().unwrap();
            let timestamp = input["timestamp"].as_str().unwrap();
            let nonce = input["nonce"].as_str().unwrap();
            assert_eq!(
                signing_payload(&request, key_id, timestamp, nonce),
                vector["expected"]["payload"].as_str().unwrap(),
                "{}",
                vector["id"]
            );
            let headers = sign(&key, key_id, &request, timestamp, nonce);
            assert_eq!(headers[0], ("X-Admin-Key-Id", key_id.to_owned()));
            assert_eq!(
                headers[3].1,
                vector["expected"]["signature_b64"].as_str().unwrap(),
                "{}",
                vector["id"]
            );
        }
        // All of them passed: the conformance receipt, when asked for.
        if let Some(dir) = std::env::var_os(RECEIPTS).filter(|d| !d.is_empty()) {
            write_receipt(std::path::Path::new(&dir), vectors.len());
        }
    }

    /// Conformance receipts (the core's contract bundle, schema
    /// `gm.contract.receipt/1`): with `GM_CONFORMANCE_RECEIPTS` naming a
    /// directory, the runner of the shared suite writes
    /// `<dir>/admin_auth.admin_auth.json` once every vector passed, for the
    /// core's `gm_contract.py receipt-check`. Unset, nothing is written; a
    /// failing runner writes nothing. The browser signer
    /// (`tools/test_ui_signing.mjs`) runs the same vectors but writes no
    /// receipt: the check adds up the receipts of a suite, and every vector
    /// counts once.
    const RECEIPTS: &str = "GM_CONFORMANCE_RECEIPTS";

    fn receipt(ran: usize) -> Value {
        json!({
            "schema": "gm.contract.receipt/1",
            "suite": "admin_auth",
            "file": "tests/reference/admin_auth.json",
            "runner": "src/admin_auth.rs:tests::matches_the_shared_reference_vectors",
            // The suite's vectors have no kind: they count under "*".
            "run": {"*": ran},
            "not_run": {},
        })
    }

    fn write_receipt(dir: &std::path::Path, ran: usize) {
        std::fs::create_dir_all(dir).unwrap();
        let mut text = serde_json::to_string_pretty(&receipt(ran)).unwrap();
        text.push('\n');
        std::fs::write(dir.join("admin_auth.admin_auth.json"), text).unwrap();
    }

    #[test]
    fn the_receipt_names_the_suite_copy_and_counts_every_vector_once() {
        let suite: Value =
            serde_json::from_str(include_str!("../tests/reference/admin_auth.json")).unwrap();
        let vectors = suite["vectors"].as_array().unwrap();
        // The receipt counts kinds; this suite has none.
        assert!(vectors.iter().all(|v| v.get("kind").is_none()));
        let dir = std::env::temp_dir().join(format!("gm-gateway-receipt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_receipt(&dir, vectors.len());
        let written: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("admin_auth.admin_auth.json")).unwrap(),
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(written, receipt(vectors.len()));
        assert_eq!(written["run"]["*"], 3);
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(root.join(written["file"].as_str().unwrap()).is_file());
        let source = include_str!("admin_auth.rs");
        assert!(source.contains("fn matches_the_shared_reference_vectors()"));
    }
}
