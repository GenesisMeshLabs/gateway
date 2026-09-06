//! Read-only, implementation-independent authority onboarding checks.
use crate::{canonical::to_canonical_json_excluding, crypto::CachedPublicKey};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};

/// Validate a bare operator-selected origin. Plain HTTP requires explicit opt-in.
pub fn origin(value: &str, allow_http: bool) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(value).map_err(|_| "Invalid authority origin")?;
    if !(url.scheme() == "https" || allow_http && url.scheme() == "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("Use a bare HTTPS origin; HTTP requires --allow-http".into());
    }
    Ok(url)
}

/// Verify the named signer over canonical protocol JSON.
pub fn signed(record: &Value, key: &str, issuer: &str) -> bool {
    let Ok(key) = CachedPublicKey::parse(key) else {
        return false;
    };
    let Ok(body) = to_canonical_json_excluding(record, &["signatures"]) else {
        return false;
    };
    record["signatures"].as_array().is_some_and(|sigs| {
        sigs.iter().any(|s| {
            s["key_id"] == issuer
                && s["sig"]
                    .as_str()
                    .is_some_and(|s| key.verify(body.as_bytes(), s).unwrap_or(false))
        })
    })
}

fn date(v: &Value) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(v.as_str()?)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Evaluate pinned identity, signature and freshness checks without changing trust.
pub fn assess(
    network: &str,
    key: &str,
    genesis: &Value,
    crl: &Value,
    feed: &Value,
    treaties: &Value,
) -> Value {
    let now = Utc::now();
    let na = &genesis["network_authority"];
    let checks = [
        ("network_identity", genesis["network_name"] == network),
        (
            "pinned_authority_key",
            na["public_key"] == key && CachedPublicKey::parse(key).is_ok(),
        ),
        (
            "genesis_signature",
            genesis["root_public_key"].as_str().is_some_and(|root| {
                genesis["signatures"].as_array().is_some_and(|sigs| {
                    sigs.iter().any(|s| {
                        s["key_id"]
                            .as_str()
                            .is_some_and(|id| signed(genesis, root, id))
                    })
                })
            }),
        ),
        (
            "crl_signature",
            crl["issuer"]
                .as_str()
                .is_some_and(|id| signed(crl, key, id)),
        ),
        (
            "crl_window",
            date(&crl["issued_at"]).is_some_and(|d| d <= now)
                && date(&crl["next_update"]).is_some_and(|d| d > now),
        ),
        ("crl_sequence", crl["sequence"].as_u64().is_some()),
        ("feed_identity", feed["issuer_sovereign_id"] == network),
        (
            "feed_signature",
            feed["issued_by"]
                .as_str()
                .is_some_and(|id| signed(feed, key, id)),
        ),
        (
            "feed_window",
            date(&feed["issued_at"])
                .is_some_and(|d| d <= now + Duration::minutes(5) && d >= now - Duration::hours(24)),
        ),
        ("feed_sequence", feed["sequence"].as_u64().is_some()),
        (
            "recognition_catalog",
            treaties["recognition_treaties"].is_array(),
        ),
        (
            "authority_delegation_window",
            date(&na["valid_from"]).is_some_and(|d| d <= now)
                && date(&na["valid_to"]).is_some_and(|d| d > now),
        ),
    ];
    json!({"network":network,"checked_at":now,"passed":checks.iter().all(|(_,v)|*v),
        "checks":checks.iter().map(|(check,passed)|json!({"check":check,"passed":passed})).collect::<Vec<_>>(),
        "coverage":"Signed HTTP preflight, not full RFC conformance. Confirm root ownership out of band.",
        "remaining_proofs":["Scoped treaty exchange","Membership acceptance before revocation","Rejection after propagated revocation","Restart and key rotation continuity"]})
}

/// Fetch bounded JSON with redirects disabled and no ambient proxy credentials.
pub async fn read(
    client: &reqwest::Client,
    base: &reqwest::Url,
    path: &str,
) -> Result<Value, String> {
    let url = base.join(path).map_err(|_| "Invalid path")?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "Authority connection failed")?;
    if !response.status().is_success() {
        return Err(format!("Authority returned HTTP {}", response.status()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Authority response interrupted")?
    {
        if bytes.len() + chunk.len() > 2_097_152 {
            return Err("Authority response exceeds 2 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let v: Value = serde_json::from_slice(&bytes).map_err(|_| "Authority returned invalid JSON")?;
    if !v.is_object() {
        return Err("Expected a JSON object".into());
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_credentials_paths_and_implicit_http() {
        for url in [
            "http://example.org",
            "https://user:password@example.org",
            "https://example.org/path",
            "https://example.org?x=1",
            "file:///tmp/a",
        ] {
            assert!(origin(url, false).is_err());
        }
        assert!(origin("http://127.0.0.1:8443", true).is_ok());
        assert!(origin("https://example.org", false).is_ok());
    }
    #[test]
    fn signature_rejects_tampering_wrong_key_and_wrong_signer() {
        let key = crate::KeyPair::generate().unwrap();
        let mut record = json!({"sequence":1,"signatures":[]});
        let body = to_canonical_json_excluding(&record, &["signatures"]).unwrap();
        record["signatures"] = json!([{"key_id":"na","sig":key.sign_b64(body.as_bytes())}]);
        assert!(signed(&record, &key.public_key_b64(), "na"));
        assert!(!signed(&record, &key.public_key_b64(), "other"));
        assert!(!signed(
            &record,
            &crate::KeyPair::generate().unwrap().public_key_b64(),
            "na"
        ));
        record["sequence"] = json!(2);
        assert!(!signed(&record, &key.public_key_b64(), "na"));
        assert_eq!(
            assess(
                "a",
                &key.public_key_b64(),
                &json!({}),
                &record,
                &record,
                &json!({})
            )["passed"],
            false
        );
    }
}
