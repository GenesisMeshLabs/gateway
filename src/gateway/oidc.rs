//! Pinned OIDC issuer/audience validation with explicit subject-to-service bindings.
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    issuer: String,
    audience: String,
    jwks_url: String,
    bindings: Vec<Binding>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    subject: String,
    client_id: String,
    #[serde(default)]
    required_claims: BTreeMap<String, String>,
}

/// Keys are fetched only from a configured HTTPS endpoint, never a JWT-supplied URL.
pub struct Oidc {
    settings: Settings,
    http: reqwest::Client,
    keys: tokio::sync::Mutex<Option<(Instant, JwkSet)>>,
}
impl Oidc {
    /// Load nonsecret issuer settings. Credentials are mapped to existing policy scopes.
    pub fn load(path: &str, policy: &super::security::SecurityPolicy) -> Result<Self, String> {
        let raw = std::fs::read(path).map_err(|_| "cannot read OIDC settings")?;
        if raw.len() > 1_048_576 {
            return Err("OIDC settings exceed limit".into());
        }
        let settings: Settings =
            serde_json::from_slice(&raw).map_err(|_| "invalid OIDC settings")?;
        let url = reqwest::Url::parse(&settings.jwks_url).map_err(|_| "invalid JWKS URL")?;
        let issuer = reqwest::Url::parse(&settings.issuer).map_err(|_| "invalid OIDC issuer")?;
        if url.scheme() != "https"
            || issuer.scheme() != "https"
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || settings.audience.is_empty()
            || settings.bindings.is_empty()
            || settings.bindings.len() > 4096
        {
            return Err("OIDC requires HTTPS issuer/JWKS, audience and explicit bindings".into());
        }
        let mut subjects = std::collections::BTreeSet::new();
        if settings.bindings.iter().any(|b| {
            b.subject.is_empty()
                || !subjects.insert(&b.subject)
                || !policy.clients.iter().any(|c| c.id == b.client_id)
        }) {
            return Err(
                "OIDC bindings must have unique subjects and existing policy clients".into(),
            );
        }
        Ok(Self {
            settings,
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(3))
                .build()
                .map_err(|_| "OIDC HTTP setup failed")?,
            keys: Default::default(),
        })
    }

    /// Validate signature, expiry, not-before, issuer, audience, subject and required claims.
    pub async fn authenticate(&self, token: &str) -> Option<String> {
        if token.len() > 16_384 {
            return None;
        }
        let header = decode_header(token).ok()?;
        if !matches!(
            header.alg,
            Algorithm::RS256 | Algorithm::ES256 | Algorithm::EdDSA
        ) {
            return None;
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|s| !s.is_empty() && s.len() <= 256)?;
        let mut cache = self.keys.lock().await;
        if cache
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(300))
        {
            let mut response = self.http.get(&self.settings.jwks_url).send().await.ok()?;
            if !response.status().is_success() {
                return None;
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.ok()? {
                if bytes.len() + chunk.len() > 1_048_576 {
                    return None;
                }
                bytes.extend_from_slice(&chunk);
            }
            let set: JwkSet = serde_json::from_slice(&bytes).ok()?;
            if set.keys.len() > 64 {
                return None;
            }
            *cache = Some((Instant::now(), set));
        }
        let jwk = cache.as_ref()?.1.find(kid)?;
        use jsonwebtoken::jwk::{KeyAlgorithm, KeyOperations, PublicKeyUse};
        let expected = match header.alg {
            Algorithm::RS256 => KeyAlgorithm::RS256,
            Algorithm::ES256 => KeyAlgorithm::ES256,
            Algorithm::EdDSA => KeyAlgorithm::EdDSA,
            _ => return None,
        };
        if jwk
            .common
            .public_key_use
            .as_ref()
            .is_some_and(|usage| *usage != PublicKeyUse::Signature)
            || jwk
                .common
                .key_operations
                .as_ref()
                .is_some_and(|ops| !ops.contains(&KeyOperations::Verify))
            || jwk.common.key_algorithm.is_some_and(|alg| alg != expected)
            || cache
                .as_ref()?
                .1
                .keys
                .iter()
                .filter(|k| k.common.key_id.as_deref() == Some(kid))
                .count()
                != 1
        {
            return None;
        }
        let key = DecodingKey::from_jwk(jwk).ok()?;
        drop(cache);
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.settings.issuer]);
        validation.set_audience(&[&self.settings.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = 30;
        let claims = decode::<Value>(token, &key, &validation).ok()?.claims;
        let subject = claims["sub"].as_str()?;
        self.settings
            .bindings
            .iter()
            .find(|b| {
                b.subject == subject
                    && b.required_claims
                        .iter()
                        .all(|(k, v)| claims[k].as_str() == Some(v.as_str()))
            })
            .map(|b| b.client_id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine,
    };
    fn token(key: &crate::KeyPair, claims: &Value, kid: &str) -> String {
        let header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({"alg":"EdDSA","kid":kid})).unwrap());
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let input = format!("{header}.{body}");
        let signature =
            URL_SAFE_NO_PAD.encode(STANDARD.decode(key.sign_b64(input.as_bytes())).unwrap());
        format!("{input}.{signature}")
    }
    #[tokio::test]
    async fn rejects_wrong_signature_issuer_audience_subject_expiry_and_required_claim() {
        let key = crate::KeyPair::generate().unwrap();
        let set: JwkSet = serde_json::from_value(serde_json::json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test","alg":"EdDSA","use":"sig","x":URL_SAFE_NO_PAD.encode(STANDARD.decode(key.public_key_b64()).unwrap())}]})).unwrap();
        let verifier = Oidc {
            settings: Settings {
                issuer: "https://id.example.org".into(),
                audience: "gateway".into(),
                jwks_url: "https://id.example.org/keys".into(),
                bindings: vec![Binding {
                    subject: "operator-1".into(),
                    client_id: "agency-service".into(),
                    required_claims: [("department".into(), "operations".into())].into(),
                }],
            },
            http: reqwest::Client::new(),
            keys: tokio::sync::Mutex::new(Some((Instant::now(), set))),
        };
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({"iss":"https://id.example.org","aud":"gateway","sub":"operator-1","exp":now+300,"nbf":now-60,"department":"operations"});
        assert_eq!(
            verifier.authenticate(&token(&key, &claims, "test")).await,
            Some("agency-service".into())
        );
        for (field, value) in [
            ("iss", serde_json::json!("https://evil.example")),
            ("aud", serde_json::json!("other")),
            ("sub", serde_json::json!("unknown")),
            ("exp", serde_json::json!(now - 60)),
            ("nbf", serde_json::json!(now + 300)),
            ("nbf", serde_json::json!((now + 300).to_string())),
            ("nbf", serde_json::json!(null)),
            ("nbf", serde_json::json!({"value": now + 300})),
            ("exp", serde_json::json!((now + 300).to_string())),
            ("department", serde_json::json!("other")),
        ] {
            let mut bad = claims.clone();
            bad[field] = value;
            assert!(
                verifier
                    .authenticate(&token(&key, &bad, "test"))
                    .await
                    .is_none(),
                "{field}"
            );
        }
        assert!(verifier
            .authenticate(&token(
                &crate::KeyPair::generate().unwrap(),
                &claims,
                "test"
            ))
            .await
            .is_none());
        assert!(verifier
            .authenticate(&token(&key, &claims, "unknown"))
            .await
            .is_none());
        assert!(verifier.authenticate("not-a-jwt").await.is_none());
    }
}
