//! Operator-owned, immutable trust and client authorization policy.

use crate::{
    crypto::{self, CachedPublicKey},
    models::{CertificateRevocationList, JoinCertificate, Signed},
    trust::TrustAnchors,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use subtle::ConstantTimeEq;

/// Loaded once at startup. Replace atomically and restart to apply changes.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityPolicy {
    /// Auditable operator-assigned policy revision.
    pub revision: String,
    /// Named network trust domains.
    pub networks: BTreeMap<String, NetworkPolicy>,
    /// Individually revocable service credentials.
    pub clients: Vec<Client>,
    /// SHA-256(token) → client index, built when the policy is prepared.
    #[serde(skip)]
    pub token_index: HashMap<[u8; 32], usize>,
}

/// A service identity and its least-privilege network scope.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    /// Allowed authority service groups. Empty disables authority access.
    #[serde(default)]
    pub service_groups: BTreeSet<String>,
    /// Permit operator-signed authority operations in the allowed groups.
    #[serde(default)]
    pub authority_admin: bool,
    /// Nonsecret audit identity.
    pub id: String,
    /// SHA-256 digest of a high-entropy bearer token, lowercase hex.
    pub token_sha256: String,
    /// Exact allowed network names; no wildcard semantics.
    pub networks: BTreeSet<String>,
    /// Whether this identity can scrape metrics.
    #[serde(default)]
    pub metrics: bool,
    /// Per-process request allowance in each sixty-second window.
    pub requests_per_minute: u32,
    /// Decoded `token_sha256`, filled when the policy is prepared.
    #[serde(skip)]
    pub token_digest: [u8; 32],
}

/// Pinned Genesis Mesh verification material for one network.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    /// Additional explicitly pinned CRL issuers for this same trust domain.
    /// Entries use the same snapshot shape but cannot nest additional issuers.
    #[serde(default)]
    pub additional_issuers: BTreeMap<String, Box<NetworkPolicy>>,
    /// Publish a minimal read-only topology for this network. Private by default.
    #[serde(default)]
    pub public_mesh: bool,
    /// Operator-pinned authority origin used by the explicit service allowlist.
    #[serde(default)]
    pub authority_url: Option<String>,
    /// Optional pinned authority CRL endpoint, refreshed every sixty seconds.
    #[serde(default)]
    pub crl_url: Option<String>,
    /// Explicit opt-in for a private HTTP authority endpoint.
    #[serde(default)]
    pub allow_http: bool,
    /// Authority keys approved by the operator.
    pub anchors: TrustAnchors,
    /// Signed revocation snapshot; freshness is mandatory.
    pub crl: CertificateRevocationList,
    /// Minimum accepted sequence, from the operator's durable high-water mark.
    pub minimum_crl_sequence: u64,
    /// Every listed role must occur in an accepted certificate.
    #[serde(default)]
    pub required_roles: BTreeSet<String>,
    /// Parsed anchor keys, filled when the policy is prepared.
    #[serde(skip)]
    pub verifying_keys: HashMap<String, CachedPublicKey>,
    /// First revocation entry for each certificate ID, prepared with the snapshot.
    #[serde(skip)]
    pub revoked_index: HashMap<String, usize>,
}

impl SecurityPolicy {
    /// Reject ambiguous, malformed or unusable security configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.revision.is_empty() || self.networks.is_empty() || self.clients.is_empty() {
            return Err("policy needs revision, networks and clients".into());
        }
        let mut ids = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        for client in &self.clients {
            if client.id.is_empty()
                || !ids.insert(&client.id)
                || !hashes.insert(&client.token_sha256)
                || client.token_sha256.len() != 64
                || !client
                    .token_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || client.requests_per_minute == 0
                || (!client.metrics && client.networks.is_empty())
                || client
                    .networks
                    .iter()
                    .any(|n| !self.networks.contains_key(n))
            {
                return Err(
                    "invalid or duplicate client identity, credential, quota or scope".into(),
                );
            }
        }
        for (name, network) in &self.networks {
            if network.additional_issuers.len() > 8 {
                return Err("at most eight additional CRL issuers per network".into());
            }
            for (issuer, additional) in &network.additional_issuers {
                if issuer != &additional.crl.issuer
                    || issuer == &network.crl.issuer
                    || !additional.additional_issuers.is_empty()
                    || !additional.required_roles.is_empty()
                    || additional.public_mesh
                    || additional.authority_url.is_some()
                {
                    return Err("additional issuers must be flat CRL sources; roles and service origin belong to the parent network".into());
                }
                let single = SecurityPolicy {
                    revision: self.revision.clone(),
                    networks: [(name.clone(), (**additional).clone())].into(),
                    clients: self
                        .clients
                        .iter()
                        .cloned()
                        .map(|mut c| {
                            c.networks = [name.clone()].into();
                            c
                        })
                        .collect(),
                    token_index: Default::default(),
                };
                single.validate()?;
            }
            if let Some(raw) = &network.authority_url {
                let url = reqwest::Url::parse(raw).map_err(|_| "invalid authority URL")?;
                if !(url.scheme() == "https" || (url.scheme() == "http" && network.allow_http))
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || url.path() != "/"
                {
                    return Err("authority URL must be an HTTPS origin without credentials, path, query or fragment; private HTTP requires opt-in".into());
                }
            }
            if let Some(raw) = &network.crl_url {
                let url = reqwest::Url::parse(raw).map_err(|_| "invalid CRL URL")?;
                if !(url.scheme() == "https" || (url.scheme() == "http" && network.allow_http))
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                {
                    return Err("CRL URL requires HTTPS or explicit private HTTP opt-in, without credentials or fragment".into());
                }
            }
            if name.is_empty() || network.anchors.is_empty() {
                return Err("network name and anchors must not be empty".into());
            }
            for (id, key) in &network.anchors {
                if id.is_empty() || !crypto::validate_public_key(key).unwrap_or(false) {
                    return Err("invalid trust anchor".into());
                }
            }
            // A signed expired bootstrap snapshot can recover from its pinned
            // authority. Readiness remains false until a fresh snapshot arrives.
            if !network.authentic()
                || network.crl.sequence < network.minimum_crl_sequence
                || network.crl.issued_at > Utc::now()
                || network.crl.issued_at >= network.crl.next_update
                || (!network.primary_ready(Utc::now()) && network.crl_url.is_none())
            {
                return Err("CRL is invalid, stale, future-dated or below minimum sequence".into());
            }
        }
        Ok(())
    }

    /// Build O(1) token lookup and parsed authority keys after a successful validate.
    pub fn rebuild_indexes(&mut self) {
        self.token_index.clear();
        for (i, client) in self.clients.iter_mut().enumerate() {
            if let Some(digest) = parse_hex32(&client.token_sha256) {
                client.token_digest = digest;
                self.token_index.insert(digest, i);
            }
        }
        for network in self.networks.values_mut() {
            network.rebuild_crypto_cache();
        }
    }

    /// Resolve an opaque token without comparing secret strings directly.
    pub fn authenticate(&self, token: &str) -> Option<usize> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if let Some(&i) = self.token_index.get(&digest) {
            return bool::from(self.clients[i].token_digest.ct_eq(&digest)).then_some(i);
        }
        if !self.token_index.is_empty() {
            return None;
        }
        let hex = hex_lower32(&digest);
        self.clients.iter().position(|c| {
            c.token_sha256.len() == 64
                && bool::from(c.token_sha256.as_bytes().ct_eq(hex.as_slice()))
        })
    }
}

impl NetworkPolicy {
    /// A snapshot must be signed by its named issuer and fresh right now.
    pub fn ready(&self, now: DateTime<Utc>) -> bool {
        self.primary_ready(now)
            && self
                .additional_issuers
                .values()
                .all(|n| n.primary_ready(now))
    }

    pub(super) fn primary_ready(&self, now: DateTime<Utc>) -> bool {
        let crl = &self.crl;
        crl.sequence >= self.minimum_crl_sequence && crl.issued_at <= now && now < crl.next_update
    }

    pub(super) fn authentic(&self) -> bool {
        let crl = &self.crl;
        self.anchors.get(&crl.issuer).is_some_and(|key| {
            crl.signing_input().ok().is_some_and(|payload| {
                crl.signatures.iter().any(|s| {
                    s.key_id == crl.issuer
                        && crypto::verify_b64(payload.as_bytes(), &s.sig, key).unwrap_or(false)
                })
            })
        })
    }

    pub(super) fn rebuild_crypto_cache(&mut self) {
        for additional in self.additional_issuers.values_mut() {
            additional.rebuild_crypto_cache();
        }
        self.revoked_index.clear();
        for (index, entry) in self.crl.revoked_certificates.iter().enumerate() {
            self.revoked_index
                .entry(entry.certificate_id.clone())
                .or_insert(index);
        }
        self.verifying_keys.clear();
        for (id, key) in &self.anchors {
            if let Ok(parsed) = CachedPublicKey::parse(key) {
                self.verifying_keys.insert(id.clone(), parsed);
            }
        }
    }

    /// Additional deployment policy, separate from the portable wire protocol.
    ///
    /// Signature verification is left to [`crate::trust::verify_join_certificate`]
    /// so each certificate is canonicalized and checked once.
    pub fn accepts(&self, cert: &JoinCertificate, now: DateTime<Utc>) -> bool {
        self.issuer(&cert.issued_by).is_some_and(|issuer| {
            issuer.primary_ready(now)
                && cert.issued_at < cert.expires_at
                && issuer.anchors.contains_key(&cert.issued_by)
                && crypto::validate_public_key(&cert.node_public_key).unwrap_or(false)
                && self.required_roles.iter().all(|r| cert.roles.contains(r))
        })
    }

    /// Select only the CRL and pinned keys belonging to the certificate's named issuer.
    pub fn issuer(&self, id: &str) -> Option<&NetworkPolicy> {
        if id == self.crl.issuer {
            Some(self)
        } else {
            self.additional_issuers.get(id).map(Box::as_ref)
        }
    }
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex_lower32(bytes: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, byte) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX[(byte & 0xf) as usize];
    }
    out
}
