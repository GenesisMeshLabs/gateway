//! Ed25519 identities: generation, signing, verification.
//!
//! Wire compatibility notes, matching `genesis_mesh/crypto/`:
//!
//! * A "private key" on the wire is the base64 of the raw 32-byte Ed25519
//!   **seed** — this is what PyNaCl's `bytes(SigningKey)` yields, so the two
//!   implementations can load each other's key files.
//! * A public key is the base64 of the raw 32-byte compressed point.
//! * A signature is the base64 of the raw 64-byte detached signature.
//!
//! All base64 is standard alphabet **with** padding.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::{Error, Result};

/// Length of an Ed25519 seed and of a public key, in bytes.
pub const KEY_LEN: usize = 32;
/// Length of a detached Ed25519 signature, in bytes.
pub const SIG_LEN: usize = 64;

/// An Ed25519 signing identity.
pub struct KeyPair {
    signing: SigningKey,
}

impl KeyPair {
    /// Generate a fresh identity from system randomness.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; KEY_LEN];
        getrandom::getrandom(&mut seed).map_err(|e| Error::Random(e.to_string()))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Load an identity from a base64 seed, as written by either implementation.
    pub fn from_seed_b64(seed_b64: &str) -> Result<Self> {
        let seed = decode_fixed::<KEY_LEN>("private key", seed_b64)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Base64 of the raw 32-byte seed. Treat as secret.
    pub fn seed_b64(&self) -> String {
        STANDARD.encode(self.signing.to_bytes())
    }

    /// Base64 of the raw 32-byte public key. Safe to publish.
    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.signing.verifying_key().to_bytes())
    }

    /// Sign a message, returning the base64 detached signature.
    pub fn sign_b64(&self, message: &[u8]) -> String {
        STANDARD.encode(self.signing.sign(message).to_bytes())
    }
}

/// Prints the public key only — the seed must never reach a log.
impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key_b64", &self.public_key_b64())
            .finish_non_exhaustive()
    }
}

/// Verify a base64 detached signature against a base64 public key.
///
/// Returns `Ok(false)` for a well-formed but incorrect signature, and `Err` only
/// when an input could not be decoded at all — the caller can then distinguish
/// "this does not verify" from "this was not a key".
pub fn verify_b64(message: &[u8], signature_b64: &str, public_key_b64: &str) -> Result<bool> {
    let key_bytes = decode_fixed::<KEY_LEN>("public key", public_key_b64)?;
    let verifying = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Error::MalformedPublicKey(e.to_string()))?;
    let sig_bytes = decode_fixed::<SIG_LEN>("signature", signature_b64)?;
    let signature = Signature::from_bytes(&sig_bytes);
    Ok(verifying.verify(message, &signature).is_ok())
}

fn decode_fixed<const N: usize>(field: &'static str, value: &str) -> Result<[u8; N]> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|source| Error::Base64 { field, source })?;
    let actual = bytes.len();
    bytes.try_into().map_err(|_| Error::KeyLength {
        field,
        expected: N,
        actual,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_signature() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign_b64(b"hello mesh");
        assert!(verify_b64(b"hello mesh", &sig, &kp.public_key_b64()).unwrap());
    }

    #[test]
    fn rejects_a_tampered_message() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign_b64(b"hello mesh");
        assert!(!verify_b64(b"goodbye mesh", &sig, &kp.public_key_b64()).unwrap());
    }

    #[test]
    fn seed_round_trips_through_base64() {
        let kp = KeyPair::generate().unwrap();
        let reloaded = KeyPair::from_seed_b64(&kp.seed_b64()).unwrap();
        assert_eq!(kp.public_key_b64(), reloaded.public_key_b64());
    }

    #[test]
    fn wrong_length_key_is_an_error() {
        let err = KeyPair::from_seed_b64("aGk=").unwrap_err();
        assert!(matches!(err, Error::KeyLength { expected: 32, .. }));
    }
}
