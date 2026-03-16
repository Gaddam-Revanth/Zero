//! Ed25519 digital signatures for ZERO Protocol.

use crate::error::CryptoError;
use ed25519_dalek::{Signer, Verifier, SigningKey, Signature, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SECRET_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ed25519PublicKey(pub [u8; ED25519_PUBLIC_KEY_SIZE]);

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519SecretKey(pub [u8; ED25519_SECRET_KEY_SIZE]);

impl std::fmt::Debug for Ed25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ed25519SecretKey([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Signature(pub Vec<u8>);

impl std::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ed25519Signature")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ed25519Keypair {
    #[serde(with = "serde_signing_key")]
    signing_key: SigningKey,
}

mod serde_signing_key {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(key: &SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        key.to_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SigningKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(SigningKey::from_bytes(&bytes))
    }
}

impl Ed25519Keypair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        Self { signing_key }
    }

    pub fn from_secret_bytes(bytes: [u8; ED25519_SECRET_KEY_SIZE]) -> Self {
        let signing_key = SigningKey::from_bytes(&bytes);
        Self { signing_key }
    }

    pub fn secret_key(&self) -> Ed25519SecretKey {
        Ed25519SecretKey(self.signing_key.to_bytes())
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.signing_key.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let signature = self.signing_key.sign(message);
        Ed25519Signature(signature.to_bytes().to_vec())
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), CryptoError> {
        if signature.0.len() != ED25519_SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let sig_bytes: [u8; 64] = signature.0.as_slice().try_into().unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        self.signing_key.verifying_key()
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

pub fn ed25519_sign(secret: &Ed25519SecretKey, message: &[u8]) -> Ed25519Signature {
    let kp = Ed25519Keypair::from_secret_bytes(secret.0);
    kp.sign(message)
}

pub fn ed25519_verify(
    public_key: &Ed25519PublicKey,
    message: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(&public_key.0)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    if signature.0.len() != ED25519_SIGNATURE_SIZE {
        return Err(CryptoError::InvalidSignature);
    }
    let sig_bytes: [u8; 64] = signature.0.as_slice().try_into().unwrap();
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(message, &sig)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}
