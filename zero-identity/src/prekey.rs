//! Prekeys — X25519 signed prekeys and one-time prekeys for ZKX.

use crate::error::IdentityError;
use serde::{Deserialize, Serialize};
use zero_crypto::{
    dh::{X25519Keypair, X25519PublicKey, X25519SecretKey},
    sign::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature, ed25519_verify},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of one-time prekeys to generate per batch.
pub const OPKS_BATCH_SIZE: usize = 100;

/// A signed prekey: one X25519 keypair + Ed25519 signature from ISK proving ownership.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SignedPrekey {
    /// SPK index (monotonically increasing).
    pub index: u32,
    /// X25519 public key.
    #[zeroize(skip)]
    pub public_key: X25519PublicKey,
    /// Private key (held locally, never sent).
    pub secret_key: Option<X25519SecretKey>,
    /// Ed25519 signature by ISK over the SPK public key bytes.
    #[zeroize(skip)]
    pub signature: Ed25519Signature,
}

impl std::fmt::Debug for SignedPrekey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedPrekey")
            .field("index", &self.index)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl SignedPrekey {
    /// Generate a new signed prekey, signing it with the identity signing key.
    pub fn generate(index: u32, isk: &Ed25519Keypair) -> Self {
        let kp = X25519Keypair::generate();
        let signature = isk.sign(&kp.public_key().0);
        Self {
            index,
            public_key: kp.public_key(),
            secret_key: Some(kp.secret_key()),
            signature,
        }
    }

    /// Verify the SPK signature against a given ISK public key.
    pub fn verify(&self, isk_pub: &Ed25519PublicKey) -> Result<(), IdentityError> {
        ed25519_verify(isk_pub, &self.public_key.0, &self.signature)
            .map_err(|_| IdentityError::InvalidSpkSignature)
    }

    /// The public-only version for publishing to the DHT.
    pub fn public_view(&self) -> SignedPrekeyPublic {
        SignedPrekeyPublic {
            index: self.index,
            public_key: self.public_key.clone(),
            signature: self.signature.clone(),
        }
    }
}

/// Serializable public view of a SignedPrekey (no secret key).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPrekeyPublic {
    /// SPK index.
    pub index: u32,
    /// X25519 public key.
    pub public_key: X25519PublicKey,
    /// Signature proving ownership by ISK.
    pub signature: Ed25519Signature,
}

/// A one-time prekey: single-use X25519 keypair. Consumed on first contact.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OneTimePrekey {
    /// OPK index within the current batch.
    pub index: u32,
    /// X25519 public key (published to DHT).
    #[zeroize(skip)]
    pub public_key: X25519PublicKey,
    /// Private key (held locally, used at most once).
    pub secret_key: Option<X25519SecretKey>,
    /// True if this OPK has been consumed.
    pub consumed: bool,
}

impl std::fmt::Debug for OneTimePrekey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneTimePrekey")
            .field("index", &self.index)
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

impl OneTimePrekey {
    /// Generate a single one-time prekey.
    pub fn generate(index: u32) -> Self {
        let kp = X25519Keypair::generate();
        Self {
            index,
            public_key: kp.public_key(),
            secret_key: Some(kp.secret_key()),
            consumed: false,
        }
    }

    /// Generate a batch of OPKS_BATCH_SIZE one-time prekeys.
    pub fn generate_batch(start_index: u32) -> Vec<Self> {
        (0..OPKS_BATCH_SIZE as u32)
            .map(|i| Self::generate(start_index + i))
            .collect()
    }

    /// Consume this OPK — marks it used and returns the secret key.
    pub fn consume(&mut self) -> Option<X25519SecretKey> {
        if self.consumed {
            return None;
        }
        self.consumed = true;
        self.secret_key.take()
    }
}

/// Public view of a one-time prekey (for publishing to DHT).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePrekeyPublic {
    /// OPK index.
    pub index: u32,
    /// X25519 public key.
    pub public_key: X25519PublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_crypto::sign::Ed25519Keypair;

    #[test]
    fn test_spk_signature_verifies() {
        let isk = Ed25519Keypair::generate();
        let spk = SignedPrekey::generate(0, &isk);
        assert!(spk.verify(&isk.public_key()).is_ok());
    }

    #[test]
    fn test_spk_wrong_isk_fails() {
        let isk1 = Ed25519Keypair::generate();
        let isk2 = Ed25519Keypair::generate();
        let spk = SignedPrekey::generate(0, &isk1);
        assert!(spk.verify(&isk2.public_key()).is_err());
    }

    #[test]
    fn test_opk_batch_size() {
        let batch = OneTimePrekey::generate_batch(0);
        assert_eq!(batch.len(), OPKS_BATCH_SIZE);
    }

    #[test]
    fn test_opk_consume_once() {
        let mut opk = OneTimePrekey::generate(0);
        let sk = opk.consume();
        assert!(sk.is_some());
        let sk2 = opk.consume();
        assert!(sk2.is_none()); // consumed already
    }

    #[test]
    fn test_opk_indices_sequential() {
        let batch = OneTimePrekey::generate_batch(50);
        for (i, opk) in batch.iter().enumerate() {
            assert_eq!(opk.index, 50 + i as u32);
        }
    }
}
