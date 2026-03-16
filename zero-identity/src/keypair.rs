//! ZERO ID keypair — all long-term keys for one identity.

use crate::error::IdentityError;
use zero_crypto::{
    dh::{X25519Keypair, X25519PublicKey},
    hash::blake2b_256,
    kem::{MlKem768EncapsKey, MlKem768Keypair},
    sign::{Ed25519Keypair, Ed25519PublicKey},
};
use serde::{Deserialize, Serialize};

/// The complete long-term keypair for one ZERO identity.
pub struct ZeroKeypair {
    /// Ed25519 Identity Signing Key (ISK) — permanent identity anchor.
    pub isk: Ed25519Keypair,
    /// X25519 Identity DH Key (IDK) — used in X3DH 4-DH computation.
    pub idk: X25519Keypair,
    /// ML-KEM-768 post-quantum keypair (PQ_ISK).
    pub pq_isk: MlKem768Keypair,
}

impl ZeroKeypair {
    /// Generate a fresh ZERO identity keypair.
    pub fn generate() -> Result<Self, IdentityError> {
        let isk = Ed25519Keypair::generate();
        let idk = X25519Keypair::generate();
        let pq_isk = MlKem768Keypair::generate()
            .map_err(|e| IdentityError::CryptoError(e.to_string()))?;
        Ok(Self { isk, idk, pq_isk })
    }

    /// Return the Ed25519 public key (ISK_pub) — the canonical ZERO identity.
    pub fn isk_pub(&self) -> Ed25519PublicKey {
        self.isk.public_key()
    }

    /// Return the X25519 IDK public key.
    pub fn idk_pub(&self) -> X25519PublicKey {
        self.idk.public_key()
    }

    /// Return the ML-KEM-768 encapsulation key (public).
    pub fn pq_isk_pub(&self) -> &MlKem768EncapsKey {
        &self.pq_isk.ek
    }

    /// Return a 32-byte hash of the PQ_ISK encapsulation key.
    pub fn pq_isk_hash(&self) -> [u8; 32] {
        blake2b_256(&self.pq_isk.ek.0)
    }

    /// Export a serializable snapshot of the public key material.
    pub fn public_snapshot(&self) -> ZeroKeypairPublic {
        ZeroKeypairPublic {
            isk_pub: self.isk.public_key(),
            idk_pub: self.idk.public_key(),
            pq_isk_pub: self.pq_isk.ek.0.clone(),
        }
    }
}

impl std::fmt::Debug for ZeroKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroKeypair")
            .field("isk_pub", &self.isk.public_key())
            .field("idk_pub", &self.idk.public_key())
            .finish_non_exhaustive()
    }
}

/// Public key material — safe to serialize and share.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroKeypairPublic {
    /// Ed25519 ISK public key.
    pub isk_pub: Ed25519PublicKey,
    /// X25519 IDK public key.
    pub idk_pub: X25519PublicKey,
    /// ML-KEM-768 encapsulation key (1184 bytes).
    pub pq_isk_pub: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let kp = ZeroKeypair::generate().unwrap();
        let pub_snap = kp.public_snapshot();
        assert_eq!(pub_snap.isk_pub.0.len(), 32);
        assert_eq!(pub_snap.idk_pub.0.len(), 32);
        assert_eq!(pub_snap.pq_isk_pub.len(), 1184);
    }

    #[test]
    fn test_two_identities_differ() {
        let kp1 = ZeroKeypair::generate().unwrap();
        let kp2 = ZeroKeypair::generate().unwrap();
        assert_ne!(kp1.isk_pub().0, kp2.isk_pub().0);
    }
}
