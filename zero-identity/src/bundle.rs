//! Key bundle — the complete public key set published to ZDHT for ZKX.

use crate::{
    error::IdentityError,
    keypair::ZeroKeypair,
    prekey::{OneTimePrekey, OneTimePrekeyPublic, SignedPrekey, SignedPrekeyPublic},
    zeroid::ZeroId,
};
use serde::{Deserialize, Serialize};
use zero_crypto::dh::X25519PublicKey;
use zero_crypto::sign::Ed25519PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public key bundle published to ZDHT. Alice fetches this to initiate ZKX with Bob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBundle {
    /// Bob's ZERO ID.
    pub zero_id: ZeroId,
    /// Ed25519 ISK public key.
    pub isk_pub: Ed25519PublicKey,
    /// X25519 IDK public key.
    pub idk_pub: X25519PublicKey,
    /// ML-KEM-768 encapsulation key (1184 bytes).
    pub pq_isk_pub: Vec<u8>,
    /// Current signed prekey + signature.
    pub spk: SignedPrekeyPublic,
    /// One-time prekey (if available). None if all exhausted.
    pub opk: Option<OneTimePrekeyPublic>,
    /// Unix timestamp when this bundle was created.
    pub created_at: u64,
}

impl KeyBundle {
    /// Verify the bundle's internal consistency (SPK signature).
    pub fn verify(&self) -> Result<(), IdentityError> {
        let id_comp = self.zero_id.components();
        if self.isk_pub.0 != id_comp.isk_pub || self.idk_pub.0 != id_comp.idk_pub {
            return Err(IdentityError::CryptoError(
                "Bundle keys do not match ZeroId".into(),
            ));
        }
        let pq_hash = zero_crypto::hash::blake2b_256(&self.pq_isk_pub);
        if pq_hash[..4] != id_comp.pq_hash {
            return Err(IdentityError::CryptoError(
                "PQ ISK hash does not match ZeroId".into(),
            ));
        }

        zero_crypto::sign::ed25519_verify(
            &self.isk_pub,
            &self.spk.public_key.0,
            &self.spk.signature,
        )
        .map_err(|_| IdentityError::InvalidSpkSignature)
    }

    /// Serialize to CBOR bytes for DHT storage.
    pub fn to_cbor(&self) -> Result<Vec<u8>, IdentityError> {
        zero_crypto::cbor::to_vec(self)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))
    }

    /// Deserialize from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, IdentityError> {
        zero_crypto::cbor::from_slice(bytes)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))
    }
}

/// Owned key bundle — includes private material for the local user.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OwnedKeyBundle {
    /// The user's long-term keypair.
    pub keypair: ZeroKeypair,
    /// Current signed prekey (with secret key).
    pub current_spk: SignedPrekey,
    /// Pool of one-time prekeys.
    pub opks: Vec<OneTimePrekey>,
    /// Current SPK index.
    pub spk_index: u32,
    /// Unix timestamp of last SPK rotation.
    pub spk_created_at: u64,
    /// History of old signed prekeys to support out-of-order handshakes.
    #[zeroize(skip)]
    pub old_spks: std::collections::HashMap<u32, SignedPrekey>,
    /// Cache of recent handshakes to prevent replay DoS when OPKs are omitted.
    #[zeroize(skip)]
    pub recent_handshakes: std::collections::HashMap<[u8; 32], u64>,
}

impl OwnedKeyBundle {
    /// Create a new owned bundle, generating all keys.
    pub fn generate(created_at: u64) -> Result<Self, IdentityError> {
        let keypair = ZeroKeypair::generate()?;
        let spk = SignedPrekey::generate(0, &keypair.isk);
        let opks = OneTimePrekey::generate_batch(0);
        Ok(Self {
            keypair,
            current_spk: spk,
            opks,
            spk_index: 0,
            spk_created_at: created_at,
            old_spks: std::collections::HashMap::new(),
            recent_handshakes: std::collections::HashMap::new(),
        })
    }

    /// Build a public KeyBundle from this owned bundle, consuming one OPK.
    pub fn public_bundle(&mut self, zero_id: &ZeroId) -> KeyBundle {
        let opk = self
            .opks
            .iter()
            .find(|o| !o.consumed)
            .map(|o| OneTimePrekeyPublic {
                index: o.index,
                public_key: o.public_key.clone(),
            });

        KeyBundle {
            zero_id: zero_id.clone(),
            isk_pub: self.keypair.isk.public_key(),
            idk_pub: self.keypair.idk.public_key(),
            pq_isk_pub: self.keypair.pq_isk.ek.0.clone(),
            spk: self.current_spk.public_view(),
            opk,
            created_at: self.spk_created_at,
        }
    }

    /// Rotate the signed prekey (call every 7 days).
    pub fn rotate_spk(&mut self, now: u64) {
        let old_spk = std::mem::replace(
            &mut self.current_spk,
            SignedPrekey::generate(self.spk_index + 1, &self.keypair.isk),
        );
        self.old_spks.insert(self.spk_index, old_spk);
        self.spk_index += 1;
        self.spk_created_at = now;

        // Prune old SPKs (keep only last 10)
        if self.old_spks.len() > 10 {
            let min_index = self.old_spks.keys().min().copied().unwrap_or_default();
            self.old_spks.remove(&min_index);
        }
    }

    /// Replenish OPKs when running low.
    pub fn replenish_opks(&mut self) {
        let max_index = self.opks.iter().map(|o| o.index).max().unwrap_or(0);
        let mut new_opks = OneTimePrekey::generate_batch(max_index + 1);
        self.opks.append(&mut new_opks);
        // Trim consumed ones to avoid unbounded growth
        self.opks.retain(|o| !o.consumed);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_verify() {
        let mut owned = OwnedKeyBundle::generate(1000).unwrap();
        let id = ZeroId::from_keypair(&owned.keypair, [0u8; 4]);
        let bundle = owned.public_bundle(&id);
        assert!(bundle.verify().is_ok());
    }

    #[test]
    fn test_bundle_cbor_roundtrip() {
        let mut owned = OwnedKeyBundle::generate(1000).unwrap();
        let id = ZeroId::from_keypair(&owned.keypair, [0u8; 4]);
        let bundle = owned.public_bundle(&id);
        let cbor = bundle.to_cbor().unwrap();
        let decoded = KeyBundle::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.isk_pub.0, bundle.isk_pub.0);
    }

    #[test]
    fn test_spk_rotation() {
        let mut owned = OwnedKeyBundle::generate(0).unwrap();
        let old_pub = owned.current_spk.public_key.clone();
        owned.rotate_spk(7 * 24 * 3600);
        assert_ne!(owned.current_spk.public_key.0, old_pub.0);
        assert_eq!(owned.spk_index, 1);
    }
}
