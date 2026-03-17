//! ZKX Master Secret output type.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of the ZKX master secret in bytes.
pub const MASTER_SECRET_SIZE: usize = 64;

/// The master secret produced by ZKX.
/// Used to seed the initial Zero Ratchet state.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret(pub [u8; MASTER_SECRET_SIZE]);

impl MasterSecret {
    /// R4: Derive a confirmation key from the master secret.
    pub fn derive_confirm_key(&self) -> Result<[u8; 32], zero_crypto::error::CryptoError> {
        let okm = zero_crypto::kdf::hkdf_expand(
            &self.0,
            zero_crypto::kdf::KdfContext::Custom("ZERO-ZKX-v1-key-confirm"),
            32,
        )?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm);
        Ok(key)
    }

    /// R4: Generate a confirmation tag.
    pub fn generate_tag(&self, label: &str, h_noise: &[u8; 32]) -> Result<[u8; 32], crate::error::HandshakeError> {
        let confirm_key = self.derive_confirm_key()
            .map_err(|_| crate::error::HandshakeError::KdfError)?;
        
        // Tag = BLAKE2b-256(confirm_key || label || h_noise)
        let tag = zero_crypto::hash::blake2b_256_multi(&[
            &confirm_key,
            label.as_bytes(),
            h_noise,
        ]);
        Ok(tag)
    }

    /// R4: Verify a confirmation tag.
    pub fn verify_tag(&self, label: &str, h_noise: &[u8; 32], expected_tag: &[u8; 32]) -> Result<(), crate::error::HandshakeError> {
        let actual = self.generate_tag(label, h_noise)?;
        if actual == *expected_tag {
            Ok(())
        } else {
            Err(crate::error::HandshakeError::AuthenticationFailed)
        }
    }
}

impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret([REDACTED])")
    }
}

/// The complete output of a successful ZKX handshake.
#[derive(Debug)]
pub struct ZkxOutput {
    /// The shared master secret.
    pub master_secret: MasterSecret,
    /// Transcript hash from the Noise XX phase.
    pub noise_hash: [u8; 32],
    /// Remote party's ISK public key (verified).
    pub remote_isk_pub: [u8; 32],
}
