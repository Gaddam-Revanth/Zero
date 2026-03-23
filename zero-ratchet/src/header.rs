//! ZR header encryption — hides ratchet key and message counters from relays.

use crate::error::RatchetError;
use serde::{Deserialize, Serialize};
use zero_crypto::{
    aead::{decrypt, encrypt, AeadKey, AeadNonce},
    dh::X25519PublicKey,
};

/// The plaintext contents of a ZR message header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptedHeader {
    /// Sender's current DH ratchet public key.
    pub dh_pub: X25519PublicKey,
    /// Number of messages sent in the previous sending chain.
    pub prev_counter: u32,
    /// This message's counter in the current sending chain.
    pub counter: u32,
}

impl DecryptedHeader {
    /// Number of extra bytes added by encryption (nonce + tag).
    pub const OVERHEAD: usize = 12 + 16; // nonce + AEAD tag

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 4 + 4);
        buf.extend_from_slice(&self.dh_pub.0);
        buf.extend_from_slice(&self.prev_counter.to_le_bytes());
        buf.extend_from_slice(&self.counter.to_le_bytes());
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 40 {
            return None;
        }
        let mut dh_pub_arr = [0u8; 32];
        dh_pub_arr.copy_from_slice(&bytes[..32]);
        let dh_pub = X25519PublicKey(dh_pub_arr);
        let prev_counter = u32::from_le_bytes(bytes[32..36].try_into().ok()?);
        let counter = u32::from_le_bytes(bytes[36..40].try_into().ok()?);
        Some(Self {
            dh_pub,
            prev_counter,
            counter,
        })
    }
}

/// An encrypted header blob — opaque to relay servers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedHeader(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// Encrypt a header with the header key HKs.
pub fn encrypt_header(
    hk: &AeadKey,
    header: &DecryptedHeader,
) -> Result<EncryptedHeader, RatchetError> {
    let plaintext = header.to_bytes();
    let nonce = AeadNonce::random();
    let ct = encrypt(hk, &nonce, &plaintext, b"ZR-header")
        .map_err(|_| RatchetError::DecryptionFailed)?;
    let mut blob = nonce.0.to_vec();
    blob.extend_from_slice(&ct);
    Ok(EncryptedHeader(blob))
}

/// Decrypt a header with the header key HKr.
pub fn decrypt_header(
    hk: &AeadKey,
    enc: &EncryptedHeader,
) -> Result<DecryptedHeader, RatchetError> {
    let blob = &enc.0;
    if blob.len() < 12 {
        return Err(RatchetError::HeaderDecryptionFailed);
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&blob[..12]);
    let nonce = AeadNonce(nonce_bytes);
    let pt = decrypt(hk, &nonce, &blob[12..], b"ZR-header")
        .map_err(|_| RatchetError::HeaderDecryptionFailed)?;
    DecryptedHeader::from_bytes(&pt).ok_or(RatchetError::HeaderDecryptionFailed)
}
