//! ChaCha20-Poly1305 authenticated encryption (AEAD).

use crate::error::CryptoError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const AEAD_KEY_SIZE: usize = 32;
pub const AEAD_NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey(pub [u8; AEAD_KEY_SIZE]);

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AeadKey([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadNonce(pub [u8; AEAD_NONCE_SIZE]);

impl AeadNonce {
    pub fn random() -> Self {
        let mut bytes = [0u8; AEAD_NONCE_SIZE];
        OsRng.fill_bytes(&mut bytes);
        AeadNonce(bytes)
    }

    pub fn increment(&self) -> Self {
        let mut nonce = self.0;
        for i in 0..12 {
            nonce[i] = nonce[i].wrapping_add(1);
            if nonce[i] != 0 { break; }
        }
        AeadNonce(nonce)
    }
}

pub fn encrypt(
    key: &AeadKey,
    nonce: &AeadNonce,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let n = Nonce::from_slice(&nonce.0);
    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };
    cipher
        .encrypt(n, payload)
        .map_err(|_| CryptoError::EncryptionFailed)
}

pub fn decrypt(
    key: &AeadKey,
    nonce: &AeadNonce,
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < TAG_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let n = Nonce::from_slice(&nonce.0);
    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };
    cipher
        .decrypt(n, payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}
