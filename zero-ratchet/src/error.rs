//! Ratchet error types.

use thiserror::Error;

/// ZR ratchet errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RatchetError {
    /// Message encryption failed.
    #[error("Message encryption failed")]
    EncryptionFailed,

    /// Message decryption failed — tampered or wrong key.
    #[error("Message decryption failed")]
    DecryptionFailed,

    /// Header decryption failed.
    #[error("Header decryption failed")]
    HeaderDecryptionFailed,

    /// Message key not found in skipped-key cache.
    #[error("Unknown message: counter={counter}, no cached key")]
    UnknownMessageKey {
        /// The counter of the unknown message.
        counter: u32,
    },

    /// Too many skipped messages — potential DoS.
    #[error("Too many skipped messages: {skipped} > {max}")]
    TooManySkippedKeys {
        /// Number of keys skipped.
        skipped: usize,
        /// Maximum allowed skip count.
        max: usize,
    },

    /// DH ratchet step failed.
    #[error("DH ratchet failed")]
    DhFailed,

    /// KDF operation failed.
    #[error("KDF failed")]
    KdfError,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<zero_crypto::CryptoError> for RatchetError {
    fn from(_e: zero_crypto::CryptoError) -> Self {
        RatchetError::DecryptionFailed
    }
}
