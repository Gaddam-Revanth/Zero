//! Error types for zero-identity.

use thiserror::Error;

/// Identity-layer errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// Invalid Base58Check encoding for a ZERO ID string.
    #[error("Invalid ZERO ID encoding: {0}")]
    InvalidEncoding(String),

    /// ZERO ID checksum mismatch — corrupted or mistyped ID.
    #[error("ZERO ID checksum mismatch")]
    ChecksumMismatch,

    /// The key bundle is missing required fields.
    #[error("Incomplete key bundle: missing {0}")]
    IncompleteBundle(&'static str),

    /// Signed prekey signature verification failed.
    #[error("Signed prekey signature invalid")]
    InvalidSpkSignature,

    /// No one-time prekeys remaining in bundle.
    #[error("No one-time prekeys available")]
    NoOpkAvailable,

    /// Cryptographic error from zero-crypto layer.
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<zero_crypto::CryptoError> for IdentityError {
    fn from(e: zero_crypto::CryptoError) -> Self {
        IdentityError::CryptoError(e.to_string())
    }
}
