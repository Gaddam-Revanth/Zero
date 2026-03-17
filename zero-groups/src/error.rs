//! ZGP error types.

use thiserror::Error;

/// Group errors.
#[derive(Debug, Error)]
pub enum GroupError {
    /// Failed to decrypt message.
    #[error("Decryption failed")]
    DecryptionFailed,
    /// Invalid signature from member.
    #[error("Invalid signature")]
    InvalidSignature,
    /// Member not found.
    #[error("Member not found")]
    MemberNotFound,
    /// Not an admin.
    #[error("Action requires admin privileges")]
    NotAdmin,
    /// Crypto error.
    #[error("Crypto error: {0}")]
    CryptoError(String),
}
