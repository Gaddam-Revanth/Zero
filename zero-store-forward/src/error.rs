//! ZSF error types.

use thiserror::Error;

/// ZSF errors.
#[derive(Debug, Error)]
pub enum ZsfError {
    /// Proof of work is invalid or missing.
    #[error("Invalid Proof of Work")]
    InvalidPow,
    /// Inner envelope decryption failed.
    #[error("Envelope decryption failed")]
    DecryptionFailed,
    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
    /// Outer envelope decryption failed.
    #[error("Outer envelope decryption failed")]
    OuterDecryptionFailed,
}
