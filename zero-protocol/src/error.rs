//! Top-level ZERO Protocol Errors.

use thiserror::Error;

/// Public-facing errors.
#[derive(Debug, Error)]
pub enum ZeroError {
    /// Identity errors (e.g., bad ZERO ID string).
    #[error("Identity error: {0}")]
    IdentityError(String),
    /// Handshake/Auth errors.
    #[error("Handshake failed")]
    HandshakeFailed,
    /// Network connection errors.
    #[error("Connection failed")]
    ConnectionFailed,
    /// Invalid payload size/format.
    #[error("Invalid payload")]
    InvalidPayload,
}

impl From<zero_identity::IdentityError> for ZeroError {
    fn from(e: zero_identity::IdentityError) -> Self {
        ZeroError::IdentityError(e.to_string())
    }
}
