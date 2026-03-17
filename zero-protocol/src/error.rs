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
    /// Generic/Custom error message.
    #[error("Error: {0}")]
    Custom(String),
}

impl From<zero_identity::IdentityError> for ZeroError {
    fn from(e: zero_identity::IdentityError) -> Self {
        ZeroError::IdentityError(e.to_string())
    }
}

impl From<zero_transport::error::TransportError> for ZeroError {
    fn from(_e: zero_transport::error::TransportError) -> Self {
        ZeroError::ConnectionFailed
    }
}

impl From<zero_ratchet::error::RatchetError> for ZeroError {
    fn from(e: zero_ratchet::error::RatchetError) -> Self {
        ZeroError::Custom(e.to_string())
    }
}
