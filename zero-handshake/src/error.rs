//! Handshake error types.

use thiserror::Error;

/// ZKX handshake errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Noise handshake state machine protocol violation.
    #[error("Noise protocol error: {0}")]
    NoiseError(String),

    /// X3DH key bundle verification failed.
    #[error("Key bundle verification failed: {0}")]
    BundleVerificationFailed(String),

    /// ML-KEM encapsulation/decapsulation failed.
    #[error("ML-KEM error: {0}")]
    KemError(String),

    /// HKDF derivation failed.
    #[error("Key derivation error")]
    KdfError,

    /// DH computation failed (low-order point).
    #[error("DH computation failed")]
    DhFailed,

    /// Received message has wrong length.
    #[error("Message length error: expected {expected}, got {got}")]
    MessageLength { 
        /// Expected length of the message.
        expected: usize, 
        /// Actual length of the message.
        got: usize 
    },

    /// Authentication failed — possible MITM.
    #[error("Authentication failed")]
    AuthenticationFailed,
}

impl From<zero_crypto::CryptoError> for HandshakeError {
    fn from(e: zero_crypto::CryptoError) -> Self {
        HandshakeError::NoiseError(e.to_string())
    }
}

impl From<zero_identity::IdentityError> for HandshakeError {
    fn from(e: zero_identity::IdentityError) -> Self {
        HandshakeError::BundleVerificationFailed(e.to_string())
    }
}
