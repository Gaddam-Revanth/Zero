//! DHT error types.

use thiserror::Error;

/// ZDHT errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DhtError {
    /// Node not found in routing table.
    #[error("Node not found")]
    NodeNotFound,
    /// Record not stored for this NodeID.
    #[error("Record not found for node {node_id}")]
    RecordNotFound { node_id: String },
    /// Network I/O error.
    #[error("Network error: {0}")]
    NetworkError(String),
    /// CBOR serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
    /// Onion routing failed.
    #[error("Onion routing failed: {0}")]
    OnionError(String),
    /// Record signature verification failed.
    #[error("Record signature invalid")]
    InvalidSignature,
    /// Crypto error.
    #[error("Crypto error: {0}")]
    CryptoError(String),
    /// Authentication failed (e.g., onion peel).
    #[error("Authentication failed")]
    AuthenticationFailed,
}
