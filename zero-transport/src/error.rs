//! Transport errors.

use thiserror::Error;

/// Transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Connection failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    /// Stream error.
    #[error("Stream error: {0}")]
    StreamError(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// TLS error.
    #[error("TLS error: {0}")]
    TlsError(String),
}
