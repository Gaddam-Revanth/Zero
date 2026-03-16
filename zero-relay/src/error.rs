//! Relay error types.

use thiserror::Error;

/// Relay errors.
#[derive(Debug, Error)]
pub enum RelayError {
    /// Relay route not found (recipient disconnected).
    #[error("Route not found for destination")]
    RouteNotFound,
    /// Connection limit exceeded.
    #[error("Too many connections to relay")]
    LimitExceeded,
    /// Invalid relay protocol.
    #[error("Invalid protocol message")]
    InvalidProtocol,
}
