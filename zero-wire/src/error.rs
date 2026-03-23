//! Wire framing errors.

use thiserror::Error;

/// Errors produced when parsing/validating wire packets.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Packet magic mismatch.
    #[error("Invalid magic")]
    InvalidMagic,
    /// Unsupported or malformed version.
    #[error("Unsupported version {0:?}")]
    UnsupportedVersion(super::types::Version),
    /// Header length mismatch.
    #[error("Invalid header length: expected {expected}, got {got}")]
    InvalidHeaderLen {
        /// Expected header length.
        expected: u16,
        /// Actual header length.
        got: u16,
    },
    /// Body length is too large.
    #[error("Body too large: {got} > {max}")]
    BodyTooLarge {
        /// Actual body length.
        got: u32,
        /// Maximum allowed.
        max: u32,
    },
    /// Packet buffer is too short.
    #[error("Truncated packet")]
    Truncated,
    /// Reserved bits were set.
    #[error("Reserved bits set in flags")]
    ReservedBitsSet,
}
