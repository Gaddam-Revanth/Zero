//! # zero-ratchet
//!
//! ZR — ZERO Ratchet. Double Ratchet Algorithm with header encryption.
//!
//! Improvements over the original Double Ratchet:
//! - **Header encryption**: hides ratchet public key and message counters from relay servers
//! - **BLAKE2b KDF chains**: faster than HMAC-SHA256 on 64-bit
//! - **PQ ratchet step**: optional ML-KEM-512 re-encapsulation every 1,000 messages
//!
//! ## Security Properties:
//! - Per-message forward secrecy (each message has unique key, deleted after use)
//! - Post-compromise security (heals after new DH exchange)
//! - Out-of-order delivery (up to 2,000 skipped keys cached, max 7 days)

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod error;
pub mod header;
pub mod skipped_keys;
pub mod state;

pub use error::RatchetError;
pub use header::{DecryptedHeader, EncryptedHeader};
pub use state::{RatchetMessage, RatchetSession, SessionInit};
