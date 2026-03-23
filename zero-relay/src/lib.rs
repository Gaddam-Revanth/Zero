//! # zero-relay
//!
//! TCP Relay Server implementation.
//! Used when peer-to-peer UDP hole punching fails.
//! Relays are blind — they only see sender/receiver NodeIDs, encrypted payloads, and sizes.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod error;
pub mod protocol;
pub mod server;

pub use error::RelayError;
pub use server::{RelayConfig, RelayServer};
