//! # zero-wire
//!
//! Universal wire framing for ZERO Protocol:
//! - fixed universal header
//! - strict size limits
//! - deterministic AAD bytes
//! - replay token generation + cache
//!
//! This crate is intentionally transport-agnostic. QUIC/TCP relay layers should treat the
//! packet bytes produced here as the canonical on-the-wire form.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod aad;
pub mod error;
pub mod header;
pub mod replay;
pub mod types;

pub use aad::aad_bytes_v1;
pub use error::WireError;
pub use header::{Packet, PacketHeader};
pub use replay::{ReplayCache, ReplayToken};
pub use types::{PacketFlags, PacketType, Version};
