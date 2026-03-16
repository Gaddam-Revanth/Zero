//! # zero-transport
//!
//! Transport layer for ZERO Protocol.
//! Fallback hierarchy:
//! 1. QUIC over UDP (primary, port 44300)
//! 2. QUIC over UDP (hole-punched)
//! 3. TCP + TLS 1.3
//! 4. TCP Relay

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod error;
pub mod nat;
pub mod quic;
pub mod tcp_tls;

pub use error::TransportError;
pub use quic::{QuicTransport, StreamType};
