//! # zero-store-forward
//!
//! ZSF — ZERO Store and Forward. Offline delivery protocol.
//!
//! Features:
//! - **Sealed Sender**: Relay cannot see the sender's NodeID.
//! - **Proof of Work**: Hashcash-based anti-spam per envelope.
//! - **Recipient Anonymity**: Envelopes are fetched by NodeID, but inner contents are encrypted.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod envelope;
pub mod error;
pub mod pow;

pub use envelope::{decrypt_outer_for_relay, ZsfEnvelope, SealedSenderInner};
pub use error::ZsfError;
pub use pow::{ProofOfWork, verify_pow};
