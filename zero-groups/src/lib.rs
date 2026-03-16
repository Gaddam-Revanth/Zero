//! # zero-groups
//!
//! ZGP — ZERO Group Protocol.
//! O(1) group messaging inspired by Matrix Megolm.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod error;
pub mod group;
pub mod member;

pub use error::GroupError;
pub use group::GroupState;
