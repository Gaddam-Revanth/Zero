//! # ZERO Protocol
//!
//! The top-level crate orchestrating all ZERO components.
//! Exposes a stable UniFFI interface for Android/Kotlin integration.

#![deny(missing_docs)]

pub mod api;
pub mod error;
pub mod discovery;
pub mod zft;
pub mod zav;
pub mod nat;
pub mod persistence;

pub use api::{init_logger, ZeroNode, ZeroContact};
pub use error::ZeroError;

// Initialize UniFFI macros
uniffi::include_scaffolding!("zero");
