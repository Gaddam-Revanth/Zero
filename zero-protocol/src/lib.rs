//! # ZERO Protocol
//!
//! The top-level crate orchestrating all ZERO components.
//! Exposes a stable UniFFI interface for Android/Kotlin integration.

#![deny(missing_docs)]
#![allow(clippy::empty_line_after_doc_comments)]

pub mod api;
pub mod discovery;
pub mod error;
pub mod nat;
pub mod persistence;
pub mod zav;
pub mod zft;

pub use api::{init_logger, ZeroContact, ZeroNode};
pub use error::ZeroError;

// Initialize UniFFI macros
uniffi::include_scaffolding!("zero");
