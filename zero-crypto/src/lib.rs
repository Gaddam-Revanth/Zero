//! # zero-crypto
//!
//! Cryptographic primitives for the ZERO Protocol.
//! No custom cryptography — only proven, peer-reviewed primitives.
//!
//! ## Primitive Set
//! - **Ed25519** (ed25519-dalek) — identity signatures
//! - **X25519** (x25519-dalek) — Diffie-Hellman key exchange
//! - **ML-KEM-768** (ml-kem, FIPS 203) — post-quantum KEM
//! - **ChaCha20-Poly1305** — authenticated encryption (AEAD)
//! - **BLAKE2b-512** — hashing
//! - **HKDF-BLAKE2b** — key derivation
//! - **Argon2id** — password-based KDF
//! - **Zeroize** — secure memory erasure
//!
//! # Safety
//! Internal functions use fixed-size arrays where possible to ensure compile-time length checks.
//! Complex types are zeroized on drop.

//#![deny(missing_docs)]
//#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod aead;
pub mod dh;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod sign;

pub use error::CryptoError;

/// Re-export key types used throughout the workspace
pub use aead::{decrypt, encrypt, AeadKey, AeadNonce, AEAD_KEY_SIZE, AEAD_NONCE_SIZE, TAG_SIZE};
pub use dh::{x25519_diffie_hellman, X25519PublicKey, X25519SecretKey, X25519Keypair};
pub use hash::{blake2b_256, blake2b_512, Blake2b256, Blake2b512};
pub use kdf::{argon2id_derive, hkdf, hkdf_expand, hkdf_extract, KdfContext};
pub use kem::{MlKem768Ciphertext, MlKem768DecapsKey, MlKem768EncapsKey, MlKem768SharedSecret, MlKem768Keypair, ml_kem_768_encapsulate, ml_kem_768_decapsulate};
pub use sign::{ed25519_sign, ed25519_verify, Ed25519PublicKey, Ed25519SecretKey, Ed25519Keypair, Ed25519Signature};
