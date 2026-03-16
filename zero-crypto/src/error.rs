//! Error types for zero-crypto.

use thiserror::Error;

/// All cryptographic errors in ZERO Protocol.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD encryption failed (invalid key, nonce, or plaintext).
    #[error("AEAD encryption failed")]
    EncryptionFailed,

    /// AEAD decryption failed — message is corrupt or tampered.
    #[error("AEAD decryption failed: authentication tag mismatch")]
    DecryptionFailed,

    /// Ed25519 signature verification failed.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid key length provided.
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    /// ML-KEM encapsulation failed.
    #[error("ML-KEM encapsulation failed")]
    KemEncapsulationFailed,

    /// ML-KEM decapsulation failed.
    #[error("ML-KEM decapsulation failed")]
    KemDecapsulationFailed,

    /// HKDF expansion failed (output length too large).
    #[error("HKDF expansion failed")]
    HkdfError,

    /// Argon2id key derivation failed.
    #[error("Argon2id KDF error: {0}")]
    Argon2Error(String),

    /// Random number generation failed.
    #[error("RNG failure")]
    RngFailure,

    /// Invalid public key bytes.
    #[error("Invalid public key encoding")]
    InvalidPublicKey,

    /// Invalid signature bytes.
    #[error("Invalid signature encoding")]
    InvalidSignature,
}
