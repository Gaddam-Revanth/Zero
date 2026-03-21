//! ZR Session Persistence.
//!
//! Persists ZR [`RatchetSession`] state to an encrypted local file so that
//! conversations survive app restarts. (§14.2)
//!
//! # Encryption
//! The session bytes are AEAD-encrypted using a key derived from the user's
//! master passphrase via Argon2id. The nonce is stored alongside the ciphertext.

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use zero_ratchet::RatchetSession;
use zero_identity::bundle::OwnedKeyBundle;
use zero_crypto::aead::{encrypt, decrypt, AeadKey, AeadNonce};
use crate::error::ZeroError;

/// Derives a 32-byte storage key from a passphrase using Argon2id.
fn derive_storage_key(passphrase: &[u8]) -> Result<AeadKey, ZeroError> {
    use argon2::{Argon2, Algorithm, Version, Params};
    
    let mut key = [0u8; 32];
    let salt = b"ZERO-ZR-storage-salt-v1"; // In production: use per-user salt stored in config
    
    let params = Params::new(15360, 2, 1, None).map_err(|e| ZeroError::Custom(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    argon2.hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| ZeroError::Custom(format!("Argon2 error: {}", e)))?;
        
    Ok(AeadKey(key))
}

/// Serialized, encrypted session blob stored on disk.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedSession {
    /// Random 12-byte nonce.
    nonce: [u8; 12],
    /// AEAD ciphertext of the CBOR-encoded RatchetSession.
    ciphertext: Vec<u8>,
}

/// Save a `RatchetSession` to `path`, encrypted with the given passphrase.
pub fn save_session(
    session: &RatchetSession,
    path: &Path,
    passphrase: &[u8],
) -> Result<(), ZeroError> {
    let plaintext = zero_crypto::cbor::to_vec(session)
        .map_err(|e| ZeroError::Custom(format!("Serialize: {}", e)))?;
    let key = derive_storage_key(passphrase)?;
    let nonce = AeadNonce::random();
    let ciphertext = encrypt(&key, &nonce, &plaintext, b"ZR-session-v1")
        .map_err(|e| ZeroError::Custom(format!("Encrypt: {:?}", e)))?;

    let blob = EncryptedSession { nonce: nonce.0, ciphertext };
    let bytes = zero_crypto::cbor::to_vec(&blob)
        .map_err(|e| ZeroError::Custom(format!("Outer serialize: {}", e)))?;

    std::fs::write(path, bytes)
        .map_err(|e| ZeroError::Custom(format!("Write session: {}", e)))?;

    tracing::info!("Saved ZR session to {}", path.display());
    Ok(())
}

/// Load and decrypt a `RatchetSession` from `path`.
pub fn load_session(path: &Path, passphrase: &[u8]) -> Result<RatchetSession, ZeroError> {
    let bytes = std::fs::read(path)
        .map_err(|e| ZeroError::Custom(format!("Read session: {}", e)))?;
    let blob: EncryptedSession = zero_crypto::cbor::from_slice(&bytes)
        .map_err(|e| ZeroError::Custom(format!("Outer deserialize: {}", e)))?;

    let key = derive_storage_key(passphrase)?;
    let nonce = AeadNonce(blob.nonce);
    let plaintext = decrypt(&key, &nonce, &blob.ciphertext, b"ZR-session-v1")
        .map_err(|e| ZeroError::Custom(format!("Decrypt session: {:?}", e)))?;

    zero_crypto::cbor::from_slice(&plaintext)
        .map_err(|e| ZeroError::Custom(format!("Deserialize session: {}", e)))
}
/// Save an `OwnedKeyBundle` to `path`, encrypted with the given passphrase.
pub fn save_identity(
    bundle: &OwnedKeyBundle,
    path: &Path,
    passphrase: &[u8],
) -> Result<(), ZeroError> {
    let plaintext = zero_crypto::cbor::to_vec(bundle)
        .map_err(|e| ZeroError::Custom(format!("Serialize: {}", e)))?;
    let key = derive_storage_key(passphrase)?;
    let nonce = AeadNonce::random();
    let ciphertext = encrypt(&key, &nonce, &plaintext, b"ZERO-identity-v1")
        .map_err(|e| ZeroError::Custom(format!("Encrypt: {:?}", e)))?;

    let blob = EncryptedSession { nonce: nonce.0, ciphertext };
    let bytes = zero_crypto::cbor::to_vec(&blob)
        .map_err(|e| ZeroError::Custom(format!("Outer serialize: {}", e)))?;

    std::fs::write(path, bytes)
        .map_err(|e| ZeroError::Custom(format!("Write identity: {}", e)))?;

    tracing::info!("Saved ZERO identity to {}", path.display());
    Ok(())
}

/// Load and decrypt an `OwnedKeyBundle` from `path`.
pub fn load_identity(path: &Path, passphrase: &[u8]) -> Result<OwnedKeyBundle, ZeroError> {
    let bytes = std::fs::read(path)
        .map_err(|e| ZeroError::Custom(format!("Read identity: {}", e)))?;
    let blob: EncryptedSession = zero_crypto::cbor::from_slice(&bytes)
        .map_err(|e| ZeroError::Custom(format!("Outer deserialize: {}", e)))?;

    let key = derive_storage_key(passphrase)?;
    let nonce = AeadNonce(blob.nonce);
    let plaintext = decrypt(&key, &nonce, &blob.ciphertext, b"ZERO-identity-v1")
        .map_err(|e| ZeroError::Custom(format!("Decrypt identity: {:?}", e)))?;

    zero_crypto::cbor::from_slice(&plaintext)
        .map_err(|e| ZeroError::Custom(format!("Deserialize identity: {}", e)))
}

/// Returns the session file path for a given contact ID within the storage directory.
pub fn session_path(storage_dir: &Path, contact_id: &str) -> PathBuf {
    // Sanitize the contact ID for use as a filename
    let safe_name: String = contact_id.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    storage_dir.join(format!("zr_{}.session", safe_name))
}
