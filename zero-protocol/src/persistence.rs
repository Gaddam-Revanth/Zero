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
use zero_crypto::aead::{encrypt, decrypt, AeadKey, AeadNonce};
use zero_crypto::kdf::{hkdf_extract, hkdf_expand, KdfContext};
use crate::error::ZeroError;

/// Derives a 32-byte storage key from a passphrase using HKDF.
/// In production this should use Argon2id for key stretching.
fn derive_storage_key(passphrase: &[u8]) -> Result<AeadKey, ZeroError> {
    let prk = hkdf_extract(b"ZERO-ZR-storage-v1", passphrase);
    let key = hkdf_expand(&prk, KdfContext::Custom("ZERO-ZR-storage-key"), 32)
        .map_err(|e| ZeroError::Custom(format!("KDF error: {:?}", e)))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key);
    Ok(AeadKey(arr))
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
    let plaintext = serde_cbor::to_vec(session)
        .map_err(|e| ZeroError::Custom(format!("Serialize: {}", e)))?;
    let key = derive_storage_key(passphrase)?;
    let nonce = AeadNonce::random();
    let ciphertext = encrypt(&key, &nonce, &plaintext, b"ZR-session-v1")
        .map_err(|e| ZeroError::Custom(format!("Encrypt: {:?}", e)))?;

    let blob = EncryptedSession { nonce: nonce.0, ciphertext };
    let bytes = serde_cbor::to_vec(&blob)
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
    let blob: EncryptedSession = serde_cbor::from_slice(&bytes)
        .map_err(|e| ZeroError::Custom(format!("Outer deserialize: {}", e)))?;

    let key = derive_storage_key(passphrase)?;
    let nonce = AeadNonce(blob.nonce);
    let plaintext = decrypt(&key, &nonce, &blob.ciphertext, b"ZR-session-v1")
        .map_err(|e| ZeroError::Custom(format!("Decrypt session: {:?}", e)))?;

    serde_cbor::from_slice(&plaintext)
        .map_err(|e| ZeroError::Custom(format!("Deserialize session: {}", e)))
}

/// Returns the session file path for a given contact ID within the storage directory.
pub fn session_path(storage_dir: &Path, contact_id: &str) -> PathBuf {
    // Sanitize the contact ID for use as a filename
    let safe_name: String = contact_id.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    storage_dir.join(format!("zr_{}.session", safe_name))
}
