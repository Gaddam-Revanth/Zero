//! Key Derivation Functions for ZERO Protocol.

use crate::error::CryptoError;
use argon2::{Argon2, Params as Argon2Params};
use hkdf::Hkdf;
use sha2::Sha256 as HkdfHash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfContext {
    ZkxMasterSecret,
    ZrRootChain,
    ZrSendChain,
    ZrRecvChain,
    ZrMessageKey,
    ZrHeaderKeySend,
    ZrHeaderKeyRecv,
    ZsfEnvelopeKey,
    ZgpSessionKey,
    DhtRecordKey,
    OnionHopKey,
    Custom(&'static str),
}

impl KdfContext {
    fn info_bytes(&self) -> &[u8] {
        match self {
            KdfContext::ZkxMasterSecret => b"ZERO-ZKX-v1-master-secret",
            KdfContext::ZrRootChain    => b"ZERO-ZR-v1-root-chain",
            KdfContext::ZrSendChain   => b"ZERO-ZR-v1-send-chain",
            KdfContext::ZrRecvChain   => b"ZERO-ZR-v1-recv-chain",
            KdfContext::ZrMessageKey  => b"ZERO-ZR-v1-message-key",
            KdfContext::ZrHeaderKeySend => b"ZERO-ZR-v1-header-key-send",
            KdfContext::ZrHeaderKeyRecv => b"ZERO-ZR-v1-header-key-recv",
            KdfContext::ZsfEnvelopeKey => b"ZERO-ZSF-v1-envelope-key",
            KdfContext::ZgpSessionKey  => b"ZERO-ZGP-v1-session-key",
            KdfContext::DhtRecordKey   => b"ZERO-ZDHT-v1-record-key",
            KdfContext::OnionHopKey    => b"ZERO-Onion-v1-hop-key",
            KdfContext::Custom(s)      => s.as_bytes(),
        }
    }
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let (prk, _) = Hkdf::<HkdfHash>::extract(Some(salt), ikm);
    // PRK for Sha256 is exactly 32 bytes
    prk.to_vec()
}

pub fn hkdf_expand(prk: &[u8], context: KdfContext, output_len: usize) -> Result<Vec<u8>, CryptoError> {
    let hkdf = Hkdf::<HkdfHash>::from_prk(prk)
        .map_err(|_| CryptoError::HkdfError)?;
    let mut okm = vec![0u8; output_len];
    hkdf.expand(context.info_bytes(), &mut okm)
        .map_err(|_| CryptoError::HkdfError)?;
    Ok(okm)
}

/// Convenience function for one-shot HKDF (extract + expand).
pub fn hkdf(salt: &[u8], ikm: &[u8], context: KdfContext, output_len: usize) -> Result<Vec<u8>, CryptoError> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, context, output_len)
}

pub fn argon2id_derive(
    passphrase: &[u8],
    salt: &[u8; 16],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let params = Argon2Params::new(
        64 * 1024,
        3,
        4,
        Some(output_len),
    )
    .map_err(|e| CryptoError::Argon2Error(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|e| CryptoError::Argon2Error(e.to_string()))?;

    Ok(output)
}

pub fn derive_aead_key(prk: &[u8], context: KdfContext) -> Result<[u8; 32], CryptoError> {
    let okm = hkdf_expand(prk, context, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    Ok(key)
}
