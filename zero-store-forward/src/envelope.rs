//! Sealed sender envelope structure (ZSF).

use serde::{Deserialize, Serialize};
use zero_crypto::{
    aead::{decrypt, encrypt, AeadKey, AeadNonce},
    dh::{x25519_diffie_hellman, X25519Keypair, X25519PublicKey, X25519SecretKey},
    kdf::{hkdf_expand, hkdf_extract, KdfContext},
};
use zero_identity::zeroid::ZeroId;
use crate::error::ZsfError;

/// The outer wrapper that the ZSF relay sees.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZsfEnvelope {
    /// Recipient's public NodeID (routing).
    pub recipient_node_id: [u8; 32],
    /// Outer ephemeral key (for the relay to decrypt the time-to-live).
    pub relay_ephemeral_pub: [u8; 32],
    /// Proof of work (Hashcash) to prevent spam.
    pub proof_of_work: u64,
    /// Outer ciphertext (opaque to relay except TTL).
    pub outer_ciphertext: Vec<u8>,
}

/// The outer decrypted payload (visible to relay if it holds the intended relay private key).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayPayload {
    /// Time-to-live in seconds.
    pub ttl: u32,
    /// The inner ciphertext (opaque to relay, only recipient can read).
    pub inner_ciphertext: Vec<u8>,
}

/// The completely decrypted inner envelope (only visible to recipient).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedSenderInner {
    /// The ACTUAL sender's ZERO ID.
    pub sender_id: ZeroId,
    /// Sender's ephemeral key for this envelope's encryption.
    pub sender_ephemeral_pub: [u8; 32],
    /// The actual ZKX or ZR payload.
    pub payload: Vec<u8>,
}

impl ZsfEnvelope {
    /// Build an envelope for a recipient.
    pub fn build(
        recipient_idk_pub: &X25519PublicKey,
        recipient_node_id: [u8; 32],
        sender_id: &ZeroId,
        relay_pub: &X25519PublicKey, // Passed to relay outer
        payload: Vec<u8>,
    ) -> Result<Self, ZsfError> {
        // Inner encryption (for recipient)
        let sender_ephemeral = X25519Keypair::generate();
        let inner = SealedSenderInner {
            sender_id: sender_id.clone(),
            sender_ephemeral_pub: sender_ephemeral.public_key().0,
            payload,
        };
        let inner_pt = serde_cbor::to_vec(&inner)
            .map_err(|_| ZsfError::DecryptionFailed)?;

        let shared_inner = sender_ephemeral.diffie_hellman(recipient_idk_pub);
        let inner_key = derive_envelope_key(&shared_inner.0, &sender_ephemeral.public_key().0)?;
        let nonce = AeadNonce::random();
        let ct = encrypt(&inner_key, &nonce, &inner_pt, b"ZSF-inner")
            .map_err(|_| ZsfError::DecryptionFailed)?;

        // Ciphertext layout for recipient:
        // [ 12 bytes nonce ][ 32 bytes sender_ephemeral_pub ][ remaining AEAD ciphertext... ]
        let mut inner_ct_blob = Vec::with_capacity(12 + 32 + ct.len());
        inner_ct_blob.extend_from_slice(&nonce.0);
        inner_ct_blob.extend_from_slice(&sender_ephemeral.public_key().0);
        inner_ct_blob.extend_from_slice(&ct);

        let outer = RelayPayload {
            ttl: 7 * 24 * 3600, // 7 days Max
            inner_ciphertext: inner_ct_blob,
        };

        // Outer encryption (for relay). The relay uses its static X25519 secret key to derive
        // the same shared secret and decrypt `outer_ciphertext` to read only the TTL and
        // `inner_ciphertext`, never the sender identity or payload.
        let relay_ephemeral = X25519Keypair::generate();
        let relay_shared = relay_ephemeral
            .diffie_hellman(relay_pub);
        let relay_key = derive_envelope_key(&relay_shared.0, &relay_ephemeral.public_key().0)?;
        let relay_nonce = AeadNonce::random();
        let outer_pt = serde_cbor::to_vec(&outer)
            .map_err(|_| ZsfError::DecryptionFailed)?;
        let outer_ct = encrypt(&relay_key, &relay_nonce, &outer_pt, b"ZSF-outer")
            .map_err(|_| ZsfError::DecryptionFailed)?;

        let mut outer_blob = Vec::with_capacity(12 + outer_ct.len());
        outer_blob.extend_from_slice(&relay_nonce.0);
        outer_blob.extend_from_slice(&outer_ct);

        Ok(Self {
            recipient_node_id,
            relay_ephemeral_pub: relay_ephemeral.public_key().0,
            proof_of_work: crate::pow::ProofOfWork::generate(&recipient_node_id),
            outer_ciphertext: outer_blob,
        })
    }
}

/// Outer envelope decryption by the relay.
///
/// The relay learns only:
/// - TTL
/// - An opaque `inner_ciphertext` blob for the recipient (it cannot decrypt it)
///
/// This function also verifies the anti-spam proof-of-work.
pub fn decrypt_outer_for_relay(
    relay_sk: &X25519SecretKey,
    env: &ZsfEnvelope,
) -> Result<RelayPayload, ZsfError> {
    if !crate::pow::verify_pow(&env.recipient_node_id, env.proof_of_work) {
        return Err(ZsfError::InvalidPow);
    }

    // outer_ciphertext framing: [nonce 12][ct...]
    if env.outer_ciphertext.len() < 12 {
        return Err(ZsfError::OuterDecryptionFailed);
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&env.outer_ciphertext[..12]);
    let nonce = AeadNonce(nonce_bytes);

    // Derive relay key via X25519(relay_sk, relay_ephemeral_pub)
    let relay_ephemeral_pub = X25519PublicKey(env.relay_ephemeral_pub);
    let shared = x25519_diffie_hellman(relay_sk, &relay_ephemeral_pub)
        .map_err(|_| ZsfError::OuterDecryptionFailed)?;
    let relay_key = derive_envelope_key(&shared.0, &env.relay_ephemeral_pub)?;

    let pt = decrypt(&relay_key, &nonce, &env.outer_ciphertext[12..], b"ZSF-outer")
        .map_err(|_| ZsfError::OuterDecryptionFailed)?;

    serde_cbor::from_slice(&pt).map_err(|e| ZsfError::SerializationError(e.to_string()))
}

/// Inner envelope decryption by the recipient.
pub fn decrypt_inner(
    recipient_idk: &X25519SecretKey,
    inner_ct: &[u8],
) -> Result<SealedSenderInner, ZsfError> {
    if inner_ct.len() < 12 { return Err(ZsfError::DecryptionFailed); }

    // Read nonce
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&inner_ct[..12]);
    let nonce = AeadNonce(nonce_bytes);

    // To decrypt we unfortunately need the sender's ephemeral pubkey.
    // In a full sealed sender, the ephemeral pubkey is outside the inner ciphertext.
    // Here we assume it's prepended or sent out of band (omitted for brevity).
    // Let's assume the payload format is: [nonce 12][ephemeral pub 32][ct...]
    if inner_ct.len() < 44 { return Err(ZsfError::DecryptionFailed); }
    let mut ephem_bytes = [0u8; 32];
    ephem_bytes.copy_from_slice(&inner_ct[12..44]);
    let sender_ephemeral_pub = X25519PublicKey(ephem_bytes);

    let shared = x25519_diffie_hellman(recipient_idk, &sender_ephemeral_pub)
        .map_err(|_| ZsfError::DecryptionFailed)?;
    let inner_key = derive_envelope_key(&shared.0, &ephem_bytes)?;

    let pt = decrypt(&inner_key, &nonce, &inner_ct[44..], b"ZSF-inner")
        .map_err(|_| ZsfError::DecryptionFailed)?;

    serde_cbor::from_slice(&pt).map_err(|_| ZsfError::DecryptionFailed)
}

fn derive_envelope_key(shared: &[u8], ephem: &[u8]) -> Result<AeadKey, ZsfError> {
    let prk = hkdf_extract(ephem, shared);
    let key = hkdf_expand(&prk, KdfContext::ZsfEnvelopeKey, 32).map_err(|_| ZsfError::DecryptionFailed)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key);
    Ok(AeadKey(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_identity::{keypair::ZeroKeypair, zeroid::ZeroId};

    #[test]
    fn test_zsf_envelope_outer_inner_roundtrip() {
        let relay_kp = X25519Keypair::generate();
        let recipient_kp = X25519Keypair::generate();

        let sender_kp = ZeroKeypair::generate().unwrap();
        let sender_id = ZeroId::from_keypair(&sender_kp, [0x42; 4]);

        let recipient_node_id = [0xAB; 32];
        let payload = b"hello offline".to_vec();

        let env = ZsfEnvelope::build(
            &recipient_kp.public_key(),
            recipient_node_id,
            &sender_id,
            &relay_kp.public_key(),
            payload.clone(),
        )
        .expect("envelope build should succeed");

        // Relay decrypts outer
        let outer = decrypt_outer_for_relay(&relay_kp.secret_key(), &env)
            .expect("relay outer decrypt should succeed");
        assert_eq!(outer.ttl, 7 * 24 * 3600);
        assert!(!outer.inner_ciphertext.is_empty());

        // Recipient decrypts inner
        let inner = decrypt_inner(&recipient_kp.secret_key(), &outer.inner_ciphertext)
            .expect("recipient inner decrypt should succeed");
        assert_eq!(inner.sender_id, sender_id);
        assert_eq!(inner.payload, payload);
    }

    #[test]
    fn test_zsf_invalid_pow_rejected() {
        let relay_kp = X25519Keypair::generate();
        let recipient_kp = X25519Keypair::generate();

        let sender_kp = ZeroKeypair::generate().unwrap();
        let sender_id = ZeroId::from_keypair(&sender_kp, [0x42; 4]);

        let recipient_node_id = [0x11; 32];
        let mut env = ZsfEnvelope::build(
            &recipient_kp.public_key(),
            recipient_node_id,
            &sender_id,
            &relay_kp.public_key(),
            b"msg".to_vec(),
        )
        .unwrap();

        env.proof_of_work ^= 1;
        let err = decrypt_outer_for_relay(&relay_kp.secret_key(), &env).unwrap_err();
        assert!(matches!(err, ZsfError::InvalidPow));
    }

    #[test]
    fn test_zsf_outer_tamper_fails() {
        let relay_kp = X25519Keypair::generate();
        let recipient_kp = X25519Keypair::generate();

        let sender_kp = ZeroKeypair::generate().unwrap();
        let sender_id = ZeroId::from_keypair(&sender_kp, [0x42; 4]);

        let recipient_node_id = [0x22; 32];
        let mut env = ZsfEnvelope::build(
            &recipient_kp.public_key(),
            recipient_node_id,
            &sender_id,
            &relay_kp.public_key(),
            b"msg".to_vec(),
        )
        .unwrap();

        let idx = env.outer_ciphertext.len() - 1;
        env.outer_ciphertext[idx] ^= 0x80;
        let err = decrypt_outer_for_relay(&relay_kp.secret_key(), &env).unwrap_err();
        assert!(matches!(
            err,
            ZsfError::OuterDecryptionFailed | ZsfError::SerializationError(_)
        ));
    }

    #[test]
    fn test_zsf_wrong_relay_key_fails() {
        let relay_kp = X25519Keypair::generate();
        let wrong_relay_kp = X25519Keypair::generate();
        let recipient_kp = X25519Keypair::generate();

        let sender_kp = ZeroKeypair::generate().unwrap();
        let sender_id = ZeroId::from_keypair(&sender_kp, [0x42; 4]);

        let recipient_node_id = [0x33; 32];
        let env = ZsfEnvelope::build(
            &recipient_kp.public_key(),
            recipient_node_id,
            &sender_id,
            &relay_kp.public_key(),
            b"msg".to_vec(),
        )
        .unwrap();

        let err = decrypt_outer_for_relay(&wrong_relay_kp.secret_key(), &env).unwrap_err();
        assert!(matches!(
            err,
            ZsfError::OuterDecryptionFailed | ZsfError::SerializationError(_)
        ));
    }
}
