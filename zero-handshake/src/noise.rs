//! Noise XX handshake — mutual authentication channel for ZKX.
//!
//! Pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2b`
//! Provides: mutual authentication, identity hiding from passive observers.
//!
//! Message flow:
//!   → msg1: e                          (Alice sends ephemeral)
//!   ← msg2: e, ee, s, es              (Bob sends ephemeral + static, DH)
//!   → msg3: s, se, payload            (Alice sends static, DH, initial payload)

use crate::error::HandshakeError;
use zero_crypto::{
    aead::{decrypt, encrypt, AeadKey, AeadNonce},
    dh::{X25519Keypair, X25519PublicKey},
    hash::{blake2b_256, blake2b_256_multi},
    kdf::{hkdf, hkdf_extract, hkdf_expand, KdfContext},
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// R2: Structured Handshake Prologue for Downgrade Resistance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakePrologue {
    /// Protocol name (e.g., "ZERO-Protocol").
    pub protocol: String,
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Feature flags (e.g., bit 0 = PQ enabled).
    pub flags: u16,
}

impl HandshakePrologue {
    /// ZERO Protocol v1.0 default prologue.
    pub fn v1_0(flags: u16) -> Self {
        Self {
            protocol: "ZERO-Protocol".to_string(),
            major: 1,
            minor: 0,
            flags,
        }
    }

    /// Encode to bytes for Noise mix_hash.
    pub fn encode(&self) -> Vec<u8> {
        // Use CBOR or simple binary packing. We'll use CBOR for consistency with ZERO wire.
        zero_crypto::cbor::to_vec(self).unwrap_or_default()
    }
}

/// Noise protocol name — embedded in the prologue.
pub const NOISE_PROTOCOL_NAME: &[u8] = b"Noise_XX_25519_ChaChaPoly_BLAKE2b";

/// Maximum Noise message size (64 KiB).
pub const NOISE_MAX_MESSAGE: usize = 65535;

/// Role in the Noise handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum NoiseRole {
    /// Initiator (Alice — sends first message).
    Initiator,
    /// Responder (Bob — responds to first message).
    Responder,
}

/// Noise handshake symmetric state (ck + h).
#[derive(Zeroize, ZeroizeOnDrop)]
struct SymmetricState {
    /// Chaining key — updated via HKDF after each DH.
    ck: [u8; 32],
    /// Transcript hash — covers all sent/received bytes.
    h: [u8; 32],
    /// Current encryption key (k).
    k: Option<[u8; 32]>,
    /// Nonce counter for AEAD.
    n: u64,
}

impl SymmetricState {
    fn new(protocol_name: &[u8]) -> Self {
        let h = if protocol_name.len() <= 32 {
            let mut arr = [0u8; 32];
            arr[..protocol_name.len()].copy_from_slice(protocol_name);
            arr
        } else {
            blake2b_256(protocol_name)
        };
        let mut ck = [0u8; 32];
        ck.copy_from_slice(&h);
        Self { ck, h, k: None, n: 0 }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = blake2b_256_multi(&[&self.h, data]);
    }

    fn mix_key(&mut self, input_key_material: &[u8]) -> Result<(), HandshakeError> {
        let prk = hkdf_extract(&self.ck, input_key_material);
        let ck = hkdf_expand(&prk, KdfContext::Custom("ZERO-Noise-ck"), 32)
            .map_err(|e| HandshakeError::NoiseError(e.to_string()))?;
        let k  = hkdf_expand(&prk, KdfContext::Custom("ZERO-Noise-k"),  32)
            .map_err(|e| HandshakeError::NoiseError(e.to_string()))?;
        self.ck.copy_from_slice(&ck);
        let mut k_arr = [0u8; 32];
        k_arr.copy_from_slice(&k);
        self.k = Some(k_arr);
        self.n = 0;
        Ok(())
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if let Some(k) = self.k {
            let key = AeadKey(k);
            let nonce = nonce_from_counter(self.n);
            let ct = encrypt(&key, &nonce, plaintext, &self.h)
                .map_err(|_| HandshakeError::NoiseError("AEAD encrypt failed".into()))?;
            self.mix_hash(&ct);
            self.n += 1;
            Ok(ct)
        } else {
            self.mix_hash(plaintext);
            Ok(plaintext.to_vec())
        }
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if let Some(k) = self.k {
            let key = AeadKey(k);
            let nonce = nonce_from_counter(self.n);
            let pt = decrypt(&key, &nonce, ciphertext, &self.h)
                .map_err(|_| HandshakeError::AuthenticationFailed)?;
            self.mix_hash(ciphertext);
            self.n += 1;
            Ok(pt)
        } else {
            self.mix_hash(ciphertext);
            Ok(ciphertext.to_vec())
        }
    }

    fn split(&self) -> Result<(AeadKey, AeadKey), HandshakeError> {
        let k1 = hkdf(&self.ck, &[], KdfContext::Custom("ZERO-Noise-split-c1"), 32)
            .map_err(|e| HandshakeError::NoiseError(e.to_string()))?;
        let k2 = hkdf(&self.ck, &[], KdfContext::Custom("ZERO-Noise-split-c2"), 32)
            .map_err(|e| HandshakeError::NoiseError(e.to_string()))?;
        let mut k1_arr = [0u8; 32];
        let mut k2_arr = [0u8; 32];
        k1_arr.copy_from_slice(&k1);
        k2_arr.copy_from_slice(&k2);
        Ok((AeadKey(k1_arr), AeadKey(k2_arr)))
    }
}

fn nonce_from_counter(n: u64) -> AeadNonce {
    let mut arr = [0u8; 12];
    arr[0..8].copy_from_slice(&n.to_le_bytes());
    AeadNonce(arr)
}

/// The output of a completed Noise XX handshake.
#[derive(Debug)]
pub struct NoiseOutput {
    /// Sending cipher key.
    pub send_key: AeadKey,
    /// Receiving cipher key.
    pub recv_key: AeadKey,
    /// Handshake hash — used as transcript binding in ZKX.
    pub handshake_hash: [u8; 32],
    /// The remote party's static (identity) public key.
    pub remote_static_key: X25519PublicKey,
}

/// Noise XX handshake state machine.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NoiseHandshakeState {
    role: NoiseRole,
    sym: SymmetricState,
    /// Local static keypair (X25519, derived from IDK).
    local_static: X25519Keypair,
    /// Local ephemeral keypair (fresh per session).
    local_ephemeral: X25519Keypair,
    /// Remote ephemeral public key (learned during handshake).
    #[zeroize(skip)]
    remote_ephemeral: Option<X25519PublicKey>,
    /// Remote static public key (learned during handshake).
    #[zeroize(skip)]
    remote_static: Option<X25519PublicKey>,
    /// Which message step we are on (0, 1, 2).
    step: usize,
}

impl NoiseHandshakeState {
    /// Create a new Noise XX handshake state with a structured prologue and a provided ephemeral key.
    pub fn new(
        role: NoiseRole,
        local_static: X25519Keypair,
        local_ephemeral: X25519Keypair,
        prologue: &HandshakePrologue,
    ) -> Self {
        let mut sym = SymmetricState::new(NOISE_PROTOCOL_NAME);
        sym.mix_hash(&prologue.encode());
        Self {
            role,
            sym,
            local_static: local_static.clone(),
            local_ephemeral: local_ephemeral.clone(),
            remote_ephemeral: None,
            remote_static: None,
            step: 0,
        }
    }

    /// **Initiator**: Produce message 1 → `e`
    pub fn write_message1(&mut self) -> Result<Vec<u8>, HandshakeError> {
        if self.role != NoiseRole::Initiator || self.step != 0 {
            return Err(HandshakeError::NoiseError("Invalid state for write_message1".into()));
        }
        let e_pub = self.local_ephemeral.public_key();
        self.sym.mix_hash(&e_pub.0);
        let payload = self.sym.encrypt_and_hash(&[])?;
        self.step = 1;
        let mut msg = e_pub.0.to_vec();
        msg.extend_from_slice(&payload);
        Ok(msg)
    }

    /// **Responder**: Process message 1, produce message 2 → `e, ee, s, es`
    pub fn read_message1_write_message2(
        &mut self,
        msg1: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        if self.role != NoiseRole::Responder || self.step != 0 {
            return Err(HandshakeError::NoiseError("Invalid state for read_message1_write_message2".into()));
        }
        if msg1.len() < 32 {
            return Err(HandshakeError::MessageLength { expected: 32, got: msg1.len() });
        }
        // Read remote ephemeral
        let mut re_bytes = [0u8; 32];
        re_bytes.copy_from_slice(&msg1[..32]);
        let re = X25519PublicKey(re_bytes);
        self.sym.mix_hash(&re.0);
        self.sym.decrypt_and_hash(&msg1[32..])?;
        self.remote_ephemeral = Some(re.clone());

        // Build response: e, ee, s, es
        let e_pub = self.local_ephemeral.public_key();
        self.sym.mix_hash(&e_pub.0);
        // ee
        let ee_shared = self.local_ephemeral.diffie_hellman(&re);
        self.sym.mix_key(&ee_shared.0)?;
        // s (encrypt our static key)
        let s_ct = self.sym.encrypt_and_hash(&self.local_static.public_key().0)?;
        // es
        let es_shared = self.local_static.diffie_hellman(&re);
        self.sym.mix_key(&es_shared.0)?;
        // payload
        let payload_ct = self.sym.encrypt_and_hash(&[])?;

        self.step = 1;
        let mut msg = e_pub.0.to_vec();
        msg.extend_from_slice(&s_ct);
        msg.extend_from_slice(&payload_ct);
        Ok(msg)
    }

    /// **Initiator**: Process message 2, produce message 3 → `s, se, payload`
    pub fn read_message2_write_message3(
        &mut self,
        msg2: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        if self.role != NoiseRole::Initiator || self.step != 1 {
            return Err(HandshakeError::NoiseError("Invalid state for read_message2_write_message3".into()));
        }
        let mut pos = 0;

        // Remote ephemeral
        if msg2.len() < 32 { return Err(HandshakeError::MessageLength { expected: 32, got: msg2.len() }); }
        let mut re_bytes = [0u8; 32];
        re_bytes.copy_from_slice(&msg2[pos..pos+32]);
        let re = X25519PublicKey(re_bytes);
        self.sym.mix_hash(&re.0);
        pos += 32;

        // ee
        let ee_shared = self.local_ephemeral.diffie_hellman(&re);
        self.sym.mix_key(&ee_shared.0)?;
        self.remote_ephemeral = Some(re.clone());

        // s (remote static, encrypted)
        let rs_ct_len = 32 + 16; // key + tag
        if msg2.len() < pos + rs_ct_len { return Err(HandshakeError::MessageLength { expected: pos+rs_ct_len, got: msg2.len() }); }
        let rs_pt = self.sym.decrypt_and_hash(&msg2[pos..pos+rs_ct_len])?;
        let mut rs_bytes = [0u8; 32];
        rs_bytes.copy_from_slice(&rs_pt);
        let rs = X25519PublicKey(rs_bytes);
        self.remote_static = Some(rs.clone());
        pos += rs_ct_len;

        // es
        let es_shared = self.local_ephemeral.diffie_hellman(&rs);
        self.sym.mix_key(&es_shared.0)?;

        // Decrypt payload
        self.sym.decrypt_and_hash(&msg2[pos..])?;

        // Now produce msg3: s, se
        let s_ct = self.sym.encrypt_and_hash(&self.local_static.public_key().0)?;
        // se
        let se_shared = self.local_static.diffie_hellman(&re);
        self.sym.mix_key(&se_shared.0)?;
        let payload_ct = self.sym.encrypt_and_hash(payload)?;

        self.step = 2;
        let mut msg = s_ct;
        msg.extend_from_slice(&payload_ct);
        Ok(msg)
    }

    /// **Responder**: Process message 3, complete handshake.
    pub fn read_message3(&mut self, msg3: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if self.role != NoiseRole::Responder || self.step != 1 {
            return Err(HandshakeError::NoiseError("Invalid state for read_message3".into()));
        }
        if self.remote_ephemeral.is_none() {
            return Err(HandshakeError::NoiseError("Missing remote ephemeral".into()));
        }

        // s (remote static, encrypted)
        let rs_ct_len = 32 + 16;
        if msg3.len() < rs_ct_len { return Err(HandshakeError::MessageLength { expected: rs_ct_len, got: msg3.len() }); }
        let rs_pt = self.sym.decrypt_and_hash(&msg3[..rs_ct_len])?;
        let mut rs_bytes = [0u8; 32];
        rs_bytes.copy_from_slice(&rs_pt);
        let rs = X25519PublicKey(rs_bytes);
        self.remote_static = Some(rs.clone());

        // se
        let se_shared = self.local_ephemeral.diffie_hellman(&rs);
        self.sym.mix_key(&se_shared.0)?;

        // payload
        let payload = self.sym.decrypt_and_hash(&msg3[rs_ct_len..])?;
        self.step = 2;
        Ok(payload)
    }

    /// Complete the handshake and obtain the session keys + transcript hash.
    pub fn finalize(self) -> Result<NoiseOutput, HandshakeError> {
        if self.step != 2 {
            return Err(HandshakeError::NoiseError("Handshake not complete".into()));
        }
        let (k1, k2) = self.sym.split()?;
        let (send_key, recv_key) = match self.role {
            NoiseRole::Initiator => (k1, k2),
            NoiseRole::Responder => (k2, k1),
        };
        let remote_static_key = self.remote_static.clone()
            .ok_or_else(|| HandshakeError::NoiseError("Missing remote static".into()))?;
        Ok(NoiseOutput {
            send_key,
            recv_key,
            handshake_hash: self.sym.h,
            remote_static_key,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_xx_full_handshake() {
        let alice_static = X25519Keypair::generate();
        let bob_static = X25519Keypair::generate();
        let prologue = HandshakePrologue::v1_0(0);

        let mut alice = NoiseHandshakeState::new(
            NoiseRole::Initiator, alice_static, X25519Keypair::generate(), &prologue,
        );
        let mut bob = NoiseHandshakeState::new(
            NoiseRole::Responder, bob_static, X25519Keypair::generate(), &prologue,
        );

        // Handshake
        let msg1 = alice.write_message1().unwrap();
        let msg2 = bob.read_message1_write_message2(&msg1).unwrap();
        let msg3 = alice.read_message2_write_message3(&msg2, b"ZKX payload").unwrap();
        let payload = bob.read_message3(&msg3).unwrap();

        assert_eq!(payload, b"ZKX payload");

        let alice_out = alice.finalize().unwrap();
        let bob_out = bob.finalize().unwrap();

        // Session keys must match
        assert_eq!(alice_out.send_key.0, bob_out.recv_key.0);
        assert_eq!(alice_out.recv_key.0, bob_out.send_key.0);
        // Both agree on transcript hash
        assert_eq!(alice_out.handshake_hash, bob_out.handshake_hash);
    }
}
