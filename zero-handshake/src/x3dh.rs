//! X3DH + ML-KEM-768 hybrid key exchange for ZKX.

use crate::error::HandshakeError;
use serde::{Deserialize, Serialize};
use zero_crypto::{
    dh::{X25519Keypair, X25519PublicKey, X25519SecretKey, x25519_diffie_hellman},
    kem::{MlKem768EncapsKey, MlKem768Ciphertext, ml_kem_768_encapsulate, ml_kem_768_decapsulate},
    kdf::{hkdf, KdfContext},
    sign::{Ed25519PublicKey},
};
use zero_identity::{bundle::KeyBundle};
use zero_identity::keypair::ZeroKeypair;
use super::master_secret::{MasterSecret, MASTER_SECRET_SIZE};

/// The initial ZKX message Alice sends to Bob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkxInitMessage {
    /// Alice's ISK public key.
    pub alice_isk_pub: Ed25519PublicKey,
    /// Alice's IDK public key.
    pub alice_idk_pub: X25519PublicKey,
    /// Alice's ephemeral X25519 public key (EK).
    pub alice_ek_pub: X25519PublicKey,
    /// Index of Bob's SPK used.
    pub bob_spk_index: u32,
    /// Index of Bob's OPK used (None if no OPK available).
    pub bob_opk_index: Option<u32>,
    /// ML-KEM-768 ciphertext (Alice → Bob).
    pub kem_ciphertext: Vec<u8>,
    /// R4: Alice's confirmation tag.
    pub alice_tag: [u8; 32],
}

/// Bob's response to Alice's initiation (optional extension for confirmation).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkxConfirmMessage {
    /// R4: Bob's confirmation tag.
    pub bob_tag: [u8; 32],
}

/// ZKX initiator (Alice).
pub struct X3dhInitiator {
    /// Alice's ephemeral X25519 keypair for the initial handshake phase.
    ek: X25519Keypair,
}

impl X3dhInitiator {
    /// Create a new X3DH initiator with the provided ephemeral key.
    pub fn new(ek: X25519Keypair) -> Self {
        Self { ek }
    }

    /// Start the X3DH key agreement with Bob.
    pub fn initiate(
        &self,
        alice_keypair: &ZeroKeypair,
        bob_bundle: &KeyBundle,
    ) -> Result<(ZkxInitMessage, MasterSecret), HandshakeError> {
        self.initiate_with_noise_hash(alice_keypair, bob_bundle, None)
    }

    /// Start the X3DH key agreement with Bob, optionally binding to the Noise XX handshake hash.
    ///
    /// If `noise_hash` is provided, it is included in the input key material for the master secret
    /// derivation to cryptographically bind the Noise and X3DH phases.
    pub fn initiate_with_noise_hash(
        &self,
        alice_keypair: &ZeroKeypair,
        bob_bundle: &KeyBundle,
        noise_hash: Option<[u8; 32]>,
    ) -> Result<(ZkxInitMessage, MasterSecret), HandshakeError> {
        bob_bundle.verify().map_err(HandshakeError::from)?;

        let bob_spk_pub = X25519PublicKey(bob_bundle.spk.public_key.0);
        let bob_idk_pub = X25519PublicKey(bob_bundle.idk_pub.0);
        let alice_idk_sk = alice_keypair.idk.secret_key();
        let initiator_ek_sk = self.ek.secret_key();
        let pq_ek_bytes = bob_bundle.pq_isk_pub.clone();
        let bob_opk = bob_bundle.opk.clone();

        // Parallelize DH and KEM operations
        let (dh_results, kem_result) = rayon::join(
            || {
                let dh1 = x25519_diffie_hellman(&alice_idk_sk, &bob_spk_pub);
                let dh2 = x25519_diffie_hellman(&initiator_ek_sk, &bob_idk_pub);
                let dh3 = x25519_diffie_hellman(&initiator_ek_sk, &bob_spk_pub);
                
                let dh4 = if let Some(opk) = &bob_opk {
                    let opk_pub = X25519PublicKey(opk.public_key.0);
                    Some(x25519_diffie_hellman(&initiator_ek_sk, &opk_pub))
                } else {
                    None
                };

                (dh1, dh2, dh3, dh4)
            },
            || {
                let pq_ek = MlKem768EncapsKey(pq_ek_bytes);
                ml_kem_768_encapsulate(&pq_ek)
            }
        );

        let (dh1, dh2, dh3, dh4_opt) = dh_results;
        let dh1 = dh1.map_err(|_| HandshakeError::DhFailed)?;
        let dh2 = dh2.map_err(|_| HandshakeError::DhFailed)?;
        let dh3 = dh3.map_err(|_| HandshakeError::DhFailed)?;
        
        let (dh4_bytes, opk_index) = match (dh4_opt, &bob_opk) {
            (Some(res), Some(opk)) => {
                let dh = res.map_err(|_| HandshakeError::DhFailed)?;
                (dh.0.to_vec(), Some(opk.index))
            },
            _ => (vec![], None),
        };

        let (kem_ct, kem_ss) = kem_result
            .map_err(|e| HandshakeError::KemError(e.to_string()))?;

        let mut ikm = Vec::with_capacity(32 + 32 * 5 + kem_ss.0.len());
        if let Some(h) = noise_hash {
            ikm.extend_from_slice(&h);
        }
        ikm.extend_from_slice(&dh1.0);
        ikm.extend_from_slice(&dh2.0);
        ikm.extend_from_slice(&dh3.0);
        if !dh4_bytes.is_empty() { ikm.extend_from_slice(&dh4_bytes); }
        ikm.extend_from_slice(&kem_ss.0);

        let ms_bytes = hkdf(b"ZERO-ZKX-v1", &ikm, KdfContext::ZkxMasterSecret, MASTER_SECRET_SIZE)
            .map_err(|_| HandshakeError::KdfError)?;
        let mut ms_arr = [0u8; MASTER_SECRET_SIZE];
        ms_arr.copy_from_slice(&ms_bytes);
        
        let ms = MasterSecret(ms_arr);
        
        // R4: Generate Alice's tag
        let alice_tag = if let Some(h) = noise_hash {
            ms.generate_tag("A->B", &h)?
        } else {
            [0u8; 32]
        };

        let init_msg = ZkxInitMessage {
            alice_isk_pub: alice_keypair.isk.public_key(),
            alice_idk_pub: alice_keypair.idk.public_key(),
            alice_ek_pub: self.ek.public_key(),
            bob_spk_index: bob_bundle.spk.index,
            bob_opk_index: opk_index,
            kem_ciphertext: kem_ct.0,
            alice_tag,
        };

        Ok((init_msg, ms))
    }
}

/// The X3DH responder (Bob) who creates a master secret from Alice's ZKX initiation.
pub struct X3dhResponder;

impl X3dhResponder {
    /// Respond to an incoming ZKX initiation message.
    pub fn respond(
        bob_bundle_owned: &mut zero_identity::bundle::OwnedKeyBundle,
        init_msg: &ZkxInitMessage,
    ) -> Result<(MasterSecret, [u8; 32]), HandshakeError> {
        Self::respond_with_noise_hash(bob_bundle_owned, init_msg, None)
    }

    /// Respond to an incoming ZKX initiation message, optionally binding to the Noise XX hash.
    /// Returns both the MasterSecret and Bob's confirmation tag.
    pub fn respond_with_noise_hash(
        bob_bundle_owned: &mut zero_identity::bundle::OwnedKeyBundle,
        init_msg: &ZkxInitMessage,
        noise_hash: Option<[u8; 32]>,
    ) -> Result<(MasterSecret, [u8; 32]), HandshakeError> {
        let bob_keypair = &bob_bundle_owned.keypair;
        let alice_ek_pub  = init_msg.alice_ek_pub.clone();

        if init_msg.bob_opk_index.is_none() {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            if bob_bundle_owned.recent_handshakes.len() > 1000 {
                bob_bundle_owned.recent_handshakes.retain(|_, &mut ts| now.saturating_sub(ts) < 3600);
            }
            if bob_bundle_owned.recent_handshakes.contains_key(&alice_ek_pub.0) {
                return Err(HandshakeError::AuthenticationFailed);
            }
            bob_bundle_owned.recent_handshakes.insert(alice_ek_pub.0, now);
        }

        let alice_idk_pub = init_msg.alice_idk_pub.clone();

        let spk_sk = if bob_bundle_owned.current_spk.index == init_msg.bob_spk_index {
            X25519SecretKey(bob_bundle_owned.current_spk.secret_key.as_ref().unwrap().0)
        } else {
            let old_spk = bob_bundle_owned.old_spks.get(&init_msg.bob_spk_index)
                .ok_or_else(|| HandshakeError::BundleVerificationFailed(format!("SPK index {} not found in history", init_msg.bob_spk_index)))?;
            X25519SecretKey(old_spk.secret_key.as_ref().unwrap().0)
        };

        let idk_sk = bob_keypair.idk.secret_key();
        let pq_dk = &bob_keypair.pq_isk.dk;
        let kem_ct = MlKem768Ciphertext(init_msg.kem_ciphertext.clone());

        // Parallelize DH and KEM operations
        let (dh_results, kem_result) = rayon::join(
            || {
                let dh1 = x25519_diffie_hellman(&spk_sk, &alice_idk_pub);
                let dh2 = x25519_diffie_hellman(&idk_sk, &alice_ek_pub);
                let dh3 = x25519_diffie_hellman(&spk_sk, &alice_ek_pub);
                (dh1, dh2, dh3)
            },
            || {
                ml_kem_768_decapsulate(pq_dk, &kem_ct)
            }
        );

        let (dh1, dh2, dh3) = dh_results;
        let dh1 = dh1.map_err(|_| HandshakeError::DhFailed)?;
        let dh2 = dh2.map_err(|_| HandshakeError::DhFailed)?;
        let dh3 = dh3.map_err(|_| HandshakeError::DhFailed)?;

        let dh4_bytes: Vec<u8> = if let Some(opk_index) = init_msg.bob_opk_index {
            let opk = bob_bundle_owned.opks.iter_mut()
                .find(|o| o.index == opk_index)
                .ok_or_else(|| HandshakeError::BundleVerificationFailed("OPK not found".into()))?;
            let sk = opk.consume()
                .ok_or_else(|| HandshakeError::BundleVerificationFailed("OPK already consumed".into()))?;
            let dh = x25519_diffie_hellman(&sk, &alice_ek_pub)
                .map_err(|_| HandshakeError::DhFailed)?;
            dh.0.to_vec()
        } else {
            vec![]
        };

        let kem_ss = kem_result
            .map_err(|e| HandshakeError::KemError(e.to_string()))?;

        let mut ikm = Vec::with_capacity(32 + 32 * 5);
        if let Some(h) = noise_hash {
            ikm.extend_from_slice(&h);
        }
        ikm.extend_from_slice(&dh1.0);
        ikm.extend_from_slice(&dh2.0);
        ikm.extend_from_slice(&dh3.0);
        if !dh4_bytes.is_empty() { ikm.extend_from_slice(&dh4_bytes); }
        ikm.extend_from_slice(&kem_ss.0);

        let ms_bytes = hkdf(b"ZERO-ZKX-v1", &ikm, KdfContext::ZkxMasterSecret, MASTER_SECRET_SIZE)
            .map_err(|_| HandshakeError::KdfError)?;
        let mut ms_arr = [0u8; MASTER_SECRET_SIZE];
        ms_arr.copy_from_slice(&ms_bytes);
        
        let ms = MasterSecret(ms_arr);

        // R4: Verify Alice's tag
        let bob_tag = if let Some(h) = noise_hash {
            ms.verify_tag("A->B", &h, &init_msg.alice_tag)?;
            // R4: Generate Bob's tag
            ms.generate_tag("B->A", &h)?
        } else {
            [0u8; 32]
        };

        Ok((ms, bob_tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_identity::{bundle::OwnedKeyBundle, zeroid::ZeroId};

    #[test]
    fn test_zkx_master_secrets_match() {
        let alice_kp = ZeroKeypair::generate().unwrap();
        let mut bob_owned = OwnedKeyBundle::generate(0).unwrap();
        let bob_id = ZeroId::from_keypair(&bob_owned.keypair, [0u8; 4]);
        let bob_bundle = bob_owned.public_bundle(&bob_id);

        let initiator = X3dhInitiator::new(X25519Keypair::generate());
        let (init_msg, alice_ms) = initiator.initiate(&alice_kp, &bob_bundle).unwrap();

        let mut bob_owned_correct = bob_owned;
        let (bob_ms, _bob_tag) = X3dhResponder::respond(
            &mut bob_owned_correct,
            &init_msg,
        ).unwrap();

        assert_eq!(alice_ms.0, bob_ms.0);
    }
}
