//! ZDHT node records — encrypted IP:port data per authorised contact.
//!
//! In Tox DHT, every node can see every other node's IP.
//! In ZDHT, node records are encrypted with each contact's X25519 public key,
//! so only authorised contacts can learn your current IP address.

use serde::{Deserialize, Serialize};
use zero_crypto::{
    aead::{decrypt, encrypt, AeadKey, AeadNonce},
    dh::{X25519Keypair, X25519PublicKey, x25519_diffie_hellman},
    kdf::{hkdf_expand, hkdf_extract, KdfContext},
    sign::{Ed25519Keypair, Ed25519Signature, ed25519_verify, Ed25519PublicKey},
};
use crate::error::DhtError;
use crate::NodeId;

/// A plaintext node record (what the owner knows about themselves).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeRecord {
    /// Our NodeID.
    pub node_id: NodeId,
    /// ISK public key.
    pub isk_pub: [u8; 32],
    /// Current IP address bytes (IPv4=4, IPv6=16).
    pub ip: Vec<u8>,
    /// UDP port.
    pub port: u16,
    /// Preferred ZSF relay node IDs (up to 3).
    pub zsf_relays: Vec<NodeId>,
    /// Timestamp (Unix seconds).
    pub timestamp: u64,
    /// Ed25519 signature over all other fields.
    pub signature: Ed25519Signature,
}

impl NodeRecord {
    /// Create and sign a node record.
    pub fn create(
        node_id: NodeId,
        isk_keypair: &Ed25519Keypair,
        ip: Vec<u8>,
        port: u16,
        zsf_relays: Vec<NodeId>,
        timestamp: u64,
    ) -> Self {
        let mut record = Self {
            node_id,
            isk_pub: isk_keypair.public_key().0,
            ip,
            port,
            zsf_relays,
            timestamp,
            signature: Ed25519Signature(vec![0u8; 64]),
        };
        let data = record.signable_bytes();
        let sig = isk_keypair.sign(&data);
        record.signature = sig;
        record
    }

    /// Verify the record's signature.
    pub fn verify(&self) -> Result<(), DhtError> {
        let data = self.signable_bytes();
        let isk_pub = Ed25519PublicKey(self.isk_pub);
        ed25519_verify(&isk_pub, &data, &self.signature)
            .map_err(|_| DhtError::InvalidSignature)
    }

    fn signable_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.node_id.0);
        data.extend_from_slice(&self.isk_pub);
        data.extend_from_slice(&self.ip);
        data.extend_from_slice(&self.port.to_le_bytes());
        for relay in &self.zsf_relays { data.extend_from_slice(&relay.0); }
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
}

/// An encrypted node record — IP:port encrypted for a specific contact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedNodeRecord {
    /// The owner's NodeID (publicly visible — needed to store/find).
    pub node_id: NodeId,
    /// Owner's ISK public key (for record signature verification).
    pub isk_pub: [u8; 32],
    /// Ephemeral X25519 public key used for this encryption.
    pub ephemeral_pub: [u8; 32],
    /// ChaCha20-Poly1305 ciphertext of the serialized NodeRecord.
    pub ciphertext: Vec<u8>,
    /// Timestamp for freshness checking.
    pub timestamp: u64,
}

impl EncryptedNodeRecord {
    /// Encrypt a NodeRecord for a specific contact's X25519 public key.
    pub fn encrypt(
        record: &NodeRecord,
        contact_pub: &X25519PublicKey,
    ) -> Result<Self, DhtError> {
        let ephemeral = X25519Keypair::generate();
        let shared = ephemeral.diffie_hellman(contact_pub);
        let aead_key = derive_record_key(&shared.0, &ephemeral.public_key().0)
            .map_err(|e| DhtError::CryptoError(e.to_string()))?;
        let nonce = AeadNonce::random();
        let plaintext = zero_crypto::cbor::to_vec(record)
            .map_err(|e| DhtError::SerializationError(e.to_string()))?;
        let mut aad = Vec::new();
        aad.extend_from_slice(b"ZERO-v1");
        aad.extend_from_slice(&record.node_id.0);

        let mut ct_blob = nonce.0.to_vec();
        let ct = encrypt(&aead_key, &nonce, &plaintext, &aad)
            .map_err(|e| DhtError::CryptoError(e.to_string()))?;
        ct_blob.extend_from_slice(&ct);
        Ok(Self {
            node_id: record.node_id,
            isk_pub: record.isk_pub,
            ephemeral_pub: ephemeral.public_key().0,
            ciphertext: ct_blob,
            timestamp: record.timestamp,
        })
    }

    /// Decrypt a node record using our X25519 secret key and verify freshness against current time.
    pub fn decrypt(&self, our_secret: &zero_crypto::dh::X25519SecretKey, now_unix: u64) -> Result<NodeRecord, DhtError> {
        let their_pub = X25519PublicKey(self.ephemeral_pub);
        let shared = x25519_diffie_hellman(our_secret, &their_pub)
            .map_err(|e| DhtError::CryptoError(e.to_string()))?;
        let aead_key = derive_record_key(&shared.0, &self.ephemeral_pub)
            .map_err(|e| DhtError::CryptoError(e.to_string()))?;
        let ct = &self.ciphertext;
        if ct.len() < 12 { return Err(DhtError::CryptoError("Too short".into())); }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&ct[..12]);
        let nonce = AeadNonce(nonce_bytes);
        
        // Spec 6.3: AAD MUST be bound to NodeId AND protocol version
        let mut aad = Vec::new();
        aad.extend_from_slice(b"ZERO-v1");
        aad.extend_from_slice(&self.node_id.0);
        
        let pt = decrypt(&aead_key, &nonce, &ct[12..], &aad)
            .map_err(|_| DhtError::CryptoError("Decryption failed".into()))?;
        let record: NodeRecord = zero_crypto::cbor::from_slice(&pt)
            .map_err(|e| DhtError::SerializationError(e.to_string()))?;
        record.verify()?;
        
        // Spec 6.3: Decrypting clients MUST verify freshness window (+/- 10 minutes)
        let diff = record.timestamp.abs_diff(now_unix);
        if diff > 600 {
            return Err(DhtError::CryptoError("Freshness window exceeded".into()));
        }
        
        Ok(record)
    }
}

fn derive_record_key(shared: &[u8], ephemeral_pub: &[u8]) -> Result<AeadKey, zero_crypto::CryptoError> {
    let prk = hkdf_extract(ephemeral_pub, shared);
    let key = hkdf_expand(&prk, KdfContext::DhtRecordKey, 32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key);
    Ok(AeadKey(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_crypto::dh::X25519Keypair;
    use zero_crypto::sign::Ed25519Keypair;

    #[test]
    fn test_record_sign_verify() {
        let isk = Ed25519Keypair::generate();
        let record = NodeRecord::create(
            NodeId([1u8; 32]), &isk, vec![127, 0, 0, 1], 44300, vec![], 1000,
        );
        assert!(record.verify().is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_record() {
        let isk = Ed25519Keypair::generate();
        let contact_kp = X25519Keypair::generate();
        let record = NodeRecord::create(
            NodeId([1u8; 32]), &isk, vec![1, 2, 3, 4], 44300, vec![], 0,
        );
        let enc = EncryptedNodeRecord::encrypt(&record, &contact_kp.public_key()).unwrap();
        let dec = enc.decrypt(&contact_kp.secret_key(), 0).unwrap();
        assert_eq!(dec.ip, vec![1u8, 2, 3, 4]);
        assert_eq!(dec.port, 44300);
    }

    #[test]
    fn test_wrong_key_fails() {
        let isk = Ed25519Keypair::generate();
        let contact_kp = X25519Keypair::generate();
        let wrong_kp = X25519Keypair::generate();
        let record = NodeRecord::create(NodeId([1u8; 32]), &isk, vec![127, 0, 0, 1], 44300, vec![], 0);
        let enc = EncryptedNodeRecord::encrypt(&record, &contact_kp.public_key()).unwrap();
        assert!(enc.decrypt(&wrong_kp.secret_key(), 0).is_err());
    }
}
