use zero_crypto::{
    aead::{encrypt, decrypt, AeadKey, AeadNonce},
};
use serde::{Deserialize, Serialize};
use crate::{NodeId, DhtError};

/// A single layer in the onion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnionLayer {
    /// Next hop Node ID.
    pub next_hop: NodeId,
    /// Encrypted payload for the next hop.
    pub inner_payload: Vec<u8>,
}

/// A 3-hop onion packet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnionPacket {
    /// The public key used for the outermost layer's DH (to derive AEAD key).
    /// In ZDHT, we assume nodes have stable Onion/X25519 keys published.
    pub ephemeral_pub: [u8; 32],
    /// The encrypted layers.
    pub encrypted_data: Vec<u8>,
}

impl OnionPacket {
    /// Alice (Searcher) wraps a FIND_RECORD_REQ in 3 layers.
    pub fn wrap_3_hops(
        payload: &[u8],
        hops: &[NodeId; 3],
        hop_keys: &[AeadKey; 3],
        ephemeral_pub: [u8; 32],
    ) -> Result<Self, DhtError> {
        // 1. Innermost layer (H3): contains payload + final destination info
        let layer3 = OnionLayer {
            next_hop: hops[2], // H3 performs the actual DHT lookup
            inner_payload: payload.to_vec(),
        };
        let l3_encoded = serde_cbor::to_vec(&layer3).map_err(|_| DhtError::SerializationError("OnionLayer 3".into()))?;
        let nonce3 = AeadNonce::random();
        let mut ct3_blob = nonce3.0.to_vec();
        let ct3 = encrypt(&hop_keys[2], &nonce3, &l3_encoded, &[])
            .map_err(|_| DhtError::CryptoError("H3 encrypt failed".into()))?;
        ct3_blob.extend_from_slice(&ct3);

        // 2. Middle layer (H2): forwards to H3
        let layer2 = OnionLayer {
            next_hop: hops[2],
            inner_payload: ct3_blob,
        };
        let l2_encoded = serde_cbor::to_vec(&layer2).map_err(|_| DhtError::SerializationError("OnionLayer 2".into()))?;
        let nonce2 = AeadNonce::random();
        let mut ct2_blob = nonce2.0.to_vec();
        let ct2 = encrypt(&hop_keys[1], &nonce2, &l2_encoded, &[])
            .map_err(|_| DhtError::CryptoError("H2 encrypt failed".into()))?;
        ct2_blob.extend_from_slice(&ct2);

        // 3. Outermost layer (H1): forwards to H2
        let layer1 = OnionLayer {
            next_hop: hops[1],
            inner_payload: ct2_blob,
        };
        let l1_encoded = serde_cbor::to_vec(&layer1).map_err(|_| DhtError::SerializationError("OnionLayer 1".into()))?;
        let nonce1 = AeadNonce::random();
        let mut ct1_blob = nonce1.0.to_vec();
        let ct1 = encrypt(&hop_keys[0], &nonce1, &l1_encoded, &[])
            .map_err(|_| DhtError::CryptoError("H1 encrypt failed".into()))?;
        ct1_blob.extend_from_slice(&ct1);

        Ok(Self {
            ephemeral_pub,
            encrypted_data: ct1_blob,
        })
    }

    /// Peel one layer from the onion.
    pub fn peel(
        &self,
        my_key: &AeadKey,
    ) -> Result<OnionLayer, DhtError> {
        let ct = &self.encrypted_data;
        if ct.len() < 12 { return Err(DhtError::CryptoError("Onion ciphertext too short".into())); }
        
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&ct[..12]);
        let nonce = AeadNonce(nonce_bytes);

        let pt = decrypt(my_key, &nonce, &ct[12..], &[]) 
            .map_err(|_| DhtError::AuthenticationFailed)?;
        
        let layer: OnionLayer = serde_cbor::from_slice(&pt)
            .map_err(|_| DhtError::SerializationError("Peel OnionLayer".into()))?;
            
        Ok(layer)
    }
}
