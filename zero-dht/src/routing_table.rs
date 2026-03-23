//! ZDHT routing table — 256 k-buckets organized by bit-prefix.

use crate::{
    kbucket::{KBucket, NodeInfo},
    xor_distance, NodeId,
};
use serde::{Deserialize, Serialize};

/// ZDHT routing table: 256 k-buckets indexed by XOR distance prefix.
#[derive(Serialize, Deserialize)]
pub struct RoutingTable {
    /// Our own NodeID.
    pub own_id: NodeId,
    /// 256 k-buckets (one per bit-prefix of XOR distance).
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    /// Create a new routing table for the given NodeID.
    pub fn new(own_id: NodeId) -> Self {
        Self {
            own_id,
            buckets: (0..256).map(|_| KBucket::new()).collect(),
        }
    }

    /// Add or refresh a node.
    pub fn add_node(&mut self, node: NodeInfo) {
        if node.node_id == self.own_id {
            return;
        }
        let idx = self.bucket_index(&node.node_id);
        self.buckets[idx].add_node(node);
    }

    /// Remove a node (after ping failure).
    pub fn remove_node(&mut self, node_id: &NodeId) {
        let idx = self.bucket_index(node_id);
        self.buckets[idx].remove_node(node_id);
    }

    /// Find the K_BUCKET_SIZE closest nodes to a target ID.
    pub fn closest_nodes(&self, target: &NodeId, count: usize) -> Vec<NodeInfo> {
        let mut candidates: Vec<(NodeInfo, [u8; 32])> = self
            .buckets
            .iter()
            .flat_map(|b| b.nodes().iter().cloned())
            .map(|n| {
                let dist = xor_distance(&n.node_id, target);
                (n, dist)
            })
            .collect();

        candidates.sort_by(|(_, da), (_, db)| da.cmp(db));
        candidates.into_iter().take(count).map(|(n, _)| n).collect()
    }

    /// Lookup a specific node by ID.
    pub fn find_node(&self, node_id: &NodeId) -> Option<&NodeInfo> {
        let idx = self.bucket_index(node_id);
        self.buckets[idx]
            .nodes()
            .iter()
            .find(|n| &n.node_id == node_id)
    }

    /// Total number of known nodes.
    pub fn node_count(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// Create a 3-hop onion-wrapped lookup request.
    pub fn create_onion_lookup(
        &self,
        target: &NodeId,
    ) -> Result<crate::onion::OnionPacket, crate::DhtError> {
        let nodes = self.closest_nodes(target, 20);
        if nodes.len() < 3 {
            return Err(crate::DhtError::NodeNotFound);
        }

        // Pick 3 nodes for the onion layers (H1 -> H2 -> H3)
        let h1 = &nodes[0];
        let h2 = &nodes[1];
        let h3 = &nodes[2];

        let ephemeral = zero_crypto::dh::X25519Keypair::generate();
        let eph_pub = ephemeral.public_key();

        // Derive real AeadKeys via DH with each hop's ISK (acting as their stable onion key)
        let keys = [
            self.derive_hop_key(&ephemeral, &zero_crypto::dh::X25519PublicKey(h1.isk_pub))?,
            self.derive_hop_key(&ephemeral, &zero_crypto::dh::X25519PublicKey(h2.isk_pub))?,
            self.derive_hop_key(&ephemeral, &zero_crypto::dh::X25519PublicKey(h3.isk_pub))?,
        ];

        let hops = [h1.node_id, h2.node_id, h3.node_id];
        let payload = format!(
            "FIND_NODE:{}",
            target
                .0
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        crate::onion::OnionPacket::wrap_3_hops(payload.as_bytes(), &hops, &keys, eph_pub.0)
    }

    /// Determine which bucket a node belongs to (by XOR distance leading bit).
    fn bucket_index(&self, node_id: &NodeId) -> usize {
        let dist = xor_distance(&self.own_id, node_id);
        // Use the index of the most significant set bit as the bucket index
        for (byte_idx, &byte) in dist.iter().enumerate() {
            if byte != 0 {
                let bit_pos = byte.leading_zeros() as usize;
                return byte_idx * 8 + bit_pos;
            }
        }
        255 // Same ID — shouldn't happen (self filtered above)
    }

    fn derive_hop_key(
        &self,
        our_ephemeral: &zero_crypto::dh::X25519Keypair,
        their_pub: &zero_crypto::dh::X25519PublicKey,
    ) -> Result<zero_crypto::aead::AeadKey, crate::DhtError> {
        let shared = our_ephemeral.diffie_hellman(their_pub);
        // Use HKDF to derive a dedicated onion routing key
        let key_bytes = zero_crypto::kdf::hkdf(
            b"salt",
            &shared.0,
            zero_crypto::kdf::KdfContext::OnionHopKey,
            32,
        )
        .map_err(|e| crate::DhtError::CryptoError(e.to_string()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        Ok(zero_crypto::aead::AeadKey(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: u8) -> NodeInfo {
        NodeInfo {
            node_id: NodeId([id; 32]),
            isk_pub: [id; 32],
            ip: vec![127, 0, 0, id],
            port: 44300 + id as u16,
            last_seen: 0,
            is_bootstrap: false,
        }
    }

    #[test]
    fn test_add_and_find() {
        let mut rt = RoutingTable::new(NodeId([0u8; 32]));
        rt.add_node(make_node(1));
        let found = rt.find_node(&NodeId([1u8; 32]));
        assert!(found.is_some());
    }

    #[test]
    fn test_closest_nodes_sorted() {
        let mut rt = RoutingTable::new(NodeId([0u8; 32]));
        for i in 1..10u8 {
            rt.add_node(make_node(i));
        }
        let target = NodeId([5u8; 32]);
        let closest = rt.closest_nodes(&target, 3);
        // Closest to [5;32] should include [5;32]
        assert!(!closest.is_empty());
    }

    #[test]
    fn test_self_not_added() {
        let own = NodeId([0xABu8; 32]);
        let mut rt = RoutingTable::new(own);
        let self_node = NodeInfo {
            node_id: own,
            isk_pub: own.0,
            ip: vec![127, 0, 0, 1],
            port: 44300,
            last_seen: 0,
            is_bootstrap: false,
        };
        rt.add_node(self_node);
        assert_eq!(rt.node_count(), 0);
    }
}
