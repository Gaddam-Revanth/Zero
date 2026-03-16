//! Kademlia k-bucket implementation for ZDHT.

use crate::NodeId;
use serde::{Deserialize, Serialize};

/// ZDHT k-bucket size (k=20 nodes per bucket, vs Tox's 8).
pub const K_BUCKET_SIZE: usize = 20;

/// Information about a known ZDHT node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// NodeID = BLAKE2b-256(ISK_pub).
    pub node_id: NodeId,
    /// ISK public key (Ed25519, 32 bytes).
    pub isk_pub: [u8; 32],
    /// IPv4 or IPv6 address as bytes (4 or 16 bytes).
    pub ip: Vec<u8>,
    /// UDP port for ZDHT communication.
    pub port: u16,
    /// Last seen timestamp (Unix seconds).
    pub last_seen: u64,
    /// Whether this node is a verified bootstrap node.
    pub is_bootstrap: bool,
}

/// A Kademlia k-bucket: holds up to K_BUCKET_SIZE nodes of similar distance.
///
/// Ordered: least-recently-seen (LRS) at front, most-recently-seen (MRS) at back.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KBucket {
    nodes: Vec<NodeInfo>,
}

impl KBucket {
    /// Create an empty k-bucket.
    pub fn new() -> Self {
        Self { nodes: Vec::with_capacity(K_BUCKET_SIZE) }
    }

    /// Add or refresh a node in this bucket.
    /// Returns true if added, false if bucket is full (caller should ping LRS).
    pub fn add_node(&mut self, node: NodeInfo) -> bool {
        // If already present, move to MRS position
        if let Some(idx) = self.nodes.iter().position(|n| n.node_id == node.node_id) {
            self.nodes.remove(idx);
            self.nodes.push(node);
            return true;
        }
        // If bucket not full, append
        if self.nodes.len() < K_BUCKET_SIZE {
            self.nodes.push(node);
            return true;
        }
        // Bucket full — cannot add without evicting
        false
    }

    /// Remove a node (when it fails to respond to pings).
    pub fn remove_node(&mut self, node_id: &NodeId) {
        self.nodes.retain(|n| &n.node_id != node_id);
    }

    /// Get the least-recently-seen node (candidate for eviction check).
    pub fn least_recently_seen(&self) -> Option<&NodeInfo> {
        self.nodes.first()
    }

    /// All nodes in this bucket.
    pub fn nodes(&self) -> &[NodeInfo] {
        &self.nodes
    }

    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True if bucket has capacity.
    pub fn has_space(&self) -> bool {
        self.nodes.len() < K_BUCKET_SIZE
    }
}

impl Default for KBucket {
    fn default() -> Self {
        Self::new()
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
            last_seen: id as u64,
            is_bootstrap: false,
        }
    }

    #[test]
    fn test_add_and_retrieve() {
        let mut bucket = KBucket::new();
        let node = make_node(1);
        assert!(bucket.add_node(node.clone()));
        assert_eq!(bucket.len(), 1);
    }

    #[test]
    fn test_dedup_moves_to_back() {
        let mut bucket = KBucket::new();
        bucket.add_node(make_node(1));
        bucket.add_node(make_node(2));
        let mut updated = make_node(1);
        updated.last_seen = 999;
        bucket.add_node(updated);
        assert_eq!(bucket.len(), 2);
        assert_eq!(bucket.nodes().last().unwrap().node_id, NodeId([1u8; 32]));
    }

    #[test]
    fn test_bucket_full() {
        let mut bucket = KBucket::new();
        for i in 0..K_BUCKET_SIZE as u8 {
            bucket.add_node(make_node(i));
        }
        assert!(!bucket.add_node(make_node(255)));
    }

    #[test]
    fn test_remove_node() {
        let mut bucket = KBucket::new();
        bucket.add_node(make_node(1));
        bucket.remove_node(&NodeId([1u8; 32]));
        assert_eq!(bucket.len(), 0);
    }
}
