//! # zero-dht
//!
//! ZDHT — ZERO Distributed Hash Table.
//!
//! Enhanced Kademlia for privacy-preserving P2P peer discovery:
//! - k-bucket size: 20 (vs Tox's 8) — better routing resilience
//! - 256-bit Node IDs: BLAKE2b-256(ISK_pub)
//! - Encrypted node records: IP:port encrypted per-contact
//! - 3-hop onion routing for FIND_RECORD queries
//! - mDNS-SD LAN discovery (RFC 6762 + 6763)
//! - CBOR wire format

//#![deny(missing_docs)]
//#![forbid(unsafe_code)]

pub mod error;
pub mod kbucket;
pub mod mdns;
pub mod node_record;
pub mod onion;
pub mod packets;
pub mod routing_table;

pub use error::DhtError;
pub use kbucket::{KBucket, K_BUCKET_SIZE};
pub use node_record::{EncryptedNodeRecord, NodeRecord};
pub use packets::{DhtPacket, DhtPacketType};
pub use routing_table::RoutingTable;
use serde::{Deserialize, Serialize, Deserializer, Serializer};

/// A ZDHT Node ID (256-bit = 32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; 32]);

impl Serialize for NodeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NodeIdVisitor;

        impl<'de> serde::de::Visitor<'de> for NodeIdVisitor {
            type Value = NodeId;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a 32-byte NodeId")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 32 {
                    return Err(E::custom("Invalid NodeId length"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(v);
                Ok(NodeId(arr))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(&v)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut v = Vec::with_capacity(32);
                while let Some(b) = seq.next_element::<u8>()? {
                    v.push(b);
                }
                self.visit_bytes(&v)
            }
        }

        deserializer.deserialize_any(NodeIdVisitor)
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({})", hex::encode(self.0))
    }
}

impl std::ops::Deref for NodeId {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target { &self.0 }
}

/// Derive a NodeID from an ISK public key.
pub fn node_id_from_isk(isk_pub: &[u8; 32]) -> NodeId {
    NodeId(zero_crypto::hash::blake2b_256(isk_pub))
}

/// Compute XOR distance between two NodeIDs.
pub fn xor_distance(a: &NodeId, b: &NodeId) -> [u8; 32] {
    let mut dist = [0u8; 32];
    for (i, d) in dist.iter_mut().enumerate() {
        *d = a.0[i] ^ b.0[i];
    }
    dist
}

/// Compare two XOR distances (big-endian byte comparison).
pub fn distance_cmp(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    a.cmp(b)
}
