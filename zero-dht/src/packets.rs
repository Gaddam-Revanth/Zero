//! ZDHT packet types and wire format (CBOR).

use serde::{Deserialize, Serialize};
use crate::NodeId;
use zero_crypto::sign::Ed25519Signature;

/// All ZDHT packet types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DhtPacketType {
    /// Liveness check.
    Ping,
    /// Response to ping.
    Pong,
    /// Request k-closest nodes to a target NodeID.
    FindNode,
    /// Response with list of known close nodes.
    NodesResponse,
    /// Fetch an encrypted node record (onion-routed).
    FindRecord,
    /// Response with encrypted node record.
    RecordResponse,
    /// Store an encrypted node record.
    StoreRecord,
    /// Confirm storage.
    StoreAck,
    /// Onion-wrapped packet (for 3-hop routing).
    OnionWrap,
}

/// A complete ZDHT packet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtPacket {
    /// Protocol version.
    pub version: u8,
    /// Packet type.
    pub packet_type: DhtPacketType,
    /// Sender NodeID.
    pub sender_id: NodeId,
    /// Transaction ID for request/response matching.
    pub transaction_id: [u8; 8],
    /// Payload (type-specific, CBOR-encoded).
    pub payload: Vec<u8>,
    /// Ed25519 signature over version||packet_type||sender_id||payload.
    pub signature: Ed25519Signature,
}

impl DhtPacket {
    /// Serialize to CBOR.
    pub fn to_cbor(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Option<Self> {
        serde_cbor::from_slice(bytes).ok()
    }
}

/// Payload for FindNode/NodesResponse.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodesPayload {
    /// Target NodeID being searched for.
    pub target: NodeId,
    /// List of close nodes (up to K_BUCKET_SIZE).
    pub nodes: Vec<CompactNodeInfo>,
}

/// Compact node info for wire format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactNodeInfo {
    /// NodeID.
    pub node_id: NodeId,
    /// IP bytes (4 for IPv4, 16 for IPv6).
    pub ip: Vec<u8>,
    /// Port.
    pub port: u16,
}

/// Payload for StoreRecord / FindRecord.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordPayload {
    /// NodeID whose record is stored/requested.
    pub node_id: NodeId,
    /// Encrypted record bytes (None on FindRecord request).
    pub record: Option<Vec<u8>>,
    /// Record TTL in seconds.
    pub ttl: u32,
}
