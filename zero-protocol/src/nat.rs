//! NAT Traversal and Hole-Punching Coordination.
//!
//! # Overview
//!
//! This module handles two key tasks:
//!
//! 1. **ICE Candidate exchange** — Gathering, encoding, and relaying ICE candidates
//!    between peers via the ZSF relay so they can establish a direct P2P connection.
//!
//! 2. **WebRTC SDP exchange** — Forwarding SDP Offer/Answer messages via the ZSF relay
//!    to complete the WebRTC handshake even when peers are behind symmetric NATs.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use crate::error::ZeroError;
use tracing::info;

/// NAT candidate address info (an ICE candidate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatCandidate {
    /// The public-facing address of this candidate.
    pub public_addr: SocketAddr,
    /// The LAN-local address of this candidate.
    pub local_addr: SocketAddr,
    /// The NAT type observed for this candidate.
    pub nat_type: NatType,
}

/// Simplified NAT types for coordination.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NatType {
    /// No NAT — directly reachable.
    Open,
    /// Full-cone / 1:1 NAT.
    FullCone,
    /// Address-restricted cone.
    RestrictedCone,
    /// Port-restricted cone.
    PortRestrictedCone,
    /// Symmetric NAT — hardest to traverse.
    Symmetric,
}

/// An ICE candidate exchange message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceExchange {
    /// Sender's peer ID.
    pub from_id: String,
    /// Recipient's peer ID.
    pub to_id: String,
    /// ICE candidates to exchange.
    pub candidates: Vec<NatCandidate>,
}

/// An SDP relay message (used for WebRTC offer/answer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdpRelay {
    /// Sender's peer ID.
    pub from_id: String,
    /// Recipient's peer ID.
    pub to_id: String,
    /// Whether this is an offer ("offer") or answer ("answer").
    pub sdp_type: String,
    /// The raw SDP string.
    pub sdp: String,
}

/// Manages NAT coordination and WebRTC SDP exchange.
pub struct NatManager;

impl NatManager {
    /// Create a new NAT manager.
    pub fn new() -> Self { Self }

    /// Collect local ICE candidates for a connection.
    ///
    /// In production this calls into the system's ICE agent (via a WebRTC lib).
    /// Returns local-reachable candidates ready to be sent to the remote peer.
    pub fn gather_local_candidates(&self, local_port: u16) -> Vec<NatCandidate> {
        let local_addr: SocketAddr = format!("0.0.0.0:{}", local_port).parse().unwrap();
        // In production: use STUN to discover the public address.
        vec![
            NatCandidate {
                public_addr: format!("0.0.0.0:{}", local_port).parse().unwrap(),
                local_addr,
                nat_type: NatType::Open,
            }
        ]
    }

    /// Coordinate a hole-punching attempt.
    ///
    /// Encodes local candidates as CBOR and would dispatch them via ZSF relay
    /// to the target peer. Returns the remote candidates on success.
    pub async fn coordinate_hole_punch(
        &self,
        target_id: &str,
        local_candidates: Vec<NatCandidate>,
    ) -> Result<Vec<NatCandidate>, ZeroError> {
        info!("Coordinating NAT hole-punching with: {}", target_id);

        // Encode our candidates for transport
        let exchange = IceExchange {
            from_id: "self".to_string(),
            to_id: target_id.to_string(),
            candidates: local_candidates,
        };
        let _encoded = serde_cbor::to_vec(&exchange)
            .map_err(|e| ZeroError::Custom(e.to_string()))?;

        // In production: send _encoded via ZSF relay to target_id,
        // then wait for their IceExchange reply over the same channel.

        // Return mock remote candidates for now
        Ok(vec![NatCandidate {
            public_addr: "1.2.3.4:44300".parse().unwrap(),
            local_addr: "192.168.1.100:44300".parse().unwrap(),
            nat_type: NatType::RestrictedCone,
        }])
    }

    /// Exchange WebRTC SDP offer/answer with a remote peer via the ZSF relay.
    ///
    /// This serializes the SDP into an `SdpRelay` envelope, encodes it as CBOR,
    /// and would dispatch it through the ZSF relay to the target peer,
    /// then await their `SdpRelay` reply and return its SDP string.
    pub async fn exchange_sdp(
        &self,
        self_id: &str,
        target_id: &str,
        local_sdp: &str,
        sdp_type: &str,
    ) -> Result<String, ZeroError> {
        info!(
            "Relaying SDP {} to {} ({} chars)",
            sdp_type, target_id, local_sdp.len()
        );

        let relay_msg = SdpRelay {
            from_id: self_id.to_string(),
            to_id: target_id.to_string(),
            sdp_type: sdp_type.to_string(),
            sdp: local_sdp.to_string(),
        };

        // Serialize to CBOR — in production this is sent via ZSF relay
        let _encoded = serde_cbor::to_vec(&relay_msg)
            .map_err(|e| ZeroError::Custom(e.to_string()))?;

        // In production:
        //   1. ZSF relay delivers `_encoded` to `target_id`'s mailbox.
        //   2. Target decodes, processes the SDP offer, creates an SDP answer.
        //   3. Target sends back an SdpRelay{ sdp_type: "answer", sdp: answer_sdp }.
        //   4. We decode it here and return the answer SDP.
        //
        // For now, return a well-formed SDP answer stub:
        let answer = format!(
            "v=0\r\no=- 0 0 IN IP4 {}\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=sctp-port:5000\r\n",
            target_id
        );
        Ok(answer)
    }
}

impl Default for NatManager {
    fn default() -> Self { Self::new() }
}
