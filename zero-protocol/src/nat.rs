//! NAT Traversal, STUN-based IP Discovery, and WebRTC SDP Relay.
//!
//! # Overview
//!
//! 1. **STUN** — RFC 5389 binding request to discover the device's public IP:port (§8.3)
//! 2. **ICE Candidate Exchange** — CBOR-serialized ICE candidates exchanged via ZSF relay
//! 3. **WebRTC SDP Exchange** — SDP offer/answer relay via ZSF for WebRTC DataChannel/media
//! 4. **Hole-Punching** — Simultaneous UDP open with sequential port guessing for symmetric NATs
#![allow(missing_docs)]

use crate::error::ZeroError;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::info;

// ─── STUN ────────────────────────────────────────────────────────────────────

/// STUN magic cookie (RFC 5389 §6).
const STUN_MAGIC: u32 = 0x2112A442;

/// A bound socket address discovered via STUN.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StunAddress {
    /// The public-facing IP:port as seen by the STUN server.
    pub public: SocketAddr,
}

/// Perform a simple STUN Binding Request and return our public address.
///
/// Uses a hardcoded STUN server (`stun.l.google.com:19302`) by default.
/// This is a synchronous UDP exchange — the caller should run this on a
/// blocking thread or inside `tokio::task::spawn_blocking`.
pub fn stun_discover_public_addr() -> Result<StunAddress, ZeroError> {
    use std::net::UdpSocket;
    use std::time::Duration;

    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| ZeroError::Custom(format!("STUN bind: {}", e)))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| ZeroError::Custom(format!("STUN timeout: {}", e)))?;

    let stun_server = "stun.l.google.com:19302";
    socket
        .connect(stun_server)
        .map_err(|e| ZeroError::Custom(format!("STUN connect: {}", e)))?;

    // Build a minimal STUN Binding Request (RFC 5389 §6)
    let mut msg = [0u8; 20];
    msg[0] = 0x00; // Binding Request
    msg[1] = 0x01;
    msg[2] = 0x00; // Message length = 0
    msg[3] = 0x00;
    // Magic cookie
    msg[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    // Transaction ID (12 cryptographically random bytes) — reuse AeadNonce's OsRng
    let nonce = zero_crypto::aead::AeadNonce::random();
    msg[8..20].copy_from_slice(&nonce.0);

    socket
        .send(&msg)
        .map_err(|e| ZeroError::Custom(format!("STUN send: {}", e)))?;

    let mut resp = [0u8; 512];
    let n = socket
        .recv(&mut resp)
        .map_err(|e| ZeroError::Custom(format!("STUN recv: {}", e)))?;

    // Parse the STUN Binding Response — look for XOR-MAPPED-ADDRESS attribute (0x0020)
    if n < 20 {
        return Err(ZeroError::Custom("STUN response too short".to_string()));
    }

    let mut i = 20;
    while i + 4 <= n {
        let attr_type = u16::from_be_bytes([resp[i], resp[i + 1]]);
        let attr_len = u16::from_be_bytes([resp[i + 2], resp[i + 3]]) as usize;
        if attr_type == 0x0020 && i + 4 + attr_len <= n {
            // XOR-MAPPED-ADDRESS: family[1] + padding[1] + port[2] + addr[4 or 16]
            let family = resp[i + 5];
            let port = u16::from_be_bytes([resp[i + 6], resp[i + 7]]) ^ 0x2112;
            if family == 0x01 && attr_len >= 8 {
                // IPv4
                let a = resp[i + 8] ^ 0x21;
                let b = resp[i + 9] ^ 0x12;
                let c = resp[i + 10] ^ 0xA4;
                let d = resp[i + 11] ^ 0x42;
                let addr: SocketAddr = format!("{}.{}.{}.{}:{}", a, b, c, d, port)
                    .parse()
                    .map_err(|e: std::net::AddrParseError| ZeroError::Custom(e.to_string()))?;
                info!("STUN discovered public address: {}", addr);
                return Ok(StunAddress { public: addr });
            }
        }
        i += 4 + attr_len;
        // Attributes are padded to 4-byte boundaries
        if !attr_len.is_multiple_of(4) {
            i += 4 - (attr_len % 4);
        }
    }
    Err(ZeroError::Custom(
        "STUN: no XOR-MAPPED-ADDRESS in response".to_string(),
    ))
}

// ─── ICE + SDP ───────────────────────────────────────────────────────────────

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

/// Simplified NAT types for coordination (§8.2).
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
    /// Symmetric NAT — hardest to traverse (fall back to port guessing).
    Symmetric,
}

/// An ICE candidate exchange message (CBOR-serialized, sent via ZSF relay).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceExchange {
    /// Sender's peer ID.
    pub from_id: String,
    /// Recipient's peer ID.
    pub to_id: String,
    /// ICE candidates to exchange.
    pub candidates: Vec<NatCandidate>,
}

/// An SDP relay message (CBOR-serialized, sent via ZSF relay).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdpRelay {
    /// Sender's peer ID.
    pub from_id: String,
    /// Recipient's peer ID.
    pub to_id: String,
    /// "offer" or "answer".
    pub sdp_type: String,
    /// Raw SDP string.
    pub sdp: String,
}

/// Manages NAT coordination, STUN discovery, and WebRTC SDP exchange.
pub struct NatManager;

impl NatManager {
    /// Create a new NAT manager.
    pub fn new() -> Self {
        Self
    }

    /// Discover our public IP:port by sending a STUN Binding Request (§8.3).
    /// Returns the `StunAddress` for use in ICE candidate gathering.
    pub async fn discover_public_addr(&self) -> Result<StunAddress, ZeroError> {
        // STUN uses blocking UDP — offload to rayon/blocking task
        tokio::task::spawn_blocking(stun_discover_public_addr)
            .await
            .map_err(|e| ZeroError::Custom(format!("STUN task: {}", e)))?
    }

    /// Gather local ICE candidates (STUN + LAN) for a connection attempt.
    pub async fn gather_candidates(&self, local_port: u16) -> Vec<NatCandidate> {
        let local_addr: SocketAddr = format!("0.0.0.0:{}", local_port).parse().unwrap();
        let mut candidates = vec![NatCandidate {
            public_addr: local_addr,
            local_addr,
            nat_type: NatType::Open,
        }];

        // Best-effort STUN discovery
        if let Ok(stun) = self.discover_public_addr().await {
            candidates.push(NatCandidate {
                public_addr: stun.public,
                local_addr,
                nat_type: NatType::RestrictedCone,
            });
        }
        candidates
    }

    /// Coordinate a hole-punching attempt (§8.3).
    ///
    /// CBOR-encodes local candidates as an IceExchange message and
    /// returns the encoded bytes ready for dispatch via ZSF relay.
    pub async fn coordinate_hole_punch(
        &self,
        target_id: &str,
        local_candidates: Vec<NatCandidate>,
    ) -> Result<Vec<u8>, ZeroError> {
        info!("Coordinating hole-punch with: {}", target_id);

        let exchange = IceExchange {
            from_id: "self".to_string(), // In production, this is our ZeroId
            to_id: target_id.to_string(),
            candidates: local_candidates,
        };

        zero_crypto::cbor::to_vec(&exchange)
            .map_err(|e| ZeroError::Custom(format!("CBOR encode IceExchange: {}", e)))
    }

    /// Perform the actual simultaneous UDP hole punch (§8.3).
    /// Effectively guesses ports if the remote is behind a Symmetric NAT.
    pub async fn perform_udp_hole_punch(
        &self,
        remote_candidates: Vec<NatCandidate>,
    ) -> Result<SocketAddr, ZeroError> {
        use std::net::UdpSocket;
        use std::time::Duration;

        if let Some(cand) = remote_candidates.into_iter().next() {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .map_err(|e| ZeroError::Custom(format!("Hole-punch bind: {}", e)))?;
            socket
                .set_read_timeout(Some(Duration::from_millis(500)))
                .ok();

            // Try the observed public port
            let _ = socket.send_to(b"ZERO-HOLE-PUNCH", cand.public_addr);

            // If symmetric NAT, attempt port guessing (±10)
            if matches!(cand.nat_type, NatType::Symmetric) {
                let base_port = cand.public_addr.port();
                for offset in -10..=10 {
                    if offset == 0 {
                        continue;
                    }
                    let guessed_port = (base_port as i32 + offset) as u16;
                    let mut guessed_addr = cand.public_addr;
                    guessed_addr.set_port(guessed_port);
                    let _ = socket.send_to(b"ZERO-HOLE-PUNCH", guessed_addr);
                }
            }

            // In a real flow, we'd await a response here.
            // For now, we return the first candidate's public address as the presumed target.
            return Ok(cand.public_addr);
        }

        Err(ZeroError::Custom("No candidates to hole-punch".to_string()))
    }

    /// Exchange WebRTC SDP offer/answer via the ZSF relay.
    ///
    /// CBOR-encodes an SdpRelay envelope for delivery to the remote peer.
    pub async fn create_sdp_relay_packet(
        &self,
        self_id: &str,
        target_id: &str,
        local_sdp: &str,
        sdp_type: &str,
    ) -> Result<Vec<u8>, ZeroError> {
        info!(
            "Creating SDP relay packet {} → {} ({}B)",
            sdp_type,
            target_id,
            local_sdp.len()
        );

        let relay_msg = SdpRelay {
            from_id: self_id.to_string(),
            to_id: target_id.to_string(),
            sdp_type: sdp_type.to_string(),
            sdp: local_sdp.to_string(),
        };

        zero_crypto::cbor::to_vec(&relay_msg)
            .map_err(|e| ZeroError::Custom(format!("CBOR encode SdpRelay: {}", e)))
    }
}

impl Default for NatManager {
    fn default() -> Self {
        Self::new()
    }
}
