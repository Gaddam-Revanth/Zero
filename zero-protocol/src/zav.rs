//! ZAV — ZERO Audio/Video Signaling.
//!
//! Complete lifecycle: Invite → Accept/Reject → ICE exchange → Hangup.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

/// ZAV Signal types covering the full WebRTC call lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZavSignal {
    /// Caller sends an SDP offer to the callee.
    Invite { call_id: String, sdp: String },
    /// Callee accepts the call, returning an SDP answer.
    Accept { call_id: String, sdp: String },
    /// Callee rejects the call.
    Reject { call_id: String },
    /// Either party sends an ICE candidate for NAT traversal.
    IceCandidate { call_id: String, candidate: String },
    /// Either party terminates the call.
    Hangup { call_id: String },
}

impl ZavSignal {
    /// Extract the call_id from any signal variant.
    pub fn call_id(&self) -> &str {
        match self {
            ZavSignal::Invite   { call_id, .. } => call_id,
            ZavSignal::Accept   { call_id, .. } => call_id,
            ZavSignal::Reject   { call_id, .. } => call_id,
            ZavSignal::IceCandidate { call_id, .. } => call_id,
            ZavSignal::Hangup   { call_id, .. } => call_id,
        }
    }
}

/// Manages A/V call signaling state.
pub struct ZavManager;

impl ZavManager {
    /// Create a new ZAV call manager.
    pub fn new() -> Self { Self }

    /// Create an SDP Invite signal (caller → callee).
    pub fn create_invite(&self, call_id: &str, sdp: &str) -> ZavSignal {
        ZavSignal::Invite { call_id: call_id.to_string(), sdp: sdp.to_string() }
    }

    /// Create an SDP Accept signal (callee → caller), completing the WebRTC handshake.
    pub fn create_accept(&self, call_id: &str, answer_sdp: &str) -> ZavSignal {
        ZavSignal::Accept { call_id: call_id.to_string(), sdp: answer_sdp.to_string() }
    }

    /// Create a Reject signal if the callee declines.
    pub fn create_reject(&self, call_id: &str) -> ZavSignal {
        ZavSignal::Reject { call_id: call_id.to_string() }
    }

    /// Create an ICE candidate signal to assist NAT traversal.
    pub fn create_ice_candidate(&self, call_id: &str, candidate: &str) -> ZavSignal {
        ZavSignal::IceCandidate { call_id: call_id.to_string(), candidate: candidate.to_string() }
    }

    /// Create a Hangup signal to end the call.
    pub fn create_hangup(&self, call_id: &str) -> ZavSignal {
        ZavSignal::Hangup { call_id: call_id.to_string() }
    }

    /// Serialize any signal to CBOR bytes for transport over ZR or ZSF.
    pub fn encode_signal(&self, signal: &ZavSignal) -> Result<Vec<u8>, String> {
        serde_cbor::to_vec(signal).map_err(|e| e.to_string())
    }

    /// Deserialize a ZavSignal from CBOR bytes.
    pub fn decode_signal(&self, bytes: &[u8]) -> Result<ZavSignal, String> {
        serde_cbor::from_slice(bytes).map_err(|e| e.to_string())
    }
}

impl Default for ZavManager {
    fn default() -> Self { Self::new() }
}
