//! ZAV — ZERO Audio/Video Signaling.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};


/// ZAV Signal types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZavSignal {
    Invite { call_id: String, sdp: String },
    Accept { call_id: String, sdp: String },
    Reject { call_id: String },
    IceCandidate { call_id: String, candidate: String },
    Hangup { call_id: String },
}

/// Manages A/V call signaling.
pub struct ZavManager;

impl ZavManager {
    /// Create a new ZAV call manager.
    pub fn new() -> Self {
        Self
    }

    /// Create an invite signal.
    pub fn create_invite(&self, call_id: &str, sdp: &str) -> ZavSignal {
        ZavSignal::Invite {
            call_id: call_id.to_string(),
            sdp: sdp.to_string(),
        }
    }
}
