//! TCP Relay protocol layout (CBOR).

use serde::{Deserialize, Serialize};

/// Relay connection commands.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayCommand {
    /// Register a NodeID on this relay.
    Register {
        /// The node's ID.
        node_id: [u8; 32],
        /// Proof of work or auth (omitted for brevity).
        auth: Vec<u8>,
    },
    /// Route an opaque payload to another node.
    Route {
        /// Destination node ID.
        dest: [u8; 32],
        /// The completely opaque ZR/ZSF encrypted message.
        payload: Vec<u8>,
    },
}
