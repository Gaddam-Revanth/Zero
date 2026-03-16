//! ZDHT Onion Routing stub.
//!
//! 3-hop onion routing for FIND_RECORD requests to hide
//! the searcher's IP address from the target node.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnionRequest {
    // To be implemented: 3 layers of crypto wrapping
    pub payload: Vec<u8>,
}

pub fn create_onion_request() -> OnionRequest {
    OnionRequest { payload: vec![] }
}
