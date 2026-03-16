//! Public API for UniFFI bindings.

use std::sync::Arc;
use tokio::sync::Mutex;
use zero_identity::{bundle::OwnedKeyBundle};
use crate::error::ZeroError;

/// Initialize the global ZERO Protocol logger.
pub fn init_logger() {
    // Stub for now.
}

/// Represents a loaded ZERO Node identity.
pub struct ZeroNode {
    #[allow(dead_code)]
    bundle: Arc<Mutex<OwnedKeyBundle>>,
}

impl ZeroNode {
    /// Generate a fresh, brand new ZERO identity.
    pub fn new() -> Result<Self, ZeroError> {
        let bundle = OwnedKeyBundle::generate(0)
            .map_err(ZeroError::from)?;
        Ok(Self { bundle: Arc::new(Mutex::new(bundle)) })
    }

    /// Connect to the DHT network.
    pub fn connect(&self) -> Result<(), ZeroError> {
        // Init QUIC + DHT sockets, connect to bootstrap nodes
        Ok(())
    }

    /// Add a contact by their String ZERO ID.
    pub fn add_contact(&self, _zero_id_str: String) -> Result<Arc<ZeroContact>, ZeroError> {
        // Fetch bundle from DHT, start ZKX
        Ok(Arc::new(ZeroContact { id: _zero_id_str }))
    }
}

/// A connected contact.
pub struct ZeroContact {
    /// Their string ZERO ID.
    pub id: String,
}

impl ZeroContact {
    /// Send a text message to this contact.
    pub fn send_message(&self, _msg: String) -> Result<(), ZeroError> {
        // Pass through ZR ratchet -> Transport -> QUIC
        Ok(())
    }
}
