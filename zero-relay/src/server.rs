//! Relay server daemon.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use crate::error::RelayError;

/// Relay Server Configuration.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Max active connections.
    pub max_connections: usize,
    /// Keep-alive timeout in seconds.
    pub keepalive_timeout: u64,
}

/// A blind TCP relay server.
/// The ZERO relay server implementation.
pub struct RelayServer {
    /// Configuration for this relay server.
    pub config: RelayConfig,
    /// Maps NodeID -> Tx channel connecting to their socket.
    pub routes: Arc<tokio::sync::Mutex<HashMap<[u8; 32], mpsc::Sender<Vec<u8>>>>>,
}

impl RelayServer {
    /// Create a new relay server instance.
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            routes: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Route a payload to a connected client.
    pub async fn route(&self, dest: &[u8; 32], payload: Vec<u8>) -> Result<(), RelayError> {
        let mut routes = self.routes.lock().await;
        if let Some(tx) = routes.get_mut(dest) {
            tx.send(payload).await.map_err(|_| RelayError::RouteNotFound)?;
            Ok(())
        } else {
            Err(RelayError::RouteNotFound)
        }
    }
}
