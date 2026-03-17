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
    #[allow(dead_code)]
    transport: Option<Arc<zero_transport::quic::QuicTransport>>,
    #[allow(dead_code)]
    dht_table: Option<Arc<Mutex<zero_dht::RoutingTable>>>,
    #[allow(dead_code)]
    active_ratchets: Arc<dashmap::DashMap<String, Arc<Mutex<zero_ratchet::RatchetSession>>>>,
}

impl ZeroNode {
    /// Generate a fresh, brand new ZERO identity.
    pub fn new() -> Result<Self, ZeroError> {
        let bundle = OwnedKeyBundle::generate(0)
            .map_err(ZeroError::from)?;
        Ok(Self { 
            bundle: Arc::new(Mutex::new(bundle)),
            transport: None,
            dht_table: None,
            active_ratchets: Arc::new(dashmap::DashMap::new()),
        })
    }

    /// Connect to the DHT network.
    pub fn connect(&self) -> Result<(), ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        
        rt.block_on(async {
            // Init QUIC on a random port for now
            let addr = "0.0.0.0:0".parse().unwrap();
            let (_transport, _cert) = zero_transport::quic::QuicTransport::bind_server(addr)
                .map_err(|e| ZeroError::from(e))?;
                
            // Let's change the struct fields to be wrapped in Mutex, or we just leave it as stub for the uniffi layer for now.
            Ok::<_, ZeroError>(())
        })?;
        Ok(())
    }

    /// Add a contact by their String ZERO ID.
    pub fn add_contact(&self, zero_id_str: String) -> Result<Arc<ZeroContact>, ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        
        rt.block_on(async {
            // 1. Decode ID
            let _target_id = zero_identity::zeroid::ZeroId::from_string(&zero_id_str)
                .map_err(|e| ZeroError::from(e))?;
                
            // 2. DHT lookup (stubbed)
            // let target_record = self.dht_table.lookup(&target_id)...
            
            // 3. ZKX handshake over QUIC (stubbed for orchestrator tests)
            // let mut zr_session = perform_zkx(transport, target_record).await?;
            
            // 4. Initialize dummy Ratchet locally for now
            let dummy_ms = [0u8; 32];
            let dh = zero_crypto::dh::X25519Keypair::generate();
            let remote_dh_pub = zero_crypto::dh::X25519PublicKey([0u8; 32]);
            
            let zr_session = zero_ratchet::RatchetSession::new(zero_ratchet::SessionInit {
                master_secret: dummy_ms.to_vec(),
                is_initiator: true,
                local_dh: dh,
                remote_dh_pub,
            }).expect("Valid dummy session");
            
            self.active_ratchets.insert(
                zero_id_str.clone(), 
                Arc::new(Mutex::new(zr_session))
            );
            
            Ok::<_, ZeroError>(())
        })?;
        
        Ok(Arc::new(ZeroContact { 
            id: zero_id_str,
            ratchets: self.active_ratchets.clone(),
            _transport: self.transport.clone(),
        }))
    }
}

/// A connected contact.
pub struct ZeroContact {
    /// Their string ZERO ID.
    pub id: String,
    ratchets: Arc<dashmap::DashMap<String, Arc<Mutex<zero_ratchet::RatchetSession>>>>,
    _transport: Option<Arc<zero_transport::quic::QuicTransport>>,
}

impl ZeroContact {
    /// Send a text message to this contact.
    pub fn send_message(&self, msg: String) -> Result<(), ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        
        rt.block_on(async {
            let ratchet_arc = self.ratchets.get(&self.id)
                .ok_or_else(|| ZeroError::Custom("No active ratchet session".to_string()))?;
                
            let mut ratchet: tokio::sync::MutexGuard<'_, zero_ratchet::RatchetSession> = ratchet_arc.lock().await;
            
            // Encrypt message
            let _ciphertext = ratchet.encrypt(msg.as_bytes(), b"")
                .map_err(|e| ZeroError::from(e))?;
                
            // In a real implementation:
            // let transport = self.transport.as_ref().unwrap();
            // let conn = get_active_connection(&self.id);
            // QuicTransport::send_packet(conn, header, ciphertext_bytes).await?;
            
            Ok::<_, ZeroError>(())
        })?;
        Ok(())
    }
}
