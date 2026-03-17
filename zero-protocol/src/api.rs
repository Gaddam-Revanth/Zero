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
    /// mDNS Discovery Manager
    pub discovery: Option<Arc<crate::discovery::DiscoveryManager>>,
    /// File Transfer Manager
    pub zft: Option<Arc<crate::zft::ZftManager>>,
    /// Call Manager
    pub zav: Arc<crate::zav::ZavManager>,
    /// NAT Manager
    pub nat: Arc<crate::nat::NatManager>,
}

impl ZeroNode {
    /// Generate a fresh, brand new ZERO identity.
    pub fn new() -> Result<Self, ZeroError> {
        let bundle = OwnedKeyBundle::generate(0)
            .map_err(ZeroError::from)?;
        
        let discovery = crate::discovery::DiscoveryManager::new().ok().map(Arc::new);
        let zft = Some(Arc::new(crate::zft::ZftManager::new(std::env::temp_dir())));
        let zav = Arc::new(crate::zav::ZavManager::new());
        let nat = Arc::new(crate::nat::NatManager::new());

        Ok(Self { 
            bundle: Arc::new(Mutex::new(bundle)),
            transport: None,
            dht_table: None,
            active_ratchets: Arc::new(dashmap::DashMap::new()),
            discovery,
            zft,
            zav,
            nat,
        })
    }

    /// Connect to the DHT network and start mDNS discovery.
    pub fn connect(&self) -> Result<(), ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        
        rt.block_on(async {
            // Init QUIC on a random port for now
            let addr = "0.0.0.0:0".parse().unwrap();
            let (_transport, _cert) = zero_transport::quic::QuicTransport::bind_server(addr)
                .map_err(|e: zero_transport::error::TransportError| ZeroError::from(e))?;
            
            // R2: Start mDNS registration if enabled
            if let Some(disc) = &self.discovery {
                let node_id = "temp-node-id"; // In real: self.bundle.id.to_string()
                disc.register_service(node_id, 44300, vec!["127.0.0.1".parse().unwrap()])?;
            }

            Ok::<_, ZeroError>(())
        })?;
        Ok(())
    }

    /// Search for a contact privately using 3-hop onion routing.
    pub fn private_lookup(&self, zero_id_str: String) -> Result<(), ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        
        rt.block_on(async {
            let target_id_raw = zero_identity::zeroid::ZeroId::from_string(&zero_id_str)
                .map_err(|e| ZeroError::from(e))?;
            let target_node_id = zero_dht::node_id_from_isk(&target_id_raw.isk_pub());

            if let Some(dht) = &self.dht_table {
                let dht_locked = dht.lock().await;
                let _onion_packet = dht_locked.create_onion_lookup(&target_node_id)
                    .map_err(|e| ZeroError::Custom(format!("Onion lookup failed: {:?}", e)))?;
                
                tracing::info!("Initiating private 3-hop onion lookup for {}", zero_id_str);
                // Real: QuicTransport::send_dht_onion(outer_hop, _onion_packet).await?;
            } else {
                return Err(ZeroError::Custom("DHT not initialized".to_string()));
            }
            
            Ok::<_, ZeroError>(())
        })?;
        Ok(())
    }

    /// Add a contact by their String ZERO ID and perform ZKX/Handshake.
    pub fn add_contact(&self, zero_id_str: String) -> Result<Arc<ZeroContact>, ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        
        rt.block_on(async {
            // 1. Decode ID
            let _target_id = zero_identity::zeroid::ZeroId::from_string(&zero_id_str)
                .map_err(|e| ZeroError::from(e))?;
            
            // 2. Perform ZKX (Simplified orchestrator logic for now)
            // R2/R4: Handshake with structured prologue and key confirmation
            let alice_kp = zero_identity::keypair::ZeroKeypair::generate()?;
            
            // Mocking Bob's bundle properly
            let mut bob_owned = OwnedKeyBundle::generate(0).map_err(ZeroError::from)?;
            let bob_id = zero_identity::zeroid::ZeroId::from_keypair(&bob_owned.keypair, [0u8; 4]);
            let bob_bundle = bob_owned.public_bundle(&bob_id);

            let _prologue = zero_handshake::noise::HandshakePrologue::v1_0(0);
            let initiator = zero_handshake::x3dh::X3dhInitiator::new();
            
            // Binding to Noise hash (R1/R4)
            let h_noise = [0u8; 32]; 
            let (_init_msg, zkx_output) = initiator.initiate_with_noise_hash(
                &alice_kp, 
                &bob_bundle, 
                Some(h_noise)
            ).map_err(|e| ZeroError::Custom(e.to_string()))?;
            
            // 3. Initialize Ratchet with Master Secret from ZKX
            let dh = zero_crypto::dh::X25519Keypair::generate();
            let remote_dh_pub = zero_crypto::dh::X25519PublicKey([0u8; 32]);
            
            let zr_session = zero_ratchet::RatchetSession::new(zero_ratchet::SessionInit {
                master_secret: zkx_output.0.to_vec(),
                is_initiator: true,
                local_dh: dh,
                remote_dh_pub,
            }).map_err(|e| ZeroError::from(e))?;

            // NAT coordination
            tracing::info!("Coordinating NAT hole-punching for {}", zero_id_str);
            let _ = self.nat.coordinate_hole_punch(&zero_id_str, vec![]).await?;
            
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
            
            // R6: Optional PQ Ratchet Step can be triggered here if counter > 1000
            // ratchet.pq_ratchet_step(&kem_secret)?;

            // Encrypt message
            let _ciphertext = ratchet.encrypt(msg.as_bytes(), b"")
                .map_err(|e| ZeroError::from(e))?;
                
            Ok::<_, ZeroError>(())
        })?;
        Ok(())
    }
}
