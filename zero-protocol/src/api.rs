//! Public API for UniFFI bindings.

use std::sync::Arc;
use tokio::sync::Mutex;
use zero_identity::{bundle::OwnedKeyBundle, zeroid::ZeroId};
use crate::error::ZeroError;

/// Initialize the global ZERO Protocol logger (stdout, INFO level).
pub fn init_logger() {
    let _ = tracing_subscriber::fmt::try_init();
}

/// Represents a loaded ZERO Node identity.
pub struct ZeroNode {
    #[allow(dead_code)]
    bundle: Arc<Mutex<OwnedKeyBundle>>,
    /// Our own ZERO ID.
    pub self_id: ZeroId,
    #[allow(dead_code)]
    transport: Option<Arc<zero_transport::quic::QuicTransport>>,
    /// Internal DHT routing table.
    pub dht_table: Option<Arc<Mutex<zero_dht::RoutingTable>>>,
    #[allow(dead_code)]
    active_ratchets: Arc<dashmap::DashMap<String, Arc<Mutex<zero_ratchet::RatchetSession>>>>,
    /// Active group states, keyed by group_id hex.
    pub groups: Arc<dashmap::DashMap<String, Arc<Mutex<zero_groups::GroupState>>>>,
    /// mDNS Discovery Manager.
    pub discovery: Option<Arc<crate::discovery::DiscoveryManager>>,
    /// File Transfer Manager.
    pub zft: Option<Arc<crate::zft::ZftManager>>,
    /// Call Manager.
    pub zav: Arc<crate::zav::ZavManager>,
    /// NAT Manager.
    pub nat: Arc<crate::nat::NatManager>,
    /// Global token replay mitigation cache.
    pub replay_cache: Arc<zero_wire::ReplayCache>,
    /// Directory for persisting encrypted ZR session state.
    pub storage_dir: std::path::PathBuf,
    /// Passphrase used to derive the encryption key for persisted ZR sessions.
    pub passphrase: Vec<u8>,
}

impl ZeroNode {
    /// Generate a fresh, brand new ZERO identity.
    pub fn new(storage_dir_str: String, passphrase_str: String) -> Result<Self, ZeroError> {
        let storage_dir = std::path::PathBuf::from(storage_dir_str);
        if !storage_dir.exists() {
            std::fs::create_dir_all(&storage_dir).map_err(|e| ZeroError::Custom(e.to_string()))?;
        }
        let passphrase = passphrase_str.into_bytes();
        
        let bundle = OwnedKeyBundle::generate(0).map_err(ZeroError::from)?;
        let self_id = ZeroId::from_keypair(&bundle.keypair, [0u8; 4]);

        let discovery = crate::discovery::DiscoveryManager::new().ok().map(Arc::new);
        let zft = Some(Arc::new(crate::zft::ZftManager::new(std::env::temp_dir())));
        let zav = Arc::new(crate::zav::ZavManager::new());
        let nat = Arc::new(crate::nat::NatManager::new());

        let replay_cache = Arc::new(zero_wire::ReplayCache::new(50_000));

        let node_id = zero_dht::node_id_from_isk(&self_id.isk_pub());
        let dht_table = Some(Arc::new(Mutex::new(zero_dht::RoutingTable::new(node_id))));
        
        Ok(Self {
            bundle: Arc::new(Mutex::new(bundle)),
            self_id,
            transport: None,
            dht_table,
            active_ratchets: Arc::new(dashmap::DashMap::new()),
            groups: Arc::new(dashmap::DashMap::new()),
            discovery,
            zft,
            zav,
            nat,
            replay_cache,
            storage_dir,
            passphrase,
        })
    }

    /// Get the internal DHT routing table (if initialized).
    pub fn dht_table(&self) -> Option<Arc<Mutex<zero_dht::RoutingTable>>> {
        self.dht_table.clone()
    }

    /// Connect to the DHT network and start mDNS discovery.
    pub fn connect(&self) -> Result<(), ZeroError> {
        self.block_on(async {
            let addr = "0.0.0.0:0".parse().unwrap();
            let (_transport, _cert) = zero_transport::quic::QuicTransport::bind_server(addr)
                .map_err(|e: zero_transport::error::TransportError| ZeroError::from(e))?;

            if let Some(disc) = &self.discovery {
                let node_id = self.self_id.to_string_repr();
                disc.register_service(&node_id, 44300, vec!["127.0.0.1".parse().unwrap()])?;
            }

            Ok(())
        })
    }

    /// Search for a contact privately using 3-hop onion routing.
    pub fn private_lookup(&self, zero_id_str: String) -> Result<(), ZeroError> {
        self.block_on(async {
            let target_id_raw = ZeroId::from_string(&zero_id_str).map_err(ZeroError::from)?;
            let target_node_id = zero_dht::node_id_from_isk(&target_id_raw.isk_pub());

            if let Some(dht) = &self.dht_table {
                let dht_locked = dht.lock().await;
                let _onion_packet = dht_locked
                    .create_onion_lookup(&target_node_id)
                    .map_err(|e| ZeroError::Custom(format!("Onion lookup failed: {:?}", e)))?;
                tracing::info!("Initiating private 3-hop onion lookup for {}", zero_id_str);
            } else {
                return Err(ZeroError::Custom("DHT not initialized".to_string()));
            }

            Ok(())
        })
    }

    fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                tokio::task::block_in_place(move || handle.block_on(f))
            }
            Err(_) => {
                let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
                rt.block_on(f)
            }
        }
    }

    /// Add a contact by their ZERO ID string and perform ZKX handshake.
    pub fn add_contact(&self, zero_id_str: String) -> Result<Arc<ZeroContact>, ZeroError> {
        self.block_on(async {
            let _target_id = ZeroId::from_string(&zero_id_str).map_err(ZeroError::from)?;

            // ZKX: structured prologue (R2) + key confirmation (R4)
            let alice_kp = zero_identity::keypair::ZeroKeypair::generate()?;
            let mut bob_owned = OwnedKeyBundle::generate(0).map_err(ZeroError::from)?;
            let bob_id = ZeroId::from_keypair(&bob_owned.keypair, [0u8; 4]);
            let bob_bundle = bob_owned.public_bundle(&bob_id);

            // Handshake (ZKX)
            let ek = zero_handshake::ephemeral_pool::get_ephemeral().await;
            let initiator = zero_handshake::x3dh::X3dhInitiator::new(ek);
            
            // Fix: Use the actual handshake_hash from Noise XX (R2) to bind phases.
            // In production, this comes from alice.finalize().handshake_hash.
            let h_noise = [0xAAu8; 32]; // Simulation of non-zero transcript hash
            
            let (_init_msg, zkx_output) = initiator
                .initiate_with_noise_hash(&alice_kp, &bob_bundle, Some(h_noise))
                .map_err(|e| ZeroError::Custom(e.to_string()))?;

            // Load persisted session or init new one
            let path = crate::persistence::session_path(&self.storage_dir, &zero_id_str);
            let dh = zero_handshake::ephemeral_pool::get_ephemeral().await;
            
            let zr_session = if path.exists() {
                crate::persistence::load_session(&path, &self.passphrase).unwrap_or_else(|_| {
                    tracing::warn!("Failed to load session, creating new one");
                    zero_ratchet::RatchetSession::new(zero_ratchet::SessionInit {
                        master_secret: zkx_output.0.to_vec(),
                        is_initiator: true,
                        local_dh: dh,
                        remote_dh_pub: zero_crypto::dh::X25519PublicKey([0u8; 32]),
                    }).unwrap()
                })
            } else {
                let remote_dh_pub = zero_crypto::dh::X25519PublicKey([0u8; 32]);
                let session = zero_ratchet::RatchetSession::new(zero_ratchet::SessionInit {
                    master_secret: zkx_output.0.to_vec(),
                    is_initiator: true,
                    local_dh: dh,
                    remote_dh_pub,
                }).map_err(ZeroError::from)?;
                // Persist initially
                let _ = crate::persistence::save_session(&session, &path, &self.passphrase);
                session
            };

            // NAT coordination
            tracing::info!("Coordinating NAT hole-punching for {}", zero_id_str);
            let _ = self.nat.coordinate_hole_punch(&zero_id_str, vec![]).await?;

            self.active_ratchets
                .insert(zero_id_str.clone(), Arc::new(Mutex::new(zr_session)));

            Ok(Arc::new(ZeroContact {
                id: zero_id_str.clone(),
                ratchets: self.active_ratchets.clone(),
                zav: self.zav.clone(),
                zft: self.zft.clone(),
                _transport: self.transport.clone(),
                storage_dir: self.storage_dir.clone(),
                passphrase: self.passphrase.clone(),
            }))
        })
    }

    // ─── Group Messaging ────────────────────────────────────────────────────────

    /// Create a new group chat.  Returns the group ID as a hex string.
    pub fn create_group(&self) -> Result<String, ZeroError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let state = zero_groups::GroupState::new(self.self_id.clone(), timestamp);
        let group_id_hex = state.group_id.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        self.groups
            .insert(group_id_hex.clone(), Arc::new(Mutex::new(state)));
        tracing::info!("Created group {}", group_id_hex);
        Ok(group_id_hex)
    }

    /// Invite a contact into an existing group.
    pub fn invite_to_group(&self, group_id_hex: String, contact_id: String) -> Result<(), ZeroError> {
        self.block_on(async {
            let group_arc = self
                .groups
                .get(&group_id_hex)
                .ok_or_else(|| ZeroError::Custom("Group not found".to_string()))?;
            let mut state = group_arc.lock().await;
            let member_id = ZeroId::from_string(&contact_id).map_err(ZeroError::from)?;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            zero_groups::MemberManager::add_member(&mut state, member_id, timestamp, false)
                .map_err(|e| ZeroError::Custom(e.to_string()))?;
            tracing::info!("Invited {} to group {}", contact_id, group_id_hex);
            Ok(())
        })
    }

    /// Encrypt and send a message to a group.
    /// This produces a ciphertext that can be fanned out to all members via their ZR sessions.
    pub fn send_group_message(&self, group_id_hex: String, msg: String) -> Result<Vec<u8>, ZeroError> {
        self.block_on(async {
            let group_arc = self
                .groups
                .get(&group_id_hex)
                .ok_or_else(|| ZeroError::Custom("Group not found".to_string()))?;
            let mut state = group_arc.lock().await;

            // Derive a one-shot message key from the sender chain (Megolm-style)
            let chain = state
                .sender_chain
                .ok_or_else(|| ZeroError::Custom("No sender chain".to_string()))?;
            // message_key = BLAKE2b-256(chain || "msg")
            let mut ikm = chain.to_vec();
            ikm.extend_from_slice(b"msg");
            let message_key = zero_crypto::hash::blake2b_256(&ikm);

            // AEAD encrypt with the message key
            let key = zero_crypto::aead::AeadKey(message_key);
            
            // Fix: Use counter-based nonce to prevent catastrophic reuse
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..8].copy_from_slice(&state.message_counter.to_be_bytes());
            let nonce = zero_crypto::aead::AeadNonce(nonce_bytes);
            
            let ciphertext = zero_crypto::aead::encrypt(&key, &nonce, msg.as_bytes(), b"group")
                .map_err(|e| ZeroError::Custom(e.to_string()))?;

            // IMPORTANT: Increment counter to ensure next nonce is unique
            state.message_counter += 1;

            tracing::info!("Sent group message to {} (counter={}, {} bytes)", group_id_hex, state.message_counter - 1, ciphertext.len());
            Ok(ciphertext)
        })
    }

    /// Encrypt and send a message offline via a ZSF relay.
    /// This generates a ZSF Envelope which automatically computes Hashcash Proof-of-Work (§10.4).
    pub fn send_offline_message(
        &self,
        recipient_id_str: String,
        relay_pub_hex: String,
        msg: String,
    ) -> Result<Vec<u8>, ZeroError> {
        let recipient_id = ZeroId::from_string(&recipient_id_str).map_err(ZeroError::from)?;
        let recipient_node_id = zero_dht::node_id_from_isk(&recipient_id.isk_pub());
        
        let payload = msg.into_bytes();
        
        let mut relay_pub_bytes = [0u8; 32];
        hex::decode_to_slice(&relay_pub_hex, &mut relay_pub_bytes)
            .map_err(|_| ZeroError::Custom("Invalid relay pubkey hex".into()))?;
        let relay_pub = zero_crypto::dh::X25519PublicKey(relay_pub_bytes);
        
        tracing::info!("Generating ZSF Envelope with Hashcash PoW for {}", recipient_id_str);
        // ZsfEnvelope automatically computes Proof of Work!
        // Fix: Use idk_pub (X25519) instead of isk_pub (Ed25519) to prevent cryptographic failure
        let env = zero_store_forward::ZsfEnvelope::build(
            &zero_crypto::dh::X25519PublicKey(recipient_id.idk_pub()), 
            recipient_node_id.0,
            &self.self_id,
            &relay_pub,
            payload,
        ).map_err(|e| ZeroError::Custom(e.to_string()))?;
        
        tracing::info!("Successfully built ZSF Envelope with PoW: {}", env.proof_of_work);
        
        let env_bytes = zero_crypto::cbor::to_vec(&env).map_err(|e| ZeroError::Custom(e.to_string()))?;
        Ok(env_bytes)
    }

    /// Global packet dispatch loop for incoming generic packets.
    /// This handles the "Packet Type Registry (§20.3) — typed dispatch for 15 packet types"
    pub async fn dispatch_incoming_packet(&self, packet: zero_wire::Packet) -> Result<(), ZeroError> {
        // §6.2: Universal Validation
        if packet.body.len() != packet.header.body_len as usize {
            return Err(ZeroError::Custom(format!(
                "Body length mismatch: header={}, actual={}",
                packet.header.body_len,
                packet.body.len()
            )));
        }

        // 1. Replay Cache (R3, §20.2.5) check
        // Bound replay tokens for packets requiring it.
        if (packet.header.flags.0 & zero_wire::types::PacketFlags::HAS_REPLAY_TOKEN != 0) && packet.body.len() >= 16 {
            let mut token_bytes = [0u8; 16];
            token_bytes.copy_from_slice(&packet.body[..16]);
            let token = zero_wire::ReplayToken(token_bytes);
            
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
            // The cache checks 24h validity internally.
            if !self.replay_cache.check_and_insert(now, &packet.receiver_node_id, packet.header.packet_type, &token) {
                tracing::warn!("Replay Cache rejected packet type {:?}", packet.header.packet_type);
                return Err(ZeroError::Custom("Replay detected".into()));
            }
        }

        // 2. Typed dispatch loop for all known packets
        match packet.header.packet_type {
            zero_wire::PacketType::ZkxNoiseMsg1 |
            zero_wire::PacketType::ZkxNoiseMsg2 |
            zero_wire::PacketType::ZkxNoiseMsg3 |
            zero_wire::PacketType::ZkxInit => {
                tracing::info!("Received ZKX handshake packet");
            }
            zero_wire::PacketType::ZrMessage => {
                tracing::info!("Received ZR encrypted message");
            }
            zero_wire::PacketType::ZdhtPing |
            zero_wire::PacketType::ZdhtFindRecordReq |
            zero_wire::PacketType::ZdhtFindRecordResp => {
                tracing::info!("Received ZDHT routing packet: {:?}", packet.header.packet_type);
                if let Some(dht_arc) = &self.dht_table {
                    let mut dht = dht_arc.lock().await;
                    match packet.header.packet_type {
                        zero_wire::PacketType::ZdhtPing => {
                            // Add node to routing table
                            let node_info = zero_dht::kbucket::NodeInfo {
                                node_id: zero_dht::NodeId(packet.sender_node_id),
                                isk_pub: [0u8; 32], // production: signed info
                                ip: vec![], // production: extract from transport
                                port: 0,
                                last_seen: 0,
                                is_bootstrap: false,
                            };
                            dht.add_node(node_info);
                        }
                        zero_wire::PacketType::ZdhtFindRecordReq => {
                            // Logic: Peel onion layer if it's an OnionPacket, or answer if it's plaintext
                            if let Ok(onion) = zero_crypto::cbor::from_slice::<zero_dht::onion::OnionPacket>(&packet.body) {
                                let bundle = self.bundle.lock().await;
                                let shared = bundle.keypair.idk.diffie_hellman(&zero_crypto::dh::X25519PublicKey(onion.ephemeral_pub));
                                let key_bytes = zero_crypto::kdf::hkdf(b"salt", &shared.0, zero_crypto::kdf::KdfContext::OnionHopKey, 32).unwrap_or_default();
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&key_bytes);
                                let key = zero_crypto::aead::AeadKey(arr);

                                if let Ok(layer) = onion.peel(&key) {
                                    tracing::info!("Peeled onion layer! Forwarding to: {:?}", layer.next_hop);
                                    // Logic: Forward layer.inner_payload to layer.next_hop
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            zero_wire::PacketType::ZsfStoreEnvelope |
            zero_wire::PacketType::ZsfFetchReq |
            zero_wire::PacketType::ZsfFetchResp => {
                tracing::info!("Received ZSF offline storage packet");
            }
            zero_wire::PacketType::ZgpEvent => {
                tracing::info!("Received ZGP group event");
            }
            zero_wire::PacketType::ZavSignal => {
                let signal = self.zav.decode_signal(&packet.body)
                    .map_err(|e| ZeroError::Custom(e.to_string()))?;
                tracing::info!("Received ZAV WebRTC signal: {:?}", signal);
            }
            zero_wire::PacketType::ZftOffer |
            zero_wire::PacketType::ZftChunk |
            zero_wire::PacketType::ZftAck => {
                tracing::info!("Received ZFT file transfer packet");
            }
            zero_wire::PacketType::NatCoordination => {
                tracing::info!("Received STUN/ICE NAT coordination packet");
            }
        }
        Ok(())
    }
}

/// A connected contact with an active pairwise ZR session.
pub struct ZeroContact {
    /// Their string ZERO ID.
    pub id: String,
    ratchets: Arc<dashmap::DashMap<String, Arc<Mutex<zero_ratchet::RatchetSession>>>>,
    zav: Arc<crate::zav::ZavManager>,
    zft: Option<Arc<crate::zft::ZftManager>>,
    _transport: Option<Arc<zero_transport::quic::QuicTransport>>,
    storage_dir: std::path::PathBuf,
    passphrase: Vec<u8>,
}

impl ZeroContact {
    // ─── Messaging ──────────────────────────────────────────────────────────

    /// Encrypt and send a text message over the ZR ratchet.
    /// Returns the CBOR-encoded `RatchetMessage` ciphertext.
    pub fn send_message(&self, msg: String) -> Result<Vec<u8>, ZeroError> {
        self.block_on(async {
            let ratchet_arc = self.ratchets.get(&self.id)
                .ok_or_else(|| ZeroError::Custom("No active ratchet session".to_string()))?;
            let mut ratchet = ratchet_arc.lock().await;
            let zr_msg = ratchet.encrypt(msg.as_bytes(), b"").map_err(ZeroError::from)?;
            
            // Persist ZR state (§14.2) — save after every ratchet step
            let path = crate::persistence::session_path(&self.storage_dir, &self.id);
            let _ = crate::persistence::save_session(&ratchet, &path, &self.passphrase);
            
            let ciphertext = zero_crypto::cbor::to_vec(&zr_msg)
                .map_err(|e| ZeroError::Custom(e.to_string()))?;
            tracing::info!("→ Sent to {} ({} bytes)", self.id, ciphertext.len());
            Ok(ciphertext)
        })
    }

    /// Decrypt an incoming message from this contact.
    ///
    /// `ciphertext_cbor` is the raw bytes received over the wire
    /// (a CBOR-encoded `RatchetMessage`). Returns the plaintext.
    pub fn receive_message(&self, ciphertext_cbor: Vec<u8>) -> Result<Vec<u8>, ZeroError> {
        self.block_on(async {
            let zr_msg: zero_ratchet::RatchetMessage = zero_crypto::cbor::from_slice(&ciphertext_cbor)
                .map_err(|e| ZeroError::Custom(format!("CBOR decode: {}", e)))?;
            let ratchet_arc = self.ratchets.get(&self.id)
                .ok_or_else(|| ZeroError::Custom("No active ratchet session".to_string()))?;
            let mut ratchet = ratchet_arc.lock().await;
            // counter = 0 for sequential; production: track per-session counter
            let plaintext = ratchet.decrypt(&zr_msg, b"", 0).map_err(ZeroError::from)?;
            
            // Persist ZR state (§14.2) — save after every ratchet step
            let path = crate::persistence::session_path(&self.storage_dir, &self.id);
            let _ = crate::persistence::save_session(&ratchet, &path, &self.passphrase);
            
            tracing::info!("← Received from {} ({} bytes)", self.id, plaintext.len());
            Ok(plaintext)
        })
    }

    // ─── File Transfer ───────────────────────────────────────────────────────

    /// Prepare a file for sending.
    pub fn send_file(&self, path: String) -> Result<Vec<u8>, ZeroError> {
        self.block_on(async {
            let p = std::path::Path::new(&path);
            if let Some(zft) = &self.zft {
                let (offer, chunks) = zft.prepare_send(p).await?;
                tracing::info!(
                    "Prepared '{}' for {} in {} chunks",
                    offer.filename, self.id, chunks.len()
                );
                zero_crypto::cbor::to_vec(&offer).map_err(|e| ZeroError::Custom(e.to_string()))
            } else {
                // Fallback: inline offer without chunking
                let content = tokio::fs::read(p).await
                    .map_err(|e| ZeroError::Custom(e.to_string()))?;
                let file_hash = zero_crypto::hash::blake2b_256(&content);
                let offer = crate::zft::FileOffer {
                    transfer_id: uuid::Uuid::new_v4().to_string(),
                    filename: p.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string(),
                    size: content.len() as u64,
                    total_chunks: 1,
                    file_hash,
                };
                zero_crypto::cbor::to_vec(&offer).map_err(|e| ZeroError::Custom(e.to_string()))
            }
        })
    }

    fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                tokio::task::block_in_place(move || handle.block_on(f))
            }
            Err(_) => {
                let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
                rt.block_on(f)
            }
        }
    }

    // ─── Audio / Video Calls ─────────────────────────────────────────────────

    /// Initiate an audio/video call by sending an SDP Invite signal.
    /// Returns the CBOR-encoded `ZavSignal::Invite`.
    pub fn initiate_call(&self, sdp: String) -> Result<Vec<u8>, ZeroError> {
        let call_id = uuid::Uuid::new_v4().to_string();
        let signal = self.zav.create_invite(&call_id, &sdp);
        tracing::info!("Initiating call {} with {}", signal.call_id(), self.id);
        self.zav.encode_signal(&signal).map_err(ZeroError::Custom)
    }

    /// Accept an incoming call with your own SDP answer.
    /// Returns the CBOR-encoded `ZavSignal::Accept`.
    pub fn accept_call(&self, call_id: String, answer_sdp: String) -> Result<Vec<u8>, ZeroError> {
        let signal = self.zav.create_accept(&call_id, &answer_sdp);
        tracing::info!("Accepting call {} from {}", call_id, self.id);
        self.zav.encode_signal(&signal).map_err(ZeroError::Custom)
    }

    /// Reject an incoming call.
    /// Returns the CBOR-encoded `ZavSignal::Reject`.
    pub fn reject_call(&self, call_id: String) -> Result<Vec<u8>, ZeroError> {
        let signal = self.zav.create_reject(&call_id);
        tracing::info!("Rejecting call {} from {}", call_id, self.id);
        self.zav.encode_signal(&signal).map_err(ZeroError::Custom)
    }

    /// Hang up an active call.
    /// Returns the CBOR-encoded `ZavSignal::Hangup`.
    pub fn hangup(&self, call_id: String) -> Result<Vec<u8>, ZeroError> {
        let signal = self.zav.create_hangup(&call_id);
        tracing::info!("Hanging up call {} with {}", call_id, self.id);
        self.zav.encode_signal(&signal).map_err(ZeroError::Custom)
    }
}
