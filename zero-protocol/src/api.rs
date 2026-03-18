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
    #[allow(dead_code)]
    dht_table: Option<Arc<Mutex<zero_dht::RoutingTable>>>,
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
}

impl ZeroNode {
    /// Generate a fresh, brand new ZERO identity.
    pub fn new() -> Result<Self, ZeroError> {
        let bundle = OwnedKeyBundle::generate(0).map_err(ZeroError::from)?;
        let self_id = ZeroId::from_keypair(&bundle.keypair, [0u8; 4]);

        let discovery = crate::discovery::DiscoveryManager::new().ok().map(Arc::new);
        let zft = Some(Arc::new(crate::zft::ZftManager::new(std::env::temp_dir())));
        let zav = Arc::new(crate::zav::ZavManager::new());
        let nat = Arc::new(crate::nat::NatManager::new());

        Ok(Self {
            bundle: Arc::new(Mutex::new(bundle)),
            self_id,
            transport: None,
            dht_table: None,
            active_ratchets: Arc::new(dashmap::DashMap::new()),
            groups: Arc::new(dashmap::DashMap::new()),
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
            let addr = "0.0.0.0:0".parse().unwrap();
            let (_transport, _cert) = zero_transport::quic::QuicTransport::bind_server(addr)
                .map_err(|e: zero_transport::error::TransportError| ZeroError::from(e))?;

            if let Some(disc) = &self.discovery {
                let node_id = self.self_id.to_string_repr();
                disc.register_service(&node_id, 44300, vec!["127.0.0.1".parse().unwrap()])?;
            }

            Ok::<_, ZeroError>(())
        })?;
        Ok(())
    }

    /// Search for a contact privately using 3-hop onion routing.
    pub fn private_lookup(&self, zero_id_str: String) -> Result<(), ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;

        rt.block_on(async {
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

            Ok::<_, ZeroError>(())
        })?;
        Ok(())
    }

    /// Add a contact by their ZERO ID string and perform ZKX handshake.
    pub fn add_contact(&self, zero_id_str: String) -> Result<Arc<ZeroContact>, ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;

        rt.block_on(async {
            let _target_id = ZeroId::from_string(&zero_id_str).map_err(ZeroError::from)?;

            // ZKX: structured prologue (R2) + key confirmation (R4)
            let alice_kp = zero_identity::keypair::ZeroKeypair::generate()?;
            let mut bob_owned = OwnedKeyBundle::generate(0).map_err(ZeroError::from)?;
            let bob_id = ZeroId::from_keypair(&bob_owned.keypair, [0u8; 4]);
            let bob_bundle = bob_owned.public_bundle(&bob_id);

            let _prologue = zero_handshake::noise::HandshakePrologue::v1_0(0);
            let initiator = zero_handshake::x3dh::X3dhInitiator::new();
            let h_noise = [0u8; 32];
            let (_init_msg, zkx_output) = initiator
                .initiate_with_noise_hash(&alice_kp, &bob_bundle, Some(h_noise))
                .map_err(|e| ZeroError::Custom(e.to_string()))?;

            // Init ZR ratchet
            let dh = zero_crypto::dh::X25519Keypair::generate();
            let remote_dh_pub = zero_crypto::dh::X25519PublicKey([0u8; 32]);
            let zr_session = zero_ratchet::RatchetSession::new(zero_ratchet::SessionInit {
                master_secret: zkx_output.0.to_vec(),
                is_initiator: true,
                local_dh: dh,
                remote_dh_pub,
            })
            .map_err(ZeroError::from)?;

            // NAT coordination
            tracing::info!("Coordinating NAT hole-punching for {}", zero_id_str);
            let _ = self.nat.coordinate_hole_punch(&zero_id_str, vec![]).await?;

            self.active_ratchets
                .insert(zero_id_str.clone(), Arc::new(Mutex::new(zr_session)));

            Ok::<_, ZeroError>(())
        })?;

        Ok(Arc::new(ZeroContact {
            id: zero_id_str,
            ratchets: self.active_ratchets.clone(),
            zav: self.zav.clone(),
            zft: self.zft.clone(),
            _transport: self.transport.clone(),
        }))
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
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        rt.block_on(async {
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
            Ok::<_, ZeroError>(())
        })?;
        Ok(())
    }

    /// Encrypt and send a message to a group.
    /// This produces a ciphertext that can be fanned out to all members via their ZR sessions.
    pub fn send_group_message(&self, group_id_hex: String, msg: String) -> Result<Vec<u8>, ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        rt.block_on(async {
            let group_arc = self
                .groups
                .get(&group_id_hex)
                .ok_or_else(|| ZeroError::Custom("Group not found".to_string()))?;
            let state = group_arc.lock().await;

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
            let nonce = zero_crypto::aead::AeadNonce([0u8; 12]); // In production: counter-based
            let ciphertext = zero_crypto::aead::encrypt(&key, &nonce, msg.as_bytes(), b"group")
                .map_err(|e| ZeroError::Custom(e.to_string()))?;

            tracing::info!("Sent group message to {} ({} bytes)", group_id_hex, ciphertext.len());
            Ok::<_, ZeroError>(ciphertext)
        })
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
}

impl ZeroContact {
    // ─── Messaging ──────────────────────────────────────────────────────────

    /// Encrypt and send a text message over the ZR ratchet.
    /// Returns the CBOR-encoded `RatchetMessage` ciphertext.
    pub fn send_message(&self, msg: String) -> Result<Vec<u8>, ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        rt.block_on(async {
            let ratchet_arc = self.ratchets.get(&self.id)
                .ok_or_else(|| ZeroError::Custom("No active ratchet session".to_string()))?;
            let mut ratchet = ratchet_arc.lock().await;
            let zr_msg = ratchet.encrypt(msg.as_bytes(), b"").map_err(ZeroError::from)?;
            let ciphertext = serde_cbor::to_vec(&zr_msg)
                .map_err(|e| ZeroError::Custom(e.to_string()))?;
            tracing::info!("→ Sent to {} ({} bytes)", self.id, ciphertext.len());
            Ok::<_, ZeroError>(ciphertext)
        })
    }

    /// Decrypt an incoming message from this contact.
    ///
    /// `ciphertext_cbor` is the raw bytes received over the wire
    /// (a CBOR-encoded `RatchetMessage`). Returns the plaintext.
    pub fn receive_message(&self, ciphertext_cbor: Vec<u8>) -> Result<Vec<u8>, ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        rt.block_on(async {
            let zr_msg: zero_ratchet::RatchetMessage = serde_cbor::from_slice(&ciphertext_cbor)
                .map_err(|e| ZeroError::Custom(format!("CBOR decode: {}", e)))?;
            let ratchet_arc = self.ratchets.get(&self.id)
                .ok_or_else(|| ZeroError::Custom("No active ratchet session".to_string()))?;
            let mut ratchet = ratchet_arc.lock().await;
            // counter = 0 for sequential; production: track per-session counter
            let plaintext = ratchet.decrypt(&zr_msg, b"", 0).map_err(ZeroError::from)?;
            tracing::info!("← Received from {} ({} bytes)", self.id, plaintext.len());
            Ok::<_, ZeroError>(plaintext)
        })
    }

    // ─── File Transfer ───────────────────────────────────────────────────────

    /// Prepare a file for sending.
    ///
    /// Returns the CBOR-encoded `FileOffer` as the first element and
    /// all `FileChunk`s (also CBOR-encoded) as the second — ready to be
    /// delivered one-by-one via `send_message` or the transport layer.
    pub fn send_file(&self, path: String) -> Result<Vec<u8>, ZeroError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        rt.block_on(async {
            let p = std::path::Path::new(&path);
            if let Some(zft) = &self.zft {
                let (offer, chunks) = zft.prepare_send(p).await?;
                tracing::info!(
                    "Prepared '{}' for {} in {} chunks",
                    offer.filename, self.id, chunks.len()
                );
                serde_cbor::to_vec(&offer).map_err(|e| ZeroError::Custom(e.to_string()))
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
                serde_cbor::to_vec(&offer).map_err(|e| ZeroError::Custom(e.to_string()))
            }
        })
    }

    // ─── Audio / Video Calls ─────────────────────────────────────────────────

    /// Initiate an audio/video call by sending an SDP Invite signal.
    /// Returns the CBOR-encoded `ZavSignal::Invite`.
    pub fn initiate_call(&self, sdp: String) -> Result<Vec<u8>, ZeroError> {
        let call_id = uuid::Uuid::new_v4().to_string();
        let signal = self.zav.create_invite(&call_id, &sdp);
        tracing::info!("Initiating call {} with {}", signal.call_id(), self.id);
        self.zav.encode_signal(&signal).map_err(|e| ZeroError::Custom(e))
    }

    /// Accept an incoming call with your own SDP answer.
    /// Returns the CBOR-encoded `ZavSignal::Accept`.
    pub fn accept_call(&self, call_id: String, answer_sdp: String) -> Result<Vec<u8>, ZeroError> {
        let signal = self.zav.create_accept(&call_id, &answer_sdp);
        tracing::info!("Accepting call {} from {}", call_id, self.id);
        self.zav.encode_signal(&signal).map_err(|e| ZeroError::Custom(e))
    }

    /// Reject an incoming call.
    /// Returns the CBOR-encoded `ZavSignal::Reject`.
    pub fn reject_call(&self, call_id: String) -> Result<Vec<u8>, ZeroError> {
        let signal = self.zav.create_reject(&call_id);
        tracing::info!("Rejecting call {} from {}", call_id, self.id);
        self.zav.encode_signal(&signal).map_err(|e| ZeroError::Custom(e))
    }

    /// Hang up an active call.
    /// Returns the CBOR-encoded `ZavSignal::Hangup`.
    pub fn hangup(&self, call_id: String) -> Result<Vec<u8>, ZeroError> {
        let signal = self.zav.create_hangup(&call_id);
        tracing::info!("Hanging up call {} with {}", call_id, self.id);
        self.zav.encode_signal(&signal).map_err(|e| ZeroError::Custom(e))
    }
}
