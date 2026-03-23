//! Group messaging state (Megolm-inspired sender ratchets).
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zero_crypto::hash::blake2b_256;
use zero_crypto::sign::{
    ed25519_sign, ed25519_verify, Ed25519Keypair, Ed25519PublicKey, Ed25519Signature,
};
use zero_identity::zeroid::ZeroId;

use crate::error::GroupError;

/// A member of a ZERO group chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMember {
    /// Member's ZERO ID.
    pub zero_id: ZeroId,
    /// Member's current public sender key (for this epoch).
    pub sender_key: [u8; 32],
    /// Whether the member has administrative privileges.
    pub is_admin: bool,
    /// When this member joined
    pub join_timestamp: u64,
}

/// A serialized group event (e.g., adding/removing a member).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupEvent {
    /// The ID of the group this event belongs to.
    pub group_id: [u8; 32],
    /// Type of the event (e.g., "add_member", "remove_member").
    pub event_type: String,
    /// The ID of the member being targeted by this event.
    pub target_id: ZeroId,
    /// When this event occurred.
    pub timestamp: u64,
    /// Payload containing the new state or keys.
    pub payload: Vec<u8>,
    /// Digital signature by the group's administrative key.
    pub signature: Vec<u8>,
}

/// The state of a ZERO group chat.
#[derive(Serialize, Deserialize)]
pub struct GroupState {
    /// Group ID (hash of the creator's ID + creation timestamp).
    pub group_id: [u8; 32],
    /// Group signing keypair (only known to admins).
    #[serde(skip)]
    pub gsk: Option<Ed25519Keypair>,
    /// Group public key.
    pub gpk: Ed25519PublicKey,
    /// Members in this group.
    pub members: HashMap<ZeroId, GroupMember>,
    /// Our current sender ratchet state (HMAC-SHA256 chain).
    #[serde(skip)]
    pub sender_chain: Option<[u8; 32]>,
    /// Counter for group messages to ensure unique nonces.
    pub message_counter: u32,
}

impl GroupState {
    /// Create a new group as an admin.
    pub fn new(admin_id: ZeroId, creation_timestamp: u64) -> Self {
        let gsk = Ed25519Keypair::generate();
        let gpk = gsk.public_key();

        let mut id_material = Vec::new();
        id_material.extend_from_slice(admin_id.as_bytes());
        id_material.extend_from_slice(&creation_timestamp.to_be_bytes());
        let group_id = blake2b_256(&id_material);

        // Initial sender chain root (32 bytes of randomness)
        let mut initial_chain = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut initial_chain);

        let mut members = HashMap::new();
        members.insert(
            admin_id.clone(),
            GroupMember {
                zero_id: admin_id,
                sender_key: initial_chain, // We use the chain as the base identifying key
                is_admin: true,
                join_timestamp: creation_timestamp,
            },
        );

        Self {
            group_id,
            gsk: Some(gsk),
            gpk,
            members,
            sender_chain: Some(initial_chain),
            message_counter: 0,
        }
    }

    /// Sign a group event (if we are an admin).
    pub fn sign_event(
        &self,
        event_type: &str,
        target_id: &ZeroId,
        timestamp: u64,
        payload: &[u8],
    ) -> Result<GroupEvent, GroupError> {
        let gsk = self.gsk.as_ref().ok_or(GroupError::NotAdmin)?;

        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(&self.group_id);
        data_to_sign.extend_from_slice(event_type.as_bytes());
        data_to_sign.extend_from_slice(target_id.as_bytes());
        data_to_sign.extend_from_slice(&timestamp.to_be_bytes());
        data_to_sign.extend_from_slice(payload);

        let sig = ed25519_sign(&gsk.secret_key(), &data_to_sign);

        Ok(GroupEvent {
            group_id: self.group_id,
            event_type: event_type.to_string(),
            target_id: target_id.clone(),
            timestamp,
            payload: payload.to_vec(),
            signature: sig.0.to_vec(),
        })
    }

    /// Verify a group event signature against the group's public key
    pub fn verify_event(&self, event: &GroupEvent) -> Result<(), GroupError> {
        if event.group_id != self.group_id {
            return Err(GroupError::InvalidSignature);
        }

        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(&event.group_id);
        data_to_sign.extend_from_slice(event.event_type.as_bytes());
        data_to_sign.extend_from_slice(event.target_id.as_bytes());
        data_to_sign.extend_from_slice(&event.timestamp.to_be_bytes());
        data_to_sign.extend_from_slice(&event.payload);

        let sig = Ed25519Signature(event.signature.clone());
        ed25519_verify(&self.gpk, &data_to_sign, &sig).map_err(|_| GroupError::InvalidSignature)?;

        Ok(())
    }

    /// Rotate our sender key (e.g. when someone is removed)
    /// This uses a BLAKE2b-based ratchet step to derive the next chain root.
    pub fn rotate_sender_key(&mut self, our_id: &ZeroId) -> Result<[u8; 32], GroupError> {
        let current_chain = self.sender_chain.unwrap_or_else(|| {
            let mut r = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut r);
            r
        });

        // Ratchet: next_chain = BLAKE2b-256(current_chain || "ZGP-ratchet-v1")
        let mut input = current_chain.to_vec();
        input.extend_from_slice(b"ZGP-ratchet-v1");
        let new_chain = blake2b_256(&input);

        self.sender_chain = Some(new_chain);

        if let Some(member) = self.members.get_mut(our_id) {
            member.sender_key = new_chain;
        }
        Ok(new_chain)
    }
}
