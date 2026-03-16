//! Group messaging state (Megolm-inspired sender ratchets).

use std::collections::HashMap;
use zero_identity::zeroid::ZeroId;
use zero_crypto::sign::{Ed25519Keypair, Ed25519PublicKey};

/// A member of a ZERO group chat.
#[derive(Clone, Debug)]
pub struct GroupMember {
    /// Member's ZERO ID.
    pub zero_id: ZeroId,
    /// Member's current public sender key (for this epoch).
    pub sender_key: [u8; 32],
    /// Whether the member has administrative privileges.
    pub is_admin: bool,
}

/// The state of a ZERO group chat.
pub struct GroupState {
    /// Group ID (hash of the creator's ID + creation timestamp).
    pub group_id: [u8; 32],
    /// Group signing keypair (only known to admins).
    pub gsk: Option<Ed25519Keypair>,
    /// Group public key.
    pub gpk: Ed25519PublicKey,
    /// Members in this group.
    pub members: HashMap<ZeroId, GroupMember>,
    /// Our current sender ratchet state (HMAC-SHA256 chain).
    pub sender_chain: Option<[u8; 32]>,
}

impl GroupState {
    /// Initialize a new group as an admin.
    pub fn new(admin_id: ZeroId) -> Self {
        let gsk = Ed25519Keypair::generate();
        let gpk = gsk.public_key();
        let mut members = HashMap::new();
        members.insert(
            admin_id.clone(),
            GroupMember {
                zero_id: admin_id,
                sender_key: [0u8; 32], // Stub
                is_admin: true,
            },
        );
        Self {
            group_id: [0u8; 32], // Stub
            gsk: Some(gsk),
            gpk,
            members,
            sender_chain: Some([0u8; 32]), // Stub
        }
    }
}
