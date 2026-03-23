//! ZGP Member Key Distribution.
//!
//! When a new member joins a group, the admin must securely deliver
//! each existing member's sender key to the new member via pairwise ZR channels.
//! When a member is removed, the admin rotates sender keys and distributes them
//! to all remaining members.

use crate::error::GroupError;
use crate::group::{GroupMember, GroupState};
use serde::{Deserialize, Serialize};
use zero_identity::zeroid::ZeroId;

/// A bundle of sender keys delivered to a new member when they join.
/// Transmitted via a pairwise ZR-encrypted message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberKeyBundle {
    /// The group ID this bundle belongs to.
    pub group_id: [u8; 32],
    /// For each existing member: their ZeroId + current sender key blob.
    pub sender_keys: Vec<MemberKeyShard>,
    /// The new member's own sender key (randomly generated for them).
    pub your_sender_key: [u8; 32],
    /// Group epoch — incremented on every re-key.
    pub epoch: u32,
}

/// A single member's sender key, delivered as part of a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberKeyShard {
    /// The member whose sender key this is.
    pub member_id: ZeroId,
    /// Their current Megolm-style sender chain root (32 bytes).
    pub sender_key: [u8; 32],
}

/// Manages group membership operations and key distribution.
pub struct MemberManager;

impl MemberManager {
    /// Add a member to an existing group.
    ///
    /// This modifies `state` and returns a [`MemberKeyBundle`] that the admin
    /// MUST send to the new member via a pairwise ZR-encrypted channel.
    pub fn add_member(
        state: &mut GroupState,
        new_member_id: ZeroId,
        timestamp: u64,
        is_admin: bool,
    ) -> Result<MemberKeyBundle, GroupError> {
        // Generate a fresh sender key for the new member
        let mut new_sender_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut new_sender_key);

        // Build the bundle: one shard per existing member
        let sender_keys: Vec<MemberKeyShard> = state
            .members
            .values()
            .map(|m| MemberKeyShard {
                member_id: m.zero_id.clone(),
                sender_key: m.sender_key,
            })
            .collect();

        let epoch = state.members.len() as u32; // simple epoch counter

        // Sign the add_member event
        let _event = state.sign_event("add_member", &new_member_id, timestamp, &new_sender_key)?;

        // Insert the new member into the group state
        state.members.insert(
            new_member_id.clone(),
            GroupMember {
                zero_id: new_member_id,
                sender_key: new_sender_key,
                is_admin,
                join_timestamp: timestamp,
            },
        );

        Ok(MemberKeyBundle {
            group_id: state.group_id,
            sender_keys,
            your_sender_key: new_sender_key,
            epoch,
        })
    }

    /// Remove a member from a group and rotate all sender keys.
    ///
    /// Returns a Vec of (ZeroId, [u8;32]) tuples — the admin must send each
    /// member their new sender key via a pairwise ZR channel.
    pub fn remove_member(
        state: &mut GroupState,
        target_id: &ZeroId,
        timestamp: u64,
    ) -> Result<Vec<(ZeroId, [u8; 32])>, GroupError> {
        if !state.members.contains_key(target_id) {
            return Err(GroupError::MemberNotFound);
        }

        // Sign the remove event before modifying state
        let _event = state.sign_event("remove_member", target_id, timestamp, &[])?;

        // Remove the member
        state.members.remove(target_id);

        // Rotate sender keys for ALL remaining members (so removed member can't decrypt)
        let mut rotations = Vec::new();
        for (id, member) in state.members.iter_mut() {
            let mut new_key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut new_key);
            member.sender_key = new_key;
            rotations.push((id.clone(), new_key));
        }

        // Also rotate our own sender chain root
        state.rotate_sender_key(
            &state
                .members
                .keys()
                .next()
                .cloned()
                .unwrap_or(target_id.clone()),
        )?;

        Ok(rotations)
    }

    /// Apply a received MemberKeyBundle (executed by the new member).
    /// Populates the GroupState with all existing members' sender keys.
    pub fn apply_join_bundle(
        state: &mut GroupState,
        bundle: MemberKeyBundle,
        our_id: &ZeroId,
    ) -> Result<(), GroupError> {
        // Install all existing member sender keys
        for shard in &bundle.sender_keys {
            if let Some(member) = state.members.get_mut(&shard.member_id) {
                member.sender_key = shard.sender_key;
            }
        }
        // Install our own sender key
        if let Some(us) = state.members.get_mut(our_id) {
            us.sender_key = bundle.your_sender_key;
        }
        state.sender_chain = Some(bundle.your_sender_key);
        Ok(())
    }
}
