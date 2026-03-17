//! Group member management logic.

use std::collections::HashMap;
use zero_identity::zeroid::ZeroId;
use crate::group::{GroupState, GroupMember, GroupEvent};
use crate::error::GroupError;

/// Manages the addition and removal of members in a group.
pub struct MemberManager;

impl MemberManager {
    /// Add a new member to the group (Admin only).
    pub fn add_member(
        state: &mut GroupState,
        new_member_id: ZeroId,
        timestamp: u64,
        is_admin: bool,
    ) -> Result<GroupEvent, GroupError> {
        let mut initial_chain = [0u8; 32];
        // In a real implementation, this would be negotiated / provided by the new member,
        // or the admin initializes it and sends it securely to them.
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut initial_chain);

        let member = GroupMember {
            zero_id: new_member_id.clone(),
            sender_key: initial_chain,
            is_admin,
            join_timestamp: timestamp,
        };

        state.members.insert(new_member_id.clone(), member);

        // Payload could be the initial sender_key or other onboarding data
        let payload = b"add".to_vec();
        state.sign_event("add_member", &new_member_id, timestamp, &payload)
    }

    /// Remove a member from the group, triggering a re-key (Admin only).
    pub fn remove_member(
        state: &mut GroupState,
        our_id: &ZeroId,
        target_id: &ZeroId,
        timestamp: u64,
    ) -> Result<(GroupEvent, HashMap<ZeroId, [u8; 32]>), GroupError> {
        if !state.members.contains_key(target_id) {
            return Err(GroupError::MemberNotFound);
        }

        // 1. Remove the member
        state.members.remove(target_id);

        // 2. We need to rotate our own keys
        state.rotate_sender_key(our_id)?;

        // 3. Create the removal event
        let payload = b"remove".to_vec();
        let event = state.sign_event("remove_member", target_id, timestamp, &payload)?;

        // 4. Determine new outbound session keys that need to be sent
        // to remaining members via pairwise ZR.
        let mut new_keys = HashMap::new();
        let our_new_key = state.sender_chain.expect("rotated");
        for member_id in state.members.keys() {
            if member_id != our_id {
                new_keys.insert(member_id.clone(), our_new_key);
            }
        }

        Ok((event, new_keys))
    }
    
    /// Process an incoming signed group event.
    pub fn process_event(state: &mut GroupState, event: &GroupEvent) -> Result<(), GroupError> {
        state.verify_event(event)?;
        
        match event.event_type.as_str() {
            "add_member" => {
                let initial_chain = [0u8; 32]; // For simplicity in this implementation
                state.members.insert(
                    event.target_id.clone(),
                    GroupMember {
                        zero_id: event.target_id.clone(),
                        sender_key: initial_chain, 
                        is_admin: false, // In a full implementation, derive from payload
                        join_timestamp: event.timestamp,
                    },
                );
            }
            "remove_member" => {
                state.members.remove(&event.target_id);
                // Note: receiving a remove_member event triggers the local client
                // to also rotate their own keys and send them out.
            }
            _ => { return Err(GroupError::InvalidSignature); /* Unknown event type */ }
        }
        
        Ok(())
    }
}
