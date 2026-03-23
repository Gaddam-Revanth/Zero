use zero_groups::group::GroupState;
use zero_identity::zeroid::ZeroId;
use zero_identity::keypair::ZeroKeypair;

#[test]
fn test_group_lifecycle() {
    let admin_kp = ZeroKeypair::generate().unwrap();
    let admin_id = ZeroId::from_keypair(&admin_kp, [0u8; 4]);
    let timestamp = 123456789;

    // 1. Create group
    let mut group = GroupState::new(admin_id.clone(), timestamp);
    assert_eq!(group.members.len(), 1);
    assert!(group.members.contains_key(&admin_id));
    assert!(group.members.get(&admin_id).unwrap().is_admin);

    // 2. Sign and verify an event
    let target_kp = ZeroKeypair::generate().unwrap();
    let target_id = ZeroId::from_keypair(&target_kp, [0u8; 4]);
    let event = group.sign_event("add_member", &target_id, timestamp + 1, b"new_member_payload").expect("sign event");
    
    group.verify_event(&event).expect("verify event");

    // 3. Sender key rotation (ratchet)
    let old_key = group.members.get(&admin_id).unwrap().sender_key;
    let new_key = group.rotate_sender_key(&admin_id).expect("rotate key");
    
    assert_ne!(old_key, new_key);
    assert_eq!(group.members.get(&admin_id).unwrap().sender_key, new_key);
}

#[test]
fn test_group_serialization() {
    let admin_kp = ZeroKeypair::generate().unwrap();
    let admin_id = ZeroId::from_keypair(&admin_kp, [0u8; 4]);
    let group = GroupState::new(admin_id.clone(), 100);

    let mut serialized = Vec::new();
    ciborium::ser::into_writer(&group, &mut serialized).expect("serialize");
    
    let deserialized: GroupState = ciborium::de::from_reader(&serialized[..]).expect("deserialize");

    assert_eq!(group.group_id, deserialized.group_id);
    assert_eq!(group.members.len(), deserialized.members.len());
}
