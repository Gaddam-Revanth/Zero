use zero_protocol::api::ZeroNode;
use zero_wire::{Packet, PacketHeader, PacketType, Version};

#[tokio::test(flavor = "multi_thread")]
async fn multi_node_protocol_simulation_v1() {
    // 1. Setup 3 Nodes: Alice, Bob, Charlie
    let tmp_dir = std::env::temp_dir();
    let alice = ZeroNode::new(
        tmp_dir.join("alice").to_str().unwrap().to_string(),
        "pass_alice".to_string(),
    )
    .unwrap();
    let bob = ZeroNode::new(
        tmp_dir.join("bob").to_str().unwrap().to_string(),
        "pass_bob".to_string(),
    )
    .unwrap();
    let charlie = ZeroNode::new(
        tmp_dir.join("charlie").to_str().unwrap().to_string(),
        "pass_charlie".to_string(),
    )
    .unwrap();

    let alice_id = alice.self_id.clone();
    let bob_id = bob.self_id.clone();
    let charlie_id = charlie.self_id.clone();

    println!("Alice: {}", alice_id);
    println!("Bob:   {}", bob_id);
    println!("Charlie: {}", charlie_id);

    // 2. Simulate Onion Routing (Alice -> Bob -> Charlie)
    let target_node_id = zero_dht::node_id_from_isk(&charlie_id.isk_pub());
    let onion_packet = {
        let alice_dht = alice.dht_table().unwrap();
        let _dht = alice_dht.lock().await;

        // Mocking: manually wrap Charlie's target for Bob
        let ephemeral = zero_crypto::dh::X25519Keypair::generate();
        let eph_pub = ephemeral.public_key();

        let shared = ephemeral.diffie_hellman(&zero_crypto::dh::X25519PublicKey(bob_id.idk_pub()));
        let key_bytes = zero_crypto::kdf::hkdf(
            b"salt",
            &shared.0,
            zero_crypto::kdf::KdfContext::OnionHopKey,
            32,
        )
        .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        let key = zero_crypto::aead::AeadKey(arr);

        let bob_dht = bob.dht_table().unwrap();
        let hops = [bob_dht.lock().await.own_id, target_node_id, target_node_id];
        let keys = [key.clone(), key.clone(), key];
        zero_dht::onion::OnionPacket::wrap_3_hops(b"FIND_CHARLIE", &hops, &keys, eph_pub.0).unwrap()
    };

    let onion_bytes = zero_crypto::cbor::to_vec(&onion_packet).unwrap();
    let packet = Packet {
        header: PacketHeader::new(
            Version { major: 1, minor: 0 },
            PacketType::ZdhtFindRecordReq,
            zero_wire::types::PacketFlags(0),
            onion_bytes.len() as u32,
        ),
        sender_node_id: zero_dht::node_id_from_isk(&alice_id.isk_pub()).0,
        receiver_node_id: zero_dht::node_id_from_isk(&bob_id.isk_pub()).0,
        body: onion_bytes.into(),
    };

    // Bob receives and dispatches
    bob.dispatch_incoming_packet(packet)
        .await
        .expect("Bob failed dispatch");

    // 3. Simulate Group Messaging
    let group_id = alice.create_group().unwrap();
    alice
        .invite_to_group(group_id.clone(), bob_id.to_string_repr())
        .unwrap();
    alice
        .invite_to_group(group_id.clone(), charlie_id.to_string_repr())
        .unwrap();

    let msg = "Hello Group!".to_string();
    let ciphertext = alice.send_group_message(group_id.clone(), msg).unwrap();
    assert!(!ciphertext.is_empty());

    let _path = tmp_dir
        .join("alice")
        .join("sessions")
        .join(hex::encode(bob_id.isk_pub()));
    println!("Simulation Successful!");
}
