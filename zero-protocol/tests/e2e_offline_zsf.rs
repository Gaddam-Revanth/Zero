// ZERO Protocol E2E Offline ZSF Test
use zero_crypto::dh::X25519Keypair;
use zero_handshake::noise::HandshakePrologue;
use zero_handshake::{NoiseHandshakeState, NoiseRole, X3dhInitiator, X3dhResponder};
use zero_identity::{bundle::OwnedKeyBundle, keypair::ZeroKeypair, zeroid::ZeroId};
use zero_ratchet::{RatchetMessage, RatchetSession, SessionInit};
use zero_store_forward::{decrypt_inner, decrypt_outer_for_relay, ZsfEnvelope};

#[test]
fn e2e_zkx_to_zr_to_zsf_offline_delivery() {
    // --- Identities / bundles ---
    let alice_kp = ZeroKeypair::generate().expect("alice keypair");
    let alice_id = ZeroId::from_keypair(&alice_kp, [0u8; 4]);
    let mut bob_owned = OwnedKeyBundle::generate(0).expect("bob bundle");
    let bob_id = ZeroId::from_keypair(&bob_owned.keypair, [0u8; 4]);
    let bob_bundle = bob_owned.public_bundle(&bob_id);

    // --- Phase 1: Noise XX (transcript binding) ---
    let prologue = HandshakePrologue::v1_0(0);

    let mut alice = NoiseHandshakeState::new(
        NoiseRole::Initiator,
        alice_kp.idk.clone(),
        X25519Keypair::generate(),
        &prologue,
    );
    let mut bob = NoiseHandshakeState::new(
        NoiseRole::Responder,
        bob_owned.keypair.idk.clone(),
        X25519Keypair::generate(),
        &prologue,
    );

    let msg1 = alice.write_message1().expect("msg1");
    let msg2 = bob.read_message1_write_message2(&msg1).expect("msg2");
    let msg3 = alice
        .read_message2_write_message3(&msg2, b"zkx")
        .expect("msg3");
    let _payload = bob.read_message3(&msg3).expect("payload");

    let alice_out = alice.finalize().expect("alice finalize");
    let bob_out = bob.finalize().expect("bob finalize");
    assert_eq!(alice_out.handshake_hash, bob_out.handshake_hash);
    let noise_hash = alice_out.handshake_hash;

    // --- Phase 2/3: X3DH + ML-KEM (bound to Noise hash) ---
    let initiator = X3dhInitiator::new(X25519Keypair::generate());
    let (init_msg, alice_ms) = initiator
        .initiate_with_noise_hash(&alice_id, &alice_kp, &bob_bundle, Some(noise_hash))
        .expect("alice initiate");

    let (bob_ms, _bob_tag) =
        X3dhResponder::respond_with_noise_hash(&mut bob_owned, &init_msg, Some(noise_hash))
            .expect("bob respond");

    assert_eq!(alice_ms.0, bob_ms.0);

    // --- ZR session init: exchange initial ratchet DH keys ---
    let alice_dh0 = X25519Keypair::generate();
    let bob_dh0 = X25519Keypair::generate();
    let mut alice_zr = RatchetSession::new(SessionInit {
        master_secret: alice_ms.0.to_vec(),
        is_initiator: true,
        local_dh: alice_dh0,
        remote_dh_pub: bob_dh0.public_key(),
    })
    .expect("alice zr");

    let mut bob_zr = RatchetSession::new(SessionInit {
        master_secret: bob_ms.0.to_vec(),
        is_initiator: false,
        local_dh: bob_dh0,
        remote_dh_pub: alice_zr.dh_pub(),
    })
    .expect("bob zr");

    // --- Alice encrypts a message under ZR ---
    let associated_data = b"aad";
    let zr_msg = alice_zr
        .encrypt(b"hello via zsf", associated_data)
        .expect("zr encrypt");
    let zr_msg_bytes = zero_crypto::cbor::to_vec(&zr_msg).expect("cbor ratchet msg");

    // --- Offline delivery via ZSF ---
    let relay_kp = X25519Keypair::generate();
    let sender_id = ZeroId::from_keypair(&alice_kp, [1u8; 4]);
    let recipient_node_id = [0xABu8; 32];

    let env = ZsfEnvelope::build(
        &bob_owned.keypair.idk.public_key(),
        recipient_node_id,
        &sender_id,
        &relay_kp.public_key(),
        zr_msg_bytes,
    )
    .expect("build envelope");

    // Relay decrypts only TTL + inner blob
    let outer = decrypt_outer_for_relay(&relay_kp.secret_key(), &env).expect("relay decrypt outer");
    assert!(outer.ttl > 0);

    // Recipient decrypts inner to recover sender_id + payload
    let inner = decrypt_inner(&bob_owned.keypair.idk.secret_key(), &outer.inner_ciphertext)
        .expect("recipient decrypt inner");
    assert_eq!(inner.sender_id, sender_id);

    // Recipient decrypts the ZR message
    let zr_msg2: RatchetMessage =
        zero_crypto::cbor::from_slice(&inner.payload).expect("decode ratchet msg");
    let pt = bob_zr
        .decrypt(&zr_msg2, associated_data, 0)
        .expect("zr decrypt");
    assert_eq!(pt, b"hello via zsf");
}
