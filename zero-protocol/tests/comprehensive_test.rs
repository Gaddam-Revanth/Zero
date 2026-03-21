//! Full end-to-end integration test for the ZERO Protocol.
//! Wires together: ZKX key agreement → Double Ratchet → ZSF store-and-forward → Replay protection.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod integration_tests {
    use zero_handshake::x3dh::{X3dhInitiator, X3dhResponder};
    use zero_identity::{bundle::OwnedKeyBundle, zeroid::ZeroId, keypair::ZeroKeypair};
    use zero_ratchet::state::{RatchetSession, SessionInit};
    use zero_store_forward::envelope::{ZsfEnvelope, decrypt_outer_for_relay, decrypt_inner};
    use zero_wire::replay::{ReplayCache, ReplayToken};
    use zero_wire::types::PacketType;
    use zero_crypto::dh::{X25519Keypair};
    use zero_dht::node_id_from_isk;

    // ── Helper: establish a ZKX session between Alice and Bob ─────────────────

    fn establish_ratchet_pair() -> (RatchetSession, RatchetSession) {
        let alice_kp = ZeroKeypair::generate().unwrap();
        let mut bob_owned = OwnedKeyBundle::generate(0).unwrap();
        let bob_id = ZeroId::from_keypair(&bob_owned.keypair, [0u8; 4]);
        let bob_bundle = bob_owned.public_bundle(&bob_id);

        // ZKX key exchange
        let ek = X25519Keypair::generate();
        let alice_init_kp = alice_kp;
        let initiator = X3dhInitiator::new(ek);
        let (init_msg, alice_ms) = initiator.initiate(&alice_init_kp, &bob_bundle).unwrap();
        let (bob_ms, _) = X3dhResponder::respond(&mut bob_owned, &init_msg).unwrap();
        assert_eq!(alice_ms.0, bob_ms.0, "ZKX master secrets must match");

        // Set up ratchet sessions from shared master secret
        let alice_dh = X25519Keypair::generate();
        let bob_dh = X25519Keypair::generate();
        let alice_pub = alice_dh.public_key();
        let bob_pub = bob_dh.public_key();

        let alice_session = RatchetSession::new(SessionInit {
            master_secret: alice_ms.0.to_vec(),
            is_initiator: true,
            local_dh: alice_dh,
            remote_dh_pub: bob_pub,
        }).unwrap();

        let bob_session = RatchetSession::new(SessionInit {
            master_secret: bob_ms.0.to_vec(),
            is_initiator: false,
            local_dh: bob_dh,
            remote_dh_pub: alice_pub,
        }).unwrap();

        (alice_session, bob_session)
    }

    #[test]
    fn test_e2e_zkx_ratchet_20_messages() {
        let (mut alice, mut bob) = establish_ratchet_pair();
        let ad = b"zero-protocol-session";

        for i in 0..10u8 {
            let plaintext = format!("Alice says: message {}", i);
            let msg = alice.encrypt(plaintext.as_bytes(), ad).unwrap();
            let recovered = bob.decrypt(&msg, ad, 0).unwrap();
            assert_eq!(recovered, plaintext.as_bytes());
        }

        for i in 0..10u8 {
            let plaintext = format!("Bob replies: message {}", i);
            let msg = bob.encrypt(plaintext.as_bytes(), ad).unwrap();
            let recovered = alice.decrypt(&msg, ad, 0).unwrap();
            assert_eq!(recovered, plaintext.as_bytes());
        }
    }

    #[test]
    fn test_e2e_wire_replay_attack_rejected() {
        let cache = ReplayCache::new(60_000);
        let receiver_id = [42u8; 32];
        let tok = ReplayToken::random();
        let t0 = 1_000_000u64;

        assert!(cache.check_and_insert(t0, &receiver_id, PacketType::ZkxInit, &tok));
        assert!(!cache.check_and_insert(t0 + 100, &receiver_id, PacketType::ZkxInit, &tok));
    }

    #[test]
    fn test_e2e_third_party_cannot_read_envelope() {
        let alice_kp = ZeroKeypair::generate().unwrap();
        let alice_id = ZeroId::from_keypair(&alice_kp, [0u8; 4]);
        
        let mut bob_owned = OwnedKeyBundle::generate(0).unwrap();
        let bob_id = ZeroId::from_keypair(&bob_owned.keypair, [0u8; 4]);
        let bob_bundle = bob_owned.public_bundle(&bob_id);

        let bob_relay_key = X25519Keypair::generate();
        let bob_relay_pub = bob_relay_key.public_key();

        let message = b"secret message for bob only";
        
        let outer = ZsfEnvelope::build(
            &bob_bundle.idk_pub,
            node_id_from_isk(&bob_id.isk_pub()).0,
            &alice_id,
            &bob_relay_pub,
            message.to_vec()
        ).unwrap();

        // Eve tries with her own relay key
        let eve_relay_key = X25519Keypair::generate();
        let eve_result = decrypt_outer_for_relay(&eve_relay_key.secret_key(), &outer);
        assert!(eve_result.is_err());

        // Bob's relay opens correctly
        let relay_payload = decrypt_outer_for_relay(&bob_relay_key.secret_key(), &outer).unwrap();
        // Bob himself opens the inner
        let inner = decrypt_inner(&bob_owned.keypair.idk.secret_key(), &relay_payload.inner_ciphertext).unwrap();
        assert_eq!(inner.payload, message);
    }
}
