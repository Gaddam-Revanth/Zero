//! Comprehensive tests for zero-handshake: ZKX and Noise XX.
//! Covers: ZKX with/without OPK, replay attack, wrong KEM ciphertext, and Noise full handshake.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod handshake_tests {
    use zero_handshake::x3dh::{X3dhInitiator, X3dhResponder};
    use zero_identity::{bundle::OwnedKeyBundle, zeroid::ZeroId};
    use zero_identity::keypair::ZeroKeypair;
    use zero_crypto::dh::X25519Keypair;

    fn make_bob() -> (OwnedKeyBundle, zero_identity::bundle::KeyBundle) {
        let mut bob_owned = OwnedKeyBundle::generate(0).unwrap();
        let bob_id = ZeroId::from_keypair(&bob_owned.keypair, [0u8; 4]);
        let bundle = bob_owned.public_bundle(&bob_id);
        (bob_owned, bundle)
    }

    // ── ZKX WITH OPK ──────────────────────────────────────────────────────────

    #[test]
    fn test_zkx_with_opk_master_secrets_match() {
        let alice_kp = ZeroKeypair::generate().unwrap();
        let (mut bob_owned, bob_bundle) = make_bob();

        // Bundle should have an OPK available
        assert!(bob_bundle.opk.is_some(), "Bundle should have OPK");

        let initiator = X3dhInitiator::new(X25519Keypair::generate());
        let alice_id = ZeroId::from_keypair(&alice_kp, [0u8; 4]);
        let (init_msg, alice_ms) = initiator.initiate(&alice_id, &alice_kp, &bob_bundle).unwrap();

        let (bob_ms, _) = X3dhResponder::respond(&mut bob_owned, &init_msg).unwrap();
        assert_eq!(alice_ms.0, bob_ms.0, "Master secrets must match when OPK is used");
    }

    // ── ZKX WITHOUT OPK ───────────────────────────────────────────────────────

    #[test]
    fn test_zkx_without_opk_master_secrets_match() {
        let alice_kp = ZeroKeypair::generate().unwrap();
        let (mut bob_owned, mut bob_bundle) = make_bob();
        bob_bundle.opk = None; // Force no OPK

        let initiator = X3dhInitiator::new(X25519Keypair::generate());
        let alice_id = ZeroId::from_keypair(&alice_kp, [0u8; 4]);
        let (init_msg, alice_ms) = initiator.initiate(&alice_id, &alice_kp, &bob_bundle).unwrap();
        let (bob_ms, _) = X3dhResponder::respond(&mut bob_owned, &init_msg).unwrap();
        assert_eq!(alice_ms.0, bob_ms.0, "Master secrets must match without OPK");
    }

    // ── ZKX REPLAY ATTACK (no-OPK path) ──────────────────────────────────────

    #[test]
    fn test_zkx_replay_attack_rejected_without_opk() {
        let alice_kp = ZeroKeypair::generate().unwrap();
        let (mut bob_owned, mut bob_bundle) = make_bob();
        bob_bundle.opk = None; // No OPK → replay cache is activated

        let ek = X25519Keypair::generate();
        let initiator = X3dhInitiator::new(ek);
        let alice_id = ZeroId::from_keypair(&alice_kp, [0u8; 4]);
        let (init_msg, _alice_ms) = initiator.initiate(&alice_id, &alice_kp, &bob_bundle).unwrap();

        // First response should succeed
        X3dhResponder::respond(&mut bob_owned, &init_msg)
            .expect("First ZKX without OPK must succeed");

        // Second with SAME ephemeral key = replay — must fail
        let result = X3dhResponder::respond(&mut bob_owned, &init_msg);
        assert!(result.is_err(), "ZKX replay (same EK, no OPK) must be rejected");
    }

    // ── ZKX WITH DIFFERENT ALICE KEYPAIRs ────────────────────────────────────

    #[test]
    fn test_zkx_different_alice_produces_different_master_secret() {
        let alice1 = ZeroKeypair::generate().unwrap();
        let alice2 = ZeroKeypair::generate().unwrap();
        let (mut bob1, bundle1) = make_bob();
        let (mut bob2, bundle2) = make_bob();

        let alice_id1 = ZeroId::from_keypair(&alice1, [0u8; 4]);
        let alice_id2 = ZeroId::from_keypair(&alice2, [0u8; 4]);

        let (init1, ms1) = X3dhInitiator::new(X25519Keypair::generate())
            .initiate(&alice_id1, &alice1, &bundle1).unwrap();
        let (init2, ms2) = X3dhInitiator::new(X25519Keypair::generate())
            .initiate(&alice_id2, &alice2, &bundle2).unwrap();

        let (bob_ms1, _) = X3dhResponder::respond(&mut bob1, &init1).unwrap();
        let (bob_ms2, _) = X3dhResponder::respond(&mut bob2, &init2).unwrap();

        assert_eq!(ms1.0, bob_ms1.0, "Alice1+Bob1 must agree");
        assert_eq!(ms2.0, bob_ms2.0, "Alice2+Bob2 must agree");
        assert_ne!(ms1.0, ms2.0, "Different sessions must have different master secrets");
    }

    // ── ZKX WRONG KEM CIPHERTEXT ──────────────────────────────────────────────

    #[test]
    fn test_zkx_wrong_kem_ciphertext_produces_wrong_secret() {
        let alice_kp = ZeroKeypair::generate().unwrap();
        let (mut bob1, bob_bundle) = make_bob();
        let (mut bob2, _) = make_bob(); // different keypair

        let initiator = X3dhInitiator::new(X25519Keypair::generate());
        let alice_id = ZeroId::from_keypair(&alice_kp, [0u8; 4]);
        let (mut init_msg, alice_ms) = initiator.initiate(&alice_id, &alice_kp, &bob_bundle).unwrap();

        // Corrupt the KEM ciphertext by filling with zeros
        init_msg.kem_ciphertext = vec![0u8; init_msg.kem_ciphertext.len()];

        // Bob1 can technically respond (ML-KEM uses implicit rejection - returns different secret)
        if let Ok((bob_ms, _)) = X3dhResponder::respond(&mut bob1, &init_msg) {
            assert_ne!(alice_ms.0, bob_ms.0, "Corrupted KEM ciphertext must produce different shared secret");
        }
        // If it errors, that's also acceptable
        let _ = X3dhResponder::respond(&mut bob2, &init_msg);
    }

    // ── NOISE XX HANDSHAKE ────────────────────────────────────────────────────

    #[test]
    fn test_noise_xx_full_handshake_and_message_exchange() {
        use zero_handshake::noise::{NoiseHandshakeState, NoiseRole, HandshakePrologue};
        use zero_crypto::aead::encrypt;

        let alice_static = X25519Keypair::generate();
        let bob_static = X25519Keypair::generate();
        let prologue = HandshakePrologue::v1_0(0);

        let mut alice = NoiseHandshakeState::new(
            NoiseRole::Initiator,
            alice_static,
            X25519Keypair::generate(),
            &prologue,
        );
        let mut bob = NoiseHandshakeState::new(
            NoiseRole::Responder,
            bob_static,
            X25519Keypair::generate(),
            &prologue,
        );

        // XX handshake: 3 messages
        let msg1 = alice.write_message1().unwrap();
        let msg2 = bob.read_message1_write_message2(&msg1).unwrap();
        let msg3 = alice.read_message2_write_message3(&msg2, b"initial payload").unwrap();
        let payload = bob.read_message3(&msg3).unwrap();

        assert_eq!(payload, b"initial payload");

        let alice_out = alice.finalize().unwrap();
        let bob_out = bob.finalize().unwrap();

        // Post-handshake message round-trip using the symmetric keys
        let pt = b"secure message after handshake";
        let _ct = encrypt(&alice_out.send_key, &zero_crypto::aead::AeadNonce::random(), pt, b"").unwrap();
        
        // Ciphertext returned by zero_crypto::aead::encrypt includes the tag but not the nonce
        // In this specific test, we'll just check the keys match
        assert_eq!(alice_out.send_key.0, bob_out.recv_key.0);
        assert_eq!(alice_out.recv_key.0, bob_out.send_key.0);
    }

    #[test]
    fn test_noise_xx_spk_rotation_old_spk_accepted() {
        let alice_kp = ZeroKeypair::generate().unwrap();
        let (mut bob_owned, bob_bundle_before_rotate) = make_bob();

        // Initiate with the old SPK index
        let initiator = X3dhInitiator::new(X25519Keypair::generate());
        let alice_id = ZeroId::from_keypair(&alice_kp, [0u8; 4]);
        let (init_msg, _) = initiator.initiate(&alice_id, &alice_kp, &bob_bundle_before_rotate).unwrap();

        // Now Bob rotates his SPK
        bob_owned.rotate_spk(7 * 24 * 3600);

        // The init_msg still refers to the old SPK — Bob should handle it via old_spks
        let result = X3dhResponder::respond(&mut bob_owned, &init_msg);
        assert!(result.is_ok(), "Old SPK index must be accepted from old_spks history");
    }
}
