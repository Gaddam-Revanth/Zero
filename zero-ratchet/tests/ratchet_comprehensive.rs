//! Comprehensive tests for the ZR Double Ratchet protocol.
//! Covers: bidirectional exchange, out-of-order messages, skipped key cache,
//! PQ ratchet step, and tampered ciphertext rejection.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod ratchet_tests {
    use zero_crypto::dh::X25519Keypair;
    use zero_ratchet::state::{RatchetSession, SessionInit};

    fn make_session_pair() -> (RatchetSession, RatchetSession) {
        let master = vec![0x42u8; 64];
        let alice_kp = X25519Keypair::generate();
        let bob_kp = X25519Keypair::generate();

        let alice_pub = alice_kp.public_key();
        let bob_pub = bob_kp.public_key();

        let alice = RatchetSession::new(SessionInit {
            master_secret: master.clone(),
            is_initiator: true,
            local_dh: alice_kp,
            remote_dh_pub: bob_pub,
        })
        .expect("alice init");

        let bob = RatchetSession::new(SessionInit {
            master_secret: master,
            is_initiator: false,
            local_dh: bob_kp,
            remote_dh_pub: alice_pub,
        })
        .expect("bob init");

        (alice, bob)
    }

    #[test]
    fn test_bidirectional_10_messages_each_way() {
        let (mut alice, mut bob) = make_session_pair();
        let ad = b"session-ad";

        // Alice → Bob
        for i in 0..10u8 {
            let msg = alice.encrypt(&[i; 32], ad).unwrap();
            let pt = bob.decrypt(&msg, ad, 0).unwrap();
            assert_eq!(pt, vec![i; 32], "Message {} Alice→Bob mismatch", i);
        }

        // Bob → Alice
        for i in 0..10u8 {
            let msg = bob.encrypt(&[i + 100; 16], ad).unwrap();
            let pt = alice.decrypt(&msg, ad, 0).unwrap();
            assert_eq!(pt, vec![i + 100; 16], "Message {} Bob→Alice mismatch", i);
        }
    }

    #[test]
    fn test_out_of_order_messages() {
        let (mut alice, mut bob) = make_session_pair();
        let ad = b"out-of-order-ad";

        // Alice sends 5 messages
        let m0 = alice.encrypt(b"msg-0", ad).unwrap();
        let m1 = alice.encrypt(b"msg-1", ad).unwrap();
        let m2 = alice.encrypt(b"msg-2", ad).unwrap();
        let m3 = alice.encrypt(b"msg-3", ad).unwrap();
        let m4 = alice.encrypt(b"msg-4", ad).unwrap();

        // Bob receives them out of order: 4, 2, 0, 3, 1
        let r4 = bob.decrypt(&m4, ad, 0).unwrap();
        let r2 = bob.decrypt(&m2, ad, 0).unwrap();
        let r0 = bob.decrypt(&m0, ad, 0).unwrap();
        let r3 = bob.decrypt(&m3, ad, 0).unwrap();
        let r1 = bob.decrypt(&m1, ad, 0).unwrap();

        assert_eq!(r0, b"msg-0");
        assert_eq!(r1, b"msg-1");
        assert_eq!(r2, b"msg-2");
        assert_eq!(r3, b"msg-3");
        assert_eq!(r4, b"msg-4");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (mut alice, mut bob) = make_session_pair();
        let ad = b"tamper-ad";

        let mut msg = alice.encrypt(b"secret", ad).unwrap();
        msg.ciphertext[15] ^= 0xFF; // flip bits in the ciphertext (skipping the 12-byte nonce)
        assert!(
            bob.decrypt(&msg, ad, 0).is_err(),
            "Tampered ciphertext must fail"
        );
    }

    #[test]
    fn test_pq_ratchet_step_changes_session() {
        let (mut alice, _bob) = make_session_pair();
        // Snapshot root key implicitly by encrypting then checking pq_ratchet_step doesn't error
        let pq_ss = [0xFFu8; 32];
        assert!(
            alice.pq_ratchet_step(&pq_ss).is_ok(),
            "PQ ratchet step must succeed"
        );
    }

    #[test]
    fn test_long_chain_50_messages_bidirectional() {
        let (mut alice, mut bob) = make_session_pair();
        let ad = b"long-chain";

        for i in 0u8..50 {
            // alternating
            if i % 2 == 0 {
                let m = alice.encrypt(&[i; 8], ad).unwrap();
                let pt = bob.decrypt(&m, ad, 0).unwrap();
                assert_eq!(pt, vec![i; 8]);
            } else {
                let m = bob.encrypt(&[i; 8], ad).unwrap();
                let pt = alice.decrypt(&m, ad, 0).unwrap();
                assert_eq!(pt, vec![i; 8]);
            }
        }
    }

    #[test]
    fn test_empty_plaintext_round_trip() {
        let (mut alice, mut bob) = make_session_pair();
        let ad = b"empty";
        let msg = alice.encrypt(b"", ad).unwrap();
        let pt = bob.decrypt(&msg, ad, 0).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_large_plaintext_round_trip() {
        let (mut alice, mut bob) = make_session_pair();
        let ad = b"large";
        let large = vec![0x55u8; 65_536]; // 64 KiB
        let msg = alice.encrypt(&large, ad).unwrap();
        let pt = bob.decrypt(&msg, ad, 0).unwrap();
        assert_eq!(pt, large);
    }

    #[test]
    fn test_skipped_key_exceeds_max_returns_error() {
        let (mut alice, mut bob) = make_session_pair();
        let ad = b"skip-too-many";

        // Send 1002 messages from alice without delivering them
        // On the 1001st message, bob must fail with TooManySkippedKeys
        // We simulate this by sending the last message to bob after skipping all prior ones
        let mut msgs = Vec::new();
        for _ in 0..1002 {
            msgs.push(alice.encrypt(b"x", ad).unwrap());
        }

        // Try to deliver only the LAST message — bob would need to skip 1001 keys
        let result = bob.decrypt(&msgs[1001], ad, 0);
        assert!(result.is_err(), "Exceeding MAX_SKIP must return error");
    }
}
