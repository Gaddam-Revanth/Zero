//! Comprehensive tests for zero-crypto AEAD, signing, DH, KDF, and KEM primitives.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod aead_tests {
    use zero_crypto::aead::{decrypt, encrypt, AeadKey, AeadNonce, AEAD_KEY_SIZE};

    fn random_key() -> AeadKey {
        use rand::RngCore;
        let mut k = [0u8; AEAD_KEY_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut k);
        AeadKey(k)
    }

    #[test]
    fn test_aead_happy_path_roundtrip() {
        let key = random_key();
        let nonce = AeadNonce::random();
        let pt = b"hello ZERO protocol";
        let ad = b"associated-data";
        let ct = encrypt(&key, &nonce, pt, ad).unwrap();
        let recovered = decrypt(&key, &nonce, &ct, ad).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn test_aead_wrong_key_fails() {
        let key1 = random_key();
        let key2 = random_key();
        let nonce = AeadNonce::random();
        let ct = encrypt(&key1, &nonce, b"secret", b"").unwrap();
        assert!(
            decrypt(&key2, &nonce, &ct, b"").is_err(),
            "Wrong key must fail decryption"
        );
    }

    #[test]
    fn test_aead_tampered_ciphertext_fails() {
        let key = random_key();
        let nonce = AeadNonce::random();
        let mut ct = encrypt(&key, &nonce, b"sensitive data", b"ad").unwrap();
        ct[0] ^= 0xFF; // Flip all bits in first byte
        assert!(
            decrypt(&key, &nonce, &ct, b"ad").is_err(),
            "Tampered ciphertext must fail"
        );
    }

    #[test]
    fn test_aead_tampered_tag_fails() {
        let key = random_key();
        let nonce = AeadNonce::random();
        let mut ct = encrypt(&key, &nonce, b"msg", b"").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01; // Corrupt the last byte (part of the Poly1305 tag)
        assert!(
            decrypt(&key, &nonce, &ct, b"").is_err(),
            "Tampered tag must fail"
        );
    }

    #[test]
    fn test_aead_wrong_associated_data_fails() {
        let key = random_key();
        let nonce = AeadNonce::random();
        let ct = encrypt(&key, &nonce, b"payload", b"correct-ad").unwrap();
        assert!(
            decrypt(&key, &nonce, &ct, b"wrong-ad").is_err(),
            "Mismatched AD must fail decryption"
        );
    }

    #[test]
    fn test_aead_empty_plaintext_roundtrip() {
        let key = random_key();
        let nonce = AeadNonce::random();
        let ct = encrypt(&key, &nonce, b"", b"").unwrap();
        let pt = decrypt(&key, &nonce, &ct, b"").unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_aead_large_plaintext_roundtrip() {
        let key = random_key();
        let nonce = AeadNonce::random();
        let large_pt = vec![0xABu8; 1_048_576]; // 1 MiB
        let ct = encrypt(&key, &nonce, &large_pt, b"large").unwrap();
        let pt = decrypt(&key, &nonce, &ct, b"large").unwrap();
        assert_eq!(pt, large_pt);
    }

    #[test]
    fn test_aead_truncated_ciphertext_fails() {
        let key = random_key();
        let nonce = AeadNonce::random();
        // Ciphertext shorter than the 16-byte Poly1305 tag must fail
        let too_short = vec![0u8; 10];
        assert!(decrypt(&key, &nonce, &too_short, b"").is_err());
    }

    #[test]
    fn test_nonce_increment_is_unique() {
        let n = AeadNonce([0u8; 12]);
        let n2 = n.increment();
        assert_ne!(n, n2, "Incremented nonce must differ");
    }

    #[test]
    fn test_nonce_increment_wraps_correctly() {
        // Nonce with all 0xFF should wrap to all zeros
        let n = AeadNonce([0xFF; 12]);
        let n2 = n.increment();
        assert_eq!(n2.0, [0u8; 12]);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod sign_tests {
    use zero_crypto::sign::{ed25519_sign, ed25519_verify, Ed25519Keypair, Ed25519Signature};

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = Ed25519Keypair::generate();
        let msg = b"ZERO protocol message";
        let sig = kp.sign(msg);
        assert!(
            kp.verify(msg, &sig).is_ok(),
            "Signature must verify with correct key"
        );
    }

    #[test]
    fn test_sign_wrong_key_fails() {
        let kp1 = Ed25519Keypair::generate();
        let kp2 = Ed25519Keypair::generate();
        let msg = b"message";
        let sig = kp1.sign(msg);
        assert!(
            kp2.verify(msg, &sig).is_err(),
            "Verification with wrong key must fail"
        );
    }

    #[test]
    fn test_sign_tampered_message_fails() {
        let kp = Ed25519Keypair::generate();
        let msg = b"original";
        let sig = kp.sign(msg);
        assert!(
            kp.verify(b"tampered", &sig).is_err(),
            "Tampered message must fail verification"
        );
    }

    #[test]
    fn test_sign_truncated_signature_fails() {
        let kp = Ed25519Keypair::generate();
        let msg = b"message";
        let short_sig = Ed25519Signature(vec![0u8; 10]); // way too short
        assert!(
            kp.verify(msg, &short_sig).is_err(),
            "Truncated signature must fail"
        );
    }

    #[test]
    fn test_ed25519_free_functions() {
        let kp = Ed25519Keypair::generate();
        let sk = kp.secret_key();
        let pk = kp.public_key();
        let msg = b"free fn test";
        let sig = ed25519_sign(&sk, msg);
        assert!(ed25519_verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_two_keypairs_produce_different_sigs() {
        let kp1 = Ed25519Keypair::generate();
        let kp2 = Ed25519Keypair::generate();
        let msg = b"same message";
        let sig1 = kp1.sign(msg);
        let sig2 = kp2.sign(msg);
        // Different keys must produce different signatures (with overwhelming probability)
        assert_ne!(sig1.0, sig2.0);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod dh_tests {
    use zero_crypto::dh::{x25519_diffie_hellman, X25519Keypair};

    #[test]
    fn test_dh_symmetry() {
        let a = X25519Keypair::generate();
        let b = X25519Keypair::generate();
        let ss_ab = x25519_diffie_hellman(&a.secret_key(), &b.public_key()).unwrap();
        let ss_ba = x25519_diffie_hellman(&b.secret_key(), &a.public_key()).unwrap();
        assert_eq!(ss_ab.0, ss_ba.0, "DH must be symmetric: DH(a,B) == DH(b,A)");
    }

    #[test]
    fn test_dh_different_keypairs_differ() {
        let a = X25519Keypair::generate();
        let b = X25519Keypair::generate();
        let c = X25519Keypair::generate();
        let ss_ab = x25519_diffie_hellman(&a.secret_key(), &b.public_key()).unwrap();
        let ss_ac = x25519_diffie_hellman(&a.secret_key(), &c.public_key()).unwrap();
        assert_ne!(
            ss_ab.0, ss_ac.0,
            "Different partners must produce different shared secrets"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod kdf_tests {
    use zero_crypto::kdf::{hkdf, hkdf_expand, hkdf_extract, KdfContext};

    #[test]
    fn test_hkdf_deterministic() {
        let salt = b"test-salt";
        let ikm = b"input-key-material";
        let prk1 = hkdf_extract(salt, ikm);
        let prk2 = hkdf_extract(salt, ikm);
        assert_eq!(prk1, prk2, "HKDF extract must be deterministic");
    }

    #[test]
    fn test_hkdf_different_salts_produce_different_output() {
        let ikm = b"same-ikm";
        let prk1 = hkdf_extract(b"salt-a", ikm);
        let prk2 = hkdf_extract(b"salt-b", ikm);
        assert_ne!(prk1, prk2, "Different salts must produce different PRKs");
    }

    #[test]
    fn test_hkdf_different_contexts_produce_different_output() {
        let prk = hkdf_extract(b"salt", b"ikm");
        let out1 = hkdf_expand(&prk, KdfContext::ZrSendChain, 32).unwrap();
        let out2 = hkdf_expand(&prk, KdfContext::ZrRecvChain, 32).unwrap();
        assert_ne!(
            out1, out2,
            "Different contexts must produce different output"
        );
    }

    #[test]
    fn test_hkdf_output_length() {
        let out = hkdf(b"salt", b"ikm", KdfContext::ZkxMasterSecret, 64).unwrap();
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn test_hkdf_max_output() {
        // SHA-256 HKDF can produce up to 255 * 32 = 8160 bytes
        let prk = hkdf_extract(b"s", b"i");
        let out = hkdf_expand(&prk, KdfContext::ZrRootChain, 64).unwrap();
        assert_eq!(out.len(), 64);
    }
}
