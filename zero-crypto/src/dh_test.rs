use zero_crypto::dh::{X25519Keypair, X25519PublicKey};

#[test]
fn test_dh_exchange() {
    let kp1 = X25519Keypair::generate();
    let kp2 = X25519Keypair::generate();
    
    let ss1 = kp1.diffie_hellman(&kp2.public_key());
    let ss2 = kp2.diffie_hellman(&kp1.public_key());
    
    assert_eq!(ss1.0, ss2.0);
    assert!(ss1.0.iter().any(|&b| b != 0));
}
