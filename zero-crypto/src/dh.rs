//! X25519 Diffie-Hellman key exchange for ZERO Protocol.

use crate::error::CryptoError;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::constants::X25519_BASEPOINT;

pub const X25519_KEY_SIZE: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct X25519PublicKey(pub [u8; X25519_KEY_SIZE]);

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey(pub [u8; X25519_KEY_SIZE]);

impl std::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519SecretKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct X25519Keypair {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

impl X25519Keypair {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut rng = OsRng;
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        
        // Clamp the secret bytes for X25519 (RFC 7748)
        secret_bytes[0] &= 248;
        secret_bytes[31] &= 127;
        secret_bytes[31] |= 64;
        
        let scalar = Scalar::from_bytes_mod_order(secret_bytes);
        let public = scalar * X25519_BASEPOINT;
        
        Self {
            secret: secret_bytes,
            public: public.to_bytes(),
        }
    }

    pub fn from_secret_bytes(bytes: [u8; X25519_KEY_SIZE]) -> Self {
        let scalar = Scalar::from_bytes_mod_order(bytes);
        let public = scalar * X25519_BASEPOINT;
        
        Self {
            secret: bytes,
            public: public.to_bytes(),
        }
    }

    pub fn secret_key(&self) -> X25519SecretKey {
        X25519SecretKey(self.secret)
    }

    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(self.public)
    }

    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> X25519SharedSecret {
        let scalar = Scalar::from_bytes_mod_order(self.secret);
        let point = MontgomeryPoint(their_public.0);
        let shared = scalar * point;
        
        X25519SharedSecret(shared.to_bytes())
    }
}

#[derive(Serialize, Deserialize)]
pub struct X25519SharedSecret(pub [u8; X25519_KEY_SIZE]);

impl std::fmt::Debug for X25519SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519SharedSecret([REDACTED])")
    }
}

impl Zeroize for X25519SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for X25519SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn x25519_diffie_hellman(
    secret_key: &X25519SecretKey,
    public_key: &X25519PublicKey,
) -> Result<X25519SharedSecret, CryptoError> {
    let scalar = Scalar::from_bytes_mod_order(secret_key.0);
    let point = MontgomeryPoint(public_key.0);
    let shared = scalar * point;
    
    let output = shared.to_bytes();
    if output.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidPublicKey);
    }
    Ok(X25519SharedSecret(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_exchange() {
        let kp1 = X25519Keypair::generate();
        let kp2 = X25519Keypair::generate();
        
        let ss1 = kp1.diffie_hellman(&kp2.public_key());
        let ss2 = kp2.diffie_hellman(&kp1.public_key());
        
        assert_eq!(ss1.0, ss2.0);
        assert!(ss1.0.iter().any(|&b| b != 0));
    }
}
