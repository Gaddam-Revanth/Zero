//! ML-KEM-768 post-quantum Key Encapsulation Mechanism (FIPS 203).
//!
//! Implements real ML-KEM-768 using the `ml-kem` v0.3.0-rc.0 crate.
//! Uses seed-based key generation to avoid `rand_core` version conflicts
//! (ml-kem v0.3.0-rc.0 requires rand_core v0.10, workspace uses v0.6).

use crate::error::CryptoError;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ML-KEM-768 sizes (FIPS 203)
/// Size of the ML-KEM-768 encapsulation (public) key in bytes.
pub const ML_KEM_768_EK_SIZE: usize = 1184;
/// Seed size for the ML-KEM-768 decapsulation key (64 bytes, FIPS 203 preferred format).
pub const ML_KEM_768_DK_SIZE: usize = 64;
/// Size of the ML-KEM-768 ciphertext in bytes.
pub const ML_KEM_768_CT_SIZE: usize = 1088;
/// Size of the ML-KEM-768 shared secret in bytes.
pub const ML_KEM_768_SS_SIZE: usize = 32;

/// An ML-KEM-768 encapsulation (public) key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKem768EncapsKey(pub Vec<u8>);

/// An ML-KEM-768 decapsulation (private) key stored as a 64-byte seed. Zeroized on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MlKem768DecapsKey(pub Vec<u8>);

impl std::fmt::Debug for MlKem768DecapsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MlKem768DecapsKey([REDACTED])")
    }
}

/// An ML-KEM-768 ciphertext produced by encapsulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKem768Ciphertext(pub Vec<u8>);

/// A 32-byte ML-KEM-768 shared secret. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem768SharedSecret(pub [u8; ML_KEM_768_SS_SIZE]);

impl std::fmt::Debug for MlKem768SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MlKem768SharedSecret([REDACTED])")
    }
}

/// A paired ML-KEM-768 encapsulation and decapsulation keypair.
pub struct MlKem768Keypair {
    /// The encapsulation (public) key.
    pub ek: MlKem768EncapsKey,
    /// The decapsulation (private) key as a 64-byte seed.
    pub dk: MlKem768DecapsKey,
}

impl MlKem768Keypair {
    /// Generate a new ML-KEM-768 keypair from OS randomness (FIPS 203 §6.1).
    pub fn generate() -> Result<Self, CryptoError> {
        use rand::RngCore;
        use rand::rngs::OsRng;
        use ml_kem::{DecapsulationKey768, Seed, kem::KeyExport};

        // Generate 64-byte seed via rand 0.8 OsRng (avoids rand_core version conflict)
        let mut seed_raw = [0u8; 64];
        OsRng.try_fill_bytes(&mut seed_raw).map_err(|_| CryptoError::RngFailure)?;

        let seed = Seed::from(seed_raw);
        let dk = DecapsulationKey768::from_seed(seed);
        let ek = dk.encapsulation_key();

        // Serialize via KeyExport trait
        let ek_bytes: Vec<u8> = ek.to_bytes().as_slice().to_vec();
        // to_seed() is Some because we just created from_seed
        let dk_seed = dk.to_seed().ok_or(CryptoError::KemEncapsulationFailed)?;
        let dk_bytes: Vec<u8> = dk_seed.as_slice().to_vec();

        Ok(Self {
            ek: MlKem768EncapsKey(ek_bytes),
            dk: MlKem768DecapsKey(dk_bytes),
        })
    }
}

/// Encapsulate a shared secret for the holder of the given encapsulation key (FIPS 203 §6.2).
pub fn ml_kem_768_encapsulate(
    ek: &MlKem768EncapsKey,
) -> Result<(MlKem768Ciphertext, MlKem768SharedSecret), CryptoError> {
    use rand::RngCore;
    use rand::rngs::OsRng;
    use ml_kem::{EncapsulationKey768, B32};

    if ek.0.len() != ML_KEM_768_EK_SIZE {
        return Err(CryptoError::InvalidKeyLength { expected: ML_KEM_768_EK_SIZE, got: ek.0.len() });
    }

    // Deserialize encapsulation key
    let ek_arr: &[u8; ML_KEM_768_EK_SIZE] = ek.0.as_slice().try_into().unwrap();
    let encaps_key = EncapsulationKey768::new(ek_arr.into())
        .map_err(|_| CryptoError::KemEncapsulationFailed)?;

    // Generate a 32-byte random message m for encapsulate_deterministic
    let mut m_raw = [0u8; 32];
    OsRng.try_fill_bytes(&mut m_raw).map_err(|_| CryptoError::RngFailure)?;
    let m = B32::from(m_raw);

    // encapsulate_deterministic is the only way to call without rand_core 0.10
    let (ct, ss) = encaps_key.encapsulate_deterministic(&m);

    let ct_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&ct).to_vec();
    let mut ss_bytes = [0u8; ML_KEM_768_SS_SIZE];
    ss_bytes.copy_from_slice(ss.as_slice());

    Ok((MlKem768Ciphertext(ct_bytes), MlKem768SharedSecret(ss_bytes)))
}

/// Decapsulate the shared secret from the ciphertext (FIPS 203 §6.3).
/// Uses implicit rejection — always returns a key (never fails), preventing oracle attacks.
pub fn ml_kem_768_decapsulate(
    dk: &MlKem768DecapsKey,
    ct: &MlKem768Ciphertext,
) -> Result<MlKem768SharedSecret, CryptoError> {
    use ml_kem::{DecapsulationKey768, Seed, ml_kem_768::Ciphertext, kem::{Decapsulate, KeyInit}};

    if dk.0.len() != ML_KEM_768_DK_SIZE {
        return Err(CryptoError::InvalidKeyLength { expected: ML_KEM_768_DK_SIZE, got: dk.0.len() });
    }
    if ct.0.len() != ML_KEM_768_CT_SIZE {
        return Err(CryptoError::InvalidKeyLength { expected: ML_KEM_768_CT_SIZE, got: ct.0.len() });
    }

    // Reconstruct decapsulation key from its seed
    let seed_arr: &[u8; ML_KEM_768_DK_SIZE] = dk.0.as_slice().try_into().unwrap();
    let seed = Seed::from(*seed_arr);
    let decaps_key = DecapsulationKey768::new(&seed);

    // Reconstruct ciphertext
    let ct_arr: &[u8; ML_KEM_768_CT_SIZE] = ct.0.as_slice().try_into().unwrap();
    let ciphertext = Ciphertext::from(*ct_arr);

    // Infallible: FIPS 203 implicit rejection returns pseudorandom key on tampering
    let ss = decaps_key.decapsulate(&ciphertext);

    let mut ss_bytes = [0u8; ML_KEM_768_SS_SIZE];
    ss_bytes.copy_from_slice(ss.as_slice());

    Ok(MlKem768SharedSecret(ss_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_768_round_trip() {
        // Generate a keypair
        let kp = MlKem768Keypair::generate().expect("keygen should succeed");

        // Encapsulate
        let (ct, ss1) = ml_kem_768_encapsulate(&kp.ek).expect("encapsulate should succeed");

        // Decapsulate
        let ss2 = ml_kem_768_decapsulate(&kp.dk, &ct).expect("decapsulate should succeed");

        // Shared secrets must match
        assert_eq!(ss1.0, ss2.0, "Shared secrets must match after round-trip");
    }

    #[test]
    fn test_ml_kem_768_wrong_key_fails() {
        let kp1 = MlKem768Keypair::generate().unwrap();
        let kp2 = MlKem768Keypair::generate().unwrap();
        let (ct, ss1) = ml_kem_768_encapsulate(&kp1.ek).unwrap();
        // Decapsulate with the wrong key — implicit rejection returns a *different* pseudorandom key
        let ss2 = ml_kem_768_decapsulate(&kp2.dk, &ct).unwrap();
        assert_ne!(ss1.0, ss2.0, "Different keys must produce different shared secrets");
    }
}
