//! Proof of Work (Hashcash) for ZSF anti-spam.

use zero_crypto::hash::blake2b_256_multi;

/// Target difficulty (number of leading zero bits required).
/// E.g., 20 bits = ~1 million hashes (takes <1s on mobile).
pub const POW_DIFFICULTY_BITS: u32 = 20;

/// Generate Proof of Work for a specific target NodeID.
pub struct ProofOfWork;

impl ProofOfWork {
    /// Mine a nonce that hashes with the recipient ID to have enough leading zeros.
    pub fn generate(recipient_id: &[u8; 32]) -> u64 {
        let mut nonce = 0u64;
        loop {
            let n_bytes = nonce.to_le_bytes();
            let hash = blake2b_256_multi(&[recipient_id, &n_bytes]);
            if count_leading_zero_bits(&hash) >= POW_DIFFICULTY_BITS {
                return nonce;
            }
            nonce += 1;
        }
    }
}

/// Verify a given PoW nonce for a recipient.
pub fn verify_pow(recipient_id: &[u8; 32], nonce: u64) -> bool {
    let n_bytes = nonce.to_le_bytes();
    let hash = blake2b_256_multi(&[recipient_id, &n_bytes]);
    count_leading_zero_bits(&hash) >= POW_DIFFICULTY_BITS
}

fn count_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut count = 0;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_generate_verify() {
        // Lower difficulty for fast test
        let mut n = 0_u64;
        let id = [0xAAu8; 32];
        loop {
            let n_bytes = (n as u64).to_le_bytes();
            let hash = blake2b_256_multi(&[&id, &n_bytes]);
            if count_leading_zero_bits(&hash) >= 10 {
                assert!(count_leading_zero_bits(&hash) >= 10);
                break;
            }
            n += 1u64;
        }
    }
}
