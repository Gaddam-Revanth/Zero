//! Base58Check encoding/decoding for ZERO IDs.
//!
//! Uses the Bitcoin Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
//! This alphabet deliberately excludes: 0, O, I, l — characters that look visually similar.

use crate::error::IdentityError;

/// Bitcoin/ZERO Base58 alphabet (no 0OIl).
const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode raw bytes as a Base58 string.
pub fn base58_encode(data: &[u8]) -> String {
    // Count leading zero bytes → map to leading '1's
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert to big-endian base-256 integer then divide repeatedly by 58
    let mut digits: Vec<u8> = Vec::with_capacity(data.len() * 138 / 100 + 1);
    for &byte in data {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            carry += (*digit as u32) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut result = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        result.push('1');
    }
    for digit in digits.iter().rev() {
        result.push(ALPHABET[*digit as usize] as char);
    }
    result
}

/// Decode a Base58 string to raw bytes.
pub fn base58_decode(s: &str) -> Result<Vec<u8>, IdentityError> {
    // Build reverse lookup table
    let mut table = [0xFFu8; 128];
    for (i, &c) in ALPHABET.iter().enumerate() {
        table[c as usize] = i as u8;
    }

    let leading_ones = s.bytes().take_while(|&b| b == b'1').count();
    let mut digits: Vec<u8> = Vec::with_capacity(s.len() * 733 / 1000 + 1);

    for byte in s.bytes() {
        if byte > 127 {
            return Err(IdentityError::InvalidEncoding(
                "Non-ASCII character in ZERO ID".into(),
            ));
        }
        let val = table[byte as usize];
        if val == 0xFF {
            return Err(IdentityError::InvalidEncoding(format!(
                "Invalid Base58 character: '{}'",
                byte as char
            )));
        }
        let mut carry = val as u32;
        for digit in digits.iter_mut() {
            carry += (*digit as u32) * 58;
            *digit = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            digits.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    let mut result = vec![0u8; leading_ones];
    for digit in digits.iter().rev() {
        result.push(*digit);
    }
    Ok(result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let data = b"Hello, ZERO Protocol!";
        let encoded = base58_encode(data);
        let decoded = base58_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_known_vector() {
        // ZERO bytes → all '1's
        let zeros = [0u8; 4];
        let encoded = base58_encode(&zeros);
        assert!(encoded.chars().all(|c| c == '1'));
    }

    #[test]
    fn test_invalid_character_fails() {
        assert!(base58_decode("Invalid0OIl!").is_err());
    }

    #[test]
    fn test_74_byte_roundtrip() {
        let data: Vec<u8> = (0..74).map(|i| i as u8).collect();
        let enc = base58_encode(&data);
        let dec = base58_decode(&enc).unwrap();
        assert_eq!(dec, data);
    }
}
