//! ZERO ID — the user-facing identity string.
//!
//! ## Format
//! `Base58Check( ISK_pub[32] || IDK_pub[32] || PQ_hash[4] || nospam[4] || checksum[2] )`
//!
//! Total raw bytes: 74. Encoded length: ~101 Base58 chars.
//! Checksum = first 2 bytes of BLAKE2b-256(ISK_pub || IDK_pub || PQ_hash || nospam).

use crate::{
    encoding::{base58_decode, base58_encode},
    error::IdentityError,
    keypair::ZeroKeypair,
};
use serde::{Deserialize, Serialize, Deserializer, Serializer};
use zero_crypto::hash::blake2b_256;

/// Expected maximum encoded ZERO ID string length.
pub const ZERO_ID_STRING_LEN: usize = 104;

/// Raw byte layout constants.
const ISK_OFFSET: usize = 0;
const IDK_OFFSET: usize = 32;
const PQ_HASH_OFFSET: usize = 64;
const NOSPAM_OFFSET: usize = 68;
const CHECKSUM_OFFSET: usize = 72;
const RAW_SIZE: usize = 74; // 32+32+4+4+2

/// A decoded ZERO ID with all its components.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroIdComponents {
    /// Ed25519 ISK public key (32 bytes).
    pub isk_pub: [u8; 32],
    /// X25519 IDK public key (32 bytes).
    pub idk_pub: [u8; 32],
    /// First 4 bytes of BLAKE2b-256(PQ_ISK_pub).
    pub pq_hash: [u8; 4],
    /// Anti-spam token — can be rotated to invalidate friend requests.
    pub nospam: [u8; 4],
    /// 2-byte BLAKE2b-based checksum for error detection.
    pub checksum: [u8; 2],
}

/// A complete ZERO ID — the user's shareable identity string.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ZeroId {
    raw: [u8; RAW_SIZE],
}

impl Serialize for ZeroId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.raw)
    }
}

impl<'de> Deserialize<'de> for ZeroId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ZeroIdVisitor;

        impl<'de> serde::de::Visitor<'de> for ZeroIdVisitor {
            type Value = ZeroId;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a {}-byte ZeroId", RAW_SIZE)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != RAW_SIZE {
                    return Err(E::custom(format!(
                        "Invalid ZeroId length: expected {}, got {}",
                        RAW_SIZE,
                        v.len()
                    )));
                }
                let mut raw = [0u8; RAW_SIZE];
                raw.copy_from_slice(v);
                Ok(ZeroId { raw })
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(&v)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut v = Vec::with_capacity(RAW_SIZE);
                while let Some(b) = seq.next_element::<u8>()? {
                    v.push(b);
                }
                self.visit_bytes(&v)
            }
        }

        deserializer.deserialize_any(ZeroIdVisitor)
    }
}

impl ZeroId {
    /// Create a new ZERO ID from a keypair.
    pub fn from_keypair(keypair: &ZeroKeypair, nospam: [u8; 4]) -> Self {
        let isk_pub = keypair.isk.public_key().0;
        let idk_pub = keypair.idk.public_key().0;
        let pq_hash_full = keypair.pq_isk_hash();
        let pq_hash: [u8; 4] = pq_hash_full[..4].try_into().unwrap();

        let checksum = compute_checksum(&isk_pub, &idk_pub, &pq_hash, &nospam);
        let mut raw = [0u8; RAW_SIZE];
        raw[ISK_OFFSET..IDK_OFFSET].copy_from_slice(&isk_pub);
        raw[IDK_OFFSET..PQ_HASH_OFFSET].copy_from_slice(&idk_pub);
        raw[PQ_HASH_OFFSET..NOSPAM_OFFSET].copy_from_slice(&pq_hash);
        raw[NOSPAM_OFFSET..CHECKSUM_OFFSET].copy_from_slice(&nospam);
        raw[CHECKSUM_OFFSET..RAW_SIZE].copy_from_slice(&checksum);
        Self { raw }
    }

    /// Encode this ZERO ID as a Base58Check string.
    pub fn to_string_repr(&self) -> String {
        base58_encode(&self.raw)
    }

    /// Decode a ZERO ID from a Base58Check string.
    pub fn from_string(s: &str) -> Result<Self, IdentityError> {
        let raw = base58_decode(s)
            .map_err(|e| IdentityError::InvalidEncoding(e.to_string()))?;
        if raw.len() != RAW_SIZE {
            return Err(IdentityError::InvalidEncoding(format!(
                "Expected {} bytes, got {}",
                RAW_SIZE,
                raw.len()
            )));
        }
        let mut arr = [0u8; RAW_SIZE];
        arr.copy_from_slice(&raw);
        let id = Self { raw: arr };
        id.verify_checksum()?;
        Ok(id)
    }

    /// Decode to individual components.
    pub fn components(&self) -> ZeroIdComponents {
        let isk_pub: [u8; 32] = self.raw[ISK_OFFSET..IDK_OFFSET].try_into().unwrap();
        let idk_pub: [u8; 32] = self.raw[IDK_OFFSET..PQ_HASH_OFFSET].try_into().unwrap();
        let pq_hash: [u8; 4] = self.raw[PQ_HASH_OFFSET..NOSPAM_OFFSET].try_into().unwrap();
        let nospam: [u8; 4] = self.raw[NOSPAM_OFFSET..CHECKSUM_OFFSET].try_into().unwrap();
        let checksum: [u8; 2] = self.raw[CHECKSUM_OFFSET..RAW_SIZE].try_into().unwrap();
        ZeroIdComponents { isk_pub, idk_pub, pq_hash, nospam, checksum }
    }

    /// Return the ISK public key bytes — the canonical peer identifier.
    pub fn isk_pub(&self) -> [u8; 32] {
        self.raw[ISK_OFFSET..IDK_OFFSET].try_into().unwrap()
    }

    /// Return the IDK public key bytes.
    pub fn idk_pub(&self) -> [u8; 32] {
        self.raw[IDK_OFFSET..PQ_HASH_OFFSET].try_into().unwrap()
    }

    /// Raw bytes of the ZERO ID.
    pub fn as_bytes(&self) -> &[u8; RAW_SIZE] {
        &self.raw
    }

    fn verify_checksum(&self) -> Result<(), IdentityError> {
        let c = self.components();
        let expected = compute_checksum(&c.isk_pub, &c.idk_pub, &c.pq_hash, &c.nospam);
        if c.checksum != expected {
            return Err(IdentityError::ChecksumMismatch);
        }
        Ok(())
    }
}

impl std::fmt::Display for ZeroId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_repr())
    }
}

impl std::fmt::Debug for ZeroId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZeroId({})", self.to_string_repr())
    }
}

fn compute_checksum(
    isk_pub: &[u8; 32],
    idk_pub: &[u8; 32],
    pq_hash: &[u8; 4],
    nospam: &[u8; 4],
) -> [u8; 2] {
    let mut data = Vec::with_capacity(72);
    data.extend_from_slice(isk_pub);
    data.extend_from_slice(idk_pub);
    data.extend_from_slice(pq_hash);
    data.extend_from_slice(nospam);
    let hash = blake2b_256(&data);
    [hash[0], hash[1]]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id() -> (ZeroKeypair, ZeroId) {
        let kp = ZeroKeypair::generate().unwrap();
        let id = ZeroId::from_keypair(&kp, [0x42; 4]);
        (kp, id)
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let (_kp, id) = make_id();
        let s = id.to_string_repr();
        let decoded = ZeroId::from_string(&s).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_tampered_id_fails_checksum() {
        let (_kp, id) = make_id();
        let s = id.to_string_repr();
        // Flip a character
        let mut s_bytes = s.into_bytes();
        s_bytes[5] = if s_bytes[5] == b'A' { b'B' } else { b'A' };
        let s = String::from_utf8(s_bytes).unwrap();
        let result = ZeroId::from_string(&s);
        assert!(result.is_err());
    }

    #[test]
    fn test_isk_pub_matches_keypair() {
        let kp = ZeroKeypair::generate().unwrap();
        let id = ZeroId::from_keypair(&kp, [0u8; 4]);
        assert_eq!(id.isk_pub(), kp.isk.public_key().0);
    }

    #[test]
    fn test_two_ids_differ() {
        let kp1 = ZeroKeypair::generate().unwrap();
        let kp2 = ZeroKeypair::generate().unwrap();
        let id1 = ZeroId::from_keypair(&kp1, [0u8; 4]);
        let id2 = ZeroId::from_keypair(&kp2, [0u8; 4]);
        assert_ne!(id1, id2);
    }
}
