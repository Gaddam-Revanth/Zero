//! BLAKE2b hashing for ZERO Protocol.

use blake2::{Blake2b512 as Blake2b512Hasher, Digest};
use blake2::digest::consts::U32;

pub const BLAKE2B_256_SIZE: usize = 32;
pub const BLAKE2B_512_SIZE: usize = 64;

pub type Blake2b256 = [u8; BLAKE2B_256_SIZE];
pub type Blake2b512 = [u8; BLAKE2B_512_SIZE];

type Blake2b256Inner = blake2::Blake2b<U32>;
type Blake2b512Inner = Blake2b512Hasher;

pub fn blake2b_256(data: &[u8]) -> Blake2b256 {
    let mut hasher = Blake2b256Inner::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn blake2b_512(data: &[u8]) -> Blake2b512 {
    let mut hasher = Blake2b512Inner::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

pub fn blake2b_256_multi(parts: &[&[u8]]) -> Blake2b256 {
    let mut hasher = Blake2b256Inner::new();
    for part in parts {
        hasher.update(part);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn blake2b_512_multi(parts: &[&[u8]]) -> Blake2b512 {
    let mut hasher = Blake2b512Inner::new();
    for part in parts {
        hasher.update(part);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}
