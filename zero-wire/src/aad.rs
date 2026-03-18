//! AAD (Additional Authenticated Data) builder.
//!
//! v1.0 uses deterministic bytes derived from the universal header to avoid any
//! cross-language CBOR canonicalization pitfalls. These bytes MUST be included as AAD
//! for all AEAD-protected payloads.

use crate::header::{PacketHeader, MAGIC};

/// Deterministic AAD bytes for ZERO v1.0.
///
/// Layout:
/// `MAGIC || ver_major || ver_minor || packet_type || flags || body_len || sender || receiver`
pub fn aad_bytes_v1(h: &PacketHeader, sender: &[u8; 32], receiver: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 2 + 2 + 2 + 2 + 4 + 32 + 32);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&h.version.major.to_be_bytes());
    out.extend_from_slice(&h.version.minor.to_be_bytes());
    out.extend_from_slice(&(h.packet_type as u16).to_be_bytes());
    out.extend_from_slice(&h.flags.0.to_be_bytes());
    out.extend_from_slice(&h.body_len.to_be_bytes());
    out.extend_from_slice(sender);
    out.extend_from_slice(receiver);
    out
}

