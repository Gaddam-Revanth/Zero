//! Replay tokens and replay cache.

use blake2::{Blake2b512, Digest};
use dashmap::DashMap;
use rand::{rngs::OsRng, RngCore};

use crate::types::PacketType;

/// 16-byte replay token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplayToken(pub [u8; 16]);

impl ReplayToken {
    /// Generate a new random replay token.
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        OsRng.fill_bytes(&mut b);
        ReplayToken(b)
    }
}

/// Replay cache key = BLAKE2b-256(receiver || type || token) truncated to 16 bytes.
fn key(receiver: &[u8; 32], ty: PacketType, tok: &ReplayToken) -> [u8; 16] {
    let mut h = Blake2b512::new();
    h.update(receiver);
    h.update((ty as u16).to_be_bytes());
    h.update(tok.0);
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Bounded replay cache with TTL.
///
/// This is intentionally simple: it stores replay keys until `expiry_ms`.
pub struct ReplayCache {
    ttl_ms: u64,
    entries: DashMap<[u8; 16], u64>,
    last_purge_ms: std::sync::atomic::AtomicU64,
}

impl ReplayCache {
    /// Create a replay cache with TTL in milliseconds.
    pub fn new(ttl_ms: u64) -> Self {
        Self { 
            ttl_ms, 
            entries: DashMap::new(),
            last_purge_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Returns true if token is fresh (inserted), false if replayed.
    pub fn check_and_insert(
        &self,
        now_ms: u64,
        receiver_node_id: &[u8; 32],
        packet_type: PacketType,
        token: &ReplayToken,
    ) -> bool {
        let last_purge = self.last_purge_ms.load(std::sync::atomic::Ordering::Relaxed);
        if now_ms.saturating_sub(last_purge) > 60_000 {
            self.purge(now_ms);
            self.last_purge_ms.store(now_ms, std::sync::atomic::Ordering::Relaxed);
        }
        let k = key(receiver_node_id, packet_type, token);
        let expiry = now_ms.saturating_add(self.ttl_ms);
        self.entries.insert(k, expiry).is_none()
    }

    /// Purge expired entries.
    pub fn purge(&self, now_ms: u64) {
        self.entries.retain(|_, exp| *exp > now_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_cache_rejects_replay() {
        let cache = ReplayCache::new(10_000);
        let receiver = [7u8; 32];
        let tok = ReplayToken::random();
        let t = 1_000;
        assert!(cache.check_and_insert(t, &receiver, PacketType::ZkxInit, &tok));
        assert!(!cache.check_and_insert(t + 1, &receiver, PacketType::ZkxInit, &tok));
    }
}

