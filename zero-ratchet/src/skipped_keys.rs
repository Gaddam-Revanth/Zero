//! Out-of-order message key cache for ZR.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zero_crypto::dh::X25519PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum skipped keys stored per session.
pub const MAX_SKIPPED_KEYS: usize = 2000;

/// A cached message key with timestamp (seconds since epoch).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CachedKey {
    /// The actual message key bytes.
    pub key: [u8; 32],
    /// Unix timestamp when this key was cached.
    pub cached_at: u64,
}

/// The skipped-key cache.
#[derive(Default, Serialize, Deserialize)]
pub struct SkippedKeyCache {
    cache: HashMap<(X25519PublicKey, u32), CachedKey>,
}

impl SkippedKeyCache {
    /// Create a new, empty cache.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Insert a cached key.
    pub fn insert(&mut self, dh_pub: X25519PublicKey, counter: u32, key: [u8; 32], now: u64) {
        if self.cache.len() >= MAX_SKIPPED_KEYS {
            // Evict oldest key
            let oldest = self
                .cache
                .iter()
                .min_by_key(|(_, v)| v.cached_at)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.cache.remove(&k);
            }
        }
        self.cache.insert(
            (dh_pub, counter),
            CachedKey {
                key,
                cached_at: now,
            },
        );
    }

    /// Try to retrieve and remove a cached key.
    pub fn take(&mut self, dh_pub: &X25519PublicKey, counter: u32) -> Option<[u8; 32]> {
        self.cache
            .remove(&(dh_pub.clone(), counter))
            .map(|ck| ck.key)
    }

    /// Purge keys older than `max_age_secs` seconds.
    pub fn purge_expired(&mut self, now: u64, max_age_secs: u64) {
        self.cache.retain(|_, v| now - v.cached_at < max_age_secs);
    }

    /// Number of cached keys.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}
