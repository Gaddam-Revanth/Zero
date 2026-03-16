//! ZKX Master Secret output type.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of the ZKX master secret in bytes.
pub const MASTER_SECRET_SIZE: usize = 64;

/// The master secret produced by ZKX.
/// Used to seed the initial Zero Ratchet state.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret(pub [u8; MASTER_SECRET_SIZE]);

impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret([REDACTED])")
    }
}

/// The complete output of a successful ZKX handshake.
#[derive(Debug)]
pub struct ZkxOutput {
    /// The shared master secret.
    pub master_secret: MasterSecret,
    /// Transcript hash from the Noise XX phase.
    pub noise_hash: [u8; 32],
    /// Remote party's ISK public key (verified).
    pub remote_isk_pub: [u8; 32],
}
