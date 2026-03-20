//! # zero-handshake
//!
//! ZKX — ZERO Key Exchange.
//!
//! Three-phase hybrid key agreement:
//! 1. **Noise XX** — mutual authentication + identity hiding channel
//! 2. **X3DH** — asynchronous classical key agreement (4 DH operations)
//! 3. **ML-KEM-768** — post-quantum layer
//!
//! Result: `master_secret = HKDF(DH1||DH2||DH3||DH4||KEM_secret, "ZKX-v1")`
//!
//! An attacker must simultaneously break BOTH classical X3DH AND ML-KEM-768
//! to compromise the key agreement.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod error;
pub mod master_secret;
pub mod noise;
pub mod x3dh;
/// Background ephemeral key pool management.
pub mod ephemeral_pool;

pub use error::HandshakeError;
pub use master_secret::{MasterSecret, ZkxOutput, MASTER_SECRET_SIZE};
pub use noise::{NoiseHandshakeState, NoiseRole};
pub use x3dh::{X3dhInitiator, X3dhResponder, ZkxInitMessage};
