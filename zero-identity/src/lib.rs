//! # zero-identity
//!
//! ZERO Identity System — self-sovereign cryptographic identity.
//!
//! ## ZERO ID Structure
//! ```text
//! ISK   — Ed25519 Identity Signing Keypair (permanent, never changes)
//! IDK   — X25519 Identity DH Keypair
//! SPK   — X25519 Signed Prekey (rotated every 7 days)
//! OPK[] — X25519 One-Time Prekeys (batch of 100, consumed once each)
//! PQ_ISK — ML-KEM-768 Keypair (post-quantum)
//! ```
//!
//! ## ZERO ID String
//! `Base58Check(ISK_pub || IDK_pub || PQ_ISK_pub_hash[4] || nospam[4] || checksum[2])`

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod bundle;
pub mod encoding;
pub mod error;
pub mod keypair;
pub mod prekey;
pub mod zeroid;

pub use bundle::{KeyBundle, OwnedKeyBundle};
pub use encoding::{base58_decode, base58_encode};
pub use error::IdentityError;
pub use keypair::ZeroKeypair;
pub use prekey::{OneTimePrekey, SignedPrekey, OPKS_BATCH_SIZE};
pub use zeroid::{ZeroId, ZeroIdComponents, ZERO_ID_STRING_LEN};
