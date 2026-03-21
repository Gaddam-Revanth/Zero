//! Centralized CBOR serialization/deserialization wrapping `ciborium`.
//! This replaces the deprecated `serde_cbor` crate to eliminate vulnerability RUSTSEC-2021-0127.

use serde::{de::DeserializeOwned, Serialize};

#[derive(thiserror::Error, Debug)]
pub enum CborError {
    #[error("Serialization failed")]
    Serialization,
    #[error("Deserialization failed")]
    Deserialization,
}

/// Serialize a value to a CBOR byte vector.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| CborError::Serialization)?;
    Ok(buf)
}

/// Deserialize a value from a CBOR byte slice.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CborError> {
    ciborium::from_reader(bytes).map_err(|_| CborError::Deserialization)
}
