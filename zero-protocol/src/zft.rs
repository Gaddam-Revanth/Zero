//! ZFT — ZERO File Transfer
#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use zero_crypto::hash::blake2b_256;
use crate::error::ZeroError;
use serde::{Deserialize, Serialize};

/// Metadata for a file transfer offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOffer {
    pub transfer_id: String,
    pub filename: String,
    pub size: u64,
    pub file_hash: [u8; 32],
}

/// A chunk of file data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub transfer_id: String,
    pub index: u32,
    pub data: Vec<u8>,
}

/// Manages file transfers for a node.
pub struct ZftManager {
    download_dir: PathBuf,
}

impl ZftManager {
    /// Create a ZFT manager with the given download directory.
    pub fn new(download_dir: PathBuf) -> Self {
        Self { download_dir }
    }

    /// Get the download directory for this manager.
    pub fn download_dir(&self) -> &Path {
        &self.download_dir
    }

    /// Prepare a file for sending.
    pub async fn offer_file(&self, path: &Path) -> Result<FileOffer, ZeroError> {
        let content = tokio::fs::read(path).await
            .map_err(|e| ZeroError::Custom(e.to_string()))?;
        
        let file_hash = blake2b_256(&content);
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(FileOffer {
            transfer_id: uuid::Uuid::new_v4().to_string(),
            filename,
            size: content.len() as u64,
            file_hash,
        })
    }

    /// Verify a received file hash.
    pub fn verify_file(&self, data: &[u8], expected_hash: &[u8; 32]) -> bool {
        let actual = blake2b_256(data);
        actual == *expected_hash
    }
}
