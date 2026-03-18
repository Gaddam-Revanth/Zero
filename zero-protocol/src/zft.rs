//! ZFT — ZERO File Transfer
//!
//! Provides chunked, hash-verified file transfer with resume capability.
#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use zero_crypto::hash::blake2b_256;
use crate::error::ZeroError;
use serde::{Deserialize, Serialize};

/// Default chunk size: 64 KiB.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Metadata for a file transfer offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOffer {
    pub transfer_id: String,
    pub filename: String,
    pub size: u64,
    pub total_chunks: u32,
    pub file_hash: [u8; 32],
}

/// A single chunk of file data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub transfer_id: String,
    pub index: u32,
    pub total: u32,
    pub data: Vec<u8>,
    /// BLAKE2b-256 hash of this chunk's data for integrity.
    pub chunk_hash: [u8; 32],
}

/// Receipt sent after successfully receiving a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkAck {
    pub transfer_id: String,
    pub index: u32,
}

/// An in-progress incoming transfer being reassembled.
#[derive(Debug)]
pub struct IncomingTransfer {
    pub offer: FileOffer,
    /// Map from chunk index to verified chunk data.
    pub received: HashMap<u32, Vec<u8>>,
}

impl IncomingTransfer {
    /// Create a new incoming transfer from a received offer.
    pub fn new(offer: FileOffer) -> Self {
        Self { offer, received: HashMap::new() }
    }

    /// Accept an incoming chunk, verify its hash, and store it.
    pub fn receive_chunk(&mut self, chunk: FileChunk) -> Result<ChunkAck, ZeroError> {
        if chunk.transfer_id != self.offer.transfer_id {
            return Err(ZeroError::Custom("Transfer ID mismatch".to_string()));
        }
        let actual_hash = blake2b_256(&chunk.data);
        if actual_hash != chunk.chunk_hash {
            return Err(ZeroError::Custom(format!(
                "Chunk {} hash mismatch — data corrupted in transit", chunk.index
            )));
        }
        self.received.insert(chunk.index, chunk.data);
        Ok(ChunkAck { transfer_id: chunk.transfer_id, index: chunk.index })
    }

    /// Check if all chunks have been received.
    pub fn is_complete(&self) -> bool {
        self.received.len() as u32 == self.offer.total_chunks
    }

    /// Reassemble all chunks into the final file bytes.
    /// Call [`is_complete`] before calling this.
    pub fn reassemble(&self) -> Result<Vec<u8>, ZeroError> {
        if !self.is_complete() {
            return Err(ZeroError::Custom("Transfer not yet complete".to_string()));
        }
        let mut data = Vec::with_capacity(self.offer.size as usize);
        for i in 0..self.offer.total_chunks {
            let chunk = self.received.get(&i)
                .ok_or_else(|| ZeroError::Custom(format!("Missing chunk {}", i)))?;
            data.extend_from_slice(chunk);
        }
        // Final integrity check
        let file_hash = blake2b_256(&data);
        if file_hash != self.offer.file_hash {
            return Err(ZeroError::Custom("Final file hash mismatch — transfer corrupted".to_string()));
        }
        Ok(data)
    }
    
    /// Save the reassembled file to disk.
    pub async fn save_to(&self, dir: &Path) -> Result<PathBuf, ZeroError> {
        let data = self.reassemble()?;
        let dest = dir.join(&self.offer.filename);
        tokio::fs::write(&dest, &data)
            .await
            .map_err(|e| ZeroError::Custom(e.to_string()))?;
        Ok(dest)
    }
}

/// Manages file transfers for a node (both outgoing offers and incoming reassembly).
pub struct ZftManager {
    download_dir: PathBuf,
    /// Tracks in-progress incoming transfers.
    pub incoming: std::sync::Arc<dashmap::DashMap<String, IncomingTransfer>>,
}

impl ZftManager {
    /// Create a ZFT manager with the given download directory.
    pub fn new(download_dir: PathBuf) -> Self {
        Self {
            download_dir,
            incoming: std::sync::Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Get the download directory for this manager.
    pub fn download_dir(&self) -> &Path {
        &self.download_dir
    }

    /// Read a file and produce a [`FileOffer`] + all chunks ready to send.
    pub async fn prepare_send(&self, path: &Path) -> Result<(FileOffer, Vec<FileChunk>), ZeroError> {
        let content = tokio::fs::read(path)
            .await
            .map_err(|e| ZeroError::Custom(e.to_string()))?;

        let file_hash = blake2b_256(&content);
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let chunks_raw: Vec<&[u8]> = content.chunks(CHUNK_SIZE).collect();
        let total_chunks = chunks_raw.len() as u32;
        let transfer_id = uuid::Uuid::new_v4().to_string();

        let offer = FileOffer {
            transfer_id: transfer_id.clone(),
            filename,
            size: content.len() as u64,
            total_chunks,
            file_hash,
        };

        let chunks: Vec<FileChunk> = chunks_raw
            .iter()
            .enumerate()
            .map(|(i, data)| {
                let chunk_hash = blake2b_256(data);
                FileChunk {
                    transfer_id: transfer_id.clone(),
                    index: i as u32,
                    total: total_chunks,
                    data: data.to_vec(),
                    chunk_hash,
                }
            })
            .collect();

        Ok((offer, chunks))
    }

    /// Start tracking an incoming transfer once we receive the offer.
    pub fn accept_offer(&self, offer: FileOffer) {
        let transfer_id = offer.transfer_id.clone();
        self.incoming.insert(transfer_id, IncomingTransfer::new(offer));
    }

    /// Process an incoming chunk for a tracked transfer.
    pub fn process_chunk(&self, chunk: FileChunk) -> Result<ChunkAck, ZeroError> {
        let mut entry = self.incoming
            .get_mut(&chunk.transfer_id)
            .ok_or_else(|| ZeroError::Custom("Unknown transfer ID".to_string()))?;
        entry.receive_chunk(chunk)
    }

    /// Finalize a complete incoming transfer — reassemble and save to disk.
    pub async fn finalize_transfer(&self, transfer_id: &str) -> Result<PathBuf, ZeroError> {
        let entry = self.incoming
            .get(transfer_id)
            .ok_or_else(|| ZeroError::Custom("Unknown transfer ID".to_string()))?;
        let dest = entry.save_to(&self.download_dir).await?;
        drop(entry);
        self.incoming.remove(transfer_id);
        Ok(dest)
    }

    /// Verify a standalone file against an expected BLAKE2b-256 hash.
    pub fn verify_file(&self, data: &[u8], expected_hash: &[u8; 32]) -> bool {
        blake2b_256(data) == *expected_hash
    }
}
