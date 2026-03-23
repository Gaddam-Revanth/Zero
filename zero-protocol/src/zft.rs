//! ZFT — ZERO File Transfer
//!
//! Provides chunked, hash-verified file transfer with full pause/resume capability.
//! Implements the complete §13 spec:
//! - Per-chunk BLAKE2b integrity
//! - Resume via `start_chunk` field (receiver tells sender where to continue)
//! - Final file-hash verification after reassembly
#![allow(missing_docs)]

use crate::error::ZeroError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zero_crypto::hash::blake2b_256;

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

/// Acceptance from the receiver, optionally requesting resume from a chunk index.
/// Per §13.3: `start_chunk > 0` enables resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccept {
    pub transfer_id: String,
    /// The first chunk the receiver needs. 0 = start from beginning.
    /// Set to `N` to resume from chunk N (already received 0..N-1).
    pub start_chunk: u32,
}

/// A resume request sent on reconnect.
/// Per §13.3: receiver sends this after reconnecting to a broken transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResume {
    pub transfer_id: String,
    /// The index of the last successfully received chunk.
    pub last_received_chunk: u32,
}

/// A single chunk of file data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub transfer_id: String,
    pub index: u32,
    pub total: u32,
    pub data: Vec<u8>,
    /// BLAKE2b-256 hash of this chunk's data for per-chunk integrity.
    pub chunk_hash: [u8; 32],
}

/// Receipt sent by receiver after successfully receiving and verifying a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkAck {
    pub transfer_id: String,
    pub index: u32,
}

/// Completion confirmation sent by receiver after full file assembly.
/// Per §13.3: receiver sends this with the full file hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileComplete {
    pub transfer_id: String,
    /// BLAKE2b-256 hash of the fully reassembled file.
    pub file_hash: [u8; 32],
}

/// An in-progress incoming transfer being reassembled.
#[derive(Debug)]
pub struct IncomingTransfer {
    pub offer: FileOffer,
    /// Map from chunk index to verified chunk data.
    pub received: HashMap<u32, Vec<u8>>,
}

impl IncomingTransfer {
    /// Create a new incoming transfer tracker from a received offer.
    pub fn new(offer: FileOffer) -> Self {
        Self {
            offer,
            received: HashMap::new(),
        }
    }

    /// The index of the next chunk we need (for generating a resume request).
    pub fn next_needed_chunk(&self) -> u32 {
        // Return the first gap in our received sequence
        for i in 0..self.offer.total_chunks {
            if !self.received.contains_key(&i) {
                return i;
            }
        }
        self.offer.total_chunks
    }

    /// Build a FileResume request for this transfer after a reconnect.
    pub fn build_resume(&self) -> FileResume {
        let last = self.next_needed_chunk().saturating_sub(1);
        FileResume {
            transfer_id: self.offer.transfer_id.clone(),
            last_received_chunk: last,
        }
    }

    /// Accept an incoming chunk, verify its hash, and store it.
    pub fn receive_chunk(&mut self, chunk: FileChunk) -> Result<ChunkAck, ZeroError> {
        if chunk.transfer_id != self.offer.transfer_id {
            return Err(ZeroError::Custom("Transfer ID mismatch".to_string()));
        }
        let actual_hash = blake2b_256(&chunk.data);
        if actual_hash != chunk.chunk_hash {
            return Err(ZeroError::Custom(format!(
                "Chunk {} hash mismatch — data corrupted in transit",
                chunk.index
            )));
        }
        self.received.insert(chunk.index, chunk.data);
        Ok(ChunkAck {
            transfer_id: chunk.transfer_id,
            index: chunk.index,
        })
    }

    /// Check if all chunks have been received.
    pub fn is_complete(&self) -> bool {
        self.received.len() as u32 == self.offer.total_chunks
    }

    /// Reassemble all chunks into the final file bytes and verify the overall hash.
    pub fn reassemble(&self) -> Result<Vec<u8>, ZeroError> {
        if !self.is_complete() {
            return Err(ZeroError::Custom("Transfer not yet complete".to_string()));
        }
        let mut data = Vec::with_capacity(self.offer.size as usize);
        for i in 0..self.offer.total_chunks {
            let chunk = self
                .received
                .get(&i)
                .ok_or_else(|| ZeroError::Custom(format!("Missing chunk {}", i)))?;
            data.extend_from_slice(chunk);
        }
        let file_hash = blake2b_256(&data);
        if file_hash != self.offer.file_hash {
            return Err(ZeroError::Custom(
                "Final file hash mismatch — transfer is corrupted".to_string(),
            ));
        }
        Ok(data)
    }

    /// Build a FileComplete confirmation after successful reassembly.
    pub fn build_complete(&self, reassembled: &[u8]) -> FileComplete {
        FileComplete {
            transfer_id: self.offer.transfer_id.clone(),
            file_hash: blake2b_256(reassembled),
        }
    }

    /// Save the reassembled file to disk and return its path.
    pub async fn save_to(&self, dir: &Path) -> Result<PathBuf, ZeroError> {
        let data = self.reassemble()?;
        let dest = dir.join(&self.offer.filename);
        tokio::fs::write(&dest, &data)
            .await
            .map_err(|e| ZeroError::Custom(e.to_string()))?;
        Ok(dest)
    }
}

/// Manages file transfers (both outgoing and incoming).
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

    /// Read a file and produce a FileOffer + all chunks ready to send.
    /// Returns (offer, all_chunks) — caller sends the offer first, then chunks
    /// starting from `start_chunk` (0 for fresh transfer, >0 for resume).
    pub async fn prepare_send(
        &self,
        path: &Path,
    ) -> Result<(FileOffer, Vec<FileChunk>), ZeroError> {
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

    /// Filter the full chunk list to only include chunks from `start_chunk` onward.
    /// Use after receiving a FileAccept or FileResume to honour resume requests.
    pub fn chunks_from(chunks: Vec<FileChunk>, start_chunk: u32) -> Vec<FileChunk> {
        chunks
            .into_iter()
            .filter(|c| c.index >= start_chunk)
            .collect()
    }

    /// Start tracking an incoming transfer once we receive the offer.
    pub fn accept_offer(&self, offer: FileOffer) {
        self.incoming
            .insert(offer.transfer_id.clone(), IncomingTransfer::new(offer));
    }

    /// Process an incoming chunk. Returns ChunkAck on success.
    pub fn process_chunk(&self, chunk: FileChunk) -> Result<ChunkAck, ZeroError> {
        let mut entry = self
            .incoming
            .get_mut(&chunk.transfer_id)
            .ok_or_else(|| ZeroError::Custom("Unknown transfer ID".to_string()))?;
        entry.receive_chunk(chunk)
    }

    /// Build a resume request for an interrupted transfer.
    pub fn build_resume(&self, transfer_id: &str) -> Result<FileResume, ZeroError> {
        let entry = self
            .incoming
            .get(transfer_id)
            .ok_or_else(|| ZeroError::Custom("Unknown transfer ID".to_string()))?;
        Ok(entry.build_resume())
    }

    /// Finalize a complete incoming transfer — reassemble, verify, and save to disk.
    pub async fn finalize_transfer(&self, transfer_id: &str) -> Result<PathBuf, ZeroError> {
        let dest = {
            let entry = self
                .incoming
                .get(transfer_id)
                .ok_or_else(|| ZeroError::Custom("Unknown transfer ID".to_string()))?;
            entry.save_to(&self.download_dir).await?
        };
        self.incoming.remove(transfer_id);
        Ok(dest)
    }

    /// Verify a standalone file against an expected BLAKE2b-256 hash.
    pub fn verify_file(&self, data: &[u8], expected_hash: &[u8; 32]) -> bool {
        blake2b_256(data) == *expected_hash
    }
}
