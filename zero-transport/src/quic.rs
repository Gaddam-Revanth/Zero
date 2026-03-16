//! QUIC transport via Quinn.
//!
//! QUIC is the primary transport for ZERO Protocol.
//! - UDP-based, fast connection establishment
//! - Built-in encryption (we use self-signed certs + ZKX on top)
//! - Connection migration (switch Wi-Fi ↔ Cellular without dropping)
//! - Multiple streams (avoid head-of-line blocking)

use crate::error::TransportError;
use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use zero_wire::{Packet, PacketHeader};
use bytes::Bytes;
use tokio::io::AsyncWriteExt;

/// Protocol Stream IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Stream 0: ZKX Handshake + Control messages.
    Control = 0,
    /// Stream 1: File transfers (ZFT).
    FileTransfer = 1,
    /// Stream 2: DHT packets.
    Dht = 2,
    /// Streams 3+: ZR encrypted messages.
    Message = 3,
}

/// A ZERO QUIC transport endpoint.
pub struct QuicTransport {
    endpoint: Endpoint,
}

impl QuicTransport {
    /// Bind to a local UDP port and start the QUIC endpoint.
    pub fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        let endpoint = Endpoint::client(addr).map_err(|e| TransportError::Io(e))?;
        Ok(Self { endpoint })
    }

    /// Connect to a remote ZERO node.
    pub async fn connect(&self, addr: SocketAddr) -> Result<Connection, TransportError> {
        // Stub: we'd connect and accept any certificate since we rely on ZKX for auth
        self.endpoint
            .connect(addr, "zero.local")
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))
    }

    /// Send a framed ZERO packet on a new bidirectional stream.
    pub async fn send_packet(
        conn: &Connection,
        header: PacketHeader,
        body: Bytes,
    ) -> Result<(), TransportError> {
        let pkt = Packet { header, body };
        let bytes = pkt.encode_v1().map_err(|e| TransportError::StreamError(e.to_string()))?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::StreamError(e.to_string()))?;
        send.write_all(&bytes)
            .await
            .map_err(|e| TransportError::StreamError(e.to_string()))?;
        send.finish().map_err(|e| TransportError::StreamError(e.to_string()))?;
        // Drain peer response if any (for future use)
        let _ = recv.read_to_end(usize::MAX).await;
        Ok(())
    }

    /// Receive a single framed ZERO packet from an incoming bidirectional stream.
    pub async fn recv_packet(
        mut recv: quinn::RecvStream,
    ) -> Result<Packet, TransportError> {
        let bytes = recv
            .read_to_end((zero_wire::header::HEADER_LEN_V1 as usize) + (zero_wire::header::MAX_BODY_LEN as usize))
            .await
            .map_err(|e| TransportError::StreamError(e.to_string()))?;
        Packet::decode_v1(&bytes).map_err(|e| TransportError::StreamError(e.to_string()))
    }
}
