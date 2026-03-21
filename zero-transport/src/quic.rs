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
use std::sync::Arc;
use std::sync::Once;

fn ensure_rustls_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Use ring backend (workspace enables rustls "ring" feature).
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

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
        let endpoint = Endpoint::client(addr).map_err(TransportError::Io)?;
        Ok(Self { endpoint })
    }

    /// Bind a QUIC server endpoint and return the DER-encoded certificate to trust.
    ///
    /// This is suitable for local development and tests. Production deployments should
    /// pin identity via ZKX and/or use a stable cert distribution mechanism.
    pub fn bind_server(addr: SocketAddr) -> Result<(Self, Vec<u8>), TransportError> {
        ensure_rustls_provider();
        // Generate a self-signed cert for "zero.local".
        let ck = rcgen::generate_simple_self_signed(vec!["zero.local".into()])
            .map_err(|e| TransportError::TlsError(e.to_string()))?;
        let cert_der = ck.cert.der().to_vec();
        let key_der = ck.key_pair.serialize_der();

        let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der.clone())];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
        );

        let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, key)
            .map_err(|e| TransportError::TlsError(e.to_string()))?;
        // Conservative defaults for tests; production should tune transport params.
        Arc::get_mut(&mut server_config.transport)
            .expect("unique transport config")
            .max_concurrent_bidi_streams(16_u32.into());

        let endpoint = Endpoint::server(server_config, addr)
            .map_err(TransportError::Io)?;
        Ok((Self { endpoint }, cert_der))
    }

    /// Bind a QUIC client endpoint that trusts the provided server certificate DER.
    pub fn bind_client_trusting(addr: SocketAddr, server_cert_der: &[u8]) -> Result<Self, TransportError> {
        ensure_rustls_provider();
        let mut endpoint = Endpoint::client(addr).map_err(TransportError::Io)?;

        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(server_cert_der.to_vec()))
            .map_err(|e| TransportError::TlsError(e.to_string()))?;

        let client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| TransportError::TlsError(e.to_string()))?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Return the socket address the endpoint is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(TransportError::Io)
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

    /// Accept the next incoming QUIC connection.
    pub async fn accept(&self) -> Result<Connection, TransportError> {
        let incoming = self.endpoint.accept().await
            .ok_or_else(|| TransportError::ConnectionFailed("endpoint closed".into()))?;
        let conn = incoming.await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        Ok(conn)
    }

    /// Send a framed ZERO packet on a bidirectional stream.
    pub async fn send_packet(
        send: &mut quinn::SendStream,
        pkt: &Packet,
    ) -> Result<(), TransportError> {
        let bytes = pkt.encode_v1().map_err(|e| TransportError::StreamError(e.to_string()))?;
        send.write_all(&bytes)
            .await
            .map_err(|e| TransportError::StreamError(e.to_string()))?;
        Ok(())
    }

    /// Receive a single framed ZERO packet from an incoming receive stream.
    pub async fn recv_packet(
        recv: &mut quinn::RecvStream,
    ) -> Result<Packet, TransportError> {
        let mut head_bytes = [0u8; zero_wire::header::HEADER_LEN_V1 as usize];
        recv.read_exact(&mut head_bytes)
            .await
            .map_err(|e| TransportError::StreamError(e.to_string()))?;
            
        let header = PacketHeader::decode_v1(&head_bytes)
            .map_err(|e| TransportError::StreamError(e.to_string()))?;
            
        let mut sender_node_id = [0u8; 32];
        recv.read_exact(&mut sender_node_id)
            .await
            .map_err(|e| TransportError::StreamError(e.to_string()))?;
            
        let mut receiver_node_id = [0u8; 32];
        recv.read_exact(&mut receiver_node_id)
            .await
            .map_err(|e| TransportError::StreamError(e.to_string()))?;
            
        let mut body = vec![0u8; header.body_len as usize];
        recv.read_exact(&mut body)
            .await
            .map_err(|e| TransportError::StreamError(e.to_string()))?;
            
        Ok(Packet { 
            header,
            sender_node_id,
            receiver_node_id,
            body: Bytes::from(body),
        })
    }
}
