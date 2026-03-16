//! TCP + TLS 1.3 fallback transport.
//!
//! Used when UDP (QUIC) is blocked by firewalls.
//! Uses exact same stream multiplexing semantics (via a custom multiplexer or yamux).

use crate::error::TransportError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zero_wire::{Packet, PacketHeader};

use std::sync::Once;

fn ensure_rustls_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// TCP/TLS fallback transport.
///
/// Framing: length-prefixed packets over a single TLS stream.
/// - prefix: u32 big-endian length of packet bytes
/// - payload: `zero-wire` packet bytes (header+body)
pub struct TcpTlsTransport;

impl TcpTlsTransport {
    /// Bind a TCP/TLS server and return the DER certificate to trust.
    pub async fn bind_server(addr: SocketAddr) -> Result<(TcpListener, Vec<u8>, TlsAcceptor), TransportError> {
        ensure_rustls_provider();

        let ck = rcgen::generate_simple_self_signed(vec!["zero.local".into()])
            .map_err(|e| TransportError::TlsError(e.to_string()))?;
        let cert_der = ck.cert.der().to_vec();
        let key_der = ck.key_pair.serialize_der();

        let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der.clone())];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
        );

        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| TransportError::TlsError(e.to_string()))?;

        let acceptor = TlsAcceptor::from(Arc::new(server_crypto));
        let listener = TcpListener::bind(addr).await?;
        Ok((listener, cert_der, acceptor))
    }

    /// Connect as a TCP/TLS client trusting a server certificate DER.
    pub async fn connect(addr: SocketAddr, server_cert_der: &[u8]) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TransportError> {
        ensure_rustls_provider();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(server_cert_der.to_vec()))
            .map_err(|e| TransportError::TlsError(e.to_string()))?;

        let client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(client_crypto));
        let tcp = TcpStream::connect(addr).await?;

        let server_name = rustls::pki_types::ServerName::try_from("zero.local")
            .map_err(|e| TransportError::TlsError(e.to_string()))?;
        connector.connect(server_name, tcp)
            .await
            .map_err(|e| TransportError::TlsError(e.to_string()))
    }

    /// Accept one incoming TCP connection and perform TLS.
    pub async fn accept(
        listener: &TcpListener,
        acceptor: &TlsAcceptor,
    ) -> Result<tokio_rustls::server::TlsStream<TcpStream>, TransportError> {
        let (tcp, _peer) = listener.accept().await?;
        acceptor.accept(tcp).await.map_err(|e| TransportError::TlsError(e.to_string()))
    }

    /// Send a framed packet on a TLS stream.
    pub async fn send_packet<S>(stream: &mut S, header: PacketHeader, body: Bytes) -> Result<(), TransportError>
    where
        S: AsyncWriteExt + Unpin,
    {
        let pkt = Packet { header, body };
        let bytes = pkt.encode_v1().map_err(|e| TransportError::StreamError(e.to_string()))?;
        let mut frame = BytesMut::with_capacity(4 + bytes.len());
        frame.put_u32(bytes.len() as u32);
        frame.put_slice(&bytes);
        stream.write_all(&frame).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Receive one framed packet from a TLS stream.
    pub async fn recv_packet<S>(stream: &mut S) -> Result<Packet, TransportError>
    where
        S: AsyncReadExt + Unpin,
    {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let mut b = &len_buf[..];
        let len = b.get_u32() as usize;
        // Bound maximum read to avoid memory DoS
        let max = (zero_wire::header::HEADER_LEN_V1 as usize) + (zero_wire::header::MAX_BODY_LEN as usize);
        if len > max {
            return Err(TransportError::StreamError("frame too large".into()));
        }
        let mut pkt_buf = vec![0u8; len];
        stream.read_exact(&mut pkt_buf).await?;
        Packet::decode_v1(&pkt_buf).map_err(|e| TransportError::StreamError(e.to_string()))
    }
}
