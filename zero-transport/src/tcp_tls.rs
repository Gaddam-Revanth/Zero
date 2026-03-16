//! TCP + TLS 1.3 fallback transport.
//!
//! Used when UDP (QUIC) is blocked by firewalls.
//! Uses exact same stream multiplexing semantics (via a custom multiplexer or yamux).

/// Stub for TCP/TLS fallback transport.
pub struct TcpFallback;

impl TcpFallback {
    /// Stub for TCP connection flow.
    pub async fn connect(_addr: std::net::SocketAddr) -> Result<(), crate::error::TransportError> {
        Ok(())
    }
}
