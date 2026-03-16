use bytes::Bytes;
use zero_transport::{TransportError};
use zero_transport::tcp_tls::TcpTlsTransport;
use zero_wire::{PacketFlags, PacketHeader, PacketType, Version};

#[tokio::test]
async fn tcp_tls_loopback_sends_and_receives_framed_packet() -> Result<(), TransportError> {
    let (listener, cert_der, acceptor) = TcpTlsTransport::bind_server("127.0.0.1:0".parse().unwrap()).await?;
    let addr = listener.local_addr()?;

    let server_task = tokio::spawn(async move {
        let mut tls = TcpTlsTransport::accept(&listener, &acceptor).await.expect("accept tls");
        let pkt = TcpTlsTransport::recv_packet(&mut tls).await.expect("recv");
        pkt
    });

    let mut client_tls = TcpTlsTransport::connect(addr, &cert_der).await?;
    let header = PacketHeader {
        version: Version::V1_0,
        packet_type: PacketType::ZrMessage,
        flags: PacketFlags(PacketFlags::SEALED_SENDER),
        body_len: 5,
        sender_node_id: [0u8; 32],
        receiver_node_id: [1u8; 32],
    };
    TcpTlsTransport::send_packet(&mut client_tls, header.clone(), Bytes::from_static(b"hello")).await?;

    let pkt = server_task.await.expect("join");
    assert_eq!(pkt.body.as_ref(), b"hello");
    Ok(())
}

