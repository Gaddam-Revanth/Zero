use bytes::Bytes;
use zero_transport::QuicTransport;
use zero_wire::{PacketFlags, PacketHeader, PacketType, Version};

#[tokio::test]
async fn quic_loopback_sends_and_receives_framed_packet() {
    let (server, cert_der) = QuicTransport::bind_server("127.0.0.1:0".parse().unwrap())
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let client = QuicTransport::bind_client_trusting("127.0.0.1:0".parse().unwrap(), &cert_der)
        .expect("bind client");

    // accept one connection
    let accept_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("accept");
        let (_send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let pkt = QuicTransport::recv_packet(&mut recv).await.expect("recv_packet");
        pkt
    });

    let conn = client.connect(server_addr).await.expect("connect");
    let header = PacketHeader {
        version: Version::V1_0,
        packet_type: PacketType::ZrMessage,
        flags: PacketFlags(PacketFlags::SEALED_SENDER),
        body_len: 5,
        sender_node_id: [0u8; 32],
        receiver_node_id: [9u8; 32],
    };
    
    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
    let pkt = zero_wire::Packet {
        header: header.clone(),
        body: Bytes::from_static(b"hello"),
    };
    QuicTransport::send_packet(&mut send, &pkt)
        .await
        .expect("send_packet");

    let pkt = accept_task.await.expect("join");
    assert_eq!(pkt.header.version, header.version);
    assert_eq!(pkt.header.packet_type as u16, header.packet_type as u16);
    assert_eq!(pkt.body.as_ref(), b"hello");
}

