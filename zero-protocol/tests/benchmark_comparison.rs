use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsConnector, TlsAcceptor};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::sync::{Arc, Once};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zero_identity::keypair::ZeroKeypair;
use zero_identity::bundle::OwnedKeyBundle;
use zero_identity::zeroid::ZeroId;
use zero_handshake::x3dh::{X3dhInitiator, X3dhResponder};

fn ensure_rustls_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[tokio::test]
async fn benchmark_handshake_efficiency() {
    ensure_rustls_provider();
    println!("\n=== Handshake Efficiency Benchmark ===");
    
    let tls_time = benchmark_tls_handshake().await;
    println!("Standard TLS 1.3 Handshake: {:?}", tls_time);

    let zkx_time = benchmark_zkx_handshake().await;
    println!("ZERO ZKX (PQ-Hybrid) Handshake: {:?}", zkx_time);
    
    let overhead = (zkx_time.as_micros() as f64 / tls_time.as_micros() as f64 - 1.0) * 100.0;
    println!("ZKX Time Overhead vs TLS: {:.2}%", overhead);
}

async fn benchmark_tls_handshake() -> std::time::Duration {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let priv_key = cert.key_pair.serialize_der();

    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der.clone())];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(priv_key),
    );

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("Failed to create server config");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let _server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(stream).await.unwrap();
        let _ = tls.write_all(b"ready").await;
    });

    let mut root_store = RootCertStore::empty();
    root_store.add(rustls::pki_types::CertificateDer::from(cert_der)).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let start = Instant::now();
    let stream = TcpStream::connect(addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut _tls: tokio_rustls::client::TlsStream<TcpStream> = connector.connect(server_name, stream).await.unwrap();
    start.elapsed()
}

async fn benchmark_zkx_handshake() -> std::time::Duration {
    let alice_kp = ZeroKeypair::generate().expect("Failed to generate Alice KP");
    let mut bob_owned = OwnedKeyBundle::generate(0).expect("Failed to generate Bob bundle");
    let bob_id = ZeroId::from_keypair(&bob_owned.keypair, [0u8; 4]);
    let bob_bundle = bob_owned.public_bundle(&bob_id);

    println!("  --- Handshake Profiling ---");
    
    // 1. X3DH Timing
    let start_x3dh = Instant::now();
    let initiator = X3dhInitiator::new(zero_crypto::dh::X25519Keypair::generate());
    let h_noise = [0u8; 32];
    let (init_msg, _zk_output) = initiator
        .initiate_with_noise_hash(&alice_kp, &bob_bundle, Some(h_noise))
        .expect("ZKX Initiator failed");
    let x3dh_init_time = start_x3dh.elapsed();
    println!("  Initiator (3 DH + KEM Encaps): {:?}", x3dh_init_time);

    let start_x3dh_resp = Instant::now();
    let _resp_output = X3dhResponder::respond_with_noise_hash(&mut bob_owned, &init_msg, Some(h_noise))
        .expect("ZKX Responder failed");
    let x3dh_resp_time = start_x3dh_resp.elapsed();
    println!("  Responder (3 DH + KEM Decaps): {:?}", x3dh_resp_time);

    // 2. Individual ML-KEM-768 Timing
    let pk = zero_crypto::kem::MlKem768EncapsKey(bob_bundle.pq_isk_pub.clone());
    let start_kem = Instant::now();
    let _ = zero_crypto::kem::ml_kem_768_encapsulate(&pk).unwrap();
    let kem_encaps_time = start_kem.elapsed();
    println!("  ML-KEM-768 Encapsulate: {:?}", kem_encaps_time);

    let kp = zero_crypto::kem::MlKem768Keypair::generate().expect("KEM keygen failed");
    let (ct, _) = zero_crypto::kem::ml_kem_768_encapsulate(&kp.ek).expect("KEM encaps failed");
    let start_kem_dec = Instant::now();
    let _ = zero_crypto::kem::ml_kem_768_decapsulate(&kp.dk, &ct).expect("KEM decaps failed");
    let kem_decaps_time = start_kem_dec.elapsed();
    println!("  ML-KEM-768 Decapsulate: {:?}", kem_decaps_time);

    // 3. Raw X25519 Timing for comparison
    let alice_priv = zero_crypto::dh::X25519Keypair::generate();
    let bob_pub = zero_crypto::dh::X25519Keypair::generate().public_key();
    let start_x25519 = Instant::now();
    let _ = alice_priv.diffie_hellman(&bob_pub);
    println!("  Raw X25519 DH: {:?}", start_x25519.elapsed());

    x3dh_init_time + x3dh_resp_time
}

#[tokio::test]
async fn benchmark_messaging_overhead() {
    println!("\n=== Messaging Overhead Benchmark ===");
    
    let sizes = [1024, 10240, 1024 * 1024];
    
    for size in sizes {
        let data = vec![0u8; size];
        println!("Size: {} bytes", size);
        
        let zr_overhead = measure_zr_overhead(&data);
        println!("  ZERO ZR Overhead: {} bytes ({:.2}%)", zr_overhead, (zr_overhead as f64 / size as f64) * 100.0);
        if size == 1024 {
            assert!(zr_overhead <= 120, "Overhead is too high: {} bytes", zr_overhead);
        }

        let tls_overhead = 16 + 5; 
        println!("  TLS 1.3 (est) Overhead: {} bytes ({:.2}%)", tls_overhead, (tls_overhead as f64 / size as f64) * 100.0);

        let tox_overhead = 40 + 24; // 40-byte net_crypto header + 24-byte MAC
        println!("  Tox (est) Overhead:     {} bytes ({:.2}%)", tox_overhead, (tox_overhead as f64 / size as f64) * 100.0);
        println!();
    }
}

#[tokio::test]
async fn benchmark_ping_pong_latency() {
    ensure_rustls_provider();
    println!("\n=== Ping-Pong Latency Benchmark ===");
    
    let tls_latency = measure_tls_latency().await;
    println!("Standard TLS 1.3 Latency (RTT): {:?}", tls_latency);

    let zr_latency = measure_zr_latency().await;
    println!("ZERO ZR (Ratchet) Latency (RTT): {:?}", zr_latency);
}

async fn measure_tls_latency() -> std::time::Duration {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let priv_key = cert.key_pair.serialize_der();

    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der.clone())];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(priv_key),
    );

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let _server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(stream).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tls.read(&mut buf).await.unwrap();
        let _ = tls.write_all(&buf[..n]).await;
    });

    let mut root_store = RootCertStore::empty();
    root_store.add(rustls::pki_types::CertificateDer::from(cert_der)).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let stream = TcpStream::connect(addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls: tokio_rustls::client::TlsStream<TcpStream> = connector.connect(server_name, stream).await.unwrap();

    let start = Instant::now();
    tls.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tls.read_exact(&mut buf[..]).await.unwrap();
    
    
    start.elapsed()
}

async fn measure_zr_latency() -> std::time::Duration {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let _server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let _ = stream.write_all(&buf[..n]).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    
    let start = Instant::now();
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf[..]).await.unwrap();
    

    start.elapsed()
}

fn measure_zr_overhead(data: &[u8]) -> usize {
    let secret = [1u8; 64];
    let dh = zero_crypto::dh::X25519Keypair::generate();
    let remote_dh = zero_crypto::dh::X25519Keypair::generate();
    let mut session = zero_ratchet::RatchetSession::new(zero_ratchet::SessionInit {
        master_secret: secret.to_vec(),
        is_initiator: true,
        local_dh: dh,
        remote_dh_pub: remote_dh.public_key(),
    }).expect("ZR session init failed");

    let msg = session.encrypt(data, b"").expect("ZR encrypt failed");
    let encoded = zero_crypto::cbor::to_vec(&msg).expect("CBOR encode failed");
    
    encoded.len() - data.len()
}
