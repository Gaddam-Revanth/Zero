//! Comprehensive tests for zero-wire: PacketHeader, Packet framing, and ReplayCache.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod wire_tests {
    use bytes::Bytes;
    use zero_wire::{
        header::{Packet, PacketHeader, HEADER_LEN_V1},
        replay::{ReplayCache, ReplayToken},
        types::{PacketFlags, PacketType, Version},
    };

    fn v1() -> Version {
        Version { major: 1, minor: 0 }
    }

    // ── PacketHeader tests ─────────────────────────────────────────────────────

    #[test]
    fn test_header_encode_decode_roundtrip() {
        let hdr = PacketHeader::new(v1(), PacketType::ZkxInit, PacketFlags(0), 512);
        let encoded = hdr.encode_v1();
        let decoded = PacketHeader::decode_v1(&encoded).unwrap();
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn test_header_invalid_magic_fails() {
        let mut bytes = vec![0u8; HEADER_LEN_V1 as usize];
        bytes[0] = b'X'; // corrupt magic byte
        bytes[1] = b'X';
        bytes[2] = b'X';
        bytes[3] = b'X';
        assert!(
            PacketHeader::decode_v1(&bytes).is_err(),
            "Invalid magic must fail"
        );
    }

    #[test]
    fn test_header_unsupported_version_fails() {
        let hdr = PacketHeader::new(
            Version {
                major: 99,
                minor: 0,
            }, // unsupported
            PacketType::ZkxInit,
            PacketFlags(0),
            0,
        );
        let encoded = hdr.encode_v1();
        assert!(
            PacketHeader::decode_v1(&encoded).is_err(),
            "Version 99 must fail"
        );
    }

    #[test]
    fn test_header_reserved_bits_set_fails() {
        // PacketFlags with reserved high bits set
        let hdr = PacketHeader::new(
            v1(),
            PacketType::ZkxInit,
            PacketFlags(0xFF00), // reserved bits
            0,
        );
        assert!(
            hdr.validate_v1().is_err(),
            "Reserved bits in flags must fail validation"
        );
    }

    #[test]
    fn test_header_truncated_fails() {
        let bytes = vec![0u8; 10]; // less than HEADER_LEN_V1
        assert!(
            PacketHeader::decode_v1(&bytes).is_err(),
            "Truncated header must fail"
        );
    }

    // ── Packet framing tests ───────────────────────────────────────────────────

    #[test]
    fn test_packet_encode_decode_roundtrip() {
        let body = Bytes::from_static(b"test-body");
        let packet = Packet {
            header: PacketHeader::new(v1(), PacketType::ZkxInit, PacketFlags(0), body.len() as u32),
            sender_node_id: [1u8; 32],
            receiver_node_id: [2u8; 32],
            body: body.clone(),
        };
        let encoded = packet.encode_v1().unwrap();
        let decoded = Packet::decode_v1(&encoded).unwrap();
        assert_eq!(decoded.header, packet.header);
        assert_eq!(decoded.sender_node_id, packet.sender_node_id);
        assert_eq!(decoded.receiver_node_id, packet.receiver_node_id);
        assert_eq!(decoded.body, body);
    }

    #[test]
    fn test_packet_empty_body_roundtrip() {
        let packet = Packet {
            header: PacketHeader::new(v1(), PacketType::ZkxInit, PacketFlags(0), 0),
            sender_node_id: [0u8; 32],
            receiver_node_id: [9u8; 32],
            body: Bytes::new(),
        };
        let encoded = packet.encode_v1().unwrap();
        let decoded = Packet::decode_v1(&encoded).unwrap();
        assert!(decoded.body.is_empty());
    }

    #[test]
    fn test_packet_truncated_body_fails() {
        let body = Bytes::from_static(b"full-body");
        let packet = Packet {
            header: PacketHeader::new(v1(), PacketType::ZkxInit, PacketFlags(0), body.len() as u32),
            sender_node_id: [0u8; 32],
            receiver_node_id: [0u8; 32],
            body,
        };
        let encoded = packet.encode_v1().unwrap();
        let truncated = &encoded[..encoded.len() - 2]; // cut off last 2 bytes
        assert!(
            Packet::decode_v1(truncated).is_err(),
            "Truncated packet must fail"
        );
    }

    // ── ReplayCache tests ──────────────────────────────────────────────────────

    #[test]
    fn test_replay_cache_unique_tokens_accepted() {
        let cache = ReplayCache::new(60_000);
        let receiver = [1u8; 32];
        for _ in 0..50 {
            let tok = ReplayToken::random();
            assert!(
                cache.check_and_insert(1000, &receiver, PacketType::ZkxInit, &tok),
                "Unique token must be accepted"
            );
        }
    }

    #[test]
    fn test_replay_cache_immediate_replay_rejected() {
        let cache = ReplayCache::new(60_000);
        let receiver = [2u8; 32];
        let tok = ReplayToken::random();
        assert!(cache.check_and_insert(1000, &receiver, PacketType::ZkxInit, &tok));
        assert!(
            !cache.check_and_insert(1001, &receiver, PacketType::ZkxInit, &tok),
            "Replay must be rejected"
        );
    }

    #[test]
    fn test_replay_cache_different_receiver_no_collision() {
        let cache = ReplayCache::new(60_000);
        let tok = ReplayToken::random(); // same token
        let recv_a = [0u8; 32];
        let recv_b = [1u8; 32]; // different receiver
                                // Both should be accepted independently
        assert!(cache.check_and_insert(1000, &recv_a, PacketType::ZkxInit, &tok));
        assert!(
            cache.check_and_insert(1000, &recv_b, PacketType::ZkxInit, &tok),
            "Same token for different receiver must be independent"
        );
    }

    #[test]
    fn test_replay_cache_expire_and_purge() {
        let ttl_ms = 1_000; // 1 second TTL
        let cache = ReplayCache::new(ttl_ms);
        let receiver = [3u8; 32];
        let tok = ReplayToken::random();
        let t0 = 0u64;
        let t_expired = t0 + ttl_ms + 100_001; // well past TTL + 60s purge cycle

        cache.check_and_insert(t0, &receiver, PacketType::ZkxInit, &tok);
        // Force purge
        cache.purge(t_expired);
        // After TTL+purge, the slot is freed — inserting again should succeed
        assert!(
            cache.check_and_insert(t_expired, &receiver, PacketType::ZkxInit, &tok),
            "Re-insertion after expiry must succeed"
        );
    }

    #[test]
    fn test_replay_cache_different_packet_types_are_independent() {
        let cache = ReplayCache::new(60_000);
        let receiver = [4u8; 32];
        let tok = ReplayToken::random();
        // Same token, same receiver, different packet type — cache key includes packet type
        assert!(cache.check_and_insert(1000, &receiver, PacketType::ZkxInit, &tok));
        assert!(
            cache.check_and_insert(1000, &receiver, PacketType::ZsfStoreEnvelope, &tok),
            "Different packet types must use independent cache keys"
        );
    }
}
