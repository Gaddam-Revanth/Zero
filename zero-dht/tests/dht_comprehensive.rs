//! Comprehensive tests for zero-dht onion routing and routing table.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod onion_tests {
    use zero_dht::onion::{OnionPacket};
    use zero_dht::NodeId;
    use zero_crypto::aead::{AeadKey, AEAD_KEY_SIZE};

    fn rand_key() -> AeadKey {
        use rand::RngCore;
        let mut k = [0u8; AEAD_KEY_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut k);
        AeadKey(k)
    }

    fn rand_node_id() -> [u8; 32] {
        use rand::RngCore;
        let mut id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    #[test]
    fn test_onion_3_hop_wrap_peel_each_layer() {
        let hop1_key = rand_key();
        let hop2_key = rand_key();
        let hop3_key = rand_key();

        let hops = [NodeId(rand_node_id()), NodeId(rand_node_id()), NodeId(rand_node_id())];
        let keys = [hop1_key, hop2_key, hop3_key];
        let eph_pub = rand_node_id();

        let payload = b"find this record in the dht";
        let onion = OnionPacket::wrap_3_hops(payload, &hops, &keys, eph_pub).unwrap();

        // H1 peels outermost layer
        let layer1 = onion.peel(&keys[0]).unwrap();
        assert_eq!(layer1.next_hop, hops[1], "Layer 1 next hop must point to H2");

        // H2 peels middle layer
        let packet2 = OnionPacket {
            ephemeral_pub: eph_pub,
            encrypted_data: layer1.inner_payload,
        };
        let layer2 = packet2.peel(&keys[1]).unwrap();
        assert_eq!(layer2.next_hop, hops[2], "Layer 2 next hop must point to H3");

        // H3 peels innermost layer
        let packet3 = OnionPacket {
            ephemeral_pub: eph_pub,
            encrypted_data: layer2.inner_payload,
        };
        let layer3 = packet3.peel(&keys[2]).unwrap();
        assert_eq!(layer3.inner_payload, payload, "H3 must recover original payload exactly");
    }

    #[test]
    fn test_onion_wrong_key_at_layer1_fails() {
        let hop1_key = rand_key();
        let hop2_key = rand_key();
        let hop3_key = rand_key();
        let wrong_key = rand_key();

        let hops = [NodeId(rand_node_id()), NodeId(rand_node_id()), NodeId(rand_node_id())];
        let keys = [hop1_key, hop2_key, hop3_key];

        let onion = OnionPacket::wrap_3_hops(b"secret", &hops, &keys, rand_node_id()).unwrap();
        assert!(onion.peel(&wrong_key).is_err(), "Wrong key at H1 must fail");
    }

    #[test]
    fn test_onion_tampered_ciphertext_fails() {
        let hop1_key = rand_key();
        let hop2_key = rand_key();
        let hop3_key = rand_key();
        let hops = [NodeId(rand_node_id()), NodeId(rand_node_id()), NodeId(rand_node_id())];
        let keys = [hop1_key, hop2_key, hop3_key];

        let mut onion = OnionPacket::wrap_3_hops(b"data", &hops, &keys, rand_node_id()).unwrap();
        let last = onion.encrypted_data.len() - 1;
        onion.encrypted_data[last] ^= 0xFF;
        assert!(onion.peel(&keys[0]).is_err(), "Tampered ciphertext must fail authentication");
    }

    #[test]
    fn test_onion_too_short_ciphertext_fails() {
        let key = rand_key();
        let onion = OnionPacket {
            ephemeral_pub: [0u8; 32],
            encrypted_data: vec![0u8; 5],
        };
        assert!(onion.peel(&key).is_err(), "Too-short ciphertext must fail");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod routing_table_tests {
    use zero_dht::{
        routing_table::RoutingTable,
        kbucket::NodeInfo,
        NodeId,
    };
    use zero_identity::keypair::ZeroKeypair;

    fn rand_node_id() -> [u8; 32] {
        use rand::RngCore;
        let mut id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    #[test]
    fn test_routing_table_closest_nodes_sorted_by_xor() {
        let self_id = NodeId(rand_node_id());
        let mut rt = RoutingTable::new(self_id);

        for _ in 0..5 {
            let kp = ZeroKeypair::generate().unwrap();
            let id = NodeId(rand_node_id());
            let node = NodeInfo {
                node_id: id,
                isk_pub: kp.isk.public_key().0,
                ip: vec![127, 0, 0, 1],
                port: 4000,
                last_seen: 0,
                is_bootstrap: false,
            };
            rt.add_node(node);
        }

        let target = NodeId(rand_node_id());
        let closest = rt.closest_nodes(&target, 3);
        for i in 1..closest.len() {
            let d_prev = xor_dist(&closest[i-1].node_id.0, &target.0);
            let d_curr = xor_dist(&closest[i].node_id.0, &target.0);
            assert!(d_prev <= d_curr);
        }
    }

    #[test]
    fn test_routing_table_self_not_added() {
        let self_id = NodeId(rand_node_id());
        let mut rt = RoutingTable::new(self_id);
        let kp = ZeroKeypair::generate().unwrap();
        let node = NodeInfo {
            node_id: self_id,
            isk_pub: kp.isk.public_key().0,
            ip: vec![127, 0, 0, 1],
            port: 0,
            last_seen: 0,
            is_bootstrap: false,
        };
        rt.add_node(node);
        assert_eq!(rt.node_count(), 0);
    }

    fn xor_dist(a: &[u8; 32], b: &[u8; 32]) -> Vec<u8> {
        a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
    }
}
