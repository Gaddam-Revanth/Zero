# ZERO Protocol — v1.0.0
> **Decentralized · Post-Quantum · Privacy-Preserving**

ZERO is a hybrid P2-P messaging protocol designed from the ground up to eliminate metadata exposure, provide post-quantum security, and enable high-performance decentralized communication. It serves as a modern successor to legacy P2P systems, addressing critical flaws in identity protection and network resilience.

---

## 🛠 Features

- **Post-Quantum Security**: Hybrid ML-KEM-768 (Kyber) integrated into the base handshake.
- **Identity Privacy**: IP addresses are encrypted per-contact; no public identity-to-IP mapping exists.
- **Double Ratchet (ZR)**: Per-message forward secrecy with header encryption for total metadata obfuscation.
- **Onion Discovery**: 3-hop onion-wrapped DHT lookups hide your social graph from the network.
- **NAT Traversal**: Advanced UDP hole-punching with symmetric NAT port guessing.
- **Offline Messaging (ZSF)**: Decentralized Store-and-Forward relay system with Hashcash anti-spam.

---

## 🏗 Architecture

The ZERO Protocol is implemented as a modular Rust workspace:

| Crate | Responsibility |
| :--- | :--- |
| `zero-crypto` | Cryptographic primitives (AEAD, DH, Sign, KEM, Hash). |
| `zero-identity` | ZERO ID management and key bundle serialization. |
| `zero-handshake` | ZKX (Noise XX + X3DH) mutual authentication state machine. |
| `zero-ratchet` | ZR (Double Ratchet) engine with encrypted headers. |
| `zero-dht` | Distributed Hash Table for decentralized peer discovery. |
| `zero-protocol` | High-level orchestrator and UniFFI bindings for Android. |
| `zero-groups` | ZGP group messaging with Megolm-style symmetric ratchets. |
| `zero-wire` | Protocol wire format and packet serialization (CBOR). |

---

## 🔐 Security Audit Status

- **Cryptographic Review**: COMPLETED. All primitives follow NIST/FIPS standards.
- **Identity Binding**: COMPLETED. ZKX is cryptographically bound to the Noise transcript.
- **Timing Hardening**: COMPLETED. Constant-time operations enabled for sensitive checks.
- **Test Coverage**: 150+ Passing Tests across the entire protocol stack.

---

## 🚀 Getting Started

### Prerequisites
- [Rust](https://rustup.rs/) v1.75+

### Installation
```bash
git clone https://github.com/zero-protocol/zero-protocol
cd zero-protocol
cargo build --release
```

### Running Tests
```bash
cargo test --workspace --all-features
```

---

## 📄 License
This reference implementation is licensed under **GPL-3.0**. The protocol specification itself is licensed under **MIT**.

---

*“Privacy is not an option, it is a fundamental human right. ZERO makes it a reality.”*
