<div align="center">
  <h1>ZERO Protocol</h1>
  <p><b>Peer-to-peer, end-to-end encrypted, post-quantum resilient messaging protocol.</b></p>
  <p><i>Serverless. Private. Future-proof.</i></p>
</div>

---

## What is ZERO Protocol?

**ZERO Protocol** is a complete architectural evolution of decentralized messaging (inspired by the serverless P2P philosophy of Tox). It is designed to act as a flawless structural modernization of secure messaging, fixing critical mathematical weaknesses in existing P2P protocols while providing state-of-the-art cryptography and native offline messaging capabilities.

It combines the extreme censorship resistance of Tox with the mathematically proven forward-secrecy and post-quantum cryptography of Signal.

### The v1.0.0 Milestone
The core Rust workspace is officially at **v1.0.0**. All rigorous cryptographic requirements (Transcript Binding, Downgrade Resistance, Key Confirmation, exact HKDF hashing, and ML-KEM-768 parameters) are fully enforced.

---

## 🌟 Core Features & Architecture

ZERO Protocol is built natively in **Rust** as a workspace of modular crates, focused on absolute memory safety and zero-cost abstractions:

- **End-to-End Encryption (ZKX & ZR)**: Handshakes utilize the **Noise XX** pattern mixed with **X3DH**. Messaging utilizes the **Double Ratchet** algorithm with full **Header Encryption** to hide metadata from relays.
- **Post-Quantum Resilience**: Integrates NIST-standardized **ML-KEM-768 (FIPS 203)** directly into the handshake alongside classical X25519. An attacker must break both simultaneously to compromise a session.
- **Identity & Peer Discovery (ZDHT)**: Solves the "IP exposure" problem of standard DHTs. **Encrypted Node Records** ensure that only mutually authorized contacts can discover your IP address over the Kademlia-based DHT.
- **Offline Messaging (ZSF)**: Fixes Tox's fatal flaw (dropped messages when offline). Uses a **"Sealed Sender" Store & Forward** architecture. Relays route envelopes but cannot see the sender's identity or read the message payload. Incorporates **Hashcash Proof-of-Work** to prevent relay spam.
- **Group Chats (ZGP)**: O(1) decentralized group messaging inspired by Megolm, allowing asynchronous group participation.
- **Modern Transport**: Utilizes **QUIC** for multiplexed streams (control, text, file transfer, A/V). Includes robust NAT hole-punching (STUN) and TCP/TLS fallback mechanisms.
- **Future-Ready Bindings**: Designed for mobile/desktop integration via Mozilla UniFFI (`zero.udl`), providing native Kotlin/Swift bindings out of the box.

---

## 📦 Project Structure

The cargo workspace securely isolates responsibilities across these interdependent crates:

| Crate | Description |
|---|---|
| `zero-crypto` | Safe wrappers around vetted primitives (Ed25519, X25519, ML-KEM, ChaCha20-Poly1305, BLAKE2b). |
| `zero-identity` | ZERO ID generation, Base58Check encoding, Long-term keys, X3DH prekey bundles. |
| `zero-handshake` | ZKX Handshake state machine (Noise XX + X3DH + ML-KEM). Immunity to KCI attacks. |
| `zero-ratchet` | ZR Messaging (Double Ratchet + Header Encryption + Out-of-order bounds). |
| `zero-dht` | Kademlia-based peer discovery, AEAD-encrypted node records with strict freshness checks. |
| `zero-transport` | Networking layer: QUIC, standard TCP/TLS fallback, NAT hole-punching. |
| `zero-relay` | Blind TCP Relay Server to handle traffic when direct P2P connection fails. |
| `zero-store-forward`| Offline message delivery with sealed-sender envelopes and Proof-of-Work. |
| `zero-groups` | State management and sender key ratchets for decentralized group chats. |
| `zero-wire` | Canonical CBOR routing boundaries, 32-byte exact universal headers, Replay Cache mitigation. |
| `zero-protocol` | Top-level orchestrator exposing a unified `ZeroNode` API and `uniffi` bindings. |

---

## 🛠 Quick Start

### Prerequisites
- [Rust](https://rustup.rs/) (stable, 1.75+)
- Android NDK & specific Rust targets (if compiling mobile Kotlin bindings)

### Building the Workspace

The entire workspace compiles cleanly and without warnings:
```bash
cd ZERO
cargo build --workspace
```

### Running the Test Suite

Automated tests cover all primitives, serialization round-trips, validation, handshake state machines, DHT freshness, ZSF anti-spam, and ratchet synchronizations.

```bash
cargo test --workspace
```

### Generating Mobile Bindings

The `zero-protocol` crate exports a UniFFI UDL file to automatically generate Android (Kotlin) bindings for app integration.

```bash
cargo run --bin uniffi-bindgen generate zero-protocol/src/zero.udl --language kotlin --out-dir ./bindings
```

---

## 🔒 Security & Cryptography Defaults

ZERO Protocol avoids custom algorithms, strictly relying on vetted, trusted cryptographic primitives:

- **Identity Signatures**: Ed25519
- **Key Exchange (Classical)**: X25519
- **Key Exchange (Post-Quantum)**: ML-KEM-768 (FIPS 203)
- **Symmetric Encryption**: ChaCha20-Poly1305
- **Hashing**: BLAKE2b-256 / BLAKE2b-512
- **Key Derivation**: HKDF-SHA512

---

## 📄 License

This project is licensed under the GPL-3.0 License. See the `LICENSE` file for details.
