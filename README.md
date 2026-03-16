# ZERO Protocol

**Peer-to-peer, end-to-end encrypted, post-quantum resistant messaging protocol.**

ZERO Protocol is a complete reimplementation and architectural evolution of decentralized messaging concepts (inspired by Tox and Noise), designed to fix critical weaknesses in existing P2P protocols while providing state-of-the-art cryptography and offline messaging capabilities.

---

## Core Features & Architecture

ZERO Protocol is built natively in Rust as a workspace of modular crates:

- **End-to-End Encryption**: Noise XX + X3DH handshake, Double Ratchet messaging (ZR).
- **Post-Quantum Resistance**: Integrates ML-KEM-768 (FIPS 203) alongside classical X25519 into the handshake and ratchet.
- **Privacy First (ZDHT)**: Solves the "IP exposure" problem of standard DHTs by encrypting node records (IP/port) with contacts' X25519 public keys, meaning only authorized contacts know your IP.
- **Offline Messaging (ZSF)**: 
  - "Sealed Sender" Store & Forward architecture.
  - Relays route messages but cannot see the sender's identity or message content.
  - Incorporates Proof-of-Work (Hashcash) anti-spam to prevent exhaustion of relay storage.
- **Group Chats (ZGP)**: O(1) group messaging inspired by Megolm, avoiding the requirement that all members be online simultaneously to establish encryption.
- **Modern Transport**: Utilizes QUIC (via `quinn`) for multiplexed streams (control, text, file transfers, media) and fast resuming, with TCP+TLS fallback mechanisms.
- **Multi-Platform**: Designed for mobile/desktop integration via Mozilla Uniffi (`zero-protocol/src/zero.udl`), providing native Kotlin/Swift bindings out of the box.

## Current Status (Code)

This repository already includes working building blocks with tests:

- **`zero-store-forward` (ZSF)**:
  - Sealed-sender envelope with **inner encryption for the recipient** and **outer encryption for the relay**
  - Relay-side decryption helper `decrypt_outer_for_relay()` (verifies PoW, decrypts TTL + opaque inner blob)
  - Recipient-side `decrypt_inner()` (reveals sender ID + payload)
- **`zero-dht` / `zero-identity`**:
  - CBOR serialization round-trips for core types (including byte-string encoding compatibility)
- **`zero-handshake`**:
  - Noise XX handshake state machine (panic-resistant state checks)
  - X3DH+ML-KEM hybrid master-secret derivation
  - Optional API support for binding X3DH to the Noise transcript hash (`*_with_noise_hash`)

## Project Structure

The cargo workspace consists of 10 interdependent crates:

| Crate | Description |
|---|---|
| `zero-crypto` | Safe wrappers around core primitives (Ed25519, X25519, ML-KEM, ChaCha20-Poly1305, BLAKE2b, HKDF). |
| `zero-identity` | ZERO ID generation, Base58Check encoding, Long-term keys, X3DH prekey bundles. |
| `zero-handshake` | ZKX Handshake state machine (Noise XX + X3DH + ML-KEM-768). |
| `zero-ratchet` | ZR Messaging (Double Ratchet + Header Encryption + out-of-order handling). |
| `zero-dht` | Kademlia-based peer discovery, encrypted node records, XOR distance routing. |
| `zero-transport` | Networking layer: QUIC, TCP/TLS fallback, NAT hole-punching concepts. |
| `zero-relay` | Blind TCP Relay Server to handle traffic when direct P2P connection fails. |
| `zero-store-forward` | Offline message delivery with sealed-sender envelopes and proof-of-work. |
| `zero-groups` | State management and sender key ratchets for decentralized group chats. |
| `zero-protocol` | Top-level orchestrator exposing a unified `ZeroNode` API and `uniffi` bindings. |

## Quick Start

### Prerequisites
- [Rust](https://rustup.rs/) (stable, 1.75+)
- Android NDK & specific Rust targets (if compiling mobile bindings)

### Building the Workspace

```bash
cd ZERO
cargo build --workspace
```

### Running Tests

Automated tests cover all primitives, serialization round-trips, handshake state machines, and ratchet synchronizations.

```bash
cargo test --workspace
```

*(Note: Ensure your local environment has internet access to crates.io to download dependencies.)*

### Generating Mobile Bindings

The `zero-protocol` crate exports a Uniffi UDL file to generate Android (Kotlin) bindings.

```bash
# Requires uniffi-bindgen
cargo run --bin uniffi-bindgen generate zero-protocol/src/zero.udl --language kotlin --out-dir ./bindings
```

## Security & Cryptography Defaults

ZERO Protocol strictly relies on vetted, trusted cryptographic primitives rather than custom algorithms:

- **Identity Signatures**: Ed25519 (`ed25519-dalek`)
- **Key Exchange (Classical)**: X25519 (`x25519-dalek`)
- **Key Exchange (Post-Quantum)**: ML-KEM-768 (`ml-kem` - FIPS 203)
- **Symmetric Encryption**: ChaCha20-Poly1305 (`chacha20poly1305`)
- **Hashing**: BLAKE2b-256 / BLAKE2b-512 (`blake2`)
- **Key Derivation**: HKDF (`hkdf`)

## License

This project is licensed under the GPL-3.0 License.
