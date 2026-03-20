# ZERO Protocol Specification — v1.0.0
> **Peer-to-Peer · Post-Quantum · Privacy-First**

ZERO is a hybrid P2P messaging protocol designed as a modern, post-quantum secure successor to legacy systems like Tox. It eliminates metadata exposure, prevents man-in-the-middle attacks via formally verified handshakes, and enables asynchronous messaging in a truly decentralized environment.

---

## Table of Contents
1.  [Protocol Overview & Philosophy](#1-protocol-overview--philosophy)
2.  [ZERO ID — Identity System](#2-zero-id--identity-system)
3.  [Cryptographic Foundations](#3-cryptographic-foundations)
4.  [ZERO Key Exchange (ZKX)](#4-zero-key-exchange-zkx)
5.  [ZERO Ratchet (ZR)](#5-zero-ratchet-zr)
6.  [ZERO DHT (ZDHT)](#6-zero-dht-zdht)
7.  [Transport Layer — QUIC + Fallbacks](#7-transport-layer--quic--fallbacks)
8.  [NAT Traversal & Hole-Punching](#8-nat-traversal--hole-punching)
9.  [TCP Relay System](#9-tcp-relay-system)
10. [ZERO Store & Forward (ZSF)](#10-zero-store--forward-zsf)
11. [ZERO Group Protocol (ZGP)](#11-zero-group-protocol-zgp)
12. [ZERO Audio/Video Calls (ZAV)](#12-zero-audiovideo-calls-zav)
13. [File Transfer Protocol (ZFT)](#13-file-transfer-protocol-zft)
14. [Connection Lifecycle — Full Flow](#14-connection-lifecycle--full-flow)
15. [Security Properties & Threat Model](#15-security-properties--threat-model)
16. [Post-Quantum Cryptography Deep-Dive](#16-post-quantum-cryptography-deep-dive)
17. [Rust Implementation Architecture](#17-rust-implementation-architecture)
18. [Android App Integration](#18-android-app-integration)
19. [Global Language Support](#19-global-language-support)
20. [Protocol Wire Format & Packet Structures](#20-protocol-wire-format--packet-structures)
21. [Comparison: ZERO vs Tox vs Signal vs Matrix](#21-comparison-zero-vs-tox-vs-signal-vs-matrix)
22. [Known Limitations & Future Work](#22-known-limitations--future-work)
23. [Licensing, Governance & Audit Plan](#23-licensing-governance--audit-plan)

---

## 1. Protocol Overview & Philosophy
The ZERO Protocol is built on three core pillars:
- **True Decentralization**: No central servers for routing, identity, or message storage.
- **Privacy as a Default**: Total metadata obfuscation (IP addresses hidden via encrypted headers).
- **Quantum Resilience**: Every handshake is hybrid Post-Quantum secure.

ZERO follows the "Don't Roll Your Own Crypto" philosophy, composing proven primitives (Noise Framework, Signal's Double Ratchet, NIST-standardized ML-KEM) into a resilient P2P mesh.

## 2. ZERO ID — Identity System
A **ZERO ID** is a permanent, cryptographically-backed handle. Unlike Tox, it supports multiple devices and cryptographic agility.
- **IK_ed**: Ed25519 public key for identity signatures.
- **IK_dh**: X25519 public key for the handshake layer.
- **PQ_IK_hash**: Hash of the ML-KEM-768 identity public key.
- **NoSpam**: 4-byte anti-spam token.

**Encoding**: `Base58Check(IK_ed || IK_dh || PQ_IK_hash || NoSpam || Checksum)`. Total length: ~160-180 characters.

## 3. Cryptographic Foundations
ZERO utilizes a curated set of industry-standard primitives:
- **Signatures**: Ed25519
- **Diffie-Hellman**: X25519
- **Post-Quantum**: ML-KEM-768 (Kyber)
- **AEAD**: ChaCha20-Poly1305
- **Hashing**: BLAKE2b (256/512)
- **KDF**: HKDF-BLAKE2b

## 4. ZERO Key Exchange (ZKX)
ZKX is the mutual authentication handshake based on the **Noise XX** pattern, extended with a Post-Quantum KEM layer.
- **Pattern**: `Noise_XX_25519_ChaChaPoly_BLAKE2b`
- **PQ-Hybrid**: During the handshake, Alice encapsulates a secret using Bob's ML-KEM key.
- **Master Secret**: derived via `HKDF(Noise_Shared_Secret || ML_KEM_Secret)`.

## 5. ZERO Ratchet (ZR) — Message Encryption
ZR is an implementation of the Double Ratchet Algorithm with **Header Encryption**.
- **Per-message Keys**: Unique keys generated via symmetric ratchet.
- **DH Ratchet**: New X25519 pairs generated every round trip for post-compromise security.
- **Header Encryption**: Ratchet public keys and counters are encrypted using the root-key-derived header key, preventing metadata leaks to P2P relay nodes.

## 6. ZERO DHT (ZDHT) — Peer Discovery
A Kademlia-inspired DHT for locating peers.
- **Ephemerality**: Nodes use random DHT-specific keys, rotated hourly to prevent long-term tracking.
- **Onion Lookups**: DHT queries are routed through 3-hop onion paths to prevent DHT nodes from seeing who is searching for whom.

## 7. Transport Layer — QUIC + Fallbacks
The primary transport is **QUIC over UDP**.
- **Multiplexing**: Support for multiple streams (chat, file, AV) on one connection.
- **IP Mobility**: Seamless roaming between WiFi and Mobile data without dropping sessions.
- **Fallback**: TLS-encrypted TCP for environments where UDP is blocked.

## 8. NAT Traversal & Hole-Punching
Standard UDP Hole-Punching protocol:
1. Alice and Bob learn each other's IP/Ports from ZDHT.
2. Direct ping-pong exchange through NAT gateways.
3. Fallback to Relays if hole-punching fails after 10 seconds.

## 9. TCP Relay System
Permissionless relay nodes facilitate connectivity for users behind Symmetric NAT.
- **Privacy**: Relays only see Noise-encrypted "Envelopes." They cannot see the sender's identity or the plaintext.

## 10. ZERO Store & Forward (ZSF) — Offline Delivery
ZSF solves the "online-only" limitation of P2P.
- **Sealed Sender**: Envelopes are stored on volunteer relays.
- **Retrieval**: Recipient queries relays using a blinded token.
- **Anti-Spam**: Storing a message requires a small Proof-of-Work (Hashcash).

## 11. ZERO Group Protocol (ZGP)
Based on Megolm-inspired **Sender Keys**.
- Each member maintains their own symmetric ratchet chain.
- Messages are O(1) encrypted (one ciphertext for the entire group).
- Forward secrecy via pairwise re-keying on member removal.

## 12. ZERO Audio/Video Calls (ZAV)
Signaling over ZR-encrypted channels.
- **Media**: SRTP via WebRTC (Opus/VP9).
- **Security**: DTLS-SRTP keys derived from ZKX to prevent MitM.

## 13. File Transfer Protocol (ZFT)
Resumable, multi-stream file transfers.
- **Integrity**: BLAKE2b Merkle trees for chunk verification.
- **Resumption**: Support for pausing and continuing transfers across IP roaming.

## 14. Connection Lifecycle — Full Flow A to Z
1. **Bootstrap**: Node connects to hardcoded seeds.
2. **DHT Join**: Publishes blinded contact address.
3. **Lookup**: Alice finds Bob's current relay/IP via ZDHT onion search.
4. **ZKX**: Mutual handshake (+PQ-KEM).
5. **ZR**: Session established; first message sent.

## 15. Security Properties & Threat Model
- **Forward Secrecy**: Compromise of long-term identity keys does not reveal past messages.
- **Post-Compromise Security**: Ongoing sessions "heal" within one round-trip after a device compromise.
- **Quantum Resistance**: Data is secure against recorded traffic attacks from future quantum computers.

## 16. Post-Quantum Cryptography Deep-Dive
ZERO uses **ML-KEM-768** (formerly Kyber768), part of the NIST FIPS 203 standard.
- **Why?**: Labeled as "Shor's Algorithm proof."
- **Overhead**: Handshake size increases by ~1KB, but ongoing traffic overhead is unaffected.

## 17. Rust Implementation Architecture
Modular Cargo Workspace:
- `zero-crypto`: Cryptographic primitives wrapper.
- `zero-handshake`: ZKX (Noise) state machine.
- `zero-ratchet`: ZR (Double Ratchet) engine.
- `zero-dht`: ZDHT networking logic.
- `zero-transport`: QUIC/UDP abstractions.

## 18. Android App Integration (Kotlin + UniFFI)
- **UniFFI**: Generates foreign-function interfaces between Rust and Kotlin.
- **Storage**: Encrypted SQLite (SQLDelight) for local message history.
- **Service**: Foreground service categories for persistent P2P connectivity.

## 19. Global Language Support
- **Encoding**: Strict UTF-8 throughout.
- **Normalization**: Unicode NFC for message comparison.
- **Search**: ICU4J-based client-side encrypted search.

## 20. Protocol Wire Format & Packet Structures
Packets are serialized via **CBOR**:
- `PacketType`: 1 byte
- `Version`: 2 bytes
- `Payload`: Var-length byte array

## 21. Comparison: ZERO vs Tox vs Signal vs Matrix
| Feature | ZERO | Tox | Signal | Matrix |
| :--- | :--- | :--- | :--- | :--- |
| **Decentralized** | Yes | Yes | No | Federated |
| **Post-Quantum** | Yes | No | Yes (PQXDH) | Experimental |
| **Offline** | Yes | No | Yes | Yes |
| **Header Enc.** | Yes | No | Limited | No |

## 22. Known Limitations & Future Work
- **Group Scale**: ZGP is O(N) for key distribution; working on TreeKEM (MLS) for large groups.
- **Discovery Latency**: Onion DHT lookups add ~300ms latency.

## 23. Licensing, Governance & Audit Plan
- **License**: MIT (Protocol Specs), GPL-3.0 (Reference Imp).
- **Audit**: Scheduled for Q4 2026 by an independent security firm.

---

### APPENDIX A: ZERO ID Encoding Reference
`z[Base58Check(magic_0x42 || data)]`

### APPENDIX B: Cryptographic Primitive Reference
- **KDF**: `HKDF-Extract(salt, ikm)` -> `HKDF-Expand(prk, info, len)`

### APPENDIX C: Bootstrap Node Specification
Bootstrap nodes MUST run on fixed IPv6 addresses and support ZDHT-v1 port 33445.

### APPENDIX D: Error Codes Reference
- `0x01`: Authentication Failed (ZKX)
- `0x02`: Out-of-window counter (ZR)
- `0x03`: DHT Peer Not Found (ZDHT)
