# TRUE-TRUST-PROTOCOL 🔐

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org)
[![GitHub stars](https://img.shields.io/github/stars/niirmataa/True-Trust-Protocol.svg?style=social&label=Star)](https://github.com/niirmataa/True-Trust-Protocol)
[![GitHub forks](https://img.shields.io/github/forks/niirmataa/True-Trust-Protocol.svg?style=social&label=Fork)](https://github.com/niirmataa/True-Trust-Protocol)
[![GitHub issues](https://img.shields.io/github/issues/niirmataa/True-Trust-Protocol.svg)](https://github.com/niirmataa/True-Trust-Protocol/issues)
[![GitHub last commit](https://img.shields.io/github/last-commit/niirmataa/True-Trust-Protocol.svg)](https://github.com/niirmataa/True-Trust-Protocol/commits/main)
[![Lines of Code](https://img.shields.io/tokei/lines/github/niirmataa/True-Trust-Protocol)](https://github.com/niirmataa/True-Trust-Protocol)
[![Security: Post-Quantum](https://img.shields.io/badge/security-post--quantum-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Code Size](https://img.shields.io/github/languages/code-size/niirmataa/True-Trust-Protocol.svg)](https://github.com/niirmataa/True-Trust-Protocol)

Post-quantum secure blockchain with deterministic consensus, STARK proofs, and advanced cryptographic primitives.

## 🌟 Key Features

### 🔒 Post-Quantum Cryptography (PQC-Only)
- **Falcon-512**: NIST-approved lattice signatures (128-bit PQ security)
- **Kyber-768**: NIST-approved Module-LWE KEM (IND-CCA2 secure)
- **KMAC256/SHAKE256**: SHA3-based key derivation and hashing
- **Zero legacy crypto**: No ECC, RSA, or pre-quantum algorithms

### ⚖️ Deterministic Consensus (PRO)
- **Q32.32 fixed-point arithmetic**: Zero floating-point in consensus path
- **RTT (Recursive Trust Tree)**: Trust-based validator reputation with S-curve (3x² - 2x³)
- **Golden Trio**: 6-component quality assessment (blocks, proofs, uptime, stake lock, fees, network)
- **Weighted leader selection**: `W = 0.4·T + 0.3·V + 0.3·Q` (trust, vouching, work)

### 🌐 Secure Networking
- **3-message PQ handshake**: ClientHello → ServerHello(Falcon sig + Kyber CT) → ClientFinished
- **XChaCha20-Poly1305 channels**: AEAD encryption with nonce counters
- **PoW anti-DDoS**: SHA3-256 challenge (20 leading zero bits) before RPC access
- **Rate limiting**: Token bucket per IP (100 req/s), connection limits (10/IP)

### 🔐 Advanced Cryptography
- **RandomX PoW**: ASIC-resistant mining (2GB dataset, full mode)
- **Winterfell v0.13 STARKs**: ZK range proofs with Poseidon hash (Goldilocks field)
- **KMAC-DRBG**: Deterministic RNG with forward secrecy (ratcheting every 4MB)
- **Hybrid commitments**: Poseidon + Pedersen for STARK-based transactions

### 💼 Quantum-Safe Wallet
- **PQ-only keys**: Falcon-512 + Kyber-768 (no ECC)
- **Bech32m addresses**: `ttq1...` prefix from SHAKE256(Falcon_PK || Kyber_PK)
- **Argon2id KDF**: Password hashing with local pepper
- **Shamir M-of-N**: Secret sharing for master seed recovery
- **AES-GCM-SIV / XChaCha20**: AEAD encryption for keystores

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       NODE CORE                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ Chain Store  │  │ Consensus PRO│  │ State/Ledger │       │
│  │  (fork-choice│  │  (RTT+Golden │  │  (UTXO-like) │       │
│  │   by weight) │  │   Trio, Q32) │  │              │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│         │                  │                  │             │
│         └──────────────────┴──────────────────┘             │
│                            │                                │
└────────────────────────────┼─────────────────────────────────┘
                             │
            ┌────────────────┴────────────────┐
            │                                 │
    ┌───────▼──────┐                 ┌───────▼──────┐
    │ P2P Network  │                 │  Secure RPC  │
    │ (Falcon+Kyber│                 │ (PoW+Falcon+ │
    │  handshake)  │                 │  Kyber+AEAD) │
    └──────────────┘                 └──────────────┘
```

### Core Modules

| Module | Purpose | LOC | Security |
|--------|---------|-----|----------|
| `consensus_pro.rs` | PRO consensus, validator registry | 372 | ✅ Q32.32, no f64 |
| `rtt_pro.rs` | Recursive Trust Tree (trust scoring) | 425 | ✅ S-curve, vouching |
| `golden_trio.rs` | 6-component quality system | 200 | ✅ Deterministic |
| `consensus_weights.rs` | Final weight computation, leader selection | 100 | ✅ SHA3 beacon |
| `p2p/secure.rs` | PQ handshake (Falcon+Kyber) | 336 | ✅ Transcript hash |
| `p2p/channel.rs` | XChaCha20-Poly1305 encrypted channels | 150 | ✅ Nonce management |
| `rpc/rpc_secure.rs` | Secure RPC server (PoW, rate limits) | 979 | ✅ Anti-DDoS |
| `crypto/kmac_drbg.rs` | KMAC-based DRBG (forward secrecy) | 305 | ✅ Ratcheting |
| `crypto/kmac.rs` | KMAC256 primitives (XOF, derive, tag) | 100 | ✅ Domain separation |
| `falcon_sigs.rs` | Falcon-512 wrapper (sign, verify, fingerprint) | 600 | ✅ PQC |
| `kyber_kem.rs` | Kyber-768 wrapper (encapsulate, decapsulate) | 500 | ✅ IND-CCA2 |
| `randomx_pow.rs` | RandomX wrapper (full dataset) | 200 | ✅ ASIC-resistant |
| `tx_stark.rs` | STARK-based transactions | 400 | ✅ Winterfell |
| `wallet/wallet_cli.rs` | PQ wallet CLI (Falcon+Kyber keys) | 1265 | ✅ Argon2id, Shamir |

---

## 🚀 Quick Start

### Prerequisites

```bash
# Rust 1.70+ (2021 edition)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# C compiler (for PQClean FFI)
sudo apt install build-essential  # Debian/Ubuntu
# or
brew install gcc  # macOS
```

### Building

```bash
# Clone repository
git clone https://github.com/niirmataa/True-Trust-Protocol.git
cd True-Trust-Protocol

# Build all components (release mode)
cargo build --release --all-features

# Run tests
cargo test --all

# Check code (no warnings)
cargo clippy --all-features -- -D warnings
```

### Running a Validator Node

```bash
# Start validator with PQ secure RPC
cargo run --release --bin tt_node -- validator \
  --data-dir ./validator-data \
  --p2p-port 9090 \
  --rpc-port 8080 \
  --stake 10000

# Output:
# 🚀 Starting TRUE_TRUST Validator Node
# 📁 Data directory: ./validator-data
# 🔑 Generating new validator keys...
# 📍 Consensus Node ID (Falcon-based): a3f9c2e1...
# 🌐 P2P identity generated (SecureNodeIdentity)
# 🔐 Secure PQ RPC listening on 0.0.0.0:8080
#    Node ID: b7d4e8f3...
# ✅ Validator node started successfully!
```

### Running a Full Node (Non-Validating)

```bash
cargo run --release --bin tt_node -- full-node \
  --data-dir ./node-data \
  --p2p-port 9090 \
  --rpc-port 8080
```

### Wallet Operations

```bash
# Initialize new PQ wallet
cargo run --release --bin wallet -- wallet-init \
  --file ./my-wallet.dat \
  --aead gcm-siv \
  --pepper os-local

# Get wallet address (Bech32m with "ttq" prefix)
cargo run --release --bin wallet -- wallet-addr \
  --file ./my-wallet.dat
# Output: ttq1qxk3j7v9p2h4f6g8d9s0a1z2x3c4v5b6n7m8q9w0e1r2t3y4u5i6o7p8

# Check balance via secure RPC
cargo run --release --bin wallet -- wallet-balance \
  --file ./my-wallet.dat \
  --rpc 127.0.0.1:8080

# Create Shamir M-of-N backup
cargo run --release --bin wallet -- shards-create \
  --file ./my-wallet.dat \
  --out-dir ./backup-shards \
  --m 3 \
  --n 5 \
  --per-share-pass
```

---

## 📊 Consensus Algorithm (PRO)

### Trust Calculation (RTT)

```
Historical trust:  H(v) = α·H_old + (1-α)·Q_t  (EWMA, α=0.99)
Vouching trust:    V(v) = min(Σ T(j)·strength(j→v), 1.0)
Work trust:        W(v) = Q_t  (Golden Trio quality)

Linear combination: Z_lin = 0.4·H + 0.3·V + 0.3·W
S-curve transform:  T(v) = 3·Z² - 2·Z³  (smooth saturation)
```

### Golden Trio Components

| Component | Weight | Metric |
|-----------|--------|--------|
| **B** Block production | 0.2 | Blocks produced / expected |
| **P** Proof generation | 0.2 | Valid STARKs / total |
| **U** Uptime | 0.2 | Online time / epoch |
| **L** Stake lock | 0.15 | Lock duration score |
| **F** Fees earned | 0.15 | Fee share / total |
| **N** Network contribution | 0.1 | P2P relay score |

**Final quality**: `Q = 0.2·B + 0.2·P + 0.2·U + 0.15·L + 0.15·F + 0.1·N`

### Leader Selection

```rust
// Deterministic, weighted selection (SHA3-256)
beacon = SHA3_256(prev_block_hash || slot)
for each validator v:
    score = SHA3_256("TT-LEADER.v1" || beacon || v.id || v.weight)
    if score > best_score:
        best_score = score
        leader = v
```

---

## 🔐 Cryptographic Specifications

### Key Sizes

| Algorithm | Public Key | Secret Key | Signature/CT | Shared Secret |
|-----------|------------|------------|--------------|---------------|
| **Falcon-512** | 897 B | 1281 B | ~666 B | - |
| **Kyber-768** | 1184 B | 2400 B | 1088 B | 32 B |

### Security Levels

- **Falcon-512**: 128-bit post-quantum (NIST Level 1)
- **Kyber-768**: 128-bit post-quantum (NIST Level 3)
- **KMAC256**: 256-bit classical, quantum-resistant
- **RandomX**: GPU/ASIC-resistant (2GB dataset)

### P2P Handshake Flow

```
Client                                  Server
  │                                       │
  ├─────── ClientHello ─────────────────→│
  │  (NodeId, Falcon_PK, Kyber_PK,       │
  │   protocol_version, timestamp,       │
  │   anti_replay_nonce)                 │
  │                                       │
  │←────── ServerHello ───────────────────┤
  │  (NodeId, Falcon_PK, Kyber_CT,       │
  │   Falcon_sig(transcript))            │
  │                                       │
  │  [Both sides derive shared secret    │
  │   via Kyber, then KDF to session     │
  │   keys: KMAC256-XOF(ss, transcript)] │
  │                                       │
  ├─────── ClientFinished ──────────────→│
  │  (Falcon_sig(transcript))            │
  │                                       │
  │←─────── [XChaCha20-Poly1305 ─────────┤
  │         encrypted channel] ──────────│
```

### RPC Security Layers

1. **PoW Challenge**: SHA3-256(challenge || nonce || timestamp) with 20 leading zero bits
2. **PQ Handshake**: Falcon-512 + Kyber-768 (same as P2P)
3. **Rate Limiting**: Token bucket (100 req/s per IP, max 10 connections/IP)
4. **Session Management**: 30-minute timeout, automatic cleanup
5. **Message Encryption**: XChaCha20-Poly1305 AEAD (separate keys per direction)

---

## 🧪 Testing

### Unit Tests

```bash
# All unit tests
cargo test --all

# Specific modules
cargo test consensus_pro
cargo test rtt_pro
cargo test crypto::kmac_drbg

# With output
cargo test -- --nocapture --test-threads=1
```

### Integration Tests

```bash
# Full end-to-end test (~5500 lines)
cargo test --test e2e_full_test

# Consensus rewards demo
cargo run --example consensus_rewards_test

# Mining demo (RandomX + STARK)
cargo run --example mining_demo
```

### Examples

```bash
# Secure RPC demo (client + server)
cargo run --example secure_rpc_demo

# Test all features
cargo run --example test_all_features
```

---

## 📦 Dependencies

### Post-Quantum Cryptography
- `pqcrypto-falcon` 0.3 - NIST-approved Falcon-512
- `pqcrypto-kyber` 0.8 - NIST-approved Kyber-768
- `pqcrypto-traits` 0.3 - Standard PQC trait interfaces

### Hashing & KDF
- `sha3` 0.10 - SHA3-256/512, SHAKE256
- `tiny-keccak` 2.0 - KMAC256 via cSHAKE

### Symmetric Encryption
- `aes-gcm-siv` 0.10 - AES-256-GCM-SIV AEAD
- `chacha20poly1305` 0.10 - XChaCha20-Poly1305 AEAD

### ZK Proofs
- `winterfell` 0.13 - STARK framework (Goldilocks field)
- `merlin` - Transcript hashing for Fiat-Shamir

### Networking
- `tokio` 1.38 - Async runtime (full features)
- `hyper` 0.14 - HTTP/RPC framework

### Other
- `randomx-rs` 1.4.1 - RandomX PoW
- `argon2` - Password KDF (Argon2id)
- `bech32` - Address encoding (Bech32m)
- `sharks` - Shamir secret sharing
- `zeroize` - Sensitive data wipeout

**Total dependencies**: ~170 crates
**Build time (release)**: ~2-3 minutes
**Binary size (tt_node)**: ~15 MB

---

## 📂 Project Structure

```
True-Trust-Protocol/
├── Cargo.toml                      # Workspace root
├── Cargo.lock                      # Dependency lock
├── README.md                       # This file
├── PROJECT_STATUS.md               # Implementation status
├── MINING_GUIDE.md                 # Mining documentation
├── WALLET_USAGE.md                 # Wallet guide
│
├── tt_node/                        # Main blockchain node
│   ├── Cargo.toml                  # Node dependencies
│   ├── src/
│   │   ├── main.rs                 # CLI entry point (647 lines)
│   │   ├── lib.rs                  # Library exports
│   │   │
│   │   ├── consensus_pro.rs        # PRO consensus (372 lines)
│   │   ├── rtt_pro.rs              # RTT trust scoring (425 lines)
│   │   ├── golden_trio.rs          # Quality assessment (200 lines)
│   │   ├── consensus_weights.rs    # Weight calculation (100 lines)
│   │   │
│   │   ├── core.rs                 # Blockchain primitives
│   │   ├── chain_store.rs          # Block storage + fork-choice
│   │   ├── node_core.rs            # Node engine (mempool, ledger)
│   │   ├── state_priv.rs           # State management
│   │   │
│   │   ├── falcon_sigs.rs          # Falcon-512 wrapper (600 lines)
│   │   ├── kyber_kem.rs            # Kyber-768 wrapper (500 lines)
│   │   ├── node_id.rs              # NodeId from Falcon PK
│   │   │
│   │   ├── crypto/
│   │   │   ├── mod.rs              # Crypto module exports
│   │   │   ├── kmac.rs             # KMAC256 primitives (100 lines)
│   │   │   ├── kmac_drbg.rs        # KMAC-DRBG (305 lines)
│   │   │   ├── randomx_pow.rs      # RandomX wrapper (200 lines)
│   │   │   ├── poseidon_hash_cpu.rs # Poseidon hash (CPU)
│   │   │   └── zk_range_poseidon.rs # Winterfell range proofs
│   │   │
│   │   ├── p2p/
│   │   │   ├── mod.rs              # P2P network
│   │   │   ├── secure.rs           # PQ handshake (336 lines)
│   │   │   └── channel.rs          # XChaCha20-Poly1305 (150 lines)
│   │   │
│   │   ├── rpc/
│   │   │   ├── mod.rs              # RPC module
│   │   │   └── rpc_secure.rs       # Secure RPC server (979 lines)
│   │   │
│   │   ├── wallet/
│   │   │   ├── mod.rs              # Wallet module
│   │   │   └── wallet_cli.rs       # CLI wallet (1265 lines)
│   │   │
│   │   ├── tx_stark.rs             # STARK transactions
│   │   ├── stealth_pq.rs           # Stealth addresses (PQ)
│   │   └── ...                     # Other modules
│   │
│   ├── bin/
│   │   └── wallet.rs               # Wallet binary entry point
│   │
│   ├── examples/
│   │   ├── mining_demo.rs          # Mining pipeline (11,878 lines!)
│   │   ├── e2e_full_test.rs        # Full integration test (5,527 lines)
│   │   ├── secure_rpc_demo.rs      # RPC demo
│   │   └── ...
│   │
│   └── tests/                      # Integration tests
│
├── falcon_seeded/                  # Deterministic Falcon-512
│   ├── Cargo.toml                  # FFI crate
│   ├── build.rs                    # PQClean C compilation
│   ├── src/
│   │   └── lib.rs                  # FFI wrappers (100+ lines)
│   │
│   └── pqclean/
│       └── crypto_sign/falcon-512/clean/
│           ├── codec.c             # Falcon C implementation
│           ├── keygen.c            # Key generation
│           ├── sign.c              # Signing
│           ├── vrfy.c              # Verification
│           └── ...
│
└── .gitignore
```

**Total lines of Rust**: ~7,800
**Total modules**: 30+
**Total examples**: 6
**Total tests**: 50+

---

## 🔧 Configuration

### Consensus Parameters (PRO)

```rust
// rtt_pro.rs
beta_history:  0.4    // Historical trust weight
beta_vouching: 0.3    // Vouching weight
beta_work:     0.3    // Current work weight
alpha_history: 0.99   // EWMA memory coefficient
min_trust_to_vouch: 0.5  // Minimum trust to vouch

// consensus_weights.rs
W_TRUST:   0.40      // Trust component weight
W_QUALITY: 0.35      // Quality component weight
W_STAKE:   0.25      // Stake component weight
```

### Security Constants (RPC)

```rust
// rpc/rpc_secure.rs
MAX_MESSAGE_SIZE: 10 MB
SESSION_TIMEOUT: 30 minutes
MAX_CONNECTIONS_PER_IP: 10
MAX_REQUESTS_PER_SECOND: 100
POW_DIFFICULTY: 20  // leading zero bits
KEY_ROTATION_INTERVAL: 24 hours
```

### Crypto Parameters

```rust
// crypto/kmac_drbg.rs
RATCHET_INTERVAL: 65536 blocks (~4 MB)

// p2p/secure.rs
MAX_CLOCK_SKEW_SECS: 60  // Timestamp tolerance
PROTOCOL_VERSION: 1
```

---

## 🛡️ Security Considerations

### ✅ Implemented Security Features

1. **Memory Safety**: `#![forbid(unsafe_code)]` everywhere (except FFI boundary)
2. **Zeroization**: All secret keys zeroized on drop (`Zeroizing<T>`)
3. **Constant-time**: PQC operations via pqcrypto (NIST reference)
4. **Anti-replay**: Nonces + timestamp validation in handshakes
5. **Rate limiting**: Token bucket + connection limits per IP
6. **Forward secrecy**: Kyber ephemeral keys + DRBG ratcheting

### ⚠️ Known Limitations

1. **No formal audit**: Code not audited by external security firm
2. **Experimental status**: Not recommended for production use
3. **P2P discovery**: Peer discovery not fully implemented
4. **Storage**: No persistent blockchain database (in-memory only)
5. **Network partitions**: Byzantine fault tolerance not fully tested

### 🔒 Threat Model

**Protected against**:
- ✅ Quantum computer attacks (Shor, Grover)
- ✅ Man-in-the-middle (MITM) attacks
- ✅ Replay attacks
- ✅ DoS via rate limiting + PoW
- ✅ Timing attacks (constant-time PQC ops)

**Not protected against**:
- ❌ Side-channel attacks (cache timing, power analysis) - requires hardware
- ❌ Social engineering / phishing
- ❌ Compromised host (malware, keyloggers)
- ❌ Quantum attacks on symmetric crypto (use 256-bit keys)

---

## 🚧 Roadmap

### ✅ Completed (v0.1)

- [x] Post-quantum cryptography (Falcon-512 + Kyber-768)
- [x] Deterministic consensus (RTT + Golden Trio)
- [x] Q32.32 fixed-point arithmetic
- [x] Secure P2P handshake (Falcon+Kyber)
- [x] Secure RPC server (PoW + rate limits)
- [x] KMAC-DRBG with forward secrecy
- [x] RandomX proof-of-work
- [x] Winterfell STARK proofs
- [x] PQ wallet CLI (Argon2id + Shamir)

### 🔨 In Progress (v0.2)

- [ ] Persistent blockchain storage (RocksDB)
- [ ] P2P peer discovery (DHT)
- [ ] Transaction mempool optimization
- [ ] Advanced fee market
- [ ] Light client support (SPV)

### 🔮 Future (v0.3+)

- [ ] Smart contracts (WASM runtime)
- [ ] Cross-chain bridges (IBC-like)
- [ ] Sharding / Layer-2
- [ ] Governance module
- [ ] Formal verification (model checking)
- [ ] Hardware wallet support
- [ ] Mobile wallets (iOS/Android)

---

## 📝 License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`cargo test --all`)
4. Run clippy (`cargo clippy --all-features -- -D warnings`)
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📚 References

- [Falcon Specification](https://falcon-sign.info/)
- [Kyber Specification](https://pq-crystals.org/kyber/)
- [NIST PQC Competition](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Winterfell STARK](https://github.com/facebook/winterfell)
- [RandomX](https://github.com/tevador/RandomX)

## 📧 Contact

- GitHub Issues: https://github.com/niirmataa/True-Trust-Protocol/issues
- Email: [your-email]
- Discord: [your-discord]

## ⚠️ Disclaimer

**EXPERIMENTAL SOFTWARE - USE AT YOUR OWN RISK**

This blockchain implementation is in active development and has NOT been audited. Do not use for:
- Production systems
- Real financial transactions
- Critical infrastructure
- Any system where security is paramount

The cryptographic primitives (Falcon, Kyber, KMAC) are based on NIST-approved standards, but the overall system design and implementation have not undergone formal security review.

---

*Built with 🦀 Rust and quantum-resistant cryptography*

