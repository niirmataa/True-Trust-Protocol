# TRUE-TRUST PROTOCOL

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Post-Quantum](https://img.shields.io/badge/crypto-post--quantum-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![STARK](https://img.shields.io/badge/ZK-STARK-purple.svg)](https://starkware.co/)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

> **Post-quantum secure blockchain with full transaction privacy using STARK proofs**

---

## Overview

TRUE-TRUST is a next-generation blockchain protocol designed for the post-quantum era. It combines NIST-approved post-quantum cryptography with zero-knowledge STARK proofs to provide **complete transaction privacy** while maintaining full verifiability.

### Key Innovations

| Feature | Technology | Benefit |
|---------|------------|---------|
| **Quantum-Safe Signatures** | Falcon-512 | 128-bit PQ security |
| **Key Encapsulation** | Kyber-768 | Secure key exchange |
| **Private Amounts** | STARK + Poseidon | Hidden values, verified range |
| **Stealth Addresses** | Kyber KEM | Unlinkable recipients |
| **Encrypted Sender** | AES-GCM + KDF | Hidden sender identity |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Private STARK TX                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Sender    │  │  Recipient  │  │   Confidential      │ │
│  │   Stealth   │  │   Stealth   │  │      Amount         │ │
│  │    (48B)    │  │   (1.1KB)   │  │     (~47KB)         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│         │                │                    │             │
│         ▼                ▼                    ▼             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Encrypted  │  │  Kyber KEM  │  │  STARK Range Proof  │ │
│  │  Sender ID  │  │  Ciphertext │  │  + Poseidon Commit  │ │
│  │    (60B)    │  │   (1088B)   │  │     (~32KB)         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                 Falcon-512 Signature (~700B)                │
├─────────────────────────────────────────────────────────────┤
│          Bincode Serialized (~35KB total, proof ~33KB)      │
│          (JSON would be ~66KB due to hex encoding!)         │
└─────────────────────────────────────────────────────────────┘
```

---

## Privacy Features

### 🔒 Full Transaction Privacy

| What's Hidden | How |
|---------------|-----|
| **Sender** | Stealth output + encrypted master_key_id |
| **Recipient** | Stealth address + Kyber KEM |
| **Amount** | Poseidon commitment + STARK range proof |
| **Link** | scan_hint filtering (17-52x speedup) |

### 📊 TX Size Comparison

| TX Type | Bincode | JSON | Privacy Level |
|---------|---------|------|---------------|
| SimplePqTx | ~2.8 KB | ~5.5 KB | None |
| CompactSimpleTx | ~786 B | ~1.5 KB | None |
| PrivateCompactTx | ~1.9 KB | ~3.8 KB | Partial |
| **PrivateStarkTx** | **~35 KB** | **~66 KB** | **Full** |

---

## Cryptographic Stack

```
┌────────────────────────────────────────┐
│           Post-Quantum Layer           │
├────────────────────────────────────────┤
│  Falcon-512    │  NIST signature std   │
│  Kyber-768     │  NIST KEM standard    │
│  KMAC256       │  Key derivation       │
├────────────────────────────────────────┤
│           Zero-Knowledge Layer         │
├────────────────────────────────────────┤
│  Winterfell    │  STARK prover/verifier│
│  Poseidon      │  ZK-friendly hash     │
│  Range Proof   │  64-bit value proof   │
├────────────────────────────────────────┤
│           Symmetric Crypto             │
├────────────────────────────────────────┤
│  AES-256-GCM   │  Sender ID encryption │
│  XChaCha20     │  Amount encryption    │
└────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

```bash
# Rust 1.70+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build essentials (for PQClean C code)
sudo apt install build-essential clang
```

### Build

```bash
git clone https://github.com/niirmataa/True-Trust-Protocol.git
cd True-Trust-Protocol

# Build node
cargo build --release -p tt_node

# Build wallet
cargo build --release -p tt_node --features wallet
```

### Run Validator

```bash
./target/release/tt_node validator \
  --rpc-port 9977 \
  --p2p-port 9090 \
  --data-dir ./data
```

### Create Wallet

```bash
./target/release/tt_wallet create --file alice.wallet

# Export keys for receiving
./target/release/tt_wallet export-keys --file alice.wallet
```

### Send Private TX

```bash
./target/release/tt_wallet private-stark-send \
  --file alice.wallet \
  --recipient-kyber-pk <BOB_KYBER_PK_HEX> \
  --amount 1000 \
  --rpc 127.0.0.1:9977
```

---

## Consensus: PRO System

Deterministic validator selection based on:

```
W = T^1.0 × Q^0.5 × S^0.8

T = Trust Score (0-1)
Q = Quality Score (Golden Trio)
S = Stake Amount
```

### Golden Trio Components

| Component | Weight | Measures |
|-----------|--------|----------|
| Block Production | 25% | Reliability |
| Proof Generation | 25% | STARK capability |
| Uptime | 20% | Availability |
| Stake Lock | 15% | Commitment |
| Fee Behavior | 10% | Fairness |
| Community | 5% | Reputation |

---

## Security

### Post-Quantum Resistance

| Algorithm | Security Level | NIST Status |
|-----------|----------------|-------------|
| Falcon-512 | 128-bit PQ | Standardized |
| Kyber-768 | 128-bit PQ | Standardized |
| KMAC256 | 256-bit | Standard |

### STARK Proofs

- **Transparent setup** (no trusted setup)
- **Quantum-resistant** (hash-based)
- **Range proof**: 64-bit values
- **Binding**: Poseidon commitment

---

## Performance

| Operation | Time | Throughput | Notes |
|-----------|------|------------|-------|
| STARK proof generation | ~35 ms | 28/sec | Winterfell |
| STARK proof verification | ~303 μs | 3.3K/sec | 16x faster than expected |
| Falcon-512 sign | ~230 μs | 4.3K/sec | PQ signature |
| Falcon-512 verify | ~40 μs | 25K/sec | Fast verification |
| Kyber-768 KEM roundtrip | ~79 μs | 12.7K/sec | Key exchange |
| Poseidon hash | ~40 μs | 25K/sec | ZK-friendly |
| View tag scan | ~112 ns | 8.9M/sec | 250x faster than KEM |
| PrivateStarkTx create | ~20 ms | 49/sec | Full privacy TX |

### Transaction Sizes

| TX Type | Bincode | JSON | Privacy Level |
|---------|---------|------|---------------|
| SimplePqTx | ~2.8 KB | ~5.5 KB | None (public) |
| CompactSimpleTx | ~786 B | ~1.5 KB | None (key registry) |
| PrivateCompactTx | ~1.9 KB | ~3.8 KB | Partial (stealth) |
| **PrivateStarkTx** | **~35 KB** | **~66 KB** | **Full** |

> **Why Bincode?** STARK proofs (~33 KB) are cryptographically random bytes.
> JSON hex-encodes binary data → 2x size overhead! Bincode stores raw bytes → 50% smaller.
> The ~35 KB is: stealth (~1.2 KB) + STARK proof (~33 KB) + signature (~0.7 KB).

---

## Project Structure

```
True-Trust-Protocol/
├── Cargo.toml                    # Workspace config
├── README.md
├── WALLET_USAGE.md               # Wallet CLI guide
├── MINING_GUIDE.md               # Validator setup
├── PROJECT_STATUS.md             # Development status
│
├── tt_node/                      # Main blockchain node
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs               # Node entry point
│   │   ├── lib.rs                # Library exports
│   │   │
│   │   ├── # ══════ CONSENSUS ══════
│   │   ├── consensus_pro.rs      # PRO consensus (T×Q×S)
│   │   ├── consensus_weights.rs  # Weight calculations
│   │   ├── golden_trio.rs        # Validator quality system
│   │   ├── rtt_pro.rs            # Real-time trust
│   │   │
│   │   ├── # ══════ TRANSACTIONS ══════
│   │   ├── private_stark_tx.rs   # Full privacy TX (STARK)
│   │   ├── simple_pq_tx.rs       # Basic PQ transaction
│   │   ├── tx_stark.rs           # STARK TX structures
│   │   ├── tx_stark_signed.rs    # Signed STARK TX
│   │   ├── stealth_pq.rs         # Stealth addresses
│   │   ├── stealth_registry.rs   # Stealth key registry
│   │   │
│   │   ├── # ══════ CRYPTOGRAPHY ══════
│   │   ├── falcon_sigs.rs        # Falcon-512 signatures
│   │   ├── kyber_kem.rs          # Kyber-768 KEM
│   │   ├── crypto_kmac_consensus.rs  # KMAC for consensus
│   │   ├── falcon_key_validator.rs   # Key validation
│   │   ├── pqc_verification.rs   # PQ crypto verification
│   │   │
│   │   ├── crypto/               # Crypto modules
│   │   │   ├── mod.rs
│   │   │   ├── kmac.rs           # KMAC256 implementation
│   │   │   ├── kmac_drbg.rs      # Deterministic RNG
│   │   │   ├── zk_range_poseidon.rs  # STARK range prover
│   │   │   ├── poseidon_hash_cpu.rs  # Poseidon hash
│   │   │   ├── poseidon_params.rs    # Poseidon parameters
│   │   │   ├── seeded.rs         # Seeded crypto
│   │   │   ├── seeded_kyber.rs   # Deterministic Kyber
│   │   │   ├── thread_safe_drbg.rs   # Thread-safe RNG
│   │   │   └── randomx_pow.rs    # RandomX PoW
│   │   │
│   │   ├── # ══════ NODE & STORAGE ══════
│   │   ├── node_core.rs          # Core node logic
│   │   ├── node_id.rs            # Node identity
│   │   ├── secure_node.rs        # Secure node wrapper
│   │   ├── chain_store.rs        # Blockchain storage
│   │   ├── key_registry.rs       # Key management
│   │   ├── state_priv.rs         # Private state
│   │   ├── snapshot_pro.rs       # State snapshots
│   │   ├── snapshot_witness.rs   # Snapshot witnesses
│   │   │
│   │   ├── # ══════ STARK/ZK ══════
│   │   ├── stark_full.rs         # Full STARK impl
│   │   ├── stark_security.rs     # STARK security
│   │   ├── ledger_stark.rs       # STARK ledger
│   │   ├── winterfell_range.rs   # Winterfell range
│   │   ├── hybrid_commit.rs      # Hybrid commitments
│   │   │
│   │   ├── # ══════ NETWORKING ══════
│   │   ├── p2p/                  # P2P layer
│   │   │   ├── mod.rs
│   │   │   ├── channel.rs        # P2P channels
│   │   │   └── secure.rs         # Secure P2P
│   │   ├── p2p_stark_tx.rs       # STARK TX broadcast
│   │   │
│   │   ├── rpc/                  # RPC server
│   │   │   ├── mod.rs
│   │   │   ├── rpc_server.rs     # Basic RPC
│   │   │   └── rpc_secure.rs     # PQ-secure RPC
│   │   │
│   │   ├── wallet/               # Wallet module
│   │   │   ├── mod.rs
│   │   │   ├── wallet_cli.rs     # CLI commands
│   │   │   └── wallet_api.rs     # Wallet API
│   │   │
│   │   ├── bin/                  # Binaries
│   │   │   ├── wallet.rs         # Wallet binary
│   │   │   └── poseidon_param_gen.rs  # Param generator
│   │   │
│   │   └── # ══════ MISC ══════
│   │       ├── signing_guard.rs  # Signing protection
│   │       ├── thread_safe_drbg.rs
│   │       └── randomx_pow.rs    # RandomX PoW
│   │
│   ├── examples/                 # Usage examples
│   │   ├── consensus_rewards_test.rs
│   │   ├── e2e_demo.rs
│   │   ├── e2e_full_test.rs
│   │   ├── mining_demo.rs
│   │   ├── secure_rpc_demo.rs
│   │   ├── stealth_demo.rs
│   │   ├── test_all_features.rs
│   │   └── wallet_balance_rpc_demo.rs
│   │
│   └── tests/                    # Integration tests
│       ├── e2e_full_test.rs
│       ├── e2e_simple_test.rs
│       ├── e2e_test.rs
│       └── unit_tests.rs
│
└── falcon_seeded/                # Deterministic Falcon-512
    ├── Cargo.toml
    ├── build.rs                  # PQClean build script
    ├── src/
    │   ├── lib.rs
    │   └── wallet/
    ├── pqclean/                  # PQClean C sources
    │   ├── common/               # Shared crypto (AES, SHA, etc.)
    │   └── crypto_sign/falcon-512/
    └── scripts/
        └── setup_pqclean.sh
```

---

## Module Overview

| Module | Purpose | Key Features |
|--------|---------|--------------|
| `private_stark_tx` | Full privacy transactions | Stealth + STARK + encrypted sender |
| `consensus_pro` | PRO consensus | T×Q×S formula, deterministic |
| `golden_trio` | Validator quality | 6-component scoring system |
| `crypto/zk_range_poseidon` | STARK prover | Winterfell, 64-bit range proof |
| `crypto/kmac` | Key derivation | KMAC256/SHAKE256 |
| `falcon_sigs` | Signatures | Falcon-512 (NIST PQ) |
| `kyber_kem` | Key exchange | Kyber-768 (NIST PQ) |
| `stealth_pq` | Stealth addresses | Kyber-based unlinkable |
| `rpc/rpc_secure` | Secure RPC | PQ-authenticated channels |
| `wallet/wallet_cli` | Wallet CLI | 20+ commands |

---

## Testing

```bash
# All tests
cargo test --release -p tt_node

# Private STARK TX tests (11 tests)
cargo test --release -p tt_node private_stark

# Benchmarks
cargo test --release -p tt_node benchmark -- --nocapture
```

### Test Coverage

| Module | Tests | Status |
|--------|-------|--------|
| private_stark_tx | 11 | ✅ Pass |
| consensus_pro | 8 | ✅ Pass |
| crypto/zk_range | 5 | ✅ Pass |
| wallet | 12 | ✅ Pass |

---

## Roadmap

- [x] Post-quantum signatures (Falcon-512)
- [x] Post-quantum KEM (Kyber-768)
- [x] Stealth addresses
- [x] STARK range proofs
- [x] Confidential amounts
- [x] Encrypted sender ID
- [x] Scan hint optimization (250x speedup)
- [ ] Multi-asset support
- [ ] Decoy outputs (ring signatures alternative)
- [ ] Hardware wallet support
- [ ] Mobile wallet

---

## Documentation

| Document | Description |
|----------|-------------|
| [CONSENSUS_DESIGN.md](tt_node/CONSENSUS_DESIGN.md) | PRO consensus specification |
| [TRUST_EXPLAINED.md](tt_node/TRUST_EXPLAINED.md) | Trust system details |
| [WALLET_USAGE.md](WALLET_USAGE.md) | Wallet CLI guide |
| [MINING_GUIDE.md](MINING_GUIDE.md) | Validator setup |

---

## License

Apache License 2.0 - see [LICENSE](LICENSE)

---

## Acknowledgments

- [Winterfell](https://github.com/facebook/winterfell) - STARK prover
- [PQClean](https://github.com/PQClean/PQClean) - Post-quantum implementations
- [pqcrypto](https://github.com/rustpq/pqcrypto) - Rust PQ bindings

---

<p align="center">
  <b>Built for the post-quantum future</b> 🔐
</p>
