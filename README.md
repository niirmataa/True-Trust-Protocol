# TRUE_TRUST Protocol - tt_node

[![Rust](https://img.shields.io/badge/Rust-1.91%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![PQC](https://img.shields.io/badge/PQC-Falcon%20%7C%20Kyber-green)](https://pq-crystals.org/)
[![STARK](https://img.shields.io/badge/ZK-STARK%20(Winterfell)-purple)](https://github.com/novifinancial/winterfell)
[![Security](https://img.shields.io/badge/Security-Post--Quantum-red)]()

Post-quantum blockchain with privacy-preserving transactions.

## Core Features

| Feature | Implementation | Security Level |
|---------|---------------|----------------|
| **Signatures** | Falcon-512 | NIST PQC L1 |
| **Key Exchange** | Kyber-768 (ML-KEM) | NIST PQC L3 |
| **ZK Proofs** | STARK (Winterfell) | 64-128 bit |
| **Hash** | Poseidon, SHA3, KMAC256 | 128+ bit |
| **PoW** | RandomX | ASIC-resistant |
| **Stealth** | Monero-style PQ | Unlinkable |

## Architecture

```
tt_node/src/
├── lib.rs                    # Library root
├── main.rs                   # Node binary entry
├── core.rs                   # Block, BlockV2, Hash32, timestamps
│
├── crypto/                   # Cryptographic primitives
│   ├── mod.rs
│   ├── kmac.rs               # KMAC256 implementation
│   ├── kmac_drbg.rs          # KMAC-based DRBG
│   ├── poseidon_hash_cpu.rs  # Poseidon hash (CPU)
│   ├── poseidon_params.rs    # Poseidon parameters (auto-generated)
│   ├── randomx_pow.rs        # RandomX PoW
│   ├── seeded.rs             # Deterministic Falcon keygen
│   ├── seeded_kyber.rs       # Deterministic Kyber keygen
│   ├── thread_safe_drbg.rs   # Thread-safe DRBG
│   └── zk_range_poseidon.rs  # STARK range proof (Winterfell)
│
├── falcon_sigs.rs            # Falcon-512 signatures
├── kyber_kem.rs              # Kyber-768 KEM
├── hybrid_commit.rs          # PQC fingerprint (Falcon + Kyber)
├── pqc_verification.rs       # PQC signature verification
│
├── tx_stark.rs               # STARK transactions + Poseidon commitments
├── private_stark_tx.rs       # Full privacy TX
├── simple_pq_tx.rs           # Simple PQ transfer
├── tx_compression.rs         # Transaction compression (zstd)
│
├── stealth_pq.rs             # PQ stealth addresses
├── stealth_registry.rs       # Stealth hint registry
│
├── consensus_pro.rs          # RTT + Stake + Quality consensus
├── consensus_weights.rs      # Weight calculation (Q32.32)
├── rtt_pro.rs                # Recursive Trust Tracking
├── golden_trio.rs            # Quality metrics
│
├── chain_store.rs            # Block storage
├── state_priv.rs             # Private state
├── snapshot_pro.rs           # State snapshots
├── snapshot_witness.rs       # Snapshot witnesses
│
├── node_core.rs              # Node logic
├── node_id.rs                # NodeId (PQC fingerprint)
├── key_registry.rs           # Key management
│
├── stark_security.rs         # STARK security analysis
├── crypto_kmac_consensus.rs  # KMAC for consensus
├── randomx_pow.rs            # RandomX PoW
│
├── p2p/                      # Peer-to-peer networking
│   ├── mod.rs
│   ├── channel.rs            # Encrypted channel (XChaCha20)
│   └── secure.rs             # PQ handshake (Falcon + Kyber)
│
├── rpc/                      # RPC server
│   ├── mod.rs
│   ├── rpc_server.rs         # HTTP RPC (dev only)
│   └── rpc_secure.rs         # Secure PQ RPC
│
├── wallet/                   # Wallet implementation
│   ├── mod.rs
│   ├── wallet_cli.rs         # CLI v7 (deterministic keys)
│   └── wallet_api.rs         # Wallet API
│
└── bin/                      # Additional binaries
    ├── wallet.rs             # Wallet binary
    └── poseidon_param_gen.rs # Poseidon parameter generator
```

## Cryptographic Primitives

### Post-Quantum
- **Falcon-512**: Identity, block signing, TX authorization
- **Kyber-768**: Ephemeral key exchange, value encryption

### Zero-Knowledge
- **STARK (Winterfell)**: Range proofs (value ≥ 0)
- **Poseidon**: ZK-friendly hash for commitments

### Symmetric
- **XChaCha20-Poly1305**: Channel encryption, value encryption
- **AES-256-GCM-SIV**: Wallet encryption
- **KMAC256-XOF**: Key derivation
- **Argon2id**: Password hashing

## Transaction Types

### SimplePqTx
Basic transfer with Falcon signature.

### TransactionStark
STARK range proof per output:
- Poseidon commitment: `H(value, blinding, recipient)`
- Kyber-encrypted value (for recipient)
- Optional stealth hint (Monero-style)

### PrivateStarkTx
Full privacy:
- Hidden sender (encrypted `master_key_id`)
- Hidden recipient (stealth address)
- Hidden amount (Poseidon + STARK proof)

## Node Identity

```
NodeId = SHA256(Falcon_PK || Kyber_PK)[0..32]
```

All nodes identified by PQC public key fingerprint.

## Consensus

```
Weight(v) = w_T * Trust(v) + w_Q * Quality(v) + w_S * Stake(v)
```

- **Trust**: RTT (Recursive Trust Tracking) - EWMA history
- **Quality**: Golden Trio metrics from execution layer
- **Stake**: Bonded tokens (normalized)
- **Leader**: Deterministic selection via weighted sampling + beacon

## P2P Handshake

```
Client                          Server
  |-- ClientHello (Falcon_PK, Kyber_PK, nonce) -->|
  |<-- ServerHello (Falcon_PK, Kyber_CT, sig) ----|
  |-- ClientFinished (sig) ---------------------->|
  |<========= Encrypted Channel =================>|
```

- Forward secrecy: Ephemeral Kyber per session
- Mutual auth: Both parties sign transcript

## Wallet

v7 deterministic:
```
Master Seed (32 bytes)
    ├── Falcon-512 keypair (KMAC + deterministic keygen)
    └── Kyber-768 keypair (KMAC + deterministic keygen)
```

Features:
- Argon2id + local pepper
- AES-GCM-SIV / XChaCha20-Poly1305
- Shamir M-of-N backup (master seed only)
- Stealth send/receive

## Build

```bash
cargo build --release
cargo test
```

## License

Apache 2.0
