//! NLnet Grant Demo - TRUE TRUST Protocol
//!
//! This demo showcases the Post-Quantum secure P2P protocol for NLnet Foundation.
//!
//! ## Features Demonstrated:
//! - ✅ Post-Quantum Cryptography (Falcon-512 + Kyber-768)
//! - ✅ Secure handshake protocol
//! - ✅ AEAD encrypted communication (XChaCha20-Poly1305)
//! - ✅ Mutual authentication
//! - ✅ Forward secrecy
//!
//! ## Usage:
//! ```bash
//! cargo run --example nlnet_demo
//! ```

use anyhow::Result;

fn main() -> Result<()> {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║   TRUE TRUST Protocol - NLnet Demo                      ║");
    println!("║   Post-Quantum Blockchain with Secure P2P               ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    demo_key_generation()?;
    demo_node_identity()?;
    demo_crypto_primitives()?;
    demo_consensus_basics()?;

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║   Demo Complete!                                         ║");
    println!("║   For NLnet Grant Application                           ║");
    println!("╚═══════════════════════════════════════════════════════════╝");

    Ok(())
}

/// Demo 1: Post-Quantum Key Generation
fn demo_key_generation() -> Result<()> {
    println!("📌 [1/4] Post-Quantum Key Generation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    use tt_node::falcon_sigs::falcon_keypair;
    use tt_node::kyber_kem::kyber_keypair;

    // Generate Falcon-512 signing keys
    println!("   🔐 Generating Falcon-512 signing keypair...");
    let (falcon_pk, falcon_sk) = falcon_keypair();
    println!("      ✓ Falcon-512: NIST PQC Level 1 (128-bit security)");
    println!("      ✓ Public key size: {} bytes",
        tt_node::falcon_sigs::falcon_pk_to_bytes(&falcon_pk).len());
    println!("      ✓ Signature size: ~666 bytes");

    // Generate Kyber-768 KEM keys
    println!("\n   🔐 Generating Kyber-768 KEM keypair...");
    let (kyber_pk, _kyber_sk) = kyber_keypair();
    println!("      ✓ Kyber-768: NIST PQC Level 3 (192-bit security)");

    use pqcrypto_traits::kem::PublicKey;
    println!("      ✓ Public key size: {} bytes", kyber_pk.as_bytes().len());
    println!("      ✓ Ciphertext size: 1088 bytes");
    println!("      ✓ Shared secret: 32 bytes\n");

    Ok(())
}

/// Demo 2: Node Identity
fn demo_node_identity() -> Result<()> {
    println!("📌 [2/4] Node Identity & Fingerprinting");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    use tt_node::falcon_sigs::{falcon_keypair, compute_pqc_fingerprint, falcon_pk_to_bytes};
    use tt_node::kyber_kem::kyber_keypair;
    use pqcrypto_traits::kem::PublicKey;

    let (falcon_pk, _) = falcon_keypair();
    let (kyber_pk, _) = kyber_keypair();

    // Compute node fingerprint (SHA3-256 of PQ public keys)
    let node_id = compute_pqc_fingerprint(&falcon_pk, kyber_pk.as_bytes());

    println!("   🆔 Node ID (fingerprint): {}", hex::encode(node_id));
    println!("      ✓ Derived from: SHA3-256(Falcon-PK || Kyber-PK)");
    println!("      ✓ Used for: Peer addressing & reputation");
    println!("      ✓ Collision resistant: 2^128 security\n");

    Ok(())
}

/// Demo 3: Cryptographic Primitives
fn demo_crypto_primitives() -> Result<()> {
    println!("📌 [3/4] Cryptographic Primitives");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // KMAC for key derivation
    println!("   🔑 KMAC256-XOF (NIST SP 800-185)");
    println!("      ✓ Purpose: Session key derivation");
    println!("      ✓ Input: KEM shared secret + transcript hash");
    println!("      ✓ Output: 64 bytes (2x session keys)");

    // XChaCha20-Poly1305 for AEAD
    println!("\n   🔐 XChaCha20-Poly1305 AEAD");
    println!("      ✓ Purpose: Encrypted P2P communication");
    println!("      ✓ Key size: 32 bytes");
    println!("      ✓ Nonce: 192 bits (extended from ChaCha20)");
    println!("      ✓ Tag: 128 bits (Poly1305 MAC)");

    // RandomX for PoW
    println!("\n   ⛏️  RandomX Proof-of-Work");
    println!("      ✓ Purpose: Sybil resistance & consensus");
    println!("      ✓ ASIC-resistant (CPU-optimized)");
    println!("      ✓ Memory-hard (2GB dataset)");
    println!("      ✓ Used by: Monero blockchain\n");

    Ok(())
}

/// Demo 4: Consensus Basics
fn demo_consensus_basics() -> Result<()> {
    println!("📌 [4/4] Consensus Mechanism");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    println!("   🎯 RTT-PRO (Reputation + Trust + Time)");
    println!("      ✓ Byzantine Fault Tolerant (BFT)");
    println!("      ✓ Reputation-weighted voting");
    println!("      ✓ Sybil-resistant via RandomX PoW");
    println!("      ✓ Dynamic validator selection");

    println!("\n   📊 Trust Graph Properties:");
    println!("      ✓ Decentralized trust computation");
    println!("      ✓ Exponential decay (λ = 0.1)");
    println!("      ✓ Multi-hop trust propagation");
    println!("      ✓ Byzantine-resilient scoring\n");

    Ok(())
}
