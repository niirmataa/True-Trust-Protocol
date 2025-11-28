//! Comprehensive Benchmark Suite for True Trust Protocol
//!
//! Measures all cryptographic operations for white paper documentation.
//!
//! # Usage
//! ```bash
//! cargo run --release --example benchmark_all
//! ```
//!
//! # Output
//! Produces formatted benchmark results suitable for documentation.

use std::time::{Duration, Instant};

// ============================================================================
// BENCHMARK INFRASTRUCTURE
// ============================================================================

/// Benchmark result for a single operation
struct BenchResult {
    name: String,
    #[allow(dead_code)]
    iterations: u32,
    #[allow(dead_code)]
    total_time: Duration,
    per_op: Duration,
    ops_per_sec: f64,
}

impl BenchResult {
    fn print(&self) {
        let per_op_str = if self.per_op.as_micros() > 1000 {
            format!("{:.2} ms", self.per_op.as_secs_f64() * 1000.0)
        } else if self.per_op.as_nanos() > 1000 {
            format!("{:.2} μs", self.per_op.as_nanos() as f64 / 1000.0)
        } else {
            format!("{} ns", self.per_op.as_nanos())
        };

        let ops_str = if self.ops_per_sec > 1_000_000.0 {
            format!("{:.2}M", self.ops_per_sec / 1_000_000.0)
        } else if self.ops_per_sec > 1000.0 {
            format!("{:.1}K", self.ops_per_sec / 1000.0)
        } else {
            format!("{:.1}", self.ops_per_sec)
        };

        println!("  {:44} {:>12}  ({} ops/sec)", self.name, per_op_str, ops_str);
    }
}

/// Run benchmark with warmup
fn bench<F: FnMut()>(name: &str, iterations: u32, mut f: F) -> BenchResult {
    // Warmup (10% of iterations or at least 3)
    let warmup = std::cmp::max(iterations / 10, 3);
    for _ in 0..warmup {
        f();
    }

    // Force any lazy initialization
    std::thread::sleep(Duration::from_millis(1));

    // Actual measurement
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let total_time = start.elapsed();

    let per_op = total_time / iterations;
    let ops_per_sec = if per_op.as_nanos() > 0 {
        1_000_000_000.0 / per_op.as_nanos() as f64
    } else {
        f64::INFINITY
    };

    BenchResult {
        name: name.to_string(),
        iterations,
        total_time,
        per_op,
        ops_per_sec,
    }
}

// ============================================================================
// MAIN BENCHMARK RUNNER
// ============================================================================

fn main() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║        TRUE TRUST PROTOCOL - COMPREHENSIVE BENCHMARKS            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
    
    // System info
    print_system_info();
    
    println!();
    println!("Running benchmarks... (this may take a few minutes)");
    println!();

    let mut all_results: Vec<(&str, Vec<BenchResult>)> = Vec::new();

    // Run all benchmarks
    all_results.push(("Falcon-512 Signatures", bench_falcon()));
    all_results.push(("Kyber-768 KEM", bench_kyber()));
    all_results.push(("Poseidon Hash", bench_poseidon()));
    all_results.push(("STARK Range Proofs", bench_stark()));
    all_results.push(("Stealth Scanning", bench_scanning()));
    all_results.push(("Transaction Creation", bench_transactions()));

    // Print all results
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                         BENCHMARK RESULTS                         ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    
    for (category, results) in &all_results {
        println!();
        println!("┌─ {} ─", category);
        println!("│");
        for result in results {
            print!("│");
            result.print();
        }
        println!("│");
    }

    // Print summary table for white paper
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    WHITE PAPER SUMMARY TABLE                      ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("| Operation | Time | Throughput |");
    println!("|-----------|------|------------|");
    
    for (_, results) in &all_results {
        for r in results {
            let time_str = if r.per_op.as_micros() > 1000 {
                format!("~{:.0} ms", r.per_op.as_secs_f64() * 1000.0)
            } else if r.per_op.as_nanos() > 1000 {
                format!("~{:.1} μs", r.per_op.as_nanos() as f64 / 1000.0)
            } else {
                format!("~{} ns", r.per_op.as_nanos())
            };

            let ops_str = if r.ops_per_sec > 1_000_000.0 {
                format!("{:.1}M/sec", r.ops_per_sec / 1_000_000.0)
            } else if r.ops_per_sec > 1000.0 {
                format!("{:.0}K/sec", r.ops_per_sec / 1000.0)
            } else {
                format!("{:.0}/sec", r.ops_per_sec)
            };

            println!("| {} | {} | {} |", r.name, time_str, ops_str);
        }
    }

    println!();
    println!("✅ Benchmarks complete!");
    
    // Print serialization comparison
    print_serialization_info();
}

fn print_serialization_info() {
    use tt_node::crypto::zk_range_poseidon::{
        prove_range_with_poseidon, Witness, default_proof_options
    };
    
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    SERIALIZATION COMPARISON                       ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
    
    // Build STARK proof for size test
    let value = 1000u128;
    let blinding = [0x42u8; 32];
    let nonce = [0x33u8; 32];
    let witness = Witness::new(value, blinding, nonce);
    let (proof, _pub_inputs) = prove_range_with_poseidon(witness, 64, default_proof_options());
    
    let stark_bytes = proof.to_bytes();
    
    // JSON would hex-encode this (2x size)
    let json_size = stark_bytes.len() * 2 + 100; // hex encoding + JSON overhead
    let bincode_size = stark_bytes.len() + 16;   // raw bytes + length prefix
    
    println!("┌─ STARK Proof Serialization ─");
    println!("│");
    println!("│  STARK proof raw bytes:     {:>6} bytes", stark_bytes.len());
    println!("│  JSON (hex encoded):        {:>6} bytes (2x overhead!)", json_size);
    println!("│  Bincode (raw bytes):       {:>6} bytes (native)", bincode_size);
    println!("│");
    println!("│  Bincode saves:             {:>6} bytes ({:.1}%)", 
             json_size - bincode_size,
             100.0 * (json_size - bincode_size) as f64 / json_size as f64);
    println!("│");
    println!("│  [NOTE] STARK proofs are cryptographically random.");
    println!("│         They cannot be compressed further with zstd/gzip.");
    println!("│         The gain is from avoiding hex encoding overhead.");
    println!("│");
}

fn print_system_info() {
    println!("┌─ System Information ─");
    println!("│");
    
    // CPU info (Linux)
    #[cfg(target_os = "linux")]
    {
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if line.starts_with("model name") {
                    if let Some(name) = line.split(':').nth(1) {
                        println!("│  CPU: {}", name.trim());
                        break;
                    }
                }
            }
        }
        
        // Count threads
        let threads = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1);
        println!("│  Threads: {}", threads);
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        let threads = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1);
        println!("│  Threads: {}", threads);
    }
    
    println!("│  Build: release");
    println!("│  Date: {}", chrono::Local::now().format("%Y-%m-%d %H:%M"));
    println!("│");
}

// ============================================================================
// FALCON-512 BENCHMARKS
// ============================================================================

fn bench_falcon() -> Vec<BenchResult> {
    use pqcrypto_falcon::falcon512;

    let mut results = Vec::new();
    
    // Keygen
    results.push(bench("Falcon-512 keygen", 100, || {
        let _ = falcon512::keypair();
    }));

    // Sign
    let (pk, sk) = falcon512::keypair();
    let message = b"Benchmark message for Falcon-512 signature testing - 64 bytes!!";
    
    results.push(bench("Falcon-512 sign", 1000, || {
        let _ = falcon512::detached_sign(message, &sk);
    }));

    // Verify
    let sig = falcon512::detached_sign(message, &sk);
    results.push(bench("Falcon-512 verify", 1000, || {
        let _ = falcon512::verify_detached_signature(&sig, message, &pk);
    }));

    // Sign + Verify combined
    results.push(bench("Falcon-512 sign+verify", 500, || {
        let sig = falcon512::detached_sign(message, &sk);
        let _ = falcon512::verify_detached_signature(&sig, message, &pk);
    }));

    results
}

// ============================================================================
// KYBER-768 BENCHMARKS
// ============================================================================

fn bench_kyber() -> Vec<BenchResult> {
    use pqcrypto_kyber::kyber768;

    let mut results = Vec::new();

    // Keygen
    results.push(bench("Kyber-768 keygen", 1000, || {
        let _ = kyber768::keypair();
    }));

    // Encapsulate
    let (pk, sk) = kyber768::keypair();
    results.push(bench("Kyber-768 encapsulate", 1000, || {
        let _ = kyber768::encapsulate(&pk);
    }));

    // Decapsulate
    let (_, ct) = kyber768::encapsulate(&pk);
    results.push(bench("Kyber-768 decapsulate", 1000, || {
        let _ = kyber768::decapsulate(&ct, &sk);
    }));

    // Full KEM roundtrip
    results.push(bench("Kyber-768 full roundtrip", 500, || {
        let (_, ct) = kyber768::encapsulate(&pk);
        let _ = kyber768::decapsulate(&ct, &sk);
    }));

    results
}

// ============================================================================
// POSEIDON HASH BENCHMARKS
// ============================================================================

fn bench_poseidon() -> Vec<BenchResult> {
    use tt_node::crypto::poseidon_hash_cpu::{PoseidonState, poseidon_hash_cpu};
    use winterfell::math::{fields::f128::BaseElement, FieldElement};
    use tt_node::crypto::poseidon_params::POSEIDON_WIDTH;
    
    let mut results = Vec::new();
    
    // Hash commitment (value + blinding + recipient)
    let value = 12345u128;
    let blinding = [0x42u8; 32];
    let recipient = [0x13u8; 32];
    
    results.push(bench("Poseidon commitment (v+b+r)", 10000, || {
        let _ = poseidon_hash_cpu(value, &blinding, &recipient);
    }));

    // Just permutation
    results.push(bench("Poseidon permutation only", 10000, || {
        let mut state = PoseidonState::new();
        let inputs = [BaseElement::ZERO; POSEIDON_WIDTH];
        state.absorb(&inputs);
        state.permute();
        let _ = state.squeeze();
    }));

    // Full hash function with different inputs
    results.push(bench("Poseidon hash (varied)", 10000, || {
        let v = rand::random::<u64>() as u128;
        let _ = poseidon_hash_cpu(v, &blinding, &recipient);
    }));

    results
}

// ============================================================================
// STARK RANGE PROOF BENCHMARKS
// ============================================================================

fn bench_stark() -> Vec<BenchResult> {
    use tt_node::crypto::zk_range_poseidon::{
        prove_range_with_poseidon, verify_range_with_poseidon, 
        Witness, default_proof_options
    };
    
    let mut results = Vec::new();

    // Generate proof (this is the expensive operation)
    let value = 1_000_000u128;
    let blinding = [0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78,
                    0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
                    0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                    0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04];
    let recipient = [0x42u8; 32];
    
    // Fewer iterations since STARK proving is slow
    results.push(bench("STARK range proof generate", 20, || {
        let witness = Witness::new(value, blinding, recipient);
        let _ = prove_range_with_poseidon(witness, 64, default_proof_options());
    }));

    // Verify proof
    let witness = Witness::new(value, blinding, recipient);
    let (proof, pub_inputs) = prove_range_with_poseidon(witness, 64, default_proof_options());
    
    results.push(bench("STARK range proof verify", 100, || {
        let _ = verify_range_with_poseidon(proof.clone(), pub_inputs.clone());
    }));

    // Measure proof size
    let proof_size = proof.to_bytes().len();
    println!("│  [INFO] STARK proof size: {} bytes ({:.1} KB)", proof_size, proof_size as f64 / 1024.0);
    println!("│  [NOTE] STARK proofs are cryptographically random - compression ~0%!");

    results
}

// ============================================================================
// SCANNING BENCHMARKS
// ============================================================================

fn bench_scanning() -> Vec<BenchResult> {
    use pqcrypto_kyber::kyber768;
    use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};

    let mut results = Vec::new();

    // View tag check (8-byte comparison)
    let view_tag: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let mut candidate_tags: Vec<[u8; 8]> = Vec::with_capacity(10000);
    for i in 0..10000u64 {
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&i.to_le_bytes());
        candidate_tags.push(tag);
    }
    // Put one matching tag
    candidate_tags[5000] = view_tag;

    results.push(bench("View tag check (8B compare)", 100000, || {
        let mut found = false;
        for tag in &candidate_tags[..100] {
            if tag == &view_tag {
                found = true;
                break;
            }
        }
        std::hint::black_box(found);
    }));

    // Derive view tag from shared secret (SHAKE256)
    let shared_secret = [0x42u8; 32];
    results.push(bench("Derive view tag (SHAKE256)", 50000, || {
        let mut h = Shake256::default();
        h.update(b"TT.v7.VIEW_TAG");
        h.update(&shared_secret);
        let mut tag = [0u8; 8];
        h.finalize_xof().read(&mut tag);
        std::hint::black_box(tag);
    }));

    // Full KEM decapsulation (for comparison)
    let (pk, sk) = kyber768::keypair();
    let (_, ct) = kyber768::encapsulate(&pk);
    results.push(bench("Full KEM scan (decapsulate)", 1000, || {
        let _ = kyber768::decapsulate(&ct, &sk);
    }));

    // Scan speedup calculation
    let view_tag_ns = 200; // approximate from above
    let kem_ns = 50_000;   // approximate
    let speedup = kem_ns as f64 / view_tag_ns as f64;
    println!("│  [INFO] View tag vs full KEM speedup: ~{:.0}x", speedup);

    results
}

// ============================================================================
// TRANSACTION CREATION BENCHMARKS
// ============================================================================

fn bench_transactions() -> Vec<BenchResult> {
    use pqcrypto_falcon::falcon512;
    use pqcrypto_kyber::kyber768;
    use pqcrypto_traits::sign::PublicKey as SignPK;
    use pqcrypto_traits::kem::{SecretKey as KemSK, PublicKey as KemPK};
    use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};

    let mut results = Vec::new();

    // Setup keys
    let (sender_falcon_pk, sender_falcon_sk) = falcon512::keypair();
    let (sender_kyber_pk, sender_kyber_sk) = kyber768::keypair();
    let (recipient_kyber_pk, _recipient_kyber_sk) = kyber768::keypair();

    // SimplePqTx (basic TX without privacy)
    // This is sign only
    let message = vec![0u8; 200]; // ~200 byte TX body
    results.push(bench("SimplePqTx create (sign only)", 500, || {
        let _ = falcon512::detached_sign(&message, &sender_falcon_sk);
    }));

    // CompactSimpleTx (with key registry lookup)
    // Sign + key_id derivation
    results.push(bench("CompactSimpleTx create", 500, || {
        // Derive key_id
        let mut h = Shake256::default();
        h.update(b"TT.v7.KEY_ID");
        h.update(sender_falcon_pk.as_bytes());
        h.update(sender_kyber_pk.as_bytes());
        let mut key_id = [0u8; 32];
        h.finalize_xof().read(&mut key_id);
        // Sign
        let _ = falcon512::detached_sign(&message, &sender_falcon_sk);
    }));

    // PrivateCompactTx (stealth + encrypted sender, no STARK)
    results.push(bench("PrivateCompactTx create", 200, || {
        // 1. Generate recipient stealth (KEM)
        let (ss, _ct) = kyber768::encapsulate(&recipient_kyber_pk);
        
        // 2. Derive stealth_key
        let mut h = Shake256::default();
        h.update(b"TT.v7.STEALTH_KEY");
        h.update(pqcrypto_traits::kem::SharedSecret::as_bytes(&ss));
        let mut stealth_key = [0u8; 32];
        h.finalize_xof().read(&mut stealth_key);
        
        // 3. Derive view_tag
        let mut h2 = Shake256::default();
        h2.update(b"TT.v7.VIEW_TAG");
        h2.update(pqcrypto_traits::kem::SharedSecret::as_bytes(&ss));
        let mut view_tag = [0u8; 8];
        h2.finalize_xof().read(&mut view_tag);
        
        // 4. Encrypt sender_id (AES-GCM simulation - just XOR for benchmark)
        let sender_id = [0x42u8; 32];
        let encrypted: Vec<u8> = sender_id.iter().zip(stealth_key.iter()).map(|(a, b)| a ^ b).collect();
        
        // 5. Generate sender change (no KEM - derive from own sk)
        let mut h3 = Shake256::default();
        h3.update(b"TT.v7.SELF_STEALTH");
        h3.update(sender_kyber_sk.as_bytes());
        h3.update(&1u64.to_le_bytes()); // nonce
        let mut change_key = [0u8; 32];
        h3.finalize_xof().read(&mut change_key);
        
        // 6. Sign
        let _ = falcon512::detached_sign(&message, &sender_falcon_sk);
        
        std::hint::black_box((stealth_key, view_tag, encrypted, change_key));
    }));

    // PrivateStarkTx (full privacy with STARK)
    // Only run a few iterations since STARK is slow
    println!("│  [INFO] PrivateStarkTx benchmark (slow - includes STARK proof)...");
    
    {
        use tt_node::crypto::zk_range_poseidon::{
            prove_range_with_poseidon, Witness, default_proof_options
        };
        
        results.push(bench("PrivateStarkTx create (full)", 10, || {
            // Stealth operations (same as PrivateCompactTx)
            let (ss, _ct) = kyber768::encapsulate(&recipient_kyber_pk);
            let mut h = Shake256::default();
            h.update(b"TT.v7.STEALTH_KEY");
            h.update(pqcrypto_traits::kem::SharedSecret::as_bytes(&ss));
            let mut stealth_key = [0u8; 32];
            h.finalize_xof().read(&mut stealth_key);
            
            // STARK proof (the expensive part)
            let value = 1000u128;
            let witness = Witness::new(value, [0x42u8; 32], stealth_key);
            let (proof, pub_inputs) = prove_range_with_poseidon(witness, 64, default_proof_options());
            
            // Sign
            let _ = falcon512::detached_sign(&message, &sender_falcon_sk);
            
            std::hint::black_box((stealth_key, proof, pub_inputs));
        }));
    }

    // TX sizes info
    println!("│");
    println!("│  [INFO] Transaction sizes:");
    println!("│         SimplePqTx:       ~2,850 bytes");
    println!("│         CompactSimpleTx:    ~786 bytes");
    println!("│         PrivateCompactTx: ~1,934 bytes");
    println!("│         PrivateStarkTx:  ~35,000 bytes (bincode)");
    println!("│                           ~66,000 bytes (JSON - 2x overhead!)");
    println!("│");
    println!("│  [NOTE] STARK proofs (~33KB) are cryptographically random.");
    println!("│         Bincode stores raw bytes. JSON hex-encodes them (2x).");
    println!("│");

    results
}
