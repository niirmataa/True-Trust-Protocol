//! Profesjonalne benchmarki kryptograficzne dla True Trust Protocol
//!
//! Uruchom: `cargo run --example benchmarks --release`
//!
//! Porównanie z White Paper v1.0 targets.

use std::time::{Duration, Instant};

use pqcrypto_falcon::falcon512;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::sign::{PublicKey as SignPK, SecretKey as SignSK, DetachedSignature};
use pqcrypto_traits::kem::{PublicKey as KemPK, SecretKey as KemSK, Ciphertext};

/// Struktura wyników benchmarku
struct BenchResult {
    name: String,
    iterations: u32,
    avg: Duration,
    min: Duration,
    max: Duration,
    throughput: f64,
}

impl BenchResult {
    fn print(&self) {
        println!(
            "│ {:<40} │ {:>10} │ {:>12} │ {:>10.0} │",
            self.name,
            format_duration(self.avg),
            format_duration(self.min),
            self.throughput
        );
    }
}

fn format_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{} ns", nanos)
    } else if nanos < 1_000_000 {
        format!("{:.2} μs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.2} ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.3} s", d.as_secs_f64())
    }
}

fn bench<F>(name: &str, iterations: u32, warmup: u32, mut f: F) -> BenchResult
where
    F: FnMut(),
{
    // Warmup
    for _ in 0..warmup {
        f();
    }

    let mut times = Vec::with_capacity(iterations as usize);
    let start_total = Instant::now();

    for _ in 0..iterations {
        let start = Instant::now();
        f();
        times.push(start.elapsed());
    }

    let total = start_total.elapsed();
    let avg = total / iterations;
    let min = *times.iter().min().unwrap();
    let max = *times.iter().max().unwrap();
    let throughput = iterations as f64 / total.as_secs_f64();

    BenchResult {
        name: name.to_string(),
        iterations,
        avg,
        min,
        max,
        throughput,
    }
}

fn main() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║            TRUE TRUST PROTOCOL - CRYPTOGRAPHIC BENCHMARKS                            ║");
    println!("║                         Post-Quantum Security Suite                                  ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Operation                                  │    Average │      Min   │  Throughput  ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════════════╣");

    // ========================================================================
    // FALCON-512 BENCHMARKS
    // ========================================================================
    
    println!("║                                                                                      ║");
    println!("║ ▶ FALCON-512 (NIST PQC Digital Signatures)                                           ║");
    println!("║                                                                                      ║");

    // Keygen
    let keygen = bench("Falcon-512 Key Generation", 50, 5, || {
        let _ = falcon512::keypair();
    });
    keygen.print();

    // Sign
    let (pk, sk) = falcon512::keypair();
    let message = b"True Trust Protocol benchmark message for signing";
    
    let sign = bench("Falcon-512 Signing", 500, 50, || {
        let _ = falcon512::detached_sign(message, &sk);
    });
    sign.print();

    // Verify
    let sig = falcon512::detached_sign(message, &sk);
    
    let verify = bench("Falcon-512 Verification", 1000, 100, || {
        let _ = falcon512::verify_detached_signature(&sig, message, &pk);
    });
    verify.print();

    // Key sizes
    println!("║                                                                                      ║");
    println!("║   Key Sizes: PK={} bytes, SK={} bytes, Sig≈{} bytes                          ║", 
        pk.as_bytes().len(), sk.as_bytes().len(), sig.as_bytes().len());

    // ========================================================================
    // KYBER-768 BENCHMARKS
    // ========================================================================
    
    println!("║                                                                                      ║");
    println!("║ ▶ KYBER-768 / ML-KEM (NIST PQC Key Encapsulation)                                    ║");
    println!("║                                                                                      ║");

    // Keygen
    let kyber_keygen = bench("Kyber-768 Key Generation", 500, 50, || {
        let _ = kyber768::keypair();
    });
    kyber_keygen.print();

    // Encapsulate
    let (kyber_pk, kyber_sk) = kyber768::keypair();
    
    let encaps = bench("Kyber-768 Encapsulation", 1000, 100, || {
        let _ = kyber768::encapsulate(&kyber_pk);
    });
    encaps.print();

    // Decapsulate
    let (ss, ct) = kyber768::encapsulate(&kyber_pk);
    
    let decaps = bench("Kyber-768 Decapsulation", 1000, 100, || {
        let _ = kyber768::decapsulate(&ct, &kyber_sk);
    });
    decaps.print();

    // Key sizes
    println!("║                                                                                      ║");
    println!("║   Key Sizes: PK={} bytes, SK={} bytes, CT={} bytes                        ║", 
        kyber_pk.as_bytes().len(), kyber_sk.as_bytes().len(), ct.as_bytes().len());

    // ========================================================================
    // COMBINED OPERATIONS
    // ========================================================================
    
    println!("║                                                                                      ║");
    println!("║ ▶ COMBINED OPERATIONS (Typical TX workflow)                                          ║");
    println!("║                                                                                      ║");

    // Sign + Verify
    let sign_verify = bench("Falcon Sign + Verify", 200, 20, || {
        let sig = falcon512::detached_sign(message, &sk);
        let _ = falcon512::verify_detached_signature(&sig, message, &pk);
    });
    sign_verify.print();

    // Full KEM roundtrip
    let kem_roundtrip = bench("Kyber Encaps + Decaps", 500, 50, || {
        let (_, ct) = kyber768::encapsulate(&kyber_pk);
        let _ = kyber768::decapsulate(&ct, &kyber_sk);
    });
    kem_roundtrip.print();

    // Full TX simulation (sign + KEM)
    let full_tx = bench("Full TX (Sign + KEM)", 200, 20, || {
        let sig = falcon512::detached_sign(message, &sk);
        let (_, ct) = kyber768::encapsulate(&kyber_pk);
        let _ = kyber768::decapsulate(&ct, &kyber_sk);
        let _ = falcon512::verify_detached_signature(&sig, message, &pk);
    });
    full_tx.print();

    // ========================================================================
    // SYMMETRIC CRYPTO (SHA3/SHAKE)
    // ========================================================================
    
    println!("║                                                                                      ║");
    println!("║ ▶ SYMMETRIC CRYPTO (SHA3/SHAKE256)                                                   ║");
    println!("║                                                                                      ║");

    use sha3::{Shake256, Sha3_256, Digest, digest::{ExtendableOutput, Update, XofReader}};
    
    let data = [0x42u8; 64];
    
    let sha3_bench = bench("SHA3-256 Hash (64B)", 10000, 1000, || {
        let mut h = Sha3_256::new();
        Digest::update(&mut h, &data);
        let _ = h.finalize();
    });
    sha3_bench.print();

    let shake_bench = bench("SHAKE256 XOF (64B → 32B)", 10000, 1000, || {
        let mut hasher = Shake256::default();
        hasher.update(&data);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
    });
    shake_bench.print();

    // ========================================================================
    // SUMMARY & COMPARISON WITH WHITE PAPER
    // ========================================================================
    
    println!("║                                                                                      ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════════════╣");
    println!("║                         COMPARISON WITH WHITE PAPER v1.0                             ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                                      ║");
    println!("║  Operation              │ White Paper Target │ Measured        │ Status             ║");
    println!("║  ───────────────────────┼────────────────────┼─────────────────┼──────────────────  ║");
    
    // Compare with WP targets
    let wp_falcon_sign = Duration::from_micros(230);
    let wp_falcon_verify = Duration::from_micros(40);
    let wp_kyber_encaps = Duration::from_micros(40);
    let wp_kyber_decaps = Duration::from_micros(41);

    fn status(measured: Duration, target: Duration) -> &'static str {
        let ratio = measured.as_nanos() as f64 / target.as_nanos() as f64;
        if ratio <= 1.0 { "✅ BETTER" }
        else if ratio <= 1.5 { "✅ OK" }
        else if ratio <= 2.0 { "⚠️  SLOWER" }
        else { "❌ MUCH SLOWER" }
    }

    println!("║  Falcon-512 Sign        │ ~230 μs            │ {:>15} │ {:>18} ║", 
        format_duration(sign.avg), status(sign.avg, wp_falcon_sign));
    println!("║  Falcon-512 Verify      │ ~40 μs             │ {:>15} │ {:>18} ║", 
        format_duration(verify.avg), status(verify.avg, wp_falcon_verify));
    println!("║  Kyber-768 Encaps       │ ~40 μs             │ {:>15} │ {:>18} ║", 
        format_duration(encaps.avg), status(encaps.avg, wp_kyber_encaps));
    println!("║  Kyber-768 Decaps       │ ~41 μs             │ {:>15} │ {:>18} ║", 
        format_duration(decaps.avg), status(decaps.avg, wp_kyber_decaps));

    println!("║                                                                                      ║");
    println!("║  Note: White Paper targets measured on AMD Ryzen 3 5300U (8 threads)                 ║");
    println!("║  STARK proof benchmarks require separate setup (see private_stark_tx.rs)             ║");
    println!("║                                                                                      ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════════╝");
    println!();

    // ========================================================================
    // TX SIZE ANALYSIS
    // ========================================================================
    
    println!("╔══════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                         TRANSACTION SIZE ANALYSIS                                    ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                                      ║");
    println!("║  Transaction Type       │ Size (bytes) │ Privacy Level     │ Use Case              ║");
    println!("║  ──────────────────────┼──────────────┼───────────────────┼─────────────────────  ║");
    println!("║  SimplePqTx             │     ~2,850   │ None              │ Testing               ║");
    println!("║  CompactSimpleTx        │       ~786   │ None              │ High throughput       ║");
    println!("║  PrivateCompactTx       │     ~1,934   │ Sender+Recipient  │ Privacy (no ZK)       ║");
    println!("║  PrivateStarkTx         │    ~35,000   │ Full (+ amounts)  │ Maximum privacy       ║");
    println!("║                                                                                      ║");
    println!("║  Key Components:                                                                     ║");
    println!("║  ├── Falcon-512 PK:       897 bytes                                                  ║");
    println!("║  ├── Falcon-512 Sig:     ~666 bytes                                                  ║");
    println!("║  ├── Kyber-768 PK:      1,184 bytes                                                  ║");
    println!("║  ├── Kyber-768 CT:      1,088 bytes                                                  ║");
    println!("║  ├── STARK Proof:      ~32,000 bytes                                                 ║");
    println!("║  └── Stealth Output:    1,128 bytes (recipient) / 48 bytes (sender change)          ║");
    println!("║                                                                                      ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════════╝");
    println!();
}
