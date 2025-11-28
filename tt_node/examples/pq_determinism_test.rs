//! PQ Keygen & Sign Determinism Test
//! Verifies that:
//! 1. Same master32 always produces identical Falcon-512 + Kyber-768 keys
//! 2. Falcon signatures are valid and verifiable
//! 3. Kyber encapsulation/decapsulation works correctly

use tt_node::crypto::seeded::falcon_keypair_deterministic;
use tt_node::crypto::seeded_kyber::{kyber_keypair_deterministic, to_pqcrypto_kyber_keys};
use pqcrypto_falcon::falcon512;
use pqcrypto_kyber::kyber768 as mlkem;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage, DetachedSignature};
use pqcrypto_traits::kem::{PublicKey as KemPK, SecretKey as KemSK, SharedSecret, Ciphertext};
use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};

fn main() {
    println!("=== TEST 6: PQ Keygen Determinism ===\n");
    
    // Fixed master seed for reproducibility
    let master32: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    
    println!("Master seed: {}", hex::encode(&master32));
    
    // === FALCON-512 DETERMINISM ===
    println!("\n--- Falcon-512 Keygen (3 iterations) ---");
    let (falcon_pk1, falcon_sk1) = falcon_keypair_deterministic(master32, b"TEST.FALCON").unwrap();
    let (falcon_pk2, falcon_sk2) = falcon_keypair_deterministic(master32, b"TEST.FALCON").unwrap();
    let (falcon_pk3, falcon_sk3) = falcon_keypair_deterministic(master32, b"TEST.FALCON").unwrap();
    
    assert_eq!(falcon_pk1, falcon_pk2, "Falcon PK mismatch iter 1-2");
    assert_eq!(falcon_pk2, falcon_pk3, "Falcon PK mismatch iter 2-3");
    assert_eq!(falcon_sk1, falcon_sk2, "Falcon SK mismatch iter 1-2");
    assert_eq!(falcon_sk2, falcon_sk3, "Falcon SK mismatch iter 2-3");
    
    println!("  Falcon PK (first 32B): {}", hex::encode(&falcon_pk1[..32]));
    println!("  ✅ 3 iterations produce identical keys");
    
    // === KYBER-768 DETERMINISM ===
    println!("\n--- Kyber-768 Keygen (3 iterations) ---");
    let (kyber_pk1, kyber_sk1) = kyber_keypair_deterministic(master32, b"TEST.KYBER").unwrap();
    let (kyber_pk2, kyber_sk2) = kyber_keypair_deterministic(master32, b"TEST.KYBER").unwrap();
    let (kyber_pk3, kyber_sk3) = kyber_keypair_deterministic(master32, b"TEST.KYBER").unwrap();
    
    assert_eq!(kyber_pk1, kyber_pk2, "Kyber PK mismatch iter 1-2");
    assert_eq!(kyber_pk2, kyber_pk3, "Kyber PK mismatch iter 2-3");
    assert_eq!(kyber_sk1, kyber_sk2, "Kyber SK mismatch iter 1-2");
    assert_eq!(kyber_sk2, kyber_sk3, "Kyber SK mismatch iter 2-3");
    
    println!("  Kyber PK (first 32B): {}", hex::encode(&kyber_pk1[..32]));
    println!("  ✅ 3 iterations produce identical keys");
    
    // === FALCON SIGN & VERIFY ===
    println!("\n--- Falcon-512 Sign & Verify ---");
    let falcon_pk = falcon512::PublicKey::from_bytes(&falcon_pk1).unwrap();
    let falcon_sk = falcon512::SecretKey::from_bytes(&falcon_sk1).unwrap();
    
    let message = b"True-Trust-Protocol: PQ signature test message 2025";
    let signed_msg = falcon512::sign(message, &falcon_sk);
    
    // Verify signature
    match falcon512::open(&signed_msg, &falcon_pk) {
        Ok(recovered) => {
            assert_eq!(&recovered[..], message, "Message mismatch after verify");
            println!("  Message: \"{}\"", String::from_utf8_lossy(message));
            println!("  Signature size: {} bytes", signed_msg.as_bytes().len() - message.len());
            println!("  ✅ Signature valid, message recovered");
        }
        Err(_) => panic!("Falcon signature verification failed!"),
    }
    
    // Detached signature
    let detached_sig = falcon512::detached_sign(message, &falcon_sk);
    match falcon512::verify_detached_signature(&detached_sig, message, &falcon_pk) {
        Ok(()) => println!("  ✅ Detached signature verified"),
        Err(_) => panic!("Detached signature verification failed!"),
    }
    
    // === KYBER ENCAP/DECAP ===
    println!("\n--- Kyber-768 Encapsulate & Decapsulate ---");
    let (kyber_pk, kyber_sk) = to_pqcrypto_kyber_keys(&kyber_pk1, &kyber_sk1).unwrap();
    
    let (shared_secret_enc, ciphertext) = mlkem::encapsulate(&kyber_pk);
    let shared_secret_dec = mlkem::decapsulate(&ciphertext, &kyber_sk);
    
    assert_eq!(
        shared_secret_enc.as_bytes(), 
        shared_secret_dec.as_bytes(),
        "Kyber shared secret mismatch!"
    );
    
    println!("  Ciphertext size: {} bytes", ciphertext.as_bytes().len());
    println!("  Shared secret (first 16B): {}", hex::encode(&shared_secret_enc.as_bytes()[..16]));
    println!("  ✅ Encapsulated secret matches decapsulated");
    
    // === ADDRESS DETERMINISM ===
    println!("\n--- Address Derivation (SHAKE256) ---");
    let mut h = Shake256::default();
    h.update(&falcon_pk1);
    h.update(&kyber_pk1);
    let mut addr = [0u8; 32];
    h.finalize_xof().read(&mut addr);
    
    // Repeat to verify determinism
    let mut h2 = Shake256::default();
    h2.update(&falcon_pk1);
    h2.update(&kyber_pk1);
    let mut addr2 = [0u8; 32];
    h2.finalize_xof().read(&mut addr2);
    
    assert_eq!(addr, addr2, "Address derivation not deterministic!");
    println!("  Address (raw): {}", hex::encode(&addr));
    println!("  ✅ Address derivation deterministic");
    
    // === SUMMARY ===
    println!("\n========================================");
    println!(" PQ KEYGEN & SIGN TEST - SUMMARY");
    println!("========================================");
    println!("┌────────────────────────────────────────┐");
    println!("│ Falcon-512 keygen determinism  │ ✅    │");
    println!("│ Falcon-512 sign & verify       │ ✅    │");
    println!("│ Falcon-512 detached signature  │ ✅    │");
    println!("│ Kyber-768 keygen determinism   │ ✅    │");
    println!("│ Kyber-768 encap/decap          │ ✅    │");
    println!("│ Address derivation (SHAKE256)  │ ✅    │");
    println!("└────────────────────────────────────────┘");
    println!("\nALL PQ CRYPTO TESTS PASSED ✅");
}
