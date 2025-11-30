//! Falcon-512 Signature Operations
//! 
//! This module provides secure Falcon-512 signature operations for
//! nullifier authorization in the hybrid PQC system.
//!
//! # Security Model
//! 
//! - **Attached signatures**: Sign message, verify by opening
//! - **Nullifier binding**: Sign 32-byte nullifier
//! - **Public key fingerprints**: KMAC-derived for commitment binding
//!
//! # Example
//! 
//! ```no_run
//! use tt_node::falcon_sigs::*;
//! 
//! // Generate keypair
//! let (pk, sk) = falcon_keypair();
//! 
//! // Sign nullifier
//! let nullifier = [0x42u8; 32];
//! let sig = falcon_sign_nullifier(&nullifier, &sk).unwrap();
//! 
//! // Verify
//! falcon_verify_nullifier(&nullifier, &sig, &pk).unwrap();
//! ```

#![forbid(unsafe_code)]

use anyhow::{anyhow, ensure, Context, Result};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey as PQPublicKey, SecretKey as PQSecretKey, SignedMessage};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub type Hash32 = [u8; 32];

/* ============================================================================
 * Core Types
 * ========================================================================== */

/// Falcon-512 public key (897 bytes)
pub type FalconPublicKey = falcon512::PublicKey;

/// Falcon-512 secret key (1281 bytes, zeroized on drop)
pub type FalconSecretKey = falcon512::SecretKey;

/// Signed nullifier (attached signature format)
/// 
/// This wraps a Falcon SignedMessage which contains:
/// - Original message (32 bytes)
/// - Signature (~666 bytes)
/// 
/// Total size: ~698 bytes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedNullifier {
    /// Attached signature (message + sig)
    pub signed_message_bytes: Vec<u8>,
}

impl Zeroize for SignedNullifier {
    fn zeroize(&mut self) {
        self.signed_message_bytes.zeroize();
    }
}

impl Drop for SignedNullifier {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SignedNullifier {
    /// Get the signed message as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.signed_message_bytes
    }
}

/* ============================================================================
 * Key Generation
 * ========================================================================== */

/// Generate new Falcon-512 keypair
/// 
/// # Returns
/// (public_key, secret_key)
/// 
/// # Security
/// Uses OS random number generator (via pqcrypto-falcon)
#[inline]
pub fn falcon_keypair() -> (FalconPublicKey, FalconSecretKey) {
    falcon512::keypair()
}

/// Import public key from bytes
pub fn falcon_pk_from_bytes(bytes: &[u8]) -> Result<FalconPublicKey> {
    FalconPublicKey::from_bytes(bytes)
        .map_err(|_| anyhow!("Invalid Falcon public key bytes"))
}

/// Import secret key from bytes
pub fn falcon_sk_from_bytes(bytes: &[u8]) -> Result<FalconSecretKey> {
    FalconSecretKey::from_bytes(bytes)
        .map_err(|_| anyhow!("Invalid Falcon secret key bytes"))
}

/// Export public key to bytes (897 bytes)
#[inline]
pub fn falcon_pk_to_bytes(pk: &FalconPublicKey) -> &[u8] {
    pk.as_bytes()
}

/// Export secret key to bytes (1281 bytes) - SENSITIVE!
#[inline]
pub fn falcon_sk_to_bytes(sk: &FalconSecretKey) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(sk.as_bytes().to_vec())
}

/* ============================================================================
 * Signing
 * ========================================================================== */

/// Sign a 32-byte nullifier with Falcon-512
/// 
/// # Arguments
/// - `nullifier`: 32-byte nullifier to sign
/// - `secret_key`: Falcon secret key
/// 
/// # Returns
/// `SignedNullifier` containing attached signature
/// 
/// # Performance
/// ~10 million cycles on modern CPU (~10ms)
pub fn falcon_sign_nullifier(
    nullifier: &Hash32,
    secret_key: &FalconSecretKey,
) -> Result<SignedNullifier> {
    // Sign with attached signature
    let signed_msg = falcon512::sign(nullifier, secret_key);
    
    Ok(SignedNullifier {
        signed_message_bytes: signed_msg.as_bytes().to_vec(),
    })
}

/// Sign arbitrary message (general purpose)
pub fn falcon_sign(
    message: &[u8],
    secret_key: &FalconSecretKey,
) -> Result<SignedNullifier> {
    let signed_msg = falcon512::sign(message, secret_key);
    
    Ok(SignedNullifier {
        signed_message_bytes: signed_msg.as_bytes().to_vec(),
    })
}

/* ============================================================================
 * Verification
 * ========================================================================== */

/// Verify Falcon-512 signature on nullifier
/// 
/// # Arguments
/// - `nullifier`: Expected 32-byte nullifier
/// - `signature`: Signed nullifier
/// - `public_key`: Falcon public key
/// 
/// # Returns
/// `Ok(())` if signature is valid, `Err` otherwise
/// 
/// # Security
/// - Uses constant-time operations (via pqcrypto-falcon)
/// - Checks that recovered message matches expected nullifier
/// 
/// # Performance
/// ~200 microseconds on modern CPU
pub fn falcon_verify_nullifier(
    nullifier: &Hash32,
    signature: &SignedNullifier,
    public_key: &FalconPublicKey,
) -> Result<()> {
    // Parse signed message
    let signed_msg = falcon512::SignedMessage::from_bytes(&signature.signed_message_bytes)
        .map_err(|_| anyhow!("Invalid Falcon SignedMessage format"))?;
    
    // Open (verify + extract message)
    let recovered_msg = falcon512::open(&signed_msg, public_key)
        .map_err(|_| anyhow!("Falcon signature verification failed"))?;
    
    // Check message matches expected nullifier
    ensure!(
        recovered_msg.len() == 32,
        "Recovered message length mismatch: expected 32, got {}",
        recovered_msg.len()
    );
    
    ensure!(
        recovered_msg.as_slice() == nullifier,
        "Nullifier mismatch: signature is for different message"
    );
    
    Ok(())
}

/// Verify arbitrary message signature (general purpose)
pub fn falcon_verify(
    expected_message: &[u8],
    signature: &SignedNullifier,
    public_key: &FalconPublicKey,
) -> Result<()> {
    let signed_msg = falcon512::SignedMessage::from_bytes(&signature.signed_message_bytes)
        .map_err(|_| anyhow!("Invalid Falcon SignedMessage format"))?;
    
    let recovered_msg = falcon512::open(&signed_msg, public_key)
        .map_err(|_| anyhow!("Falcon signature verification failed"))?;
    
    ensure!(
        recovered_msg.as_slice() == expected_message,
        "Message mismatch"
    );
    
    Ok(())
}

/// Verify signature from raw bytes (for CompactSimpleTx, BatchTransfer)
/// 
/// # Arguments
/// - `expected_message`: Message that was signed
/// - `signature_bytes`: Raw signature bytes (attached format)
/// - `public_key`: Falcon public key
/// 
/// # Performance
/// Zero-copy verification - parses signature in place without allocation.
pub fn falcon_verify_bytes(
    expected_message: &[u8],
    signature_bytes: &[u8],
    public_key: &FalconPublicKey,
) -> Result<()> {
    // Parse directly without allocation
    let signed_msg = falcon512::SignedMessage::from_bytes(signature_bytes)
        .map_err(|_| anyhow!("Invalid Falcon SignedMessage format"))?;
    
    let recovered_msg = falcon512::open(&signed_msg, public_key)
        .map_err(|_| anyhow!("Falcon signature verification failed"))?;
    
    ensure!(
        recovered_msg.as_slice() == expected_message,
        "Message mismatch"
    );
    
    Ok(())
}

/// Verify and extract message (without prior knowledge)
/// 
/// Useful for cases where you want to see what was signed
pub fn falcon_open(
    signature: &SignedNullifier,
    public_key: &FalconPublicKey,
) -> Result<Vec<u8>> {
    let signed_msg = falcon512::SignedMessage::from_bytes(&signature.signed_message_bytes)
        .map_err(|_| anyhow!("Invalid Falcon SignedMessage format"))?;
    
    let recovered_msg = falcon512::open(&signed_msg, public_key)
        .map_err(|_| anyhow!("Falcon signature verification failed"))?;
    
    Ok(recovered_msg)
}

/* ============================================================================
 * Batch Verification
 * ========================================================================== */

/// Batch verify multiple nullifier signatures
/// 
/// More efficient than calling `falcon_verify_nullifier` in a loop
/// because it can fail fast and provides better error context.
/// 
/// # Returns
/// `Ok(())` if ALL signatures are valid, `Err` on first failure
pub fn falcon_verify_batch(
    items: &[(Hash32, SignedNullifier, FalconPublicKey)],
) -> Result<()> {
    for (i, (nullifier, sig, pk)) in items.iter().enumerate() {
        falcon_verify_nullifier(nullifier, sig, pk)
            .with_context(|| format!("Signature {} failed verification", i))?;
    }
    Ok(())
}

/* ============================================================================
 * Serialization Helpers
 * ========================================================================== */

/// Serialize signature to bytes (for storage/transmission)
pub fn serialize_signature(sig: &SignedNullifier) -> Result<Vec<u8>> {
    bincode::serialize(sig).context("Failed to serialize signature")
}

/// Deserialize signature from bytes
pub fn deserialize_signature(bytes: &[u8]) -> Result<SignedNullifier> {
    bincode::deserialize(bytes).context("Failed to deserialize signature")
}

/// Serialize signature to hex string
pub fn signature_to_hex(sig: &SignedNullifier) -> String {
    hex::encode(&sig.signed_message_bytes)
}

/// Deserialize signature from hex string
pub fn signature_from_hex(hex_str: &str) -> Result<SignedNullifier> {
    let bytes = hex::decode(hex_str)
        .context("Invalid hex string")?;
    Ok(SignedNullifier {
        signed_message_bytes: bytes,
    })
}

/* ============================================================================
 * PQC Fingerprint Integration
 * ========================================================================== */

/// Compute PQC fingerprint from Falcon + ML-KEM public keys
/// 
/// This is the same function as in `hybrid_commit::pqc_fingerprint`,
/// provided here for convenience.
pub fn compute_pqc_fingerprint(
    falcon_pk: &FalconPublicKey,
    mlkem_pk: &[u8],
) -> Hash32 {
    crate::hybrid_commit::pqc_fingerprint(falcon_pk.as_bytes(), mlkem_pk)
}

/* ============================================================================
 * Utilities
 * ========================================================================== */

/// Check if public key is valid (can be parsed)
pub fn is_valid_falcon_pk(bytes: &[u8]) -> bool {
    FalconPublicKey::from_bytes(bytes).is_ok()
}

/// Get signature size estimate
#[inline]
pub const fn falcon_signature_size_estimate() -> usize {
    // SignedMessage = message + signature
    // Signature varies (~650-680 bytes), message is 32 bytes
    // Total: ~698 bytes average
    698
}

/// Get public key size
#[inline]
pub const fn falcon_pk_size() -> usize {
    897
}

/// Get secret key size
#[inline]
pub const fn falcon_sk_size() -> usize {
    1281
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (pk, sk) = falcon_keypair();
        assert_eq!(pk.as_bytes().len(), falcon_pk_size());
        assert_eq!(sk.as_bytes().len(), falcon_sk_size());
    }

    #[test]
    fn test_sign_verify_nullifier() {
        let (pk, sk) = falcon_keypair();
        let nullifier = [0x42u8; 32];
        
        // Sign
        let sig = falcon_sign_nullifier(&nullifier, &sk)
            .expect("Sign should succeed");
        
        // Verify
        let result = falcon_verify_nullifier(&nullifier, &sig, &pk);
        assert!(result.is_ok(), "Verification should succeed");
    }

    #[test]
    fn test_wrong_nullifier_fails() {
        let (pk, sk) = falcon_keypair();
        let nullifier = [0x42u8; 32];
        let wrong_nullifier = [0x99u8; 32];
        
        let sig = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        
        // Verify with wrong nullifier should fail
        let result = falcon_verify_nullifier(&wrong_nullifier, &sig, &pk);
        assert!(result.is_err(), "Wrong nullifier should fail");
    }

    #[test]
    fn test_wrong_public_key_fails() {
        let (_pk1, sk1) = falcon_keypair();
        let (pk2, _sk2) = falcon_keypair();
        
        let nullifier = [0x42u8; 32];
        let sig = falcon_sign_nullifier(&nullifier, &sk1).unwrap();
        
        // Verify with wrong public key should fail
        let result = falcon_verify_nullifier(&nullifier, &sig, &pk2);
        assert!(result.is_err(), "Wrong public key should fail");
    }

    #[test]
    fn test_batch_verification() {
        let (pk1, sk1) = falcon_keypair();
        let (pk2, sk2) = falcon_keypair();
        
        let nf1 = [0x11u8; 32];
        let nf2 = [0x22u8; 32];
        
        let sig1 = falcon_sign_nullifier(&nf1, &sk1).unwrap();
        let sig2 = falcon_sign_nullifier(&nf2, &sk2).unwrap();
        
        let batch = vec![
            (nf1, sig1, pk1),
            (nf2, sig2, pk2),
        ];
        
        let result = falcon_verify_batch(&batch);
        assert!(result.is_ok(), "Batch verification should succeed");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let (pk, sk) = falcon_keypair();
        let nullifier = [0x42u8; 32];
        
        let sig = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        
        // Serialize
        let bytes = serialize_signature(&sig).unwrap();
        
        // Deserialize
        let sig2 = deserialize_signature(&bytes).unwrap();
        
        // Verify deserialized signature
        let result = falcon_verify_nullifier(&nullifier, &sig2, &pk);
        assert!(result.is_ok(), "Deserialized signature should verify");
    }

    #[test]
    fn test_hex_roundtrip() {
        let (pk, sk) = falcon_keypair();
        let nullifier = [0x42u8; 32];
        
        let sig = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        
        // To hex
        let hex_str = signature_to_hex(&sig);
        
        // From hex
        let sig2 = signature_from_hex(&hex_str).unwrap();
        
        // Verify
        let result = falcon_verify_nullifier(&nullifier, &sig2, &pk);
        assert!(result.is_ok(), "Hex roundtrip should preserve signature");
    }

    #[test]
    fn test_open_extract_message() {
        let (pk, sk) = falcon_keypair();
        let nullifier = [0x42u8; 32];
        
        let sig = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        
        // Open and extract
        let recovered = falcon_open(&sig, &pk).unwrap();
        
        assert_eq!(recovered.as_slice(), &nullifier, "Recovered message should match");
    }

    #[test]
    fn test_pqc_fingerprint_integration() {
        let (falcon_pk, _) = falcon_keypair();
        let mlkem_pk = [0x99u8; 1184];
        
        let fp = compute_pqc_fingerprint(&falcon_pk, &mlkem_pk);
        
        assert_eq!(fp.len(), 32, "Fingerprint should be 32 bytes");
        
        // Deterministic
        let fp2 = compute_pqc_fingerprint(&falcon_pk, &mlkem_pk);
        assert_eq!(fp, fp2, "Fingerprint should be deterministic");
    }

    #[test]
    fn test_key_import_export() {
        let (pk, sk) = falcon_keypair();
        
        // Export
        let pk_bytes = falcon_pk_to_bytes(&pk);
        let sk_bytes = falcon_sk_to_bytes(&sk);
        
        // Import
        let pk2 = falcon_pk_from_bytes(pk_bytes).unwrap();
        let sk2 = falcon_sk_from_bytes(&sk_bytes).unwrap();
        
        // Test with signature
        let nullifier = [0x42u8; 32];
        let sig = falcon_sign_nullifier(&nullifier, &sk2).unwrap();
        
        falcon_verify_nullifier(&nullifier, &sig, &pk2).unwrap();
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // SECURITY ATTACK TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    /// ATAK: Podmieniony klucz publiczny
    /// Atakujący próbuje użyć cudzego klucza do weryfikacji
    #[test]
    fn test_attack_substituted_public_key() {
        let (pk_victim, sk_victim) = falcon_keypair();
        let (pk_attacker, _sk_attacker) = falcon_keypair();
        
        let nullifier = [0x42u8; 32];
        let sig = falcon_sign_nullifier(&nullifier, &sk_victim).unwrap();
        
        // Atakujący próbuje podmienić klucz
        let result = falcon_verify_nullifier(&nullifier, &sig, &pk_attacker);
        assert!(result.is_err(), "Substituted public key MUST fail verification");
    }
    
    /// ATAK: Bit-flip w podpisie
    /// Sprawdza że nawet 1-bitowa zmiana w podpisie jest wykrywana
    #[test]
    fn test_attack_signature_bit_flip() {
        let (pk, sk) = falcon_keypair();
        let nullifier = [0x42u8; 32];
        
        let sig = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        
        // Zmodyfikuj 1 bit w różnych miejscach podpisu
        for byte_idx in [0, 10, 50, 100, 200, 400, 600] {
            if byte_idx < sig.signed_message_bytes.len() {
                let mut tampered = sig.signed_message_bytes.clone();
                tampered[byte_idx] ^= 0x01; // Flip 1 bit
                
                let tampered_sig = SignedNullifier {
                    signed_message_bytes: tampered,
                };
                
                let result = falcon_verify_nullifier(&nullifier, &tampered_sig, &pk);
                assert!(result.is_err(), 
                    "Bit-flip at byte {} MUST invalidate signature", byte_idx);
            }
        }
    }
    
    /// ATAK: Truncated signature
    /// Sprawdza że obcięty podpis jest odrzucany
    #[test]
    fn test_attack_truncated_signature() {
        let (pk, sk) = falcon_keypair();
        let nullifier = [0x42u8; 32];
        
        let sig = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        let original_len = sig.signed_message_bytes.len();
        
        // Różne długości obcięcia
        for truncate_to in [0, 10, 100, 300, 500, original_len - 1] {
            let truncated = SignedNullifier {
                signed_message_bytes: sig.signed_message_bytes[..truncate_to].to_vec(),
            };
            
            let result = falcon_verify_nullifier(&nullifier, &truncated, &pk);
            assert!(result.is_err(), 
                "Truncated signature (len={}) MUST be rejected", truncate_to);
        }
    }
    
    /// ATAK: Extended signature (dodanie bajtów)
    /// Sprawdza że podpis z dodatkowymi bajtami jest odrzucany
    #[test]
    fn test_attack_extended_signature() {
        let (pk, sk) = falcon_keypair();
        let nullifier = [0x42u8; 32];
        
        let sig = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        
        // Dodaj bajty na końcu
        let mut extended = sig.signed_message_bytes.clone();
        extended.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        let extended_sig = SignedNullifier {
            signed_message_bytes: extended,
        };
        
        let result = falcon_verify_nullifier(&nullifier, &extended_sig, &pk);
        assert!(result.is_err(), "Extended signature MUST be rejected");
    }
    
    /// ATAK: Empty signature
    #[test]
    fn test_attack_empty_signature() {
        let (pk, _sk) = falcon_keypair();
        let nullifier = [0x42u8; 32];
        
        let empty_sig = SignedNullifier {
            signed_message_bytes: vec![],
        };
        
        let result = falcon_verify_nullifier(&nullifier, &empty_sig, &pk);
        assert!(result.is_err(), "Empty signature MUST be rejected");
    }
    
    /// ATAK: Garbage signature
    #[test]
    fn test_attack_garbage_signature() {
        let (pk, _sk) = falcon_keypair();
        let nullifier = [0x42u8; 32];
        
        // Random garbage (200 bytes)
        let garbage_sig = SignedNullifier {
            signed_message_bytes: vec![0xDEu8; 200],
        };
        
        let result = falcon_verify_nullifier(&nullifier, &garbage_sig, &pk);
        assert!(result.is_err(), "Garbage signature MUST be rejected");
    }
    
    /// ATAK: Signature replay (ten sam podpis dla innej wiadomości)
    #[test]
    fn test_attack_signature_replay() {
        let (pk, sk) = falcon_keypair();
        let nullifier1 = [0x11u8; 32];
        let nullifier2 = [0x22u8; 32];
        
        // Podpisz nullifier1
        let sig = falcon_sign_nullifier(&nullifier1, &sk).unwrap();
        
        // Próba użycia tego samego podpisu dla nullifier2
        let result = falcon_verify_nullifier(&nullifier2, &sig, &pk);
        assert!(result.is_err(), "Signature replay for different message MUST fail");
    }
    
    /// ATAK: Truncated public key
    #[test]
    fn test_attack_truncated_public_key() {
        let (pk, _sk) = falcon_keypair();
        let pk_bytes = falcon_pk_to_bytes(&pk);
        
        // Różne długości obcięcia
        for len in [0, 100, 500, 896] {
            let result = falcon_pk_from_bytes(&pk_bytes[..len]);
            assert!(result.is_err(), 
                "Truncated public key (len={}) MUST be rejected", len);
        }
    }
    
    /// ATAK: Oversized public key
    #[test]
    fn test_attack_oversized_public_key() {
        let (pk, _sk) = falcon_keypair();
        let mut pk_bytes = falcon_pk_to_bytes(&pk).to_vec();
        pk_bytes.extend_from_slice(&[0x00; 100]); // Dodaj 100 bajtów
        
        let result = falcon_pk_from_bytes(&pk_bytes);
        assert!(result.is_err(), "Oversized public key MUST be rejected");
    }
    
    /// ATAK: Forged signature from different keypair
    /// Atakujący generuje podpis własnym kluczem i próbuje przedstawić jako ofiary
    #[test]
    fn test_attack_forged_signature_different_keypair() {
        let (pk_victim, _sk_victim) = falcon_keypair();
        let (_pk_attacker, sk_attacker) = falcon_keypair();
        
        let nullifier = [0x42u8; 32];
        
        // Atakujący podpisuje własnym kluczem
        let forged_sig = falcon_sign_nullifier(&nullifier, &sk_attacker).unwrap();
        
        // Próba weryfikacji kluczem ofiary
        let result = falcon_verify_nullifier(&nullifier, &forged_sig, &pk_victim);
        assert!(result.is_err(), "Forged signature from different keypair MUST fail");
    }
    
    /// Test: Podpisy są niedeterministyczne (różne dla tej samej wiadomości)
    #[test]
    fn test_signatures_are_randomized() {
        let (pk, sk) = falcon_keypair();
        let nullifier = [0x42u8; 32];
        
        let sig1 = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        let sig2 = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        
        // Oba podpisy powinny być poprawne
        falcon_verify_nullifier(&nullifier, &sig1, &pk).unwrap();
        falcon_verify_nullifier(&nullifier, &sig2, &pk).unwrap();
        
        // Ale różne (randomizacja)
        assert_ne!(
            sig1.signed_message_bytes, 
            sig2.signed_message_bytes,
            "Falcon signatures should be randomized"
        );
    }
    
    /// Test: Avalanche effect - mała zmiana wiadomości = duża zmiana podpisu
    #[test]
    fn test_avalanche_effect() {
        let (pk, sk) = falcon_keypair();
        
        let msg1 = [0x00u8; 32];
        let mut msg2 = [0x00u8; 32];
        msg2[0] = 0x01; // Zmień tylko 1 bit
        
        let sig1 = falcon_sign_nullifier(&msg1, &sk).unwrap();
        let sig2 = falcon_sign_nullifier(&msg2, &sk).unwrap();
        
        // Podpisy powinny być diametralnie różne
        let mut diff_bits = 0u32;
        let min_len = sig1.signed_message_bytes.len().min(sig2.signed_message_bytes.len());
        for i in 0..min_len {
            diff_bits += (sig1.signed_message_bytes[i] ^ sig2.signed_message_bytes[i]).count_ones();
        }
        
        // Powinno być > 25% bitów różnych (strong avalanche)
        let total_bits = (min_len * 8) as u32;
        let diff_ratio = diff_bits as f64 / total_bits as f64;
        
        assert!(diff_ratio > 0.25, 
            "Avalanche effect too weak: only {:.1}% bits differ", diff_ratio * 100.0);
    }
    
    /// Test: verify_bytes API security
    #[test]
    fn test_verify_bytes_security() {
        let (pk, sk) = falcon_keypair();
        let message = b"test message for bytes API";
        
        let sig = falcon_sign(message, &sk).unwrap();
        
        // Valid verification
        falcon_verify_bytes(message, &sig.signed_message_bytes, &pk).unwrap();
        
        // Tampered message
        let result = falcon_verify_bytes(b"wrong message", &sig.signed_message_bytes, &pk);
        assert!(result.is_err(), "Wrong message MUST fail");
        
        // Tampered signature
        let mut tampered_sig = sig.signed_message_bytes.clone();
        tampered_sig[100] ^= 0xFF;
        let result = falcon_verify_bytes(message, &tampered_sig, &pk);
        assert!(result.is_err(), "Tampered signature MUST fail");
    }
}

// ============================================================================
// Block / transcript signatures (re-use SignedNullifier format)
// ============================================================================

/// Podpis bloku / transkryptu handshaku.
/// Format identyczny jak SignedNullifier (attached signature).
pub type BlockSignature = SignedNullifier;

/// Podpisz 32-bajtowy hash bloku / transkryptu.
pub fn falcon_sign_block(
    hash32: &[u8; 32],
    secret_key: &FalconSecretKey,
) -> Result<BlockSignature> {
    falcon_sign(hash32, secret_key)
}

/// Zweryfikuj podpis bloku / transkryptu.
pub fn falcon_verify_block(
    hash32: &[u8; 32],
    sig: &BlockSignature,
    public_key: &FalconPublicKey,
) -> Result<()> {
    falcon_verify(hash32, sig, public_key)
}