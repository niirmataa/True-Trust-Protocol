//! Deterministic Kyber-768 Operations via pqc_kyber
//!
//! Ten moduł zapewnia deterministyczne generowanie kluczy Kyber-768
//! używając funkcji `derive` z biblioteki `pqc_kyber`.
//!
//! # Security Properties
//!
//! - **Deterministic**: Same seed + personalization → same keys
//! - **Reproducible**: Audit-friendly, testable with known vectors
//! - **Compatible**: Keys są kompatybilne z pqcrypto-kyber
//!
//! # Usage
//!
//! ```no_run
//! use tt_node::crypto::seeded_kyber::kyber_keypair_deterministic;
//!
//! let seed = [0x42u8; 32];
//! let (pk, sk) = kyber_keypair_deterministic(seed, b"TT.v7.KYBER768").unwrap();
//! ```

#![cfg(feature = "seeded_kyber")]

use crate::crypto::kmac::kmac256_derive_key;

/// Kyber-768 public key length (from pqc_kyber)
pub const KYBER_PK_LEN: usize = 1184;

/// Kyber-768 secret key length (from pqc_kyber)
pub const KYBER_SK_LEN: usize = 2400;

/// Generate Kyber-768 keypair deterministically from seed
///
/// # Parameters
///
/// - `seed32`: 32-byte secret seed (e.g., master key, epoch-derived key)
/// - `personalization`: Context string for domain separation
///   - Should include: application label, version, key type
///
/// # Returns
///
/// - `Ok((pk, sk))`: Kyber public key (1184B) and secret key (2400B)
/// - `Err`: Keygen failed
///
/// # Example
///
/// ```no_run
/// let master_seed = [0x42u8; 32];
/// let (pk, sk) = kyber_keypair_deterministic(master_seed, b"TT.v7.KYBER768").unwrap();
/// ```
///
/// # Security
///
/// - Same (seed, personalization) always produces same keypair
/// - Personalization prevents cross-context attacks
/// - Seed should have ≥256 bits entropy for 128-bit security
pub fn kyber_keypair_deterministic(
    seed32: [u8; 32],
    personalization: &[u8],
) -> Result<([u8; KYBER_PK_LEN], [u8; KYBER_SK_LEN]), Box<dyn std::error::Error + Send + Sync>> {
    // Derive 64-byte seed for Kyber from master seed + personalization
    // pqc_kyber::derive() expects 64-byte seed
    let derived_seed_1 = kmac256_derive_key(&seed32, personalization, b"kyber.seed.part1");
    let derived_seed_2 = kmac256_derive_key(&seed32, personalization, b"kyber.seed.part2");
    
    let mut kyber_seed = [0u8; 64];
    kyber_seed[..32].copy_from_slice(&derived_seed_1);
    kyber_seed[32..].copy_from_slice(&derived_seed_2);
    
    // Use pqc_kyber::derive for deterministic keypair
    let keypair = pqc_kyber::derive(&kyber_seed)
        .map_err(|e| format!("Kyber derive failed: {:?}", e))?;
    
    // Convert to fixed-size arrays
    let mut pk = [0u8; KYBER_PK_LEN];
    let mut sk = [0u8; KYBER_SK_LEN];
    
    pk.copy_from_slice(&keypair.public);
    sk.copy_from_slice(&keypair.secret);
    
    Ok((pk, sk))
}

/// Convert pqc_kyber keys to pqcrypto-kyber format
///
/// Pozwala używać deterministycznie wygenerowanych kluczy
/// z API pqcrypto-kyber (które jest używane w reszcie kodu)
pub fn to_pqcrypto_kyber_keys(
    pk_bytes: &[u8; KYBER_PK_LEN],
    sk_bytes: &[u8; KYBER_SK_LEN],
) -> Result<(pqcrypto_kyber::kyber768::PublicKey, pqcrypto_kyber::kyber768::SecretKey), Box<dyn std::error::Error + Send + Sync>> {
    use pqcrypto_kyber::kyber768;
    use pqcrypto_traits::kem::{PublicKey, SecretKey};
    
    let pk = kyber768::PublicKey::from_bytes(pk_bytes)
        .map_err(|_| "Invalid Kyber public key bytes")?;
    let sk = kyber768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| "Invalid Kyber secret key bytes")?;
    
    Ok((pk, sk))
}

/* ============================================================================
 * Tests
 * ========================================================================== */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_keygen() {
        let seed = [0x11u8; 32];
        let pers = b"TT.v7.KYBER768.test";

        let (pk1, sk1) = kyber_keypair_deterministic(seed, pers).unwrap();
        let (pk2, sk2) = kyber_keypair_deterministic(seed, pers).unwrap();

        assert_eq!(&pk1[..], &pk2[..], "Public keys should match");
        assert_eq!(&sk1[..], &sk2[..], "Secret keys should match");
    }

    #[test]
    fn test_different_personalization() {
        let seed = [0x22u8; 32];

        let (pk1, _) = kyber_keypair_deterministic(seed, b"context-A").unwrap();
        let (pk2, _) = kyber_keypair_deterministic(seed, b"context-B").unwrap();

        assert_ne!(&pk1[..], &pk2[..], "Different context should produce different keys");
    }

    #[test]
    fn test_to_pqcrypto_conversion() {
        let seed = [0x33u8; 32];
        let (pk_bytes, sk_bytes) = kyber_keypair_deterministic(seed, b"test").unwrap();
        
        let (pk, sk) = to_pqcrypto_kyber_keys(&pk_bytes, &sk_bytes).unwrap();
        
        // Verify keys work for encapsulation/decapsulation
        use pqcrypto_kyber::kyber768;
        let (ss1, ct) = kyber768::encapsulate(&pk);
        let ss2 = kyber768::decapsulate(&ct, &sk);
        
        use pqcrypto_traits::kem::SharedSecret;
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "Shared secrets should match");
    }
}
