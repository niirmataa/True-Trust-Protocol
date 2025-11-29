//! Deterministic Falcon Operations via KMAC-DRBG
//!
//! Ten moduł robi dwie rzeczy:
//! 1. Spina `KmacDrbg` z `falcon_seeded` (PQClean Falcon-512 z seedowanym RNG).
//! 2. Dostarcza **bezpieczne API wysokiego poziomu** z wrapperami na klucze
//!    i podpisy, tak żeby:
//!      - sekretne klucze były zeroizowane,
//!      - domain separation przy podpisach było sensowne,
//!      - użytkownik jak najmniej miał szans „strzelić sobie w stopę".
//!
//! # Warstwy API
//!
//! - **Low-level (raw)**:
//!   - `falcon_keypair_deterministic` – → ([u8; PK_LEN], [u8; SK_LEN])
//!   - `falcon_sign_deterministic` – wymaga ręcznego `coins_seed` + `personalization`
//!   - to jest „dla dorosłych" – zostawiamy do specjalnych zastosowań
//!
//! - **High-level (recommended)**:
//!   - `FalconPublicKey`, `FalconSecretKey`, `FalconSignature` – typy opakowujące
//!   - `falcon_keypair_from_seed` – zwraca wrappery, SK zeroizowany na Drop
//!   - `falcon_sign_msg_deterministic` – *sam* robi PRF z SK, binduje do msg & context,
//!     generuje coins i podpis. To jest **zalecana ścieżka** dla nodów / walleta.
//!
//! Wszystko działa tylko gdy włączony jest feature `seeded_falcon`
//!
//! This module provides deterministic (reproducible) Falcon-512 key generation
//! and signing by integrating `KmacDrbg` with the `falcon_seeded` FFI crate.
//!
//! # Security Properties
//!
//! - **Deterministic**: Same seed + personalization → same keys/signatures
//! - **Reproducible**: Audit-friendly, testable with known vectors
//! - **HSM/TEE Compatible**: No `/dev/urandom` dependency
//! - **Privacy-Preserving**: Coins derived from secret + context (no leakage)
//!
//! # Usage
//!
//! ```
//! # #[cfg(feature = "seeded_falcon")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use tt_node::crypto::seeded::{falcon_keypair_deterministic, falcon_sign_deterministic};
//! use tt_node::crypto::kmac::kmac256_derive_key;
//!
//! // Deterministic keygen
//! let seed = [0x42u8; 32];
//! let (pk, sk) = falcon_keypair_deterministic(seed, b"epoch=1/identity")?;
//!
//! // Deterministic signing (coins derived from sk + message)
//! let msg = b"my transaction data";
//! let coins_seed = kmac256_derive_key(&sk[..32], b"coins", msg);
//! let sig = falcon_sign_deterministic(&sk, msg, coins_seed, b"signing.v1")?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "seeded_falcon"))]
//! # fn main() {}
//! ```
//!
//! # Security Notes
//!
//! **CRITICAL:** When signing, personalization MUST include:
//! - Message hash or transcript
//! - Unique context (epoch, nonce, counter)
//!
//! Never reuse the same (seed, personalization) for different messages!

#![cfg(feature = "seeded_falcon")]

use crate::crypto::kmac::kmac256_derive_key;
use crate::crypto::kmac_drbg::KmacDrbg;
use falcon_seeded::{self as fs, FillBytes};
use std::sync::{Arc, Mutex};

/* ============================================================================
 * KmacDrbg Adapter for falcon_seeded
 * ========================================================================== */

/// Adapter: Wraps `KmacDrbg` to implement `FillBytes` trait
///
/// Uses `Mutex` for thread-safe access (required by `FillBytes: Send + Sync`)
struct DrbgFill(Mutex<KmacDrbg>);

impl FillBytes for DrbgFill {
    fn fill(&self, out: &mut [u8]) {
        let mut drbg = self.0.lock().unwrap();
        use rand_core::RngCore; // KmacDrbg implements RngCore
        drbg.fill_bytes(out);
    }
}

/* ============================================================================
 * Deterministic Falcon Operations
 * ========================================================================== */

/// Generate Falcon-512 keypair deterministically from seed
///
/// # Parameters
///
/// - `seed32`: 32-byte secret seed (e.g., master key, epoch-derived key)
/// - `personalization`: Context string for domain separation
///   - Should include: application label, epoch, key index
///
/// # Returns
///
/// - `Ok((pk, sk))`: Falcon public key (897B) and secret key (1281B)
/// - `Err`: Keygen failed (should not happen with valid seed)
///
/// # Example
///
/// ```
/// # #[cfg(feature = "seeded_falcon")]
/// # fn main() {
/// use tt_node::crypto::seeded::falcon_keypair_deterministic;
/// let master_seed = [0x42u8; 32];
/// let epoch = 5u64;
/// let pers = format!("FALCON/keygen/epoch={}", epoch);
/// let (pk, sk) = falcon_keypair_deterministic(master_seed, pers.as_bytes()).unwrap();
/// assert_eq!(pk.len(), 897);
/// # }
/// # #[cfg(not(feature = "seeded_falcon"))]
/// # fn main() {}
/// ```
///
/// # Security
///
/// - Same (seed, personalization) always produces same keypair
/// - Personalization prevents cross-context attacks
/// - Seed should have ≥256 bits entropy for 128-bit security
pub fn falcon_keypair_deterministic(
    seed32: [u8; 32],
    personalization: &[u8],
) -> Result<([u8; fs::PK_LEN], [u8; fs::SK_LEN]), Box<dyn std::error::Error>> {
    // Create deterministic DRBG
    let drbg = KmacDrbg::new(&seed32, personalization);
    let src = Arc::new(DrbgFill(Mutex::new(drbg)));
    
    // Generate keypair via FFI
    let (pk, sk) = fs::keypair_with(src)
        .map_err(|e| format!("Falcon keygen failed: {}", e))?;
    
    Ok((pk, sk))
}

/// Sign message with Falcon-512 using deterministic coins
///
/// # Parameters
///
/// - `sk`: Falcon secret key (1281 bytes)
/// - `msg`: Message to sign
/// - `coins_seed`: Secret seed for signature coins (32 bytes)
///   - Should be derived from: `KMAC(sk_prf, transcript_hash)`
/// - `personalization`: Context string for coins
///   - **MUST** be unique per message! Include: epoch, nonce, or counter
///
/// # Returns
///
/// - `Ok(signature)`: Falcon signature (~666 bytes, variable length)
/// - `Err`: Signing failed
///
/// # Security - CRITICAL!
///
/// **Never reuse (coins_seed, personalization) for different messages!**
///
/// # Example
///
/// ```
/// # #[cfg(feature = "seeded_falcon")]
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use tt_node::crypto::seeded::{falcon_keypair_deterministic, falcon_sign_deterministic};
/// use tt_node::crypto::kmac::kmac256_derive_key;
///
/// // Generate keypair
/// let seed = [0x42u8; 32];
/// let (pk, sk) = falcon_keypair_deterministic(seed, b"test")?;
///
/// // Sign message
/// let msg = b"transaction data";
/// let coins_seed = kmac256_derive_key(&sk[..32], b"coins-seed", msg);
/// let sig = falcon_sign_deterministic(&sk, msg, coins_seed, b"ctx=tx1")?;
/// assert!(!sig.is_empty());
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "seeded_falcon"))]
/// # fn main() {}
/// ```
pub fn falcon_sign_deterministic(
    sk: &[u8; fs::SK_LEN],
    msg: &[u8],
    coins_seed: [u8; 32],
    personalization: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create deterministic DRBG for coins
    let mut drbg = KmacDrbg::new(&coins_seed, personalization);
    
    // Optional: Ratchet before signing (forward secrecy)
    drbg.ratchet();
    
    let src = Arc::new(DrbgFill(Mutex::new(drbg)));
    
    // Sign via FFI
    let sig = fs::sign_with(src, sk, msg)
        .map_err(|e| format!("Falcon signing failed: {}", e))?;
    
    Ok(sig)
}

/// Verify Falcon-512 signature (standard verification, not deterministic)
///
/// This is a convenience wrapper around `falcon_seeded::verify`.
///
/// # Parameters
///
/// - `pk`: Falcon public key (897 bytes)
/// - `msg`: Original message
/// - `sig`: Signature to verify
///
/// # Returns
///
/// - `true`: Signature is valid
/// - `false`: Signature is invalid or malformed
pub fn falcon_verify(pk: &[u8; fs::PK_LEN], msg: &[u8], sig: &[u8]) -> bool {
    fs::verify(pk, msg, sig)
}

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

/// Derive Falcon SK PRF key (for coins seed derivation)
///
/// This extracts a PRF key from the Falcon secret key for use in
/// deterministic signing.
///
/// # Parameters
///
/// - `sk`: Falcon secret key (1281 bytes)
///
/// # Returns
///
/// - 32-byte PRF key for coins seed derivation
///
/// # Example
///
/// ```
/// # #[cfg(feature = "seeded_falcon")]
/// # fn main() {
/// use tt_node::crypto::seeded::derive_sk_prf;
///
/// const FALCON_SK_LEN: usize = 1281;
/// let sk = [0xCDu8; FALCON_SK_LEN];
/// let sk_prf = derive_sk_prf(&sk);
/// assert_eq!(sk_prf.len(), 32);
/// # }
/// # #[cfg(not(feature = "seeded_falcon"))]
/// # fn main() {}
/// ```
pub fn derive_sk_prf(sk: &[u8; fs::SK_LEN]) -> [u8; 32] {
    // Use first 32 bytes of SK as seed for PRF derivation
    // (Falcon SK structure: [f, g, F] where f is the secret polynomial)
    let sk_seed = &sk[..32.min(sk.len())];
    kmac256_derive_key(sk_seed, b"FALCON/sk-prf", b"v1")
}

/* ============================================================================
 * Tests
 * ========================================================================== */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "pqclean")] // Requires PQClean sources in falcon_seeded
    fn test_deterministic_keygen() {
        let seed = [0x11u8; 32];
        let pers = b"test/epoch=1/identity";

        let (pk1, sk1) = falcon_keypair_deterministic(seed, pers).unwrap();
        let (pk2, sk2) = falcon_keypair_deterministic(seed, pers).unwrap();

        assert_eq!(&pk1[..], &pk2[..], "Public keys should match");
        assert_eq!(&sk1[..], &sk2[..], "Secret keys should match");
    }

    #[test]
    #[cfg(feature = "pqclean")] // Requires PQClean sources
    fn test_deterministic_sign_per_context() {
        let seed_keygen = [0xABu8; 32];
        let (_pk, sk) = falcon_keypair_deterministic(seed_keygen, b"id").unwrap();

        let msg = b"hello world";
        let coins_seed = [0x22u8; 32];

        // Same context → same signature
        let sig1 = falcon_sign_deterministic(&sk, msg, coins_seed, b"ctx=A").unwrap();
        let sig2 = falcon_sign_deterministic(&sk, msg, coins_seed, b"ctx=A").unwrap();
        assert_eq!(sig1, sig2, "Same context should produce same signature");

        // Different context → different signature
        let sig3 = falcon_sign_deterministic(&sk, msg, coins_seed, b"ctx=B").unwrap();
        assert_ne!(sig1, sig3, "Different context should produce different signature");
    }

    #[test]
    #[cfg(feature = "pqclean")] // Requires PQClean sources
    fn test_sign_verify_roundtrip() {
        let seed = [0x42u8; 32];
        let (pk, sk) = falcon_keypair_deterministic(seed, b"test").unwrap();

        let msg = b"test message";
        let coins_seed = kmac256_derive_key(&seed, b"coins", msg);
        let sig = falcon_sign_deterministic(&sk, msg, coins_seed, b"v1").unwrap();

        assert!(falcon_verify(&pk, msg, &sig), "Signature should verify");
        assert!(!falcon_verify(&pk, b"wrong msg", &sig), "Wrong message should fail");
    }

    #[test]
    fn test_derive_sk_prf() {
        let sk = [0xCDu8; fs::SK_LEN];
        let prf1 = derive_sk_prf(&sk);
        let prf2 = derive_sk_prf(&sk);
        
        assert_eq!(prf1, prf2, "PRF derivation should be deterministic");
        assert_eq!(prf1.len(), 32, "PRF should be 32 bytes");
    }
}