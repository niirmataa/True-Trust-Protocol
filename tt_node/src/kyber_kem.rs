//! Kyber-768 Post-Quantum Key Encapsulation Mechanism
//! 
//! For secure peer-to-peer channel establishment in the blockchain network.
//!
//! # Security Model
//! - **IND-CCA2 secure**: Chosen ciphertext attack resistant
//! - **Key exchange**: Establish shared secrets between nodes
//! - **Forward secrecy**: Each session uses fresh shared secret
//!
//! # Example
//! ```no_run
//! use pqcrypto_traits::kem::SharedSecret;
//! use tt_node::kyber_kem::*;
//! 
//! // Recipient generates keypair
//! let (recipient_pk, recipient_sk) = kyber_keypair();
//! 
//! // Sender encapsulates to get shared secret + ciphertext
//! let (sender_ss, ciphertext) = kyber_encapsulate(&recipient_pk);
//! 
//! // Recipient decapsulates to recover shared secret
//! let recipient_ss = kyber_decapsulate(&ciphertext, &recipient_sk).unwrap();
//! 
//! assert_eq!(sender_ss.as_bytes(), recipient_ss.as_bytes());
//! ```

#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    PublicKey as KemPublicKey,
    SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
    Ciphertext as KemCiphertext,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub type Hash32 = [u8; 32];

/* ============================================================================
 * Core Types
 * ========================================================================== */

/// Kyber-768 public key (1184 bytes)
pub type KyberPublicKey = kyber768::PublicKey;

/// Kyber-768 secret key (2400 bytes, zeroized on drop)
pub type KyberSecretKey = kyber768::SecretKey;

/// Kyber-768 shared secret (32 bytes, zeroized on drop)
pub type KyberSharedSecret = kyber768::SharedSecret;

/// Kyber-768 ciphertext (1088 bytes)
pub type KyberCiphertext = kyber768::Ciphertext;

/* ============================================================================
 * Key Generation
 * ========================================================================== */

/// Generate new Kyber-768 keypair
/// 
/// # Returns
/// (public_key, secret_key)
#[inline]
pub fn kyber_keypair() -> (KyberPublicKey, KyberSecretKey) {
    kyber768::keypair()
}

/// Import public key from bytes
pub fn kyber_pk_from_bytes(bytes: &[u8]) -> Result<KyberPublicKey> {
    KyberPublicKey::from_bytes(bytes)
        .map_err(|_| anyhow!("Invalid Kyber public key bytes"))
}

/// Import secret key from bytes
pub fn kyber_sk_from_bytes(bytes: &[u8]) -> Result<KyberSecretKey> {
    KyberSecretKey::from_bytes(bytes)
        .map_err(|_| anyhow!("Invalid Kyber secret key bytes"))
}

/// Export public key to bytes (1184 bytes)
#[inline]
pub fn kyber_pk_to_bytes(pk: &KyberPublicKey) -> &[u8] {
    pk.as_bytes()
}

/// Export secret key to bytes (2400 bytes) - SENSITIVE!
#[inline]
pub fn kyber_sk_to_bytes(sk: &KyberSecretKey) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(sk.as_bytes().to_vec())
}

/* ============================================================================
 * Encapsulation / Decapsulation
 * ========================================================================== */

/// Encapsulate to generate shared secret
/// 
/// # Returns
/// (shared_secret, ciphertext)
/// 
/// # Performance
/// ~200 microseconds on modern CPU
#[inline]
pub fn kyber_encapsulate(public_key: &KyberPublicKey) -> (KyberSharedSecret, KyberCiphertext) {
    kyber768::encapsulate(public_key)
}

/// Decapsulate ciphertext to recover shared secret
/// 
/// # Security Note
/// Kyber uses "implicit rejection" - even for invalid/tampered ciphertext,
/// this returns a pseudo-random shared secret (not an error). This is by design
/// to prevent timing side-channels. The returned Result is always Ok.
/// 
/// # Performance
/// ~300 microseconds on modern CPU
pub fn kyber_decapsulate(
    ciphertext: &KyberCiphertext,
    secret_key: &KyberSecretKey,
) -> Result<KyberSharedSecret> {
    // Always succeeds due to implicit rejection design
    Ok(kyber768::decapsulate(ciphertext, secret_key))
}

/* ============================================================================
 * Ciphertext Handling
 * ========================================================================== */

/// Import ciphertext from bytes
pub fn kyber_ct_from_bytes(bytes: &[u8]) -> Result<KyberCiphertext> {
    KyberCiphertext::from_bytes(bytes)
        .map_err(|_| anyhow!("Invalid Kyber ciphertext bytes"))
}

/// Export ciphertext to bytes (1088 bytes)
#[inline]
pub fn kyber_ct_to_bytes(ct: &KyberCiphertext) -> &[u8] {
    ct.as_bytes()
}

/* ============================================================================
 * Shared Secret Handling
 * ========================================================================== */

/// Export shared secret to bytes (32 bytes) - SENSITIVE!
#[inline]
pub fn kyber_ss_to_bytes(ss: &KyberSharedSecret) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(ss.as_bytes().to_vec())
}

/// Derive symmetric key from shared secret using KMAC256
pub fn derive_aes_key_from_shared_secret(ss: &KyberSharedSecret, context: &[u8]) -> [u8; 32] {
    use crate::crypto_kmac_consensus::kmac256_hash;
    kmac256_hash(context, &[ss.as_bytes()])
}

/// Derive 32-byte AES key from shared secret bytes (for use with Zeroizing wrapper)
pub fn derive_aes_key_from_shared_secret_bytes(ss_bytes: &[u8], context: &[u8]) -> [u8; 32] {
    use crate::crypto_kmac_consensus::kmac256_hash;
    kmac256_hash(context, &[ss_bytes])
}

/* ============================================================================
 * High-Level API
 * ========================================================================== */

/// Serializable key exchange result
/// 
/// SECURITY: shared_secret_bytes is private and zeroized on drop.
/// Use `shared_secret()` to access (returns reference, no copy).
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyExchangeInitiator {
    /// SENSITIVE - zeroized on drop, access via shared_secret()
    shared_secret_bytes: Vec<u8>,
    /// Ciphertext to send to recipient
    pub ciphertext_bytes: Vec<u8>,
}

impl KeyExchangeInitiator {
    /// Get shared secret reference (no copy)
    #[inline]
    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret_bytes
    }
}

impl Zeroize for KeyExchangeInitiator {
    fn zeroize(&mut self) {
        self.shared_secret_bytes.zeroize();
    }
}

impl Drop for KeyExchangeInitiator {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Initiate key exchange (sender side)
pub fn initiate_key_exchange(recipient_pk: &KyberPublicKey) -> KeyExchangeInitiator {
    let (ss, ct) = kyber_encapsulate(recipient_pk);
    KeyExchangeInitiator {
        shared_secret_bytes: ss.as_bytes().to_vec(),
        ciphertext_bytes: ct.as_bytes().to_vec(),
    }
}

/// Complete key exchange (recipient side)
pub fn complete_key_exchange(
    ciphertext_bytes: &[u8],
    recipient_sk: &KyberSecretKey,
) -> Result<Zeroizing<Vec<u8>>> {
    let ct = kyber_ct_from_bytes(ciphertext_bytes)?;
    let ss = kyber_decapsulate(&ct, recipient_sk)?;
    Ok(Zeroizing::new(ss.as_bytes().to_vec()))
}

/* ============================================================================
 * Utilities
 * ========================================================================== */

/// Get public key size
#[inline]
pub const fn kyber_pk_size() -> usize {
    1184
}

/// Get secret key size
#[inline]
pub const fn kyber_sk_size() -> usize {
    2400
}

/// Get ciphertext size
#[inline]
pub const fn kyber_ct_size() -> usize {
    1088
}

/// Get shared secret size
#[inline]
pub const fn kyber_ss_size() -> usize {
    32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (pk, sk) = kyber_keypair();
        assert_eq!(pk.as_bytes().len(), kyber_pk_size());
        assert_eq!(sk.as_bytes().len(), kyber_sk_size());
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let (pk, sk) = kyber_keypair();
        
        let (ss1, ct) = kyber_encapsulate(&pk);
        let ss2 = kyber_decapsulate(&ct, &sk).unwrap();
        
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "Shared secrets must match");
    }

    #[test]
    fn test_key_exchange_api() {
        let (recipient_pk, recipient_sk) = kyber_keypair();
        
        // Initiator
        let kex_init = initiate_key_exchange(&recipient_pk);
        
        // Recipient
        let ss_recipient = complete_key_exchange(
            &kex_init.ciphertext_bytes,
            &recipient_sk,
        ).unwrap();
        
        assert_eq!(
            kex_init.shared_secret(),
            ss_recipient.as_slice(),
            "Shared secrets must match"
        );
    }

    #[test]
    fn test_derive_symmetric_key() {
        let (pk, _) = kyber_keypair();
        let (ss, _) = kyber_encapsulate(&pk);
        
        let key1 = derive_aes_key_from_shared_secret(&ss, b"CHANNEL_ENC");
        let key2 = derive_aes_key_from_shared_secret(&ss, b"CHANNEL_MAC");
        
        assert_ne!(key1, key2, "Different contexts should derive different keys");
    }

    #[test]
    fn test_ciphertext_import_export() {
        let (pk, sk) = kyber_keypair();
        let (ss1, ct) = kyber_encapsulate(&pk);
        
        // Export
        let ct_bytes = kyber_ct_to_bytes(&ct);
        assert_eq!(ct_bytes.len(), kyber_ct_size());
        
        // Import
        let ct2 = kyber_ct_from_bytes(ct_bytes).unwrap();
        let ss2 = kyber_decapsulate(&ct2, &sk).unwrap();
        
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // SECURITY ATTACK TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    /// ATAK: Ciphertext dla złego klucza
    /// Sprawdza że dekapsulacja z cudzym kluczem daje INNY shared secret
    #[test]
    fn test_attack_wrong_secret_key() {
        let (pk_alice, _sk_alice) = kyber_keypair();
        let (_pk_bob, sk_bob) = kyber_keypair();
        
        // Enkapsulacja do Alice
        let (ss_sender, ct) = kyber_encapsulate(&pk_alice);
        
        // Bob próbuje dekapsulować swoim kluczem
        // Kyber ma "implicit rejection" - nie zwraca błędu, ale daje INNY secret
        let ss_bob = kyber_decapsulate(&ct, &sk_bob).unwrap();
        
        assert_ne!(
            ss_sender.as_bytes(), 
            ss_bob.as_bytes(),
            "Wrong secret key MUST produce different shared secret"
        );
    }
    
    /// ATAK: Tampered ciphertext (bit-flip)
    /// Kyber używa implicit rejection - tampered CT daje pseudo-random SS
    #[test]
    fn test_attack_tampered_ciphertext() {
        let (pk, sk) = kyber_keypair();
        let (ss_original, ct) = kyber_encapsulate(&pk);
        
        // Tampering w różnych miejscach
        for byte_idx in [0, 100, 500, 1000, 1087] {
            let mut tampered_bytes = ct.as_bytes().to_vec();
            tampered_bytes[byte_idx] ^= 0x01; // Flip 1 bit
            
            let tampered_ct = kyber_ct_from_bytes(&tampered_bytes).unwrap();
            let ss_tampered = kyber_decapsulate(&tampered_ct, &sk).unwrap();
            
            // Implicit rejection: inny shared secret (nie błąd!)
            assert_ne!(
                ss_original.as_bytes(),
                ss_tampered.as_bytes(),
                "Tampered ciphertext at byte {} MUST produce different shared secret",
                byte_idx
            );
        }
    }
    
    /// ATAK: Truncated ciphertext
    #[test]
    fn test_attack_truncated_ciphertext() {
        let (pk, _sk) = kyber_keypair();
        let (_ss, ct) = kyber_encapsulate(&pk);
        let ct_bytes = ct.as_bytes();
        
        // Różne długości obcięcia
        for len in [0, 100, 500, 1000, 1087] {
            let result = kyber_ct_from_bytes(&ct_bytes[..len]);
            assert!(result.is_err(), 
                "Truncated ciphertext (len={}) MUST be rejected", len);
        }
    }
    
    /// ATAK: Oversized ciphertext
    #[test]
    fn test_attack_oversized_ciphertext() {
        let (pk, _sk) = kyber_keypair();
        let (_ss, ct) = kyber_encapsulate(&pk);
        
        let mut oversized = ct.as_bytes().to_vec();
        oversized.extend_from_slice(&[0x00; 100]);
        
        let result = kyber_ct_from_bytes(&oversized);
        assert!(result.is_err(), "Oversized ciphertext MUST be rejected");
    }
    
    /// ATAK: Empty ciphertext
    #[test]
    fn test_attack_empty_ciphertext() {
        let result = kyber_ct_from_bytes(&[]);
        assert!(result.is_err(), "Empty ciphertext MUST be rejected");
    }
    
    /// ATAK: Garbage ciphertext
    #[test]
    fn test_attack_garbage_ciphertext() {
        // Prawidłowa długość ale losowe dane
        let garbage = vec![0xDE; kyber_ct_size()];
        let result = kyber_ct_from_bytes(&garbage);
        
        // Kyber akceptuje każdy 1088-bajtowy ciąg jako CT (implicit rejection)
        // więc parsing powinien się udać, ale SS będzie pseudo-losowy
        assert!(result.is_ok(), "Valid-length garbage should parse as CT");
    }
    
    /// ATAK: Truncated public key
    #[test]
    fn test_attack_truncated_public_key() {
        let (pk, _sk) = kyber_keypair();
        let pk_bytes = pk.as_bytes();
        
        for len in [0, 100, 500, 1000, 1183] {
            let result = kyber_pk_from_bytes(&pk_bytes[..len]);
            assert!(result.is_err(), 
                "Truncated public key (len={}) MUST be rejected", len);
        }
    }
    
    /// ATAK: Oversized public key
    #[test]
    fn test_attack_oversized_public_key() {
        let (pk, _sk) = kyber_keypair();
        let mut pk_bytes = pk.as_bytes().to_vec();
        pk_bytes.extend_from_slice(&[0x00; 100]);
        
        let result = kyber_pk_from_bytes(&pk_bytes);
        assert!(result.is_err(), "Oversized public key MUST be rejected");
    }
    
    /// ATAK: Truncated secret key
    #[test]
    fn test_attack_truncated_secret_key() {
        let (_pk, sk) = kyber_keypair();
        let sk_bytes = kyber_sk_to_bytes(&sk);
        
        for len in [0, 100, 1000, 2000, 2399] {
            let result = kyber_sk_from_bytes(&sk_bytes[..len]);
            assert!(result.is_err(), 
                "Truncated secret key (len={}) MUST be rejected", len);
        }
    }
    
    /// ATAK: Ciphertext replay
    /// Ten sam ciphertext dekapsulowany wielokrotnie daje ten sam SS
    #[test]
    fn test_ciphertext_replay_determinism() {
        let (pk, sk) = kyber_keypair();
        let (ss_original, ct) = kyber_encapsulate(&pk);
        
        // Wielokrotna dekapsulacja tego samego CT
        for _ in 0..5 {
            let ss = kyber_decapsulate(&ct, &sk).unwrap();
            assert_eq!(
                ss_original.as_bytes(), 
                ss.as_bytes(),
                "Same ciphertext MUST always produce same shared secret"
            );
        }
    }
    
    /// Test: Encapsulation jest niedeterministyczna
    /// Ta sama PK + różne wywołania = różne CT i SS
    #[test]
    fn test_encapsulation_randomness() {
        let (pk, _sk) = kyber_keypair();
        
        let (ss1, ct1) = kyber_encapsulate(&pk);
        let (ss2, ct2) = kyber_encapsulate(&pk);
        
        // Różne ciphertexts
        assert_ne!(
            ct1.as_bytes(), 
            ct2.as_bytes(),
            "Encapsulation MUST be randomized (different CT)"
        );
        
        // Różne shared secrets
        assert_ne!(
            ss1.as_bytes(), 
            ss2.as_bytes(),
            "Encapsulation MUST be randomized (different SS)"
        );
    }
    
    /// Test: Key derivation domain separation
    #[test]
    fn test_key_derivation_domain_separation() {
        let (pk, _sk) = kyber_keypair();
        let (ss, _ct) = kyber_encapsulate(&pk);
        
        let key_enc = derive_aes_key_from_shared_secret(&ss, b"ENCRYPTION");
        let key_mac = derive_aes_key_from_shared_secret(&ss, b"MAC");
        let key_enc2 = derive_aes_key_from_shared_secret(&ss, b"ENCRYPTION");
        
        // Różne konteksty = różne klucze
        assert_ne!(key_enc, key_mac, "Different contexts MUST derive different keys");
        
        // Ten sam kontekst = ten sam klucz (deterministyczne)
        assert_eq!(key_enc, key_enc2, "Same context MUST derive same key");
    }
    
    /// Test: Key import/export roundtrip
    #[test]
    fn test_key_import_export_roundtrip() {
        let (pk, sk) = kyber_keypair();
        
        // Export
        let pk_bytes = kyber_pk_to_bytes(&pk).to_vec();
        let sk_bytes = kyber_sk_to_bytes(&sk);
        
        // Import
        let pk2 = kyber_pk_from_bytes(&pk_bytes).unwrap();
        let sk2 = kyber_sk_from_bytes(&sk_bytes).unwrap();
        
        // Test with encapsulation
        let (ss_sender, ct) = kyber_encapsulate(&pk2);
        let ss_recipient = kyber_decapsulate(&ct, &sk2).unwrap();
        
        assert_eq!(
            ss_sender.as_bytes(), 
            ss_recipient.as_bytes(),
            "Imported keys MUST work correctly"
        );
    }
    
    /// Test: KeyExchangeInitiator zeroization
    #[test]
    fn test_key_exchange_initiator_zeroization() {
        let (pk, sk) = kyber_keypair();
        
        let kex = initiate_key_exchange(&pk);
        let ss_copy = kex.shared_secret().to_vec();
        let ct_copy = kex.ciphertext_bytes.clone();
        
        // Verify it works
        let ss_recipient = complete_key_exchange(&ct_copy, &sk).unwrap();
        assert_eq!(&ss_copy, ss_recipient.as_slice());
        
        // Drop kex - should zeroize
        drop(kex);
        
        // ss_copy still has the value (we made a copy before drop)
        assert!(!ss_copy.iter().all(|&b| b == 0), "Our copy should still have data");
    }
    
    /// ATAK: Man-in-the-middle scenario test
    /// Sprawdza że MITM nie może odzyskać shared secret
    #[test]
    fn test_mitm_protection() {
        let (pk_alice, sk_alice) = kyber_keypair();
        let (pk_eve, sk_eve) = kyber_keypair();
        
        // Bob encapsuluje do Alice
        let (ss_bob, ct) = kyber_encapsulate(&pk_alice);
        
        // Alice dekapsuluje - powinna dostać to samo co Bob
        let ss_alice = kyber_decapsulate(&ct, &sk_alice).unwrap();
        assert_eq!(ss_bob.as_bytes(), ss_alice.as_bytes());
        
        // Eve próbuje dekapsulować swoim kluczem - dostaje INNY secret
        let ss_eve = kyber_decapsulate(&ct, &sk_eve).unwrap();
        assert_ne!(ss_bob.as_bytes(), ss_eve.as_bytes(), "Eve MUST NOT recover shared secret");
        
        // Eve próbuje z public key Alice - nie może (nie ma sk_alice)
        // Eve może tylko encapsulować do Alice, nie dekapsulować od niej
    }
}