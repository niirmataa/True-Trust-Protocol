//! Deterministic Falcon-512 Signing via KMAC-DRBG
//!
//! This crate provides deterministic (reproducible) Falcon-512 key generation
//! and signing by replacing OS randomness with a user-controlled DRBG.
//!
//! # Architecture
//!
//! - **FFI to PQClean:** Direct bindings to PQClean's Falcon-512 implementation
//! - **RNG Injection:** Thread-local callback replaces `randombytes()`
//! - **Type-safe Wrapper:** Rust-friendly API with proper error handling
//! - **Deterministic:** Same seed + personalization → same keys/signatures
//!
//! # Security Properties
//!
//! - **128-bit post-quantum security** (Falcon-512)
//! - **Deterministic coins** derived from secret seed + context
//! - **Reproducible signatures** (audit-friendly, HSM/TEE compatible)
//! - **No OS RNG dependency** (full control over entropy source)
//!
//! # Example
//!
//! ```no_run
//! use falcon_seeded::{keypair_with, sign_with, verify, FillBytes};
//! use std::sync::Arc;
//!
//! // Your DRBG implementation
//! struct MyDrbg { /* ... */ }
//! impl FillBytes for MyDrbg {
//!     fn fill(&self, out: &mut [u8]) {
//!         // Fill with deterministic randomness
//!     }
//! }
//!
//! // Generate deterministic keypair
//! let drbg = Arc::new(MyDrbg {});
//! let (pk, sk) = keypair_with(drbg.clone()).unwrap();
//!
//! // Sign message deterministically
//! let signature = sign_with(drbg, &sk, b"message").unwrap();
//!
//! // Verify (standard Falcon verification)
//! assert!(verify(&pk, b"message", &signature));
//! ```

// NOTE: This crate contains necessary `unsafe` code for FFI to PQClean C implementation.
// All unsafe blocks are carefully reviewed and confined to FFI boundaries.
#![warn(missing_docs)]

use libc::{c_int, size_t};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

/// Falcon-512 public key length (bytes)
pub const PK_LEN: usize = 897;

/// Falcon-512 secret key length (bytes) - PQClean format
pub const SK_LEN: usize = 1281;

/// Falcon-512 minimum signature length (bytes)
pub const SIG_MIN_LEN: usize = 617;

/// Falcon-512 typical signature length (bytes)
pub const SIG_TYPICAL_LEN: usize = 666;

/// Falcon-512 maximum signature length (bytes)
pub const SIG_MAX_LEN: usize = 690; // ~666B typical; buffer for safety

/* ============================================================================
 * Error Types
 * ========================================================================== */

/// Falcon operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FalconError {
    /// Keypair generation failed
    KeygenFailed,
    /// Signature generation failed
    SigningFailed,
    /// Invalid signature format or length
    InvalidSignature,
    /// No RNG source available (critical security error)
    NoRngAvailable,
    /// Signature exceeds maximum allowed length
    SignatureTooLong,
}

impl std::fmt::Display for FalconError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::KeygenFailed => write!(f, "Falcon-512 keypair generation failed"),
            Self::SigningFailed => write!(f, "Falcon-512 signature generation failed"),
            Self::InvalidSignature => write!(f, "Invalid signature format or length"),
            Self::NoRngAvailable => {
                write!(f, "CRITICAL: No RNG source registered - security compromised")
            }
            Self::SignatureTooLong => write!(f, "Signature exceeds maximum length ({})", SIG_MAX_LEN),
        }
    }
}

impl std::error::Error for FalconError {}

/// Result type for Falcon operations
pub type Result<T> = std::result::Result<T, FalconError>;

/* ============================================================================
 * FFI Declarations
 * ========================================================================== */

extern "C" {
    fn tt_falcon512_keypair_seeded(
        pk: *mut u8,
        sk: *mut u8,
        fill: extern "C" fn(*mut u8, usize),
    ) -> c_int;

    fn tt_falcon512_sign_seeded(
        sig: *mut u8,
        siglen: *mut size_t,
        m: *const u8,
        mlen: size_t,
        sk: *const u8,
        fill: extern "C" fn(*mut u8, usize),
    ) -> c_int;

    fn tt_falcon512_verify(
        sig: *const u8,
        siglen: size_t,
        m: *const u8,
        mlen: size_t,
        pk: *const u8,
    ) -> c_int;
}

/* ============================================================================
 * RNG Bridge (Rust DRBG → C randombytes)
 * ========================================================================== */

/// Trait for providing random bytes to Falcon operations
///
/// Implement this for your DRBG (e.g., `KmacDrbg`)
///
/// # Security Requirements
///
/// - Must be cryptographically secure
/// - Should be seeded with sufficient entropy (≥256 bits)
/// - Must be deterministic if reproducible signatures are needed
pub trait FillBytes: Send + Sync {
    /// Fill buffer with deterministic random bytes
    ///
    /// # Panics
    ///
    /// Implementation may panic if unable to provide randomness
    fn fill(&self, out: &mut [u8]);
}

thread_local! {
    static TLS_SRC: RefCell<Option<Arc<dyn FillBytes>>> = RefCell::new(None);
}

// Global mutex for thread-safe RNG operations
// Prevents race conditions when multiple threads call keypair_with/sign_with simultaneously
static RNG_LOCK: Mutex<()> = Mutex::new(());

/// C callback adapter for RNG
///
/// # Panics
///
/// Panics if no RNG source is registered (security fail-fast)
extern "C" fn tls_fill_adapter(out: *mut u8, outlen: usize) {
    TLS_SRC.with(|slot| {
        if let Some(src) = &*slot.borrow() {
            // Safety: out is valid pointer from C, outlen is correct size
            unsafe {
                src.fill(std::slice::from_raw_parts_mut(out, outlen));
            }
        } else {
            // CRITICAL: No RNG available - panic immediately!
            // This is better than silently producing insecure output.
            // The C code also calls abort() as defense in depth.
            panic!(
                "FATAL SECURITY ERROR: No RNG source registered for Falcon operation!\n\
                 This indicates a programming error that compromises cryptographic security.\n\
                 The operation cannot continue safely."
            );
        }
    });
}

/// Execute function with RNG source in thread-local storage
///
/// # Thread Safety
///
/// Uses a global mutex to prevent race conditions when multiple threads
/// attempt to use the RNG simultaneously. This ensures that:
/// - Only one thread can set/use the TLS_SRC at a time
/// - The C callback never sees conflicting RNG sources
/// - No data races occur in the global `g_fill_bytes` pointer
///
/// # Safety
///
/// Ensures RNG is cleaned up after operation, preventing accidental reuse
fn with_src<T>(src: Arc<dyn FillBytes>, f: impl FnOnce() -> T) -> T {
    // Acquire mutex to ensure exclusive access to RNG operations
    let _guard = RNG_LOCK.lock().unwrap();

    TLS_SRC.with(|slot| {
        *slot.borrow_mut() = Some(src);
        let result = f();
        *slot.borrow_mut() = None;
        result
    })
    // Mutex is released when _guard drops
}

/* ============================================================================
 * Public API
 * ========================================================================== */

/// Generate Falcon-512 keypair with deterministic RNG
///
/// # Parameters
///
/// - `src`: DRBG implementing `FillBytes` trait
///
/// # Returns
///
/// - `Ok((pk, sk))`: Public key (897 bytes) and secret key (1281 bytes, zeroized on drop)
/// - `Err(FalconError)`: Keygen failed
///
/// # Security
///
/// - Secret key is wrapped in `Zeroizing` for automatic memory cleanup
/// - Same DRBG state produces same keypair (deterministic)
/// - DRBG should be seeded with ≥256 bits entropy
///
/// # Example
///
/// ```no_run
/// use falcon_seeded::{keypair_with, FillBytes};
/// use std::sync::Arc;
///
/// struct MyDrbg;
/// impl FillBytes for MyDrbg {
///     fn fill(&self, out: &mut [u8]) { /* ... */ }
/// }
///
/// let drbg = Arc::new(MyDrbg);
/// let (pk, sk) = keypair_with(drbg).unwrap();
/// // sk is automatically zeroized when dropped
/// ```
pub fn keypair_with(
    src: Arc<dyn FillBytes>,
) -> Result<([u8; PK_LEN], Zeroizing<[u8; SK_LEN]>)> {
    let mut pk = [0u8; PK_LEN];
    let mut sk = Zeroizing::new([0u8; SK_LEN]);

    let rc = with_src(src, || unsafe {
        tt_falcon512_keypair_seeded(pk.as_mut_ptr(), sk.as_mut_ptr(), tls_fill_adapter)
    });

    match rc {
        0 => Ok((pk, sk)),
        _ => Err(FalconError::KeygenFailed),
    }
}

/// Sign message with Falcon-512 using deterministic RNG
///
/// # Parameters
///
/// - `src`: DRBG implementing `FillBytes` trait (should be seeded with message context)
/// - `sk`: Falcon secret key (1281 bytes) - can be regular array or Zeroizing wrapper
/// - `msg`: Message to sign
///
/// # Returns
///
/// - `Ok(signature)`: Falcon signature (~666 bytes, variable length)
/// - `Err(FalconError)`: Signing failed
///
/// # Security Notes - CRITICAL!
///
/// **The DRBG must be uniquely seeded for each signature!**
///
/// Recommended seeding pattern:
/// 1. Derive PRF key from secret key
/// 2. Hash message to create transcript
/// 3. Combine PRF + transcript + unique context (nonce/epoch)
/// 4. Use as DRBG seed
///
/// **Never reuse the same DRBG state for different messages!**
///
/// # Example
///
/// ```no_run
/// use falcon_seeded::{sign_with, FillBytes};
/// use std::sync::Arc;
///
/// struct MyDrbg;
/// impl FillBytes for MyDrbg {
///     fn fill(&self, out: &mut [u8]) { /* ... */ }
/// }
///
/// let sk = [0u8; 1281]; // Your secret key
/// let drbg = Arc::new(MyDrbg); // MUST be seeded with message context!
/// let sig = sign_with(drbg, &sk, b"message").unwrap();
/// ```
pub fn sign_with<S: AsRef<[u8; SK_LEN]>>(
    src: Arc<dyn FillBytes>,
    sk: &S,
    msg: &[u8],
) -> Result<Vec<u8>> {
    let sk_bytes = sk.as_ref();
    let mut sig = vec![0u8; SIG_MAX_LEN];
    let mut siglen: usize = 0;

    let rc = with_src(src, || unsafe {
        tt_falcon512_sign_seeded(
            sig.as_mut_ptr(),
            &mut siglen as *mut usize,
            msg.as_ptr(),
            msg.len(),
            sk_bytes.as_ptr(),
            tls_fill_adapter,
        )
    });

    if rc != 0 {
        return Err(FalconError::SigningFailed);
    }

    // Validate signature length
    if siglen > SIG_MAX_LEN {
        return Err(FalconError::SignatureTooLong);
    }

    if siglen == 0 {
        return Err(FalconError::InvalidSignature);
    }

    // Additional sanity check (Falcon signatures should be in reasonable range)
    if siglen < SIG_MIN_LEN {
        return Err(FalconError::InvalidSignature);
    }

    sig.truncate(siglen);
    Ok(sig)
}

/// Verify Falcon-512 signature (standard, non-deterministic)
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
/// - `false`: Signature is invalid, malformed, or wrong length
///
/// # Example
///
/// ```no_run
/// use falcon_seeded::verify;
///
/// let pk = [0u8; 897]; // Public key
/// let msg = b"message";
/// let sig = vec![/* signature bytes */];
///
/// if verify(&pk, msg, &sig) {
///     println!("✓ Signature valid");
/// } else {
///     println!("✗ Signature invalid");
/// }
/// ```
pub fn verify(pk: &[u8; PK_LEN], msg: &[u8], sig: &[u8]) -> bool {
    // Validate signature length before FFI call
    if sig.is_empty() || sig.len() > SIG_MAX_LEN {
        return false;
    }

    // Additional sanity check
    if sig.len() < SIG_MIN_LEN {
        return false;
    }

    let rc = unsafe {
        tt_falcon512_verify(
            sig.as_ptr(),
            sig.len(),
            msg.as_ptr(),
            msg.len(),
            pk.as_ptr(),
        )
    };

    rc == 0
}

/* ============================================================================
 * Tests
 * ========================================================================== */

#[cfg(test)]
mod tests {
    use super::*;

    // Simple deterministic DRBG for testing
    struct TestDrbg {
        counter: std::sync::Mutex<u64>,
    }

    impl TestDrbg {
        fn new() -> Self {
            Self {
                counter: std::sync::Mutex::new(0),
            }
        }
    }

    impl FillBytes for TestDrbg {
        fn fill(&self, out: &mut [u8]) {
            let mut ctr = self.counter.lock().unwrap();
            for byte in out.iter_mut() {
                *byte = (*ctr & 0xFF) as u8;
                *ctr = ctr.wrapping_add(1);
            }
        }
    }

    #[test]
    #[ignore] // Requires PQClean sources
    fn test_keypair_generation() {
        let drbg = Arc::new(TestDrbg::new());
        let result = keypair_with(drbg);
        assert!(result.is_ok(), "Keypair generation should succeed");

        let (pk, sk) = result.unwrap();
        assert_eq!(pk.len(), PK_LEN);
        assert_eq!(sk.len(), SK_LEN);
    }

    #[test]
    #[ignore] // Requires PQClean sources
    fn test_sign_verify() {
        let drbg_keygen = Arc::new(TestDrbg::new());
        let (pk, sk) = keypair_with(drbg_keygen).unwrap();

        let msg = b"test message";
        let drbg_sign = Arc::new(TestDrbg::new());
        let sig = sign_with(drbg_sign, &sk, msg).unwrap();

        assert!(verify(&pk, msg, &sig), "Signature should verify");
        assert!(
            !verify(&pk, b"wrong message", &sig),
            "Wrong message should fail"
        );
    }

    #[test]
    #[ignore] // Requires PQClean sources
    fn test_deterministic_keypair() {
        use subtle::ConstantTimeEq;

        let drbg1 = Arc::new(TestDrbg::new());
        let (pk1, sk1) = keypair_with(drbg1).unwrap();

        let drbg2 = Arc::new(TestDrbg::new());
        let (pk2, sk2) = keypair_with(drbg2).unwrap();

        // Public keys can be compared normally
        assert_eq!(
            &pk1[..],
            &pk2[..],
            "Same DRBG should produce same public key"
        );

        // Secret keys should be compared in constant-time to prevent timing attacks
        assert!(
            bool::from(sk1.as_ref().ct_eq(sk2.as_ref())),
            "Same DRBG should produce same secret key (constant-time comparison)"
        );
    }

    #[test]
    #[ignore] // Requires PQClean sources
    fn test_deterministic_signing() {
        let drbg_keygen = Arc::new(TestDrbg::new());
        let (_pk, sk) = keypair_with(drbg_keygen).unwrap();

        let msg = b"deterministic test";

        // Same DRBG state should produce same signature
        let drbg1 = Arc::new(TestDrbg::new());
        let sig1 = sign_with(drbg1, &sk, msg).unwrap();

        let drbg2 = Arc::new(TestDrbg::new());
        let sig2 = sign_with(drbg2, &sk, msg).unwrap();

        assert_eq!(sig1, sig2, "Same DRBG state should produce same signature");
    }

    #[test]
    fn test_verify_rejects_invalid_length() {
        let pk = [0u8; PK_LEN];
        let msg = b"test";

        // Empty signature
        assert!(!verify(&pk, msg, &[]), "Empty signature should fail");

        // Too long signature
        let too_long = vec![0u8; SIG_MAX_LEN + 1];
        assert!(!verify(&pk, msg, &too_long), "Too long signature should fail");

        // Too short signature
        let too_short = vec![0u8; SIG_MIN_LEN - 1];
        assert!(!verify(&pk, msg, &too_short), "Too short signature should fail");
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            FalconError::KeygenFailed.to_string(),
            "Falcon-512 keypair generation failed"
        );
        assert_eq!(
            FalconError::SigningFailed.to_string(),
            "Falcon-512 signature generation failed"
        );
        assert!(FalconError::NoRngAvailable
            .to_string()
            .contains("CRITICAL"));
    }

    #[test]
    #[ignore] // Requires PQClean sources
    fn test_sk_zeroization() {
        let drbg = Arc::new(TestDrbg::new());

        // This test verifies that Zeroizing wrapper is used
        let result = keypair_with(drbg);
        assert!(result.is_ok());

        let (_pk, sk) = result.unwrap();
        // sk will be zeroized when dropped at end of scope
        drop(sk);
        // Memory should now be zeroed (can't directly test, but type guarantees it)
    }

    #[test]
    #[ignore] // Requires PQClean sources
    fn test_sign_with_regular_and_zeroizing_sk() {
        let drbg_keygen = Arc::new(TestDrbg::new());
        let (pk, sk_zeroizing) = keypair_with(drbg_keygen).unwrap();

        // Convert to regular array
        let sk_regular: [u8; SK_LEN] = *sk_zeroizing;

        let msg = b"test";

        // Sign with Zeroizing wrapper
        let drbg1 = Arc::new(TestDrbg::new());
        let sig1 = sign_with(drbg1, &sk_zeroizing, msg).unwrap();

        // Sign with regular array
        let drbg2 = Arc::new(TestDrbg::new());
        let sig2 = sign_with(drbg2, &sk_regular, msg).unwrap();

        // Both should produce same signature
        assert_eq!(sig1, sig2, "Signature should be same regardless of SK wrapper");

        // Both should verify
        assert!(verify(&pk, msg, &sig1));
        assert!(verify(&pk, msg, &sig2));
    }

    #[test]
    #[ignore] // Requires PQClean sources
    fn test_thread_safety_concurrent_operations() {
        use std::thread;

        let handles: Vec<_> = (0..4)
            .map(|i| {
                thread::spawn(move || {
                    // Each thread generates its own keypair
                    let drbg = Arc::new(TestDrbg::new());
                    let (pk, sk) = keypair_with(drbg).unwrap();

                    // Each thread signs a message
                    let msg = format!("thread {} message", i);
                    let drbg_sign = Arc::new(TestDrbg::new());
                    let sig = sign_with(drbg_sign, &sk, msg.as_bytes()).unwrap();

                    // Each thread verifies
                    assert!(verify(&pk, msg.as_bytes(), &sig));

                    (pk, sig)
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            assert!(handle.join().is_ok(), "Thread should complete successfully");
        }
    }
}
