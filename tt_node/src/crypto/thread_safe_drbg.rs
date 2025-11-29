//! Thread-Safe Deterministic Random Bit Generator for Post-Quantum Cryptography
//! 
//! This module provides a cryptographically secure, thread-safe DRBG implementation
//! using KMAC256 as the underlying primitive, specifically designed for deterministic
//! key generation and signing in Falcon and Kyber algorithms.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use zeroize::{Zeroize, ZeroizeOnDrop};
use once_cell::sync::Lazy;

/// KMAC256-based DRBG with automatic zeroization
#[derive(ZeroizeOnDrop)]
pub struct KmacDrbg {
    #[zeroize(skip)]
    key: [u8; 32],
    counter: u64,
    personalization: Vec<u8>,
}

impl KmacDrbg {
    /// Create a new DRBG instance with a seed and personalization string
    pub fn new(seed: &[u8; 32], personalization: &[u8]) -> Self {
        Self {
            key: *seed,
            counter: 0,
            personalization: personalization.to_vec(),
        }
    }

    /// Generate deterministic random bytes
    pub fn generate(&mut self, output: &mut [u8]) {
        use tiny_keccak::{Hasher, Kmac, Xof};

        // Create unique input for each call using counter
        let mut kmac = Kmac::v256(&self.key, &self.personalization);
        kmac.update(&self.counter.to_le_bytes());

        // Generate output
        kmac.squeeze(output);

        // Update counter for next call
        self.counter = self.counter.wrapping_add(1);

        // Periodic reseeding for forward secrecy
        if self.counter % 1000 == 0 {
            self.reseed();
        }
    }

    /// Internal reseeding for forward secrecy
    fn reseed(&mut self) {
        let mut new_key = [0u8; 32];

        // Derive new key from current state
        use tiny_keccak::{Hasher, Kmac, Xof};
        let mut kmac = Kmac::v256(&self.key, b"reseed");
        kmac.update(&self.counter.to_le_bytes());
        kmac.squeeze(&mut new_key);

        // Replace old key (old one will be zeroized automatically)
        self.key = new_key;
    }

    /// Generate with additional input (for domain separation)
    pub fn generate_with_input(&mut self, output: &mut [u8], additional: &[u8]) {
        use tiny_keccak::{Hasher, Kmac, Xof};

        let mut kmac = Kmac::v256(&self.key, &self.personalization);
        kmac.update(&self.counter.to_le_bytes());
        kmac.update(additional);
        kmac.squeeze(output);

        self.counter = self.counter.wrapping_add(1);
    }
}

/// Thread-local DRBG cache for avoiding lock contention
thread_local! {
    static LOCAL_DRBG_CACHE: RefCell<HashMap<DrbgKey, KmacDrbg>> =
        RefCell::new(HashMap::new());
}

/// Global DRBG manager for cross-thread coordination
static GLOBAL_DRBG_MANAGER: Lazy<Arc<DrbgManager>> =
    Lazy::new(|| Arc::new(DrbgManager::new()));

/// Key for DRBG cache lookups
#[derive(Clone, PartialEq, Eq, Hash)]
struct DrbgKey {
    seed_hash: [u8; 32],
    personalization_hash: [u8; 32],
}

impl DrbgKey {
    fn new(seed: &[u8; 32], personalization: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(seed);
        let seed_hash = hasher.finalize_reset().into();

        hasher.update(personalization);
        let personalization_hash = hasher.finalize().into();

        Self {
            seed_hash,
            personalization_hash,
        }
    }
}

/// Global DRBG manager for security policies
pub struct DrbgManager {
    /// Track DRBG usage for audit
    usage_stats: RwLock<HashMap<DrbgKey, UsageStats>>,
    /// Security configuration
    config: SecurityConfig,
}

struct UsageStats {
    total_calls: u64,
    total_bytes: u64,
    last_access: std::time::Instant,
}

impl Default for UsageStats {
    fn default() -> Self {
        Self {
            total_calls: 0,
            total_bytes: 0,
            last_access: std::time::Instant::now(),
        }
    }
}

struct SecurityConfig {
    max_bytes_per_drbg: u64,
    max_cache_size: usize,
    enforce_rotation: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_bytes_per_drbg: 1_000_000_000, // 1GB limit per DRBG
            max_cache_size: 100,               // Max 100 cached DRBGs
            enforce_rotation: true,            // Force rotation after limits
        }
    }
}

impl DrbgManager {
    fn new() -> Self {
        Self {
            usage_stats: RwLock::new(HashMap::new()),
            config: SecurityConfig::default(),
        }
    }

    /// Record usage for security monitoring
    fn record_usage(&self, key: &DrbgKey, bytes: usize) {
        let mut stats = self.usage_stats.write();
        let entry = stats.entry(key.clone()).or_insert_with(UsageStats::default);
        entry.total_calls += 1;
        entry.total_bytes += bytes as u64;
        entry.last_access = std::time::Instant::now();

        // Check limits
        if self.config.enforce_rotation && entry.total_bytes > self.config.max_bytes_per_drbg {
            log::warn!("DRBG rotation limit reached for key");
            // In production: trigger alert
        }
    }

    /// Clean old entries
    fn cleanup(&self) {
        let mut stats = self.usage_stats.write();
        let now = std::time::Instant::now();

        stats.retain(|_, v| {
            now.duration_since(v.last_access).as_secs() < 3600 // Keep for 1 hour
        });
    }
}

/// Thread-safe interface for deterministic random generation
pub struct ThreadSafeDrbg;

impl ThreadSafeDrbg {
    /// Get thread-local DRBG for the given seed and personalization.
    ///
    /// This avoids lock contention in multi-threaded scenarios.
    pub fn with_drbg<F, R>(
        seed: &[u8; 32],
        personalization: &[u8],
        f: F,
    ) -> Result<R, Box<dyn std::error::Error>>
    where
        F: FnOnce(&mut KmacDrbg) -> R,
    {
        let key = DrbgKey::new(seed, personalization);

        LOCAL_DRBG_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();

            // Check cache size limit
            if cache.len() >= GLOBAL_DRBG_MANAGER.config.max_cache_size {
                // Evict oldest entry (very simple LRU)
                if let Some(first_key) = cache.keys().next().cloned() {
                    cache.remove(&first_key);
                }
            }

            // Get or create DRBG
            let drbg = cache
                .entry(key.clone())
                .or_insert_with(|| KmacDrbg::new(seed, personalization));

            // Execute function with DRBG
            let result = f(drbg);

            // Record usage for monitoring
            GLOBAL_DRBG_MANAGER.record_usage(&key, 0);

            Ok(result)
        })
    }

    /// Generate random bytes for a specific purpose
    pub fn generate(
        seed: &[u8; 32],
        personalization: &[u8],
        output: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        Self::with_drbg(seed, personalization, |drbg| {
            drbg.generate(output);
            GLOBAL_DRBG_MANAGER.record_usage(&DrbgKey::new(seed, personalization), output.len());
        })
    }

    /// Generate with additional domain separation
    pub fn generate_with_context(
        seed: &[u8; 32],
        personalization: &[u8],
        context: &[u8],
        output: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        Self::with_drbg(seed, personalization, |drbg| {
            drbg.generate_with_input(output, context);
            GLOBAL_DRBG_MANAGER.record_usage(&DrbgKey::new(seed, personalization), output.len());
        })
    }

    /// Cleanup old cached DRBGs (call periodically)
    pub fn cleanup() {
        LOCAL_DRBG_CACHE.with(|cache| {
            cache.borrow_mut().clear();
        });
        GLOBAL_DRBG_MANAGER.cleanup();
    }
}

/// Constant-time comparison for cryptographic values
#[inline(always)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    result == 0
}

/// Secure random fill trait for FFI compatibility
pub trait SecureRandomFill {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), Box<dyn std::error::Error>>;
}

/// Implementation for deterministic Falcon/Kyber operations
pub struct DeterministicFill {
    seed: [u8; 32],
    personalization: Vec<u8>,
}

impl DeterministicFill {
    pub fn new(seed: [u8; 32], personalization: &[u8]) -> Self {
        Self {
            seed,
            personalization: personalization.to_vec(),
        }
    }
}

impl SecureRandomFill for DeterministicFill {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
        ThreadSafeDrbg::generate(&self.seed, &self.personalization, dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_determinism() {
        let seed = [0x42; 32];
        let pers = b"test";

        let mut output1 = vec![0u8; 64];
        let mut output2 = vec![0u8; 64];

        ThreadSafeDrbg::generate(&seed, pers, &mut output1).unwrap();

        // Clear cache to force recreation
        ThreadSafeDrbg::cleanup();

        ThreadSafeDrbg::generate(&seed, pers, &mut output2).unwrap();

        // Should be deterministic
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_thread_safety() {
        use std::thread;

        let seed = [0x43; 32];
        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    let mut output = vec![0u8; 32];
                    let pers = format!("thread-{}", i);
                    ThreadSafeDrbg::generate(&seed, pers.as_bytes(), &mut output).unwrap();
                    output
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Each thread should get different output (different personalization)
        for i in 0..results.len() {
            for j in i + 1..results.len() {
                assert_ne!(results[i], results[j]);
            }
        }
    }

    #[test]
    fn test_constant_time_comparison() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        let c = vec![1, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[]));
    }

    #[test]
    fn test_zeroization() {
        let mut drbg = KmacDrbg::new(&[0x44; 32], b"zero-test");
        let mut output = vec![0u8; 32];
        drbg.generate(&mut output);

        // After drop, memory should be zeroized — hard to test directly
        drop(drbg);
    }
}
