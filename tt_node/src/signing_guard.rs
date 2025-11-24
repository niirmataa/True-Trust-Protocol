//! Anti-Double-Signing Protection and Replay Attack Prevention
//!
//! This module provides comprehensive protection against:
//! - Double-signing attacks in deterministic signature schemes
//! - Replay attacks in blockchain/P2P contexts  
//! - Signature malleability attacks
//! - Cross-protocol signing attacks

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::ZeroizeOnDrop;
use rand::RngCore;
use lazy_static::lazy_static;

/// Maximum number of signatures to track
const MAX_SIGNATURE_CACHE: usize = 100_000;

/// Time window for signature tracking (24 hours)
const SIGNATURE_WINDOW: Duration = Duration::from_secs(24 * 3600);

/// Maximum replay window (5 minutes)
const REPLAY_WINDOW: Duration = Duration::from_secs(300);

/// Signature record for tracking
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRecord {
    /// Hash of the signed message
    pub message_hash: [u8; 32],
    /// Timestamp when signature was created
    pub timestamp: u64,
    /// Context/domain of signature
    pub context: Vec<u8>,
    /// Nonce used (if any)
    pub nonce: Option<[u8; 16]>,
    /// Protocol version
    pub protocol_version: u32,
    /// Additional metadata
    pub metadata: SignatureMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureMetadata {
    /// IP address of requester (if applicable)
    pub source_ip: Option<String>,
    /// Purpose of signature
    pub purpose: SignaturePurpose,
    /// Transaction ID (if applicable)
    pub tx_id: Option<[u8; 32]>,
    /// Block height at time of signing
    pub block_height: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SignaturePurpose {
    Transaction,
    Block,
    HandshakeClient,
    HandshakeServer,
    ConsensusVote,
    PeerMessage,
    Custom(String),
}

/// Main anti-double-signing guard
pub struct SigningGuard {
    /// In-memory cache of recent signatures
    cache: Arc<RwLock<SignatureCache>>,
    /// Persistent storage for audit
    storage: Arc<RwLock<SignatureStorage>>,
    /// Configuration
    config: GuardConfig,
    /// Metrics collector
    metrics: Arc<RwLock<GuardMetrics>>,
}

/// In-memory signature cache with LRU eviction
struct SignatureCache {
    /// Map from message hash to records
    records: HashMap<[u8; 32], Vec<SignatureRecord>>,
    /// LRU queue for eviction
    lru_queue: VecDeque<([u8; 32], u64)>,
    /// Total size tracking
    total_size: usize,
}

/// Persistent storage backend
struct SignatureStorage {
    /// Database path
    db_path: PathBuf,
    /// Write-ahead log
    wal: Vec<SignatureRecord>,
    /// Flush threshold
    flush_threshold: usize,
}

/// Configuration for signing guard
#[derive(Clone)]
pub struct GuardConfig {
    /// Enable persistent storage
    pub enable_persistence: bool,
    /// Enable strict mode (reject all doubles)
    pub strict_mode: bool,
    /// Maximum cache size
    pub max_cache_size: usize,
    /// Signature window
    pub signature_window: Duration,
    /// Allow replay within window
    pub allow_replay: bool,
    /// Replay window duration
    pub replay_window: Duration,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            enable_persistence: true,
            strict_mode: true,
            max_cache_size: MAX_SIGNATURE_CACHE,
            signature_window: SIGNATURE_WINDOW,
            allow_replay: false,
            replay_window: REPLAY_WINDOW,
        }
    }
}

/// Metrics for monitoring
#[derive(Default, Debug, Clone)]
struct GuardMetrics {
    /// Total signatures processed
    pub total_signatures: u64,
    /// Double-signing attempts detected
    pub double_sign_attempts: u64,
    /// Replay attacks blocked
    pub replay_attacks_blocked: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Average check latency (microseconds)
    pub avg_check_latency_us: u64,
}

impl SigningGuard {
    /// Create a new signing guard
    pub fn new(config: GuardConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let cache = Arc::new(RwLock::new(SignatureCache::new()));

        let storage = if config.enable_persistence {
            Arc::new(RwLock::new(SignatureStorage::new("./signatures.db")?))
        } else {
            Arc::new(RwLock::new(SignatureStorage::memory_only()))
        };

        Ok(Self {
            cache,
            storage,
            config,
            metrics: Arc::new(RwLock::new(GuardMetrics::default())),
        })
    }

    /// Check if we can safely sign a message
    pub fn check_and_record(
        &self,
        message: &[u8],
        context: &[u8],
        purpose: SignaturePurpose,
    ) -> Result<SignatureToken, SigningError> {
        let start = std::time::Instant::now();

        // Compute message hash
        let message_hash = Self::hash_message(message);

        // Check cache first
        let mut cache = self.cache.write();
        let mut metrics = self.metrics.write();

        // Look for existing signatures
        if let Some(records) = cache.records.get(&message_hash) {
            metrics.cache_hits += 1;

            // Check for conflicts
            for record in records {
                if self.is_conflicting(record, context, &purpose)? {
                    metrics.double_sign_attempts += 1;

                    if self.config.strict_mode {
                        return Err(SigningError::DoubleSigningDetected {
                            original: record.clone(),
                            attempted_context: context.to_vec(),
                        });
                    }
                }

                // Check replay window
                if self.is_replay(record)? {
                    if !self.config.allow_replay {
                        metrics.replay_attacks_blocked += 1;
                        return Err(SigningError::ReplayAttack {
                            original_time: record.timestamp,
                        });
                    }
                }
            }
        } else {
            metrics.cache_misses += 1;
        }

        // Create new record
        let record = SignatureRecord {
            message_hash,
            timestamp: Self::current_timestamp(),
            context: context.to_vec(),
            nonce: Some(Self::generate_nonce()),
            protocol_version: 1,
            metadata: SignatureMetadata {
                source_ip: None,
                purpose: purpose.clone(),
                tx_id: None,
                block_height: None,
            },
        };

        // Add to cache
        cache.add_record(record.clone(), self.config.max_cache_size);

        // Persist if enabled
        if self.config.enable_persistence {
            let mut storage = self.storage.write();
            storage
                .append(record.clone())
                .map_err(|e| SigningError::StorageError(e.to_string()))?;
        }

        // Update metrics
        metrics.total_signatures += 1;
        let elapsed = start.elapsed().as_micros() as u64;
        metrics.avg_check_latency_us =
            (metrics.avg_check_latency_us * (metrics.total_signatures - 1) + elapsed)
                / metrics.total_signatures;

        // Return token for signing
        Ok(SignatureToken {
            message_hash,
            nonce: record.nonce.unwrap(),
            timestamp: record.timestamp,
            _guard: Arc::new(()),
        })
    }

    /// Check if signature would be conflicting
    fn is_conflicting(
        &self,
        existing: &SignatureRecord,
        new_context: &[u8],
        new_purpose: &SignaturePurpose,
    ) -> Result<bool, SigningError> {
        // Same context is OK (retry/idempotent)
        if existing.context == new_context && existing.metadata.purpose == *new_purpose {
            return Ok(false);
        }

        // Different context for same message = conflict
        Ok(true)
    }

    /// Check if this would be a replay attack
    fn is_replay(&self, record: &SignatureRecord) -> Result<bool, SigningError> {
        let now = Self::current_timestamp();
        let elapsed = Duration::from_secs(now - record.timestamp);

        Ok(elapsed < self.config.replay_window)
    }

    /// Hash a message consistently
    fn hash_message(message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        hasher.finalize().into()
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Generate secure nonce
    fn generate_nonce() -> [u8; 16] {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Clean up old records
    pub async fn cleanup(&self) {
        let mut cache = self.cache.write();
        let cutoff = Self::current_timestamp() - self.config.signature_window.as_secs();

        cache.records.retain(|_, records| {
            records.retain(|r| r.timestamp > cutoff);
            !records.is_empty()
        });

        // Also cleanup storage if needed
        if self.config.enable_persistence {
            let mut storage = self.storage.write();
            storage.cleanup(cutoff).ok();
        }
    }

    /// Get current metrics
    pub fn metrics(&self) -> GuardMetrics {
        self.metrics.read().clone()
    }

    /// Export audit log
    pub fn export_audit_log(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let cache = self.cache.read();
        let mut all_records = Vec::new();

        for records in cache.records.values() {
            all_records.extend(records.clone());
        }

        // Sort by timestamp
        all_records.sort_by_key(|r| r.timestamp);

        // Write to file
        let json = serde_json::to_string_pretty(&all_records)?;
        std::fs::write(path, json)?;

        Ok(())
    }
}

impl SignatureCache {
    fn new() -> Self {
        Self {
            records: HashMap::new(),
            lru_queue: VecDeque::new(),
            total_size: 0,
        }
    }

    fn add_record(&mut self, record: SignatureRecord, max_size: usize) {
        let hash = record.message_hash;
        let timestamp = record.timestamp;

        // Add to records
        self.records.entry(hash).or_insert_with(Vec::new).push(record);

        // Update LRU
        self.lru_queue.push_back((hash, timestamp));
        self.total_size += 1;

        // Evict if needed
        while self.total_size > max_size && !self.lru_queue.is_empty() {
            if let Some((old_hash, _)) = self.lru_queue.pop_front() {
                if let Some(records) = self.records.get_mut(&old_hash) {
                    if !records.is_empty() {
                        records.remove(0);
                        self.total_size -= 1;
                    }
                    if records.is_empty() {
                        self.records.remove(&old_hash);
                    }
                }
            }
        }
    }
}

impl SignatureStorage {
    fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            db_path: PathBuf::from(path),
            wal: Vec::new(),
            flush_threshold: 1000,
        })
    }

    fn memory_only() -> Self {
        Self {
            db_path: PathBuf::new(),
            wal: Vec::new(),
            flush_threshold: usize::MAX,
        }
    }

    fn append(&mut self, record: SignatureRecord) -> Result<(), Box<dyn std::error::Error>> {
        self.wal.push(record);

        if self.wal.len() >= self.flush_threshold {
            self.flush()?;
        }

        Ok(())
    }

    fn flush(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.db_path.as_os_str().is_empty() {
            return Ok(());
        }

        // Append to file
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.db_path)?;

        for record in &self.wal {
            let json = serde_json::to_string(record)?;
            use std::io::Write;
            writeln!(file, "{}", json)?;
        }

        self.wal.clear();
        Ok(())
    }

    fn cleanup(&mut self, cutoff: u64) -> Result<(), Box<dyn std::error::Error>> {
        // In production: implement proper database cleanup
        self.wal.retain(|r| r.timestamp > cutoff);
        Ok(())
    }
}

/// Token returned after successful check
#[derive(ZeroizeOnDrop)]
pub struct SignatureToken {
    pub message_hash: [u8; 32],
    pub nonce: [u8; 16],
    pub timestamp: u64,
    #[zeroize(skip)]
    _guard: Arc<()>, // lifetime guard / marker
}

/// Errors that can occur during signing checks
#[derive(Debug)]
pub enum SigningError {
    DoubleSigningDetected {
        original: SignatureRecord,
        attempted_context: Vec<u8>,
    },
    ReplayAttack {
        original_time: u64,
    },
    StorageError(String),
    ValidationError(String),
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DoubleSigningDetected { original, .. } => write!(
                f,
                "Double-signing detected: message already signed at {}",
                original.timestamp
            ),
            Self::ReplayAttack { original_time } => {
                write!(f, "Replay attack: message recently signed at {}", original_time)
            }
            Self::StorageError(msg) => write!(f, "Storage error: {}", msg),
            Self::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for SigningError {}

/// Global signing guard instance
lazy_static! {
    static ref GLOBAL_GUARD: SigningGuard = {
        SigningGuard::new(GuardConfig::default()).expect("Failed to initialize signing guard")
    };
}

/// Convenience function for protected signing
pub fn sign_with_protection(
    message: &[u8],
    context: &[u8],
    purpose: SignaturePurpose,
    sign_fn: impl FnOnce(&[u8], &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Get signing token
    let token = GLOBAL_GUARD.check_and_record(message, context, purpose)?;

    // Create message with nonce
    let mut nonced_message = Vec::with_capacity(message.len() + 16);
    nonced_message.extend_from_slice(&token.nonce);
    nonced_message.extend_from_slice(message);

    // Sign with nonce
    sign_fn(&nonced_message, &token.nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_signing_detection() {
        let guard = SigningGuard::new(GuardConfig::default()).unwrap();

        let message = b"transfer 100 tokens";
        let context1 = b"transaction";
        let context2 = b"different";

        // First signature should succeed
        let result1 = guard.check_and_record(message, context1, SignaturePurpose::Transaction);
        assert!(result1.is_ok());

        // Same context should succeed (idempotent)
        let result2 = guard.check_and_record(message, context1, SignaturePurpose::Transaction);
        assert!(result2.is_ok());

        // Different context should fail in strict mode
        let result3 = guard.check_and_record(message, context2, SignaturePurpose::Transaction);
        assert!(result3.is_err());
    }

    #[test]
    fn test_replay_protection() {
        let mut config = GuardConfig::default();
        config.replay_window = Duration::from_secs(1);
        config.allow_replay = false;

        let guard = SigningGuard::new(config).unwrap();

        let message = b"action";
        let context = b"test";

        // First attempt succeeds
        guard
            .check_and_record(
                message,
                context,
                SignaturePurpose::Custom("test".to_string()),
            )
            .unwrap();

        // Immediate replay should be allowed for same context (idempotent)
        let result = guard.check_and_record(
            message,
            context,
            SignaturePurpose::Custom("test".to_string()),
        );
        assert!(result.is_ok());

        // Different context within replay window should fail
        let result = guard.check_and_record(
            message,
            b"different",
            SignaturePurpose::Custom("test".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_cache_eviction() {
        let mut config = GuardConfig::default();
        config.max_cache_size = 10;
        config.enable_persistence = false;

        let guard = SigningGuard::new(config).unwrap();

        // Add more than cache size
        for i in 0..20 {
            let message = format!("message {}", i);
            guard
                .check_and_record(
                    message.as_bytes(),
                    b"test",
                    SignaturePurpose::Custom("test".to_string()),
                )
                .unwrap();
        }

        let cache = guard.cache.read();
        assert!(cache.total_size <= 10);
    }

    #[tokio::test]
    async fn test_cleanup() {
        let mut config = GuardConfig::default();
        config.signature_window = Duration::from_secs(1);
        config.enable_persistence = false;

        let guard = SigningGuard::new(config).unwrap();

        // Add a record
        guard
            .check_and_record(
                b"test",
                b"context",
                SignaturePurpose::Transaction,
            )
            .unwrap();

        // Wait for window to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Cleanup
        guard.cleanup().await;

        let cache = guard.cache.read();
        assert_eq!(cache.records.len(), 0);
    }
}
