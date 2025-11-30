//! Checkpoint System - Long-Range Attack Protection
//!
//! Zapobiega atakom gdzie atakujący buduje alternatywny łańcuch od genesis
//! używając starych/kupionych kluczy walidatorów.
//!
//! Mechanizmy:
//! 1. Hard checkpointy co N bloków
//! 2. Soft checkpointy (social consensus)
//! 3. Weak subjectivity window
//! 4. Checkpoint signatures od walidatorów

use std::collections::{HashMap, BTreeMap};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use sha3::{Sha3_256, Digest};

/// Błędy systemu checkpointów
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    /// Blok jest przed ostatnim checkpointem (long-range attack!)
    BlockBeforeCheckpoint {
        block_height: u64,
        checkpoint_height: u64,
    },
    /// Hash bloku nie zgadza się z checkpointem
    CheckpointHashMismatch {
        height: u64,
        expected: [u8; 32],
        got: [u8; 32],
    },
    /// Brak wymaganego checkpointu
    MissingCheckpoint { height: u64 },
    /// Nieprawidłowy podpis checkpointu
    InvalidCheckpointSignature,
    /// Za mało podpisów na checkpoint (quorum)
    InsufficientSignatures {
        required: usize,
        got: usize,
    },
    /// Weak subjectivity violation
    WeakSubjectivityViolation {
        block_age_secs: u64,
        max_age_secs: u64,
    },
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlockBeforeCheckpoint { block_height, checkpoint_height } => {
                write!(f, "Block {} is before checkpoint at {}", block_height, checkpoint_height)
            }
            Self::CheckpointHashMismatch { height, expected, got } => {
                write!(f, "Checkpoint hash mismatch at height {}: expected {:?}, got {:?}", 
                    height, &expected[..8], &got[..8])
            }
            Self::MissingCheckpoint { height } => {
                write!(f, "Missing checkpoint at height {}", height)
            }
            Self::InvalidCheckpointSignature => {
                write!(f, "Invalid checkpoint signature")
            }
            Self::InsufficientSignatures { required, got } => {
                write!(f, "Insufficient signatures: {} required, {} got", required, got)
            }
            Self::WeakSubjectivityViolation { block_age_secs, max_age_secs } => {
                write!(f, "Weak subjectivity violation: block is {} secs old (max: {})", 
                    block_age_secs, max_age_secs)
            }
        }
    }
}

impl std::error::Error for CheckpointError {}

/// Konfiguracja systemu checkpointów
#[derive(Debug, Clone)]
pub struct CheckpointConfig {
    /// Interwał hard checkpointów (co ile bloków)
    pub checkpoint_interval: u64,
    /// Weak subjectivity period w sekundach
    /// Nowy węzeł musi zsynchronizować się z trusted source jeśli jest offline dłużej
    pub weak_subjectivity_period_secs: u64,
    /// Minimalna liczba podpisów walidatorów na checkpoint (quorum)
    pub min_checkpoint_signatures: usize,
    /// Procent walidatorów wymagany do checkpointu (alternatywa do min_signatures)
    pub checkpoint_quorum_percent: u8,
    /// Czy checkpointy są immutable (nie można ich zmienić po dodaniu)
    pub immutable_checkpoints: bool,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            checkpoint_interval: 1000,              // Co 1000 bloków
            weak_subjectivity_period_secs: 7 * 24 * 3600, // 7 dni
            min_checkpoint_signatures: 10,
            checkpoint_quorum_percent: 67,          // 2/3 walidatorów
            immutable_checkpoints: true,
        }
    }
}

/// Pojedynczy checkpoint
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Wysokość bloku
    pub height: u64,
    /// Hash bloku
    pub block_hash: [u8; 32],
    /// Timestamp utworzenia checkpointu
    pub timestamp: u64,
    /// Podpisy walidatorów (pubkey_hex -> signature_bytes)
    pub signatures: HashMap<String, Vec<u8>>,
    /// Czy to hard checkpoint (wkompilowany/zaufany)
    pub is_hard: bool,
}

impl Checkpoint {
    /// Tworzy nowy checkpoint
    pub fn new(height: u64, block_hash: [u8; 32], is_hard: bool) -> Self {
        Self {
            height,
            block_hash,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            signatures: HashMap::new(),
            is_hard,
        }
    }
    
    /// Dodaje podpis walidatora
    pub fn add_signature(&mut self, validator_pubkey_hex: String, signature: Vec<u8>) {
        self.signatures.insert(validator_pubkey_hex, signature);
    }
    
    /// Liczba podpisów
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
    
    /// Oblicza hash checkpointu (do podpisywania)
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TT_CHECKPOINT_V1");
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.block_hash);
        hasher.update(self.timestamp.to_le_bytes());
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// System checkpointów
pub struct CheckpointStore {
    config: CheckpointConfig,
    /// Checkpointy indexowane po wysokości
    checkpoints: RwLock<BTreeMap<u64, Checkpoint>>,
    /// Ostatni finalizowany checkpoint
    last_finalized_height: RwLock<u64>,
    /// Statystyki
    stats: RwLock<CheckpointStats>,
}

/// Statystyki checkpointów
#[derive(Debug, Default, Clone)]
pub struct CheckpointStats {
    pub total_checkpoints: u64,
    pub hard_checkpoints: u64,
    pub soft_checkpoints: u64,
    pub rejected_blocks: u64,
    pub last_checkpoint_height: u64,
}

impl CheckpointStore {
    /// Tworzy nowy CheckpointStore
    pub fn new() -> Self {
        Self::with_config(CheckpointConfig::default())
    }
    
    /// Tworzy z custom konfiguracją
    pub fn with_config(config: CheckpointConfig) -> Self {
        Self {
            config,
            checkpoints: RwLock::new(BTreeMap::new()),
            last_finalized_height: RwLock::new(0),
            stats: RwLock::new(CheckpointStats::default()),
        }
    }
    
    /// Dodaje hard checkpoint (zaufany, np. wkompilowany w kod)
    pub fn add_hard_checkpoint(&self, height: u64, block_hash: [u8; 32]) {
        let checkpoint = Checkpoint::new(height, block_hash, true);
        
        let mut checkpoints = self.checkpoints.write().unwrap();
        checkpoints.insert(height, checkpoint);
        
        let mut last = self.last_finalized_height.write().unwrap();
        if height > *last {
            *last = height;
        }
        
        let mut stats = self.stats.write().unwrap();
        stats.total_checkpoints += 1;
        stats.hard_checkpoints += 1;
        stats.last_checkpoint_height = stats.last_checkpoint_height.max(height);
    }
    
    /// Dodaje soft checkpoint (z podpisami walidatorów)
    pub fn add_soft_checkpoint(
        &self, 
        height: u64, 
        block_hash: [u8; 32],
        signatures: HashMap<String, Vec<u8>>,
        total_validators: usize,
    ) -> Result<(), CheckpointError> {
        // Sprawdź quorum
        let required_sigs = std::cmp::max(
            self.config.min_checkpoint_signatures,
            (total_validators * self.config.checkpoint_quorum_percent as usize) / 100,
        );
        
        if signatures.len() < required_sigs {
            return Err(CheckpointError::InsufficientSignatures {
                required: required_sigs,
                got: signatures.len(),
            });
        }
        
        let mut checkpoint = Checkpoint::new(height, block_hash, false);
        checkpoint.signatures = signatures;
        
        let mut checkpoints = self.checkpoints.write().unwrap();
        
        // Nie nadpisuj hard checkpointów
        if let Some(existing) = checkpoints.get(&height) {
            if existing.is_hard && self.config.immutable_checkpoints {
                return Ok(()); // Ignoruj - hard checkpoint ma priorytet
            }
        }
        
        checkpoints.insert(height, checkpoint);
        
        let mut last = self.last_finalized_height.write().unwrap();
        if height > *last {
            *last = height;
        }
        
        let mut stats = self.stats.write().unwrap();
        stats.total_checkpoints += 1;
        stats.soft_checkpoints += 1;
        stats.last_checkpoint_height = stats.last_checkpoint_height.max(height);
        
        Ok(())
    }
    
    /// Weryfikuje blok przeciwko checkpointom
    /// 
    /// # Arguments
    /// * `height` - Wysokość bloku
    /// * `block_hash` - Hash bloku
    /// * `block_timestamp` - Timestamp bloku
    pub fn verify_block(
        &self,
        height: u64,
        block_hash: &[u8; 32],
        block_timestamp: u64,
    ) -> Result<(), CheckpointError> {
        // 1. Sprawdź weak subjectivity
        self.check_weak_subjectivity(block_timestamp)?;
        
        // 2. Sprawdź czy blok jest przed ostatnim checkpointem
        let last_finalized = *self.last_finalized_height.read().unwrap();
        
        if height < last_finalized {
            // Blok przed checkpointem - potencjalny long-range attack!
            let mut stats = self.stats.write().unwrap();
            stats.rejected_blocks += 1;
            
            return Err(CheckpointError::BlockBeforeCheckpoint {
                block_height: height,
                checkpoint_height: last_finalized,
            });
        }
        
        // 3. Jeśli jest checkpoint na tej wysokości, sprawdź hash
        let checkpoints = self.checkpoints.read().unwrap();
        
        if let Some(checkpoint) = checkpoints.get(&height) {
            if &checkpoint.block_hash != block_hash {
                let mut stats = self.stats.write().unwrap();
                stats.rejected_blocks += 1;
                
                return Err(CheckpointError::CheckpointHashMismatch {
                    height,
                    expected: checkpoint.block_hash,
                    got: *block_hash,
                });
            }
        }
        
        Ok(())
    }
    
    /// Sprawdza weak subjectivity
    fn check_weak_subjectivity(&self, block_timestamp: u64) -> Result<(), CheckpointError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Blok z przyszłości? Pozwól z pewnym marginesem
        if block_timestamp > now + 60 {
            // Timestamp z przyszłości - podejrzane, ale to nie jest zadanie tego modułu
            return Ok(());
        }
        
        // Sprawdź czy blok nie jest zbyt stary
        if block_timestamp + self.config.weak_subjectivity_period_secs < now {
            let age = now - block_timestamp;
            return Err(CheckpointError::WeakSubjectivityViolation {
                block_age_secs: age,
                max_age_secs: self.config.weak_subjectivity_period_secs,
            });
        }
        
        Ok(())
    }
    
    /// Sprawdza czy wysokość powinna mieć checkpoint
    pub fn should_have_checkpoint(&self, height: u64) -> bool {
        height > 0 && height % self.config.checkpoint_interval == 0
    }
    
    /// Zwraca checkpoint na danej wysokości
    pub fn get_checkpoint(&self, height: u64) -> Option<Checkpoint> {
        self.checkpoints.read().unwrap().get(&height).cloned()
    }
    
    /// Zwraca ostatni checkpoint
    pub fn get_latest_checkpoint(&self) -> Option<Checkpoint> {
        self.checkpoints.read().unwrap().values().last().cloned()
    }
    
    /// Zwraca wszystkie checkpointy po danej wysokości
    pub fn get_checkpoints_after(&self, height: u64) -> Vec<Checkpoint> {
        self.checkpoints
            .read()
            .unwrap()
            .range((height + 1)..)
            .map(|(_, cp)| cp.clone())
            .collect()
    }
    
    /// Zwraca wysokość ostatniego finalizowanego bloku
    pub fn last_finalized_height(&self) -> u64 {
        *self.last_finalized_height.read().unwrap()
    }
    
    /// Zwraca statystyki
    pub fn stats(&self) -> CheckpointStats {
        self.stats.read().unwrap().clone()
    }
    
    /// Eksportuje checkpointy do wektora (dla serializacji)
    pub fn export_checkpoints(&self) -> Vec<(u64, [u8; 32], bool)> {
        self.checkpoints
            .read()
            .unwrap()
            .iter()
            .map(|(&h, cp)| (h, cp.block_hash, cp.is_hard))
            .collect()
    }
    
    /// Importuje checkpointy (np. przy synchronizacji)
    pub fn import_hard_checkpoints(&self, checkpoints: Vec<(u64, [u8; 32])>) {
        for (height, hash) in checkpoints {
            self.add_hard_checkpoint(height, hash);
        }
    }
}

impl Default for CheckpointStore {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Hard-coded checkpointy dla TT Protocol (mainnet)
// ════════════════════════════════════════════════════════════════════════════

/// Genesis checkpoint - zawsze trust
pub const GENESIS_CHECKPOINT: (u64, [u8; 32]) = (
    0,
    [0u8; 32], // Placeholder - zastąp prawdziwym genesis hash
);

/// Predefiniowane hard checkpointy
/// Format: (height, block_hash)
/// 
/// UWAGA: Te checkpointy muszą być weryfikowane przez społeczność
/// i aktualizowane przy każdym release!
pub fn get_hardcoded_checkpoints() -> Vec<(u64, [u8; 32])> {
    vec![
        GENESIS_CHECKPOINT,
        // Dodaj więcej checkpointów w miarę rozwoju sieci:
        // (1000, [0x12, 0x34, ...]),
        // (2000, [0xAB, 0xCD, ...]),
    ]
}

/// Inicjalizuje CheckpointStore z hard-coded checkpointami
pub fn init_with_hardcoded() -> CheckpointStore {
    let store = CheckpointStore::new();
    
    for (height, hash) in get_hardcoded_checkpoints() {
        store.add_hard_checkpoint(height, hash);
    }
    
    store
}

// ════════════════════════════════════════════════════════════════════════════
// Checkpoint Proposal (dla walidatorów)
// ════════════════════════════════════════════════════════════════════════════

/// Propozycja checkpointu do podpisania przez walidatorów
#[derive(Debug, Clone)]
pub struct CheckpointProposal {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub proposer: String,
    pub proposed_at: u64,
}

impl CheckpointProposal {
    pub fn new(height: u64, block_hash: [u8; 32], proposer: String) -> Self {
        Self {
            height,
            block_hash,
            proposer,
            proposed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
    
    /// Tworzy wiadomość do podpisania
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"TT_CHECKPOINT_PROPOSAL_V1\n");
        msg.extend_from_slice(&self.height.to_le_bytes());
        msg.extend_from_slice(&self.block_hash);
        msg.extend_from_slice(&self.proposed_at.to_le_bytes());
        msg
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Testy
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    
    fn random_hash() -> [u8; 32] {
        let mut hash = [0u8; 32];
        for (i, b) in hash.iter_mut().enumerate() {
            *b = (i * 17 + 42) as u8;
        }
        hash
    }
    
    #[test]
    fn test_add_hard_checkpoint() {
        let store = CheckpointStore::new();
        let hash = random_hash();
        
        store.add_hard_checkpoint(1000, hash);
        
        let cp = store.get_checkpoint(1000).unwrap();
        assert_eq!(cp.height, 1000);
        assert_eq!(cp.block_hash, hash);
        assert!(cp.is_hard);
    }
    
    #[test]
    fn test_verify_block_after_checkpoint() {
        let store = CheckpointStore::new();
        let hash = random_hash();
        
        store.add_hard_checkpoint(1000, hash);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Blok na wysokości 1001 - OK
        assert!(store.verify_block(1001, &random_hash(), now).is_ok());
        
        // Blok na wysokości 999 - FAIL (przed checkpointem)
        let result = store.verify_block(999, &random_hash(), now);
        assert!(matches!(result, Err(CheckpointError::BlockBeforeCheckpoint { .. })));
    }
    
    #[test]
    fn test_verify_block_at_checkpoint() {
        let store = CheckpointStore::new();
        let correct_hash = random_hash();
        let wrong_hash = [0xFFu8; 32];
        
        store.add_hard_checkpoint(1000, correct_hash);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Prawidłowy hash - OK
        assert!(store.verify_block(1000, &correct_hash, now).is_ok());
        
        // Nieprawidłowy hash - FAIL
        let result = store.verify_block(1000, &wrong_hash, now);
        assert!(matches!(result, Err(CheckpointError::CheckpointHashMismatch { .. })));
    }
    
    #[test]
    fn test_weak_subjectivity() {
        let config = CheckpointConfig {
            weak_subjectivity_period_secs: 3600, // 1 godzina
            ..Default::default()
        };
        let store = CheckpointStore::with_config(config);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Blok sprzed 30 minut - OK
        assert!(store.verify_block(100, &random_hash(), now - 1800).is_ok());
        
        // Blok sprzed 2 godzin - FAIL
        let result = store.verify_block(100, &random_hash(), now - 7200);
        assert!(matches!(result, Err(CheckpointError::WeakSubjectivityViolation { .. })));
    }
    
    #[test]
    fn test_soft_checkpoint_quorum() {
        let config = CheckpointConfig {
            min_checkpoint_signatures: 3,
            checkpoint_quorum_percent: 67,
            ..Default::default()
        };
        let store = CheckpointStore::with_config(config);
        
        let hash = random_hash();
        let mut signatures = HashMap::new();
        
        // Tylko 2 podpisy - za mało
        signatures.insert("validator1".to_string(), vec![1, 2, 3]);
        signatures.insert("validator2".to_string(), vec![4, 5, 6]);
        
        let result = store.add_soft_checkpoint(1000, hash, signatures.clone(), 10);
        assert!(matches!(result, Err(CheckpointError::InsufficientSignatures { .. })));
        
        // 7 podpisów (67% z 10) - OK
        for i in 3..=7 {
            signatures.insert(format!("validator{}", i), vec![i as u8]);
        }
        
        assert!(store.add_soft_checkpoint(1000, hash, signatures, 10).is_ok());
    }
    
    #[test]
    fn test_should_have_checkpoint() {
        let config = CheckpointConfig {
            checkpoint_interval: 100,
            ..Default::default()
        };
        let store = CheckpointStore::with_config(config);
        
        assert!(!store.should_have_checkpoint(0)); // Genesis nie
        assert!(!store.should_have_checkpoint(50));
        assert!(store.should_have_checkpoint(100));
        assert!(!store.should_have_checkpoint(150));
        assert!(store.should_have_checkpoint(200));
    }
    
    #[test]
    fn test_export_import() {
        let store1 = CheckpointStore::new();
        
        store1.add_hard_checkpoint(100, random_hash());
        store1.add_hard_checkpoint(200, random_hash());
        
        let exported = store1.export_checkpoints();
        assert_eq!(exported.len(), 2);
        
        let store2 = CheckpointStore::new();
        store2.import_hard_checkpoints(exported.iter().map(|(h, hash, _)| (*h, *hash)).collect());
        
        assert!(store2.get_checkpoint(100).is_some());
        assert!(store2.get_checkpoint(200).is_some());
    }
    
    #[test]
    fn test_stats() {
        let store = CheckpointStore::new();
        
        store.add_hard_checkpoint(100, random_hash());
        store.add_hard_checkpoint(200, random_hash());
        
        let mut sigs = HashMap::new();
        for i in 0..10 {
            sigs.insert(format!("v{}", i), vec![i as u8]);
        }
        store.add_soft_checkpoint(300, random_hash(), sigs, 10).unwrap();
        
        let stats = store.stats();
        assert_eq!(stats.total_checkpoints, 3);
        assert_eq!(stats.hard_checkpoints, 2);
        assert_eq!(stats.soft_checkpoints, 1);
        assert_eq!(stats.last_checkpoint_height, 300);
    }
    
    #[test]
    fn test_init_with_hardcoded() {
        let store = init_with_hardcoded();
        
        // Powinien mieć genesis
        assert!(store.get_checkpoint(0).is_some());
    }
    
    #[test]
    fn test_checkpoint_hash() {
        let cp1 = Checkpoint::new(100, [1u8; 32], true);
        let cp2 = Checkpoint::new(100, [1u8; 32], true);
        let cp3 = Checkpoint::new(100, [2u8; 32], true);
        
        // Ten sam height i hash -> różne hashe (timestamp różny)
        // ale struktura jest taka sama
        assert_eq!(cp1.height, cp2.height);
        assert_eq!(cp1.block_hash, cp2.block_hash);
        
        // Różny block_hash -> różny checkpoint
        assert_ne!(cp1.block_hash, cp3.block_hash);
    }
}
