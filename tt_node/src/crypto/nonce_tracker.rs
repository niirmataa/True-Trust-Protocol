//! Nonce Tracker - Replay Attack Protection
//!
//! Używa Bloom Filter dla efektywnego śledzenia widzianych nonce'ów
//! + Timestamp validation dla dodatkowej ochrony
//!
//! WAŻNE: Bloom Filter może dawać false positives (odrzucić prawidłowy nonce)
//! ale NIGDY false negatives (zaakceptować widziany nonce)

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Błędy Nonce Trackera
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceError {
    /// Nonce już widziany (replay attack!)
    NonceReused,
    /// Timestamp za stary
    TimestampTooOld { age_secs: u64, max_age_secs: u64 },
    /// Timestamp z przyszłości
    TimestampInFuture { ahead_secs: u64, max_ahead_secs: u64 },
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonceReused => write!(f, "Nonce already used (potential replay attack)"),
            Self::TimestampTooOld { age_secs, max_age_secs } => {
                write!(f, "Timestamp too old: {} secs (max: {} secs)", age_secs, max_age_secs)
            }
            Self::TimestampInFuture { ahead_secs, max_ahead_secs } => {
                write!(f, "Timestamp in future: {} secs ahead (max: {} secs)", ahead_secs, max_ahead_secs)
            }
        }
    }
}

impl std::error::Error for NonceError {}

/// Konfiguracja Nonce Trackera
#[derive(Debug, Clone)]
pub struct NonceTrackerConfig {
    /// Maksymalny wiek wiadomości w sekundach (default: 300 = 5 min)
    pub max_age_secs: u64,
    /// Maksymalne wyprzedzenie timestampu w sekundach (default: 30)
    pub max_future_secs: u64,
    /// Oczekiwana liczba nonce'ów (dla sizing Bloom Filter)
    pub expected_nonces: usize,
    /// Docelowy false positive rate dla Bloom Filter
    pub target_fp_rate: f64,
    /// Interwał czyszczenia starych nonce'ów w sekundach
    pub cleanup_interval_secs: u64,
}

impl Default for NonceTrackerConfig {
    fn default() -> Self {
        Self {
            max_age_secs: 300,           // 5 minut
            max_future_secs: 30,          // 30 sekund
            expected_nonces: 1_000_000,   // 1M nonce'ów
            target_fp_rate: 0.0001,       // 0.01% false positive
            cleanup_interval_secs: 60,    // cleanup co minutę
        }
    }
}

/// Bloom Filter - probabilistyczna struktura danych
/// 
/// Gwarancje:
/// - contains() == true: element MOŻE być w zbiorze (możliwy false positive)
/// - contains() == false: element NA PEWNO nie jest w zbiorze (zero false negatives)
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: usize,
}

impl BloomFilter {
    /// Tworzy nowy Bloom Filter
    /// 
    /// # Arguments
    /// * `expected_elements` - oczekiwana liczba elementów
    /// * `fp_rate` - docelowy false positive rate (0.0 - 1.0)
    pub fn new(expected_elements: usize, fp_rate: f64) -> Self {
        // Optymalny rozmiar: m = -n*ln(p) / (ln(2)^2)
        let ln2_sq = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        let num_bits = (-(expected_elements as f64) * fp_rate.ln() / ln2_sq).ceil() as usize;
        let num_bits = std::cmp::max(num_bits, 64); // minimum 64 bits
        
        // Optymalna liczba hash functions: k = (m/n) * ln(2)
        let num_hashes = ((num_bits as f64 / expected_elements as f64) * std::f64::consts::LN_2).ceil() as usize;
        let num_hashes = std::cmp::max(num_hashes, 1);
        let num_hashes = std::cmp::min(num_hashes, 16); // max 16 hash functions
        
        let num_words = (num_bits + 63) / 64;
        
        Self {
            bits: vec![0u64; num_words],
            num_bits,
            num_hashes,
        }
    }
    
    /// Dodaje element do filtra
    pub fn insert(&mut self, item: &[u8]) {
        for i in 0..self.num_hashes {
            let bit_idx = self.hash(item, i);
            let word_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            self.bits[word_idx] |= 1u64 << bit_pos;
        }
    }
    
    /// Sprawdza czy element może być w filtrze
    /// 
    /// Returns:
    /// - true: element MOŻE być w zbiorze (lub false positive)
    /// - false: element NA PEWNO nie jest w zbiorze
    pub fn contains(&self, item: &[u8]) -> bool {
        for i in 0..self.num_hashes {
            let bit_idx = self.hash(item, i);
            let word_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            if self.bits[word_idx] & (1u64 << bit_pos) == 0 {
                return false;
            }
        }
        true
    }
    
    /// Czyści filtr
    pub fn clear(&mut self) {
        self.bits.fill(0);
    }
    
    /// Hash function używając SipHash + seed
    fn hash(&self, item: &[u8], seed: usize) -> usize {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        item.hash(&mut hasher);
        (hasher.finish() as usize) % self.num_bits
    }
    
    /// Szacowany fill rate
    pub fn fill_rate(&self) -> f64 {
        let set_bits: usize = self.bits.iter().map(|w| w.count_ones() as usize).sum();
        set_bits as f64 / self.num_bits as f64
    }
}

/// Nonce Tracker - główna struktura do ochrony przed replay attacks
///
/// ## Semantyka bezpieczeństwa
/// 
/// Ochrona anty-replay opiera się na DWÓCH mechanizmach:
/// 1. **Timestamp validation** - wiadomości starsze niż `max_age_secs` są odrzucane
/// 2. **Nonce tracking** - Bloom Filter + HashSet śledzą widziane nonce'y
///
/// ## UWAGA o cleanup
/// 
/// Gdy Bloom Filter przekroczy 50% wypełnienia, OBIE struktury są resetowane.
/// To oznacza, że replay wiadomości z "prawidłowym" timestampem (< max_age)
/// MOŻE przejść po cleanup, jeśli oryginał był przed resetem.
///
/// W praktyce to jest akceptowalne bo:
/// - Typowe max_age = 5 minut
/// - Cleanup interval = 1 minuta  
/// - Więc "okno podatności" to max ~5 minut po cleanup
///
/// Jeśli potrzebujesz silniejszej gwarancji, użyj bucketed approach
/// (osobne struktury per time-window).
pub struct NonceTracker {
    config: NonceTrackerConfig,
    /// Bloom filter dla szybkiego testu (może mieć false positives)
    bloom: RwLock<BloomFilter>,
    /// HashSet dla dokładnego testu (używany gdy Bloom zwraca true)
    exact_set: RwLock<HashSet<[u8; 16]>>,
    /// Ostatni cleanup
    last_cleanup: RwLock<Instant>,
    /// Statystyki
    stats: RwLock<NonceStats>,
}

/// Statystyki trackera
#[derive(Debug, Default, Clone)]
pub struct NonceStats {
    pub total_checked: u64,
    pub rejected_replay: u64,
    pub rejected_timestamp: u64,
    pub bloom_false_positives: u64,
    pub cleanups_performed: u64,
}

impl NonceTracker {
    /// Tworzy nowy NonceTracker z domyślną konfiguracją
    pub fn new() -> Self {
        Self::with_config(NonceTrackerConfig::default())
    }
    
    /// Tworzy NonceTracker z custom konfiguracją
    pub fn with_config(config: NonceTrackerConfig) -> Self {
        let bloom = BloomFilter::new(config.expected_nonces, config.target_fp_rate);
        
        Self {
            config,
            bloom: RwLock::new(bloom),
            exact_set: RwLock::new(HashSet::new()),
            last_cleanup: RwLock::new(Instant::now()),
            stats: RwLock::new(NonceStats::default()),
        }
    }
    
    /// Weryfikuje i rejestruje nonce
    /// 
    /// # Arguments
    /// * `nonce` - 16-bajtowy nonce
    /// * `timestamp_secs` - Unix timestamp wiadomości
    /// 
    /// # Returns
    /// * `Ok(())` - nonce jest nowy i został zarejestrowany
    /// * `Err(NonceError)` - nonce jest replay lub timestamp invalid
    pub fn check_and_register(&self, nonce: &[u8; 16], timestamp_secs: u64) -> Result<(), NonceError> {
        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_checked += 1;
        }
        
        // Sprawdź timestamp
        self.validate_timestamp(timestamp_secs)?;
        
        // Sprawdź Bloom filter (fast path)
        let bloom_hit = {
            let bloom = self.bloom.read().unwrap();
            bloom.contains(nonce)
        };
        
        if bloom_hit {
            // Bloom mówi "może być" - sprawdź dokładnie
            let exact = self.exact_set.read().unwrap();
            if exact.contains(nonce) {
                // Definitywnie widziany - replay!
                let mut stats = self.stats.write().unwrap();
                stats.rejected_replay += 1;
                return Err(NonceError::NonceReused);
            }
            // Bloom false positive
            let mut stats = self.stats.write().unwrap();
            stats.bloom_false_positives += 1;
        }
        
        // Nonce jest nowy - zarejestruj
        {
            let mut bloom = self.bloom.write().unwrap();
            bloom.insert(nonce);
        }
        {
            let mut exact = self.exact_set.write().unwrap();
            exact.insert(*nonce);
        }
        
        // Może czas na cleanup?
        self.maybe_cleanup();
        
        Ok(())
    }
    
    /// Weryfikuje timestamp
    fn validate_timestamp(&self, timestamp_secs: u64) -> Result<(), NonceError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Za stary?
        if timestamp_secs + self.config.max_age_secs < now {
            let age = now - timestamp_secs;
            let mut stats = self.stats.write().unwrap();
            stats.rejected_timestamp += 1;
            return Err(NonceError::TimestampTooOld {
                age_secs: age,
                max_age_secs: self.config.max_age_secs,
            });
        }
        
        // Z przyszłości?
        if timestamp_secs > now + self.config.max_future_secs {
            let ahead = timestamp_secs - now;
            let mut stats = self.stats.write().unwrap();
            stats.rejected_timestamp += 1;
            return Err(NonceError::TimestampInFuture {
                ahead_secs: ahead,
                max_ahead_secs: self.config.max_future_secs,
            });
        }
        
        Ok(())
    }
    
    /// Wykonuje cleanup jeśli trzeba
    fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last = self.last_cleanup.read().unwrap();
            last.elapsed() > Duration::from_secs(self.config.cleanup_interval_secs)
        };
        
        if should_cleanup {
            // Dla uproszczenia: rotujemy Bloom Filter i czyścimy exact set
            // W produkcji: użylibyśmy time-bucketed approach
            self.perform_cleanup();
        }
    }
    
    /// Wykonuje cleanup
    fn perform_cleanup(&self) {
        // Atomowo aktualizuj last_cleanup
        {
            let mut last = self.last_cleanup.write().unwrap();
            *last = Instant::now();
        }
        
        // Sprawdź fill rate Bloom Filter
        let fill_rate = {
            let bloom = self.bloom.read().unwrap();
            bloom.fill_rate()
        };
        
        // Jeśli Bloom jest > 50% pełny, zresetuj
        // (w produkcji: użyj podwójnego Bloom Filter z rotacją)
        if fill_rate > 0.5 {
            {
                let mut bloom = self.bloom.write().unwrap();
                bloom.clear();
            }
            {
                let mut exact = self.exact_set.write().unwrap();
                exact.clear();
            }
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.cleanups_performed += 1;
        }
    }
    
    /// Zwraca statystyki
    pub fn stats(&self) -> NonceStats {
        self.stats.read().unwrap().clone()
    }
    
    /// Generuje nowy unikalny nonce
    /// 
    /// UWAGA: To generuje kryptograficznie unikalny nonce,
    /// ale NIE sprawdza czy już istnieje w trackerze.
    /// Użyj `generate_fresh_nonce()` jeśli potrzebujesz gwarancji.
    pub fn generate_nonce() -> [u8; 16] {
        use crate::crypto::hardware_rng::HardwareRng;
        
        let mut nonce = [0u8; 16];
        
        // Próbuj hardware RNG
        if let Ok(mut rng) = HardwareRng::new() {
            if rng.fill_bytes(&mut nonce).is_ok() {
                return nonce;
            }
        }
        
        // Fallback: timestamp + random
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        
        nonce[0..16].copy_from_slice(&ts.to_le_bytes());
        
        // XOR z thread-local random
        let rnd = rand::random::<u128>();
        for (i, b) in rnd.to_le_bytes().iter().enumerate() {
            nonce[i] ^= b;
        }
        
        nonce
    }
    
    /// Generuje nonce który jest GWARANTOWANY jako nowy dla tego trackera.
    /// 
    /// Rejestruje nonce w trackerze przed zwrotem.
    /// Używaj tej metody jeśli potrzebujesz "atomowej" gwarancji
    /// że nonce nie był wcześniej użyty w tym trackerze.
    pub fn generate_fresh_nonce(&self) -> [u8; 16] {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        loop {
            let nonce = Self::generate_nonce();
            // Próbuj zarejestrować - jeśli sukces, nonce jest świeży
            if self.check_and_register(&nonce, now).is_ok() {
                return nonce;
            }
            // Kolizja (ekstremalnie rzadkie) - spróbuj ponownie
        }
    }
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper
pub type SharedNonceTracker = Arc<NonceTracker>;

/// Tworzy shared NonceTracker
pub fn create_shared_tracker() -> SharedNonceTracker {
    Arc::new(NonceTracker::new())
}

// ============================================================================
// Message z wbudowanym nonce i timestamp
// ============================================================================

/// Wiadomość z wbudowaną ochroną przed replay
#[derive(Debug, Clone)]
pub struct ReplayProtectedMessage {
    /// Unikalny nonce
    pub nonce: [u8; 16],
    /// Unix timestamp
    pub timestamp: u64,
    /// Payload
    pub payload: Vec<u8>,
}

impl ReplayProtectedMessage {
    /// Tworzy nową wiadomość z automatycznym nonce i timestamp
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            nonce: NonceTracker::generate_nonce(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            payload,
        }
    }
    
    /// Serializuje do bajtów
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16 + 8 + self.payload.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
    
    /// Deserializuje z bajtów
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 24 {
            return None;
        }
        
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[0..16]);
        
        let timestamp = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let payload = bytes[24..].to_vec();
        
        Some(Self {
            nonce,
            timestamp,
            payload,
        })
    }
    
    /// Weryfikuje i rejestruje w trackerze
    pub fn verify_and_register(&self, tracker: &NonceTracker) -> Result<(), NonceError> {
        tracker.check_and_register(&self.nonce, self.timestamp)
    }
}

// ============================================================================
// Testy
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bloom_filter_basic() {
        let mut bloom = BloomFilter::new(1000, 0.01);
        
        let item1 = b"test_item_1";
        let item2 = b"test_item_2";
        
        assert!(!bloom.contains(item1));
        assert!(!bloom.contains(item2));
        
        bloom.insert(item1);
        
        assert!(bloom.contains(item1));
        // item2 może lub nie może dać false positive
    }
    
    #[test]
    fn test_bloom_filter_no_false_negatives() {
        let mut bloom = BloomFilter::new(10000, 0.001);
        
        // Wstaw dużo elementów
        for i in 0u32..1000 {
            bloom.insert(&i.to_le_bytes());
        }
        
        // Wszystkie muszą być znalezione (zero false negatives)
        for i in 0u32..1000 {
            assert!(bloom.contains(&i.to_le_bytes()), 
                "Bloom filter false negative for {}", i);
        }
    }
    
    #[test]
    fn test_nonce_tracker_basic() {
        let tracker = NonceTracker::new();
        
        let nonce1 = NonceTracker::generate_nonce();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Pierwszy raz - OK
        assert!(tracker.check_and_register(&nonce1, now).is_ok());
        
        // Drugi raz - replay!
        assert_eq!(
            tracker.check_and_register(&nonce1, now),
            Err(NonceError::NonceReused)
        );
    }
    
    #[test]
    fn test_nonce_tracker_timestamp_validation() {
        let config = NonceTrackerConfig {
            max_age_secs: 60,
            max_future_secs: 10,
            ..Default::default()
        };
        let tracker = NonceTracker::with_config(config);
        
        let nonce = NonceTracker::generate_nonce();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Za stary timestamp
        let old_result = tracker.check_and_register(&nonce, now - 120);
        assert!(matches!(old_result, Err(NonceError::TimestampTooOld { .. })));
        
        // Z przyszłości
        let nonce2 = NonceTracker::generate_nonce();
        let future_result = tracker.check_and_register(&nonce2, now + 60);
        assert!(matches!(future_result, Err(NonceError::TimestampInFuture { .. })));
        
        // Prawidłowy timestamp
        let nonce3 = NonceTracker::generate_nonce();
        assert!(tracker.check_and_register(&nonce3, now).is_ok());
    }
    
    #[test]
    fn test_replay_protected_message() {
        let tracker = NonceTracker::new();
        
        let msg = ReplayProtectedMessage::new(b"hello world".to_vec());
        
        // Serialize/deserialize
        let bytes = msg.to_bytes();
        let msg2 = ReplayProtectedMessage::from_bytes(&bytes).unwrap();
        
        assert_eq!(msg.nonce, msg2.nonce);
        assert_eq!(msg.timestamp, msg2.timestamp);
        assert_eq!(msg.payload, msg2.payload);
        
        // First verification - OK
        assert!(msg.verify_and_register(&tracker).is_ok());
        
        // Replay - fail
        assert!(msg.verify_and_register(&tracker).is_err());
    }
    
    #[test]
    fn test_nonce_uniqueness() {
        let nonces: Vec<[u8; 16]> = (0..1000)
            .map(|_| NonceTracker::generate_nonce())
            .collect();
        
        // Wszystkie muszą być unikalne
        let unique: HashSet<[u8; 16]> = nonces.iter().cloned().collect();
        assert_eq!(unique.len(), nonces.len(), "Generated nonces should be unique");
    }
    
    #[test]
    fn test_stats() {
        let tracker = NonceTracker::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Check kilka nonce'ów
        for _ in 0..10 {
            let nonce = NonceTracker::generate_nonce();
            let _ = tracker.check_and_register(&nonce, now);
        }
        
        let stats = tracker.stats();
        assert_eq!(stats.total_checked, 10);
    }
}
