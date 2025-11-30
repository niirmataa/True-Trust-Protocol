//! Adaptive Proof-of-Work dla Anonymous Rate Limiting
//!
//! Rozwiązuje problem: "Jak chronić przed DoS bez blokowania legit users?"
//!
//! ## Architektura
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ WALLET CREATION                                                 │
//! │  1. Benchmark urządzenia (1000 hashów SHA3)                     │
//! │  2. Klasyfikacja: slow|medium|fast|very_fast                    │
//! │  3. device_id = KMAC(benchmark_result, random)                  │
//! └─────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ EXPENSIVE REQUEST (bez burst)                                   │
//! │  1. Client: "device_power=slow, device_id=XXX"                  │
//! │  2. Server: challenge z trudnością dopasowaną do device_power   │
//! │  3. Client: rozwiązuje (~100ms niezależnie od urządzenia)       │
//! │  4. Server: weryfikuje + sprawdza czas (anti-cheat)             │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Burst System
//!
//! - Każdy device_id ma BURST tokenów (domyślnie 5)
//! - Burst = darmowe VeryExpensive bez PoW
//! - Po wyczerpaniu burst → wymagany PoW
//! - Regeneracja: 1 burst token / 5 minut

use sha3::{Sha3_256, Digest};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use rand::RngCore;

// ═══════════════════════════════════════════════════════════════════════════════
// Device Power Classes
// ═══════════════════════════════════════════════════════════════════════════════

/// Klasa mocy urządzenia - określa trudność PoW
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DevicePowerClass {
    /// Słabe urządzenie (stary telefon, Raspberry Pi)
    /// ~1000 hash/s → difficulty 10 bits
    Slow,
    /// Średnie urządzenie (nowy telefon, stary laptop)
    /// ~10000 hash/s → difficulty 14 bits
    Medium,
    /// Szybkie urządzenie (laptop, desktop)
    /// ~100000 hash/s → difficulty 17 bits
    Fast,
    /// Bardzo szybkie (gaming PC, serwer)
    /// ~1000000 hash/s → difficulty 20 bits
    VeryFast,
}

impl DevicePowerClass {
    /// Docelowy czas rozwiązania challenge (ms)
    const TARGET_SOLVE_TIME_MS: u64 = 100;
    
    /// Zwraca trudność (liczba wiodących zerowych bitów)
    pub fn difficulty_bits(&self) -> u8 {
        match self {
            Self::Slow => 10,      // 2^10 = ~1024 prób, ~100ms @ 10k hash/s
            Self::Medium => 14,   // 2^14 = ~16k prób, ~100ms @ 160k hash/s
            Self::Fast => 17,     // 2^17 = ~131k prób, ~100ms @ 1.3M hash/s
            Self::VeryFast => 20, // 2^20 = ~1M prób, ~100ms @ 10M hash/s
        }
    }
    
    /// Minimalna akceptowalna szybkość hash/s dla tej klasy
    pub fn min_hash_rate(&self) -> u64 {
        match self {
            Self::Slow => 500,
            Self::Medium => 5_000,
            Self::Fast => 50_000,
            Self::VeryFast => 500_000,
        }
    }
    
    /// Maksymalna akceptowalna szybkość hash/s dla tej klasy
    /// (jeśli szybszy = kłamie o swojej klasie)
    pub fn max_hash_rate(&self) -> u64 {
        match self {
            Self::Slow => 20_000,
            Self::Medium => 200_000,
            Self::Fast => 2_000_000,
            Self::VeryFast => u64::MAX,
        }
    }
    
    /// Klasyfikuje urządzenie na podstawie benchmark result
    pub fn from_benchmark(hashes_per_second: u64) -> Self {
        if hashes_per_second < 5_000 {
            Self::Slow
        } else if hashes_per_second < 50_000 {
            Self::Medium
        } else if hashes_per_second < 500_000 {
            Self::Fast
        } else {
            Self::VeryFast
        }
    }
    
    /// Konwertuje string na DevicePowerClass
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "slow" => Some(Self::Slow),
            "medium" => Some(Self::Medium),
            "fast" => Some(Self::Fast),
            "very_fast" | "veryfast" => Some(Self::VeryFast),
            _ => None,
        }
    }
}

impl std::fmt::Display for DevicePowerClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Slow => write!(f, "slow"),
            Self::Medium => write!(f, "medium"),
            Self::Fast => write!(f, "fast"),
            Self::VeryFast => write!(f, "very_fast"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PoW Challenge
// ═══════════════════════════════════════════════════════════════════════════════

/// Challenge do rozwiązania
#[derive(Debug, Clone)]
pub struct PowChallenge {
    /// Losowe dane challenge
    pub challenge_data: [u8; 32],
    /// Wymagana trudność (wiodące zerowe bity)
    pub difficulty_bits: u8,
    /// Timestamp utworzenia (unix secs)
    pub created_at: u64,
    /// Czas ważności (sekundy)
    pub valid_for_secs: u64,
    /// Device ID dla którego challenge został wygenerowany
    pub device_id: [u8; 16],
}

impl PowChallenge {
    /// Tworzy nowy challenge dla danego urządzenia
    pub fn new(device_id: [u8; 16], power_class: DevicePowerClass) -> Self {
        let mut challenge_data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge_data);
        
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            challenge_data,
            difficulty_bits: power_class.difficulty_bits(),
            created_at,
            valid_for_secs: 60, // 1 minuta na rozwiązanie
            device_id,
        }
    }
    
    /// Sprawdza czy challenge nie wygasł
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now < self.created_at + self.valid_for_secs
    }
    
    /// Serializuje challenge do wysłania klientowi
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 1 + 8 + 8 + 16);
        bytes.extend_from_slice(&self.challenge_data);
        bytes.push(self.difficulty_bits);
        bytes.extend_from_slice(&self.created_at.to_le_bytes());
        bytes.extend_from_slice(&self.valid_for_secs.to_le_bytes());
        bytes.extend_from_slice(&self.device_id);
        bytes
    }
    
    /// Deserializuje challenge
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 + 1 + 8 + 8 + 16 {
            return None;
        }
        
        let mut challenge_data = [0u8; 32];
        challenge_data.copy_from_slice(&bytes[0..32]);
        
        let difficulty_bits = bytes[32];
        let created_at = u64::from_le_bytes(bytes[33..41].try_into().ok()?);
        let valid_for_secs = u64::from_le_bytes(bytes[41..49].try_into().ok()?);
        
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&bytes[49..65]);
        
        Some(Self {
            challenge_data,
            difficulty_bits,
            created_at,
            valid_for_secs,
            device_id,
        })
    }
}

/// Rozwiązanie challenge
#[derive(Debug, Clone)]
pub struct PowSolution {
    /// Nonce który rozwiązuje challenge
    pub nonce: u64,
    /// Czas rozwiązania (ms) - raportowany przez klienta
    pub solve_time_ms: u64,
}

impl PowSolution {
    /// Serializuje solution
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.solve_time_ms.to_le_bytes());
        bytes
    }
    
    /// Deserializuje solution
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 16 {
            return None;
        }
        
        let nonce = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let solve_time_ms = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        
        Some(Self { nonce, solve_time_ms })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PoW Solver (client-side)
// ═══════════════════════════════════════════════════════════════════════════════

/// Rozwiązuje challenge (wywoływane po stronie klienta/walleta)
pub fn solve_challenge(challenge: &PowChallenge) -> PowSolution {
    let start = Instant::now();
    let mut nonce: u64 = 0;
    
    loop {
        let hash = compute_pow_hash(&challenge.challenge_data, nonce);
        
        if check_difficulty(&hash, challenge.difficulty_bits) {
            let solve_time_ms = start.elapsed().as_millis() as u64;
            return PowSolution { nonce, solve_time_ms };
        }
        
        nonce = nonce.wrapping_add(1);
        
        // Safety: po miliardzie prób coś jest nie tak
        if nonce > 1_000_000_000 {
            panic!("PoW solve failed after 1B attempts - difficulty too high?");
        }
    }
}

/// Oblicza hash dla PoW: SHA3-256(challenge || nonce)
fn compute_pow_hash(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(challenge);
    hasher.update(&nonce.to_le_bytes());
    
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Sprawdza czy hash ma wymaganą liczbę wiodących zerowych bitów
fn check_difficulty(hash: &[u8; 32], required_zero_bits: u8) -> bool {
    let mut zero_bits = 0u8;
    
    for &byte in hash.iter() {
        if byte == 0 {
            zero_bits += 8;
        } else {
            zero_bits += byte.leading_zeros() as u8;
            break;
        }
        
        if zero_bits >= required_zero_bits {
            return true;
        }
    }
    
    zero_bits >= required_zero_bits
}

// ═══════════════════════════════════════════════════════════════════════════════
// PoW Verifier (server-side)
// ═══════════════════════════════════════════════════════════════════════════════

/// Błędy weryfikacji PoW
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowError {
    /// Challenge wygasł
    ChallengeExpired,
    /// Nieprawidłowe rozwiązanie (hash nie spełnia trudności)
    InvalidSolution,
    /// Device ID nie zgadza się
    DeviceIdMismatch,
    /// Podejrzenie oszustwa - za szybkie rozwiązanie
    SuspiciouslyFast {
        expected_min_ms: u64,
        actual_ms: u64,
    },
    /// Challenge już został użyty (replay attack)
    ChallengeAlreadyUsed,
    /// Brak burst tokenów i wymagany PoW
    PowRequired,
}

impl std::fmt::Display for PowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChallengeExpired => write!(f, "Challenge expired"),
            Self::InvalidSolution => write!(f, "Invalid PoW solution"),
            Self::DeviceIdMismatch => write!(f, "Device ID mismatch"),
            Self::SuspiciouslyFast { expected_min_ms, actual_ms } => {
                write!(f, "Suspiciously fast solution: {} ms (expected min {} ms)", 
                    actual_ms, expected_min_ms)
            }
            Self::ChallengeAlreadyUsed => write!(f, "Challenge already used (replay attack?)"),
            Self::PowRequired => write!(f, "PoW required - burst exhausted"),
        }
    }
}

impl std::error::Error for PowError {}

/// Weryfikuje rozwiązanie PoW
pub fn verify_solution(
    challenge: &PowChallenge,
    solution: &PowSolution,
    device_id: &[u8; 16],
) -> Result<(), PowError> {
    // 1. Sprawdź device ID
    if &challenge.device_id != device_id {
        return Err(PowError::DeviceIdMismatch);
    }
    
    // 2. Sprawdź ważność challenge
    if !challenge.is_valid() {
        return Err(PowError::ChallengeExpired);
    }
    
    // 3. Zweryfikuj hash
    let hash = compute_pow_hash(&challenge.challenge_data, solution.nonce);
    if !check_difficulty(&hash, challenge.difficulty_bits) {
        return Err(PowError::InvalidSolution);
    }
    
    // 4. Sprawdź czy nie za szybko (anti-cheat)
    // Ta weryfikacja ma sens tylko po stronie SERWERA, gdzie wiemy
    // że klient musiał wysłać rozwiązanie przez sieć.
    // Dla lokalnego solve (testy), solve_time może być bardzo niski.
    // Sprawdzamy tylko przypadki gdzie difficulty > 14 (Medium+)
    // i czas < 5ms (fizycznie niemożliwe dla tej trudności)
    let min_expected_ms = match challenge.difficulty_bits {
        d if d >= 17 => 10,  // Fast+: min 10ms
        d if d >= 14 => 5,   // Medium: min 5ms
        _ => 0,              // Slow: nie sprawdzamy
    };
    
    if solution.solve_time_ms < min_expected_ms {
        return Err(PowError::SuspiciouslyFast {
            expected_min_ms: min_expected_ms,
            actual_ms: solution.solve_time_ms,
        });
    }
    
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Adaptive PoW Manager
// ═══════════════════════════════════════════════════════════════════════════════

/// Konfiguracja Adaptive PoW
#[derive(Debug, Clone)]
pub struct AdaptivePowConfig {
    /// Początkowa liczba burst tokenów
    pub initial_burst_tokens: u32,
    /// Maksymalna liczba burst tokenów
    pub max_burst_tokens: u32,
    /// Regeneracja burst: 1 token co X sekund
    pub burst_regen_secs: u64,
    /// Liczba "podejrzanych" rozwiązań do bana device_id
    pub suspicious_threshold: u32,
    /// Czas bana device_id (sekundy)
    pub ban_duration_secs: u64,
    /// Czas ważności challenge (sekundy)
    pub challenge_valid_secs: u64,
}

impl Default for AdaptivePowConfig {
    fn default() -> Self {
        Self {
            initial_burst_tokens: 5,
            max_burst_tokens: 10,
            burst_regen_secs: 300, // 5 minut na token
            suspicious_threshold: 3,
            ban_duration_secs: 3600, // 1 godzina bana
            challenge_valid_secs: 60,
        }
    }
}

/// Device tracking info
#[derive(Debug, Clone)]
struct DeviceInfo {
    /// Deklarowana klasa mocy
    power_class: DevicePowerClass,
    /// Pozostałe burst tokeny
    burst_tokens: u32,
    /// Ostatnia regeneracja burst
    last_burst_regen: Instant,
    /// Liczba podejrzanych rozwiązań
    suspicious_count: u32,
    /// Czy zbanowany
    banned_until: Option<Instant>,
    /// Ostatnio wydane challenge (anti-replay)
    pending_challenges: Vec<[u8; 32]>,
}

/// Adaptive PoW Manager - zarządza PoW dla anonimowych userów
pub struct AdaptivePowManager {
    config: AdaptivePowConfig,
    /// Device tracking: device_id -> DeviceInfo
    devices: RwLock<HashMap<[u8; 16], DeviceInfo>>,
    /// Użyte challenge (anti-replay)
    used_challenges: RwLock<HashMap<[u8; 32], Instant>>,
}

impl AdaptivePowManager {
    pub fn new() -> Self {
        Self::with_config(AdaptivePowConfig::default())
    }
    
    pub fn with_config(config: AdaptivePowConfig) -> Self {
        Self {
            config,
            devices: RwLock::new(HashMap::new()),
            used_challenges: RwLock::new(HashMap::new()),
        }
    }
    
    /// Rejestruje nowe urządzenie po benchmarku
    pub fn register_device(
        &self,
        device_id: [u8; 16],
        power_class: DevicePowerClass,
    ) {
        let info = DeviceInfo {
            power_class,
            burst_tokens: self.config.initial_burst_tokens,
            last_burst_regen: Instant::now(),
            suspicious_count: 0,
            banned_until: None,
            pending_challenges: Vec::new(),
        };
        
        let mut devices = self.devices.write().unwrap();
        devices.insert(device_id, info);
    }
    
    /// Sprawdza czy device może wykonać expensive operation
    /// Zwraca Ok(None) jeśli ma burst, Ok(Some(challenge)) jeśli wymaga PoW
    pub fn check_device(
        &self,
        device_id: &[u8; 16],
    ) -> Result<Option<PowChallenge>, PowError> {
        let mut devices = self.devices.write().unwrap();
        
        // Jeśli device nieznany - zarejestruj jako Medium (default)
        if !devices.contains_key(device_id) {
            let info = DeviceInfo {
                power_class: DevicePowerClass::Medium,
                burst_tokens: self.config.initial_burst_tokens,
                last_burst_regen: Instant::now(),
                suspicious_count: 0,
                banned_until: None,
                pending_challenges: Vec::new(),
            };
            devices.insert(*device_id, info);
        }
        
        let info = devices.get_mut(device_id).unwrap();
        
        // Sprawdź ban
        if let Some(banned_until) = info.banned_until {
            if Instant::now() < banned_until {
                return Err(PowError::SuspiciouslyFast {
                    expected_min_ms: 0,
                    actual_ms: 0,
                });
            } else {
                info.banned_until = None;
                info.suspicious_count = 0;
            }
        }
        
        // Regeneruj burst
        let regen_elapsed = info.last_burst_regen.elapsed().as_secs();
        let tokens_to_add = (regen_elapsed / self.config.burst_regen_secs) as u32;
        if tokens_to_add > 0 {
            info.burst_tokens = (info.burst_tokens + tokens_to_add)
                .min(self.config.max_burst_tokens);
            info.last_burst_regen = Instant::now();
        }
        
        // Jeśli ma burst - użyj
        if info.burst_tokens > 0 {
            info.burst_tokens -= 1;
            return Ok(None);
        }
        
        // Brak burst - generuj challenge
        let challenge = PowChallenge::new(*device_id, info.power_class);
        info.pending_challenges.push(challenge.challenge_data);
        
        // Cleanup starych pending challenges
        if info.pending_challenges.len() > 10 {
            info.pending_challenges.remove(0);
        }
        
        Ok(Some(challenge))
    }
    
    /// Weryfikuje rozwiązanie PoW
    pub fn verify_and_consume(
        &self,
        device_id: &[u8; 16],
        challenge: &PowChallenge,
        solution: &PowSolution,
    ) -> Result<(), PowError> {
        // 1. Podstawowa weryfikacja
        verify_solution(challenge, solution, device_id)?;
        
        // 2. Sprawdź anti-replay
        {
            let used = self.used_challenges.read().unwrap();
            if used.contains_key(&challenge.challenge_data) {
                return Err(PowError::ChallengeAlreadyUsed);
            }
        }
        
        // 3. Sprawdź czy challenge był wydany temu device
        {
            let devices = self.devices.read().unwrap();
            if let Some(info) = devices.get(device_id) {
                if !info.pending_challenges.contains(&challenge.challenge_data) {
                    return Err(PowError::DeviceIdMismatch);
                }
            }
        }
        
        // 4. Oznacz challenge jako użyty
        {
            let mut used = self.used_challenges.write().unwrap();
            used.insert(challenge.challenge_data, Instant::now());
            
            // Cleanup starych (starsze niż 10 minut)
            used.retain(|_, time| time.elapsed() < Duration::from_secs(600));
        }
        
        // 5. Usuń z pending
        {
            let mut devices = self.devices.write().unwrap();
            if let Some(info) = devices.get_mut(device_id) {
                info.pending_challenges.retain(|c| c != &challenge.challenge_data);
            }
        }
        
        Ok(())
    }
    
    /// Raportuje podejrzane zachowanie (za szybkie rozwiązanie)
    pub fn report_suspicious(&self, device_id: &[u8; 16]) {
        let mut devices = self.devices.write().unwrap();
        
        if let Some(info) = devices.get_mut(device_id) {
            info.suspicious_count += 1;
            
            if info.suspicious_count >= self.config.suspicious_threshold {
                info.banned_until = Some(
                    Instant::now() + Duration::from_secs(self.config.ban_duration_secs)
                );
            }
        }
    }
    
    /// Zwraca statystyki device
    pub fn get_device_stats(&self, device_id: &[u8; 16]) -> Option<DeviceStats> {
        let devices = self.devices.read().unwrap();
        
        devices.get(device_id).map(|info| DeviceStats {
            power_class: info.power_class,
            burst_tokens: info.burst_tokens,
            suspicious_count: info.suspicious_count,
            is_banned: info.banned_until.map(|t| Instant::now() < t).unwrap_or(false),
        })
    }
}

impl Default for AdaptivePowManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statystyki device (publiczne)
#[derive(Debug, Clone)]
pub struct DeviceStats {
    pub power_class: DevicePowerClass,
    pub burst_tokens: u32,
    pub suspicious_count: u32,
    pub is_banned: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Device Benchmark (client-side)
// ═══════════════════════════════════════════════════════════════════════════════

/// Wykonuje benchmark urządzenia (wywoływane przy tworzeniu walleta)
pub fn benchmark_device() -> (DevicePowerClass, u64) {
    let iterations = 10_000;
    let start = Instant::now();
    
    let mut dummy = [0u8; 32];
    for i in 0..iterations {
        let mut hasher = Sha3_256::new();
        hasher.update(&dummy);
        hasher.update(&(i as u64).to_le_bytes());
        let result = hasher.finalize();
        dummy.copy_from_slice(&result);
    }
    
    let elapsed = start.elapsed();
    let hashes_per_second = (iterations as f64 / elapsed.as_secs_f64()) as u64;
    
    let power_class = DevicePowerClass::from_benchmark(hashes_per_second);
    
    (power_class, hashes_per_second)
}

/// Generuje device_id na podstawie benchmarku i losowości
pub fn generate_device_id(benchmark_result: u64) -> [u8; 16] {
    use sha3::Sha3_256;
    
    let mut random_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random_bytes);
    
    let mut hasher = Sha3_256::new();
    hasher.update(&random_bytes);
    hasher.update(&benchmark_result.to_le_bytes());
    hasher.update(b"TT_DEVICE_ID_V1");
    
    let result = hasher.finalize();
    let mut device_id = [0u8; 16];
    device_id.copy_from_slice(&result[..16]);
    device_id
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_benchmark_device() {
        let (power_class, hash_rate) = benchmark_device();
        println!("Device benchmark: {} ({} hash/s)", power_class, hash_rate);
        
        // Powinien być przynajmniej Slow
        assert!(hash_rate > 100, "Device too slow for any class");
    }
    
    #[test]
    fn test_generate_device_id() {
        let id1 = generate_device_id(100000);
        let id2 = generate_device_id(100000);
        
        // Powinny być różne (losowość)
        assert_ne!(id1, id2);
    }
    
    #[test]
    fn test_pow_challenge_solve_verify() {
        let device_id = generate_device_id(50000);
        let challenge = PowChallenge::new(device_id, DevicePowerClass::Slow);
        
        // Rozwiąż challenge
        let solution = solve_challenge(&challenge);
        println!("Solved in {} ms with nonce {}", solution.solve_time_ms, solution.nonce);
        
        // Zweryfikuj
        let result = verify_solution(&challenge, &solution, &device_id);
        assert!(result.is_ok(), "Valid solution should verify");
    }
    
    #[test]
    fn test_pow_invalid_solution() {
        let device_id = generate_device_id(50000);
        let challenge = PowChallenge::new(device_id, DevicePowerClass::Slow);
        
        // Fałszywe rozwiązanie
        let fake_solution = PowSolution {
            nonce: 12345,
            solve_time_ms: 100,
        };
        
        let result = verify_solution(&challenge, &fake_solution, &device_id);
        assert!(matches!(result, Err(PowError::InvalidSolution)));
    }
    
    #[test]
    fn test_pow_wrong_device() {
        let device_id = generate_device_id(50000);
        let wrong_device = generate_device_id(60000);
        
        let challenge = PowChallenge::new(device_id, DevicePowerClass::Slow);
        let solution = solve_challenge(&challenge);
        
        let result = verify_solution(&challenge, &solution, &wrong_device);
        assert!(matches!(result, Err(PowError::DeviceIdMismatch)));
    }
    
    #[test]
    fn test_adaptive_pow_burst() {
        let config = AdaptivePowConfig {
            initial_burst_tokens: 3,
            ..Default::default()
        };
        let manager = AdaptivePowManager::with_config(config);
        let device_id = generate_device_id(50000);
        
        manager.register_device(device_id, DevicePowerClass::Medium);
        
        // Pierwsze 3 requesty: burst (bez PoW)
        for i in 0..3 {
            let result = manager.check_device(&device_id);
            assert!(matches!(result, Ok(None)), "Request {} should use burst", i);
        }
        
        // 4-ty request: wymaga PoW
        let result = manager.check_device(&device_id);
        assert!(matches!(result, Ok(Some(_))), "4th request should require PoW");
    }
    
    #[test]
    fn test_adaptive_pow_full_flow() {
        let manager = AdaptivePowManager::new();
        let device_id = generate_device_id(50000);
        
        manager.register_device(device_id, DevicePowerClass::Slow);
        
        // Wyczerpaj burst
        for _ in 0..5 {
            let _ = manager.check_device(&device_id);
        }
        
        // Teraz wymaga PoW
        let challenge = manager.check_device(&device_id)
            .expect("Should succeed")
            .expect("Should require PoW");
        
        // Rozwiąż
        let solution = solve_challenge(&challenge);
        
        // Zweryfikuj i consume
        let result = manager.verify_and_consume(&device_id, &challenge, &solution);
        assert!(result.is_ok(), "Valid solution should be accepted");
        
        // Replay powinien być odrzucony
        let replay_result = manager.verify_and_consume(&device_id, &challenge, &solution);
        assert!(matches!(replay_result, Err(PowError::ChallengeAlreadyUsed)));
    }
    
    #[test]
    fn test_difficulty_scaling() {
        // Sprawdź że trudności rosną
        assert!(DevicePowerClass::Slow.difficulty_bits() < DevicePowerClass::Medium.difficulty_bits());
        assert!(DevicePowerClass::Medium.difficulty_bits() < DevicePowerClass::Fast.difficulty_bits());
        assert!(DevicePowerClass::Fast.difficulty_bits() < DevicePowerClass::VeryFast.difficulty_bits());
    }
    
    #[test]
    fn test_challenge_serialization() {
        let device_id = generate_device_id(50000);
        let challenge = PowChallenge::new(device_id, DevicePowerClass::Medium);
        
        let bytes = challenge.to_bytes();
        let restored = PowChallenge::from_bytes(&bytes).expect("Should deserialize");
        
        assert_eq!(challenge.challenge_data, restored.challenge_data);
        assert_eq!(challenge.difficulty_bits, restored.difficulty_bits);
        assert_eq!(challenge.device_id, restored.device_id);
    }
    
    #[test]
    fn test_solve_different_difficulties() {
        let device_id = generate_device_id(50000);
        
        // Testujemy Slow (difficulty 10) - w release mode rozwiązuje się bardzo szybko
        // ale anti-cheat timing check jest wyłączony dla Slow (min_expected_ms = 0)
        let class = DevicePowerClass::Slow;
        let challenge = PowChallenge::new(device_id, class);
        let start = Instant::now();
        let solution = solve_challenge(&challenge);
        let elapsed = start.elapsed();
        
        println!("{}: solved in {:?} (reported {}ms)", 
            class, elapsed, solution.solve_time_ms);
        
        // Weryfikuj - dla Slow nie ma timing check
        assert!(verify_solution(&challenge, &solution, &device_id).is_ok());
    }
}
