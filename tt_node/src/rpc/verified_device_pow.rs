//! Verified Device PoW - Niepodrabialny system PoW dla anonimowych użytkowników
//!
//! ## Problem do rozwiązania
//!
//! Atakujący może:
//! 1. Podrobić benchmark (zadeklarować "slow" mając szybki serwer)
//! 2. Zmienić device_id (wygenerować nowy po banie)
//! 3. Użyć farm GPU do rozwiązywania PoW dla wielu "urządzeń"
//!
//! ## Rozwiązanie: Server-Verified Enrollment
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                    FAZA 1: ENROLLMENT (pierwsze uruchomienie)               │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │  1. Wallet wysyła: "Chcę się zarejestrować"                                 │
//! │  2. Serwer wysyła: ENROLLMENT_CHALLENGE (losowy, trudność = Medium)         │
//! │  3. Wallet rozwiązuje i MIERZY swój czas: solve_time_ms                     │
//! │  4. Serwer TEŻ mierzy czas od wysłania do odpowiedzi: server_measured_ms    │
//! │  5. Serwer oblicza: estimated_hash_rate = difficulty / server_measured_ms   │
//! │  6. Serwer wydaje: DeviceCredential (podpisany przez serwer!)               │
//! │     - device_id: hash(challenge_solution || server_random)                  │
//! │     - verified_power_class: obliczona z server_measured_ms                  │
//! │     - issued_at: timestamp                                                  │
//! │     - server_signature: Falcon-512(credential_data)                         │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                    FAZA 2: UŻYCIE (każdy expensive request)                 │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │  1. Wallet wysyła: credential + "chcę VeryExpensive"                        │
//! │  2. Serwer weryfikuje podpis credential                                     │
//! │  3. Serwer sprawdza burst dla tego device_id                                │
//! │  4. Jeśli brak burst:                                                       │
//! │     a) Serwer generuje PERSONALIZED CHALLENGE:                              │
//! │        challenge = hash(device_id || server_random || timestamp)            │
//! │     b) Trudność = f(verified_power_class, current_load)                     │
//! │  5. Wallet rozwiązuje, serwer MIERZY czas                                   │
//! │  6. Jeśli czas znacząco inny niż przy enrollment → SUSPICIOUS               │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Dlaczego to działa?
//!
//! - **Benchmark niepodrabialny**: Serwer sam mierzy czas, nie ufa klientowi
//! - **Device ID trwałe**: Oparte na rozwiązaniu challenge, podpisane przez serwer
//! - **PoW unikalne**: Challenge zawiera device_id, nie można użyć cudzego
//! - **Wykrywanie oszustw**: Porównanie czasu enrollment vs bieżący
//!
//! ## Security Features (v2)
//!
//! - **Enrollment Rate Limit**: Max enrollments per IP per time window
//! - **Persistent Storage**: DeviceState survives server restarts
//! - **Prometheus Metrics**: Full observability for production

use sha3::{Sha3_256, Digest};
use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::net::IpAddr;
use std::path::Path;
use std::fs;
use std::io::{self, BufRead, Write};
use rand::RngCore;

// Falcon-512 PQC signatures
use crate::falcon_sigs::{
    falcon_keypair, falcon_sign, falcon_verify,
    FalconPublicKey, FalconSecretKey, SignedNullifier,
    falcon_pk_to_bytes,
};

// ═══════════════════════════════════════════════════════════════════════════════
// Server Key - Post-Quantum (Falcon-512)
// ═══════════════════════════════════════════════════════════════════════════════

/// Klucz serwera do podpisywania credentials
/// 
/// Używamy **Falcon-512** - post-quantum signature scheme:
/// - Public key: 897 bytes
/// - Signature: ~666 bytes (attached)
/// - Security: 128-bit post-quantum
/// 
/// W produkcji: klucz prywatny w HSM z Falcon support
pub struct ServerSigningKey {
    /// Falcon-512 public key (do weryfikacji)
    pub_key: FalconPublicKey,
    /// Falcon-512 secret key (do podpisywania) - zeroized on drop
    sec_key: FalconSecretKey,
}

impl ServerSigningKey {
    /// Tworzy nowy klucz Falcon-512 (w produkcji: ładowany z HSM)
    pub fn new() -> Self {
        let (pub_key, sec_key) = falcon_keypair();
        Self { pub_key, sec_key }
    }
    
    /// Tworzy z istniejącej pary kluczy (do ładowania z storage)
    pub fn from_keypair(pub_key: FalconPublicKey, sec_key: FalconSecretKey) -> Self {
        Self { pub_key, sec_key }
    }
    
    /// Zwraca klucz publiczny (do dystrybucji do walletów)
    pub fn public_key(&self) -> &FalconPublicKey {
        &self.pub_key
    }
    
    /// Zwraca klucz publiczny jako bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        falcon_pk_to_bytes(&self.pub_key)
    }
    
    /// Podpisuje dane Falcon-512
    /// 
    /// Returns: Attached signature (message + ~666 byte signature)
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        // Domain separator dla device credentials
        let mut msg = Vec::with_capacity(data.len() + 32);
        msg.extend_from_slice(b"TT_DEVICE_CREDENTIAL_SIG_V1\x00\x00\x00\x00\x00");
        msg.extend_from_slice(data);
        
        let signed = falcon_sign(&msg, &self.sec_key)
            .expect("Falcon sign should not fail with valid key");
        signed.signed_message_bytes.clone()
    }
    
    /// Weryfikuje podpis Falcon-512
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        // Reconstruct message with domain separator
        let mut msg = Vec::with_capacity(data.len() + 32);
        msg.extend_from_slice(b"TT_DEVICE_CREDENTIAL_SIG_V1\x00\x00\x00\x00\x00");
        msg.extend_from_slice(data);
        
        let signed = SignedNullifier {
            signed_message_bytes: signature.to_vec(),
        };
        
        falcon_verify(&msg, &signed, &self.pub_key).is_ok()
    }
}

impl Default for ServerSigningKey {
    fn default() -> Self {
        Self::new()
    }
}

/// Weryfikuje podpis używając tylko klucza publicznego (client-side)
/// 
/// Wallety mogą zweryfikować credential bez dostępu do klucza prywatnego
pub fn verify_with_public_key(
    pub_key: &FalconPublicKey,
    data: &[u8],
    signature: &[u8],
) -> bool {
    let mut msg = Vec::with_capacity(data.len() + 32);
    msg.extend_from_slice(b"TT_DEVICE_CREDENTIAL_SIG_V1\x00\x00\x00\x00\x00");
    msg.extend_from_slice(data);
    
    let signed = SignedNullifier {
        signed_message_bytes: signature.to_vec(),
    };
    
    falcon_verify(&msg, &signed, pub_key).is_ok()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Device Power Class (zweryfikowana przez serwer)
// ═══════════════════════════════════════════════════════════════════════════════

/// Klasa mocy urządzenia - ZWERYFIKOWANA przez serwer podczas enrollment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VerifiedPowerClass {
    /// Bardzo słabe (stary telefon, IoT): < 1k hash/s
    VeryWeak = 0,
    /// Słabe (budget telefon): 1k - 10k hash/s
    Weak = 1,
    /// Średnie (normalny telefon): 10k - 50k hash/s
    Medium = 2,
    /// Szybkie (flagowy telefon, laptop): 50k - 200k hash/s
    Fast = 3,
    /// Bardzo szybkie (desktop): 200k - 1M hash/s
    VeryFast = 4,
    /// Ekstremalne (serwer/GPU): > 1M hash/s
    Extreme = 5,
}

impl VerifiedPowerClass {
    /// Konwertuje hash_rate na klasę
    pub fn from_hash_rate(hashes_per_second: u64) -> Self {
        match hashes_per_second {
            0..=1_000 => Self::VeryWeak,
            1_001..=10_000 => Self::Weak,
            10_001..=50_000 => Self::Medium,
            50_001..=200_000 => Self::Fast,
            200_001..=1_000_000 => Self::VeryFast,
            _ => Self::Extreme,
        }
    }
    
    /// Bazowa trudność dla tej klasy (wiodące zerowe bity)
    pub fn base_difficulty(&self) -> u8 {
        match self {
            Self::VeryWeak => 8,   // ~256 prób
            Self::Weak => 11,     // ~2k prób
            Self::Medium => 14,   // ~16k prób
            Self::Fast => 16,     // ~65k prób
            Self::VeryFast => 18, // ~262k prób
            Self::Extreme => 20,  // ~1M prób
        }
    }
    
    /// Serializacja
    pub fn to_byte(&self) -> u8 {
        *self as u8
    }
    
    /// Deserializacja
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::VeryWeak),
            1 => Some(Self::Weak),
            2 => Some(Self::Medium),
            3 => Some(Self::Fast),
            4 => Some(Self::VeryFast),
            5 => Some(Self::Extreme),
            _ => None,
        }
    }
}

impl std::fmt::Display for VerifiedPowerClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VeryWeak => write!(f, "very_weak"),
            Self::Weak => write!(f, "weak"),
            Self::Medium => write!(f, "medium"),
            Self::Fast => write!(f, "fast"),
            Self::VeryFast => write!(f, "very_fast"),
            Self::Extreme => write!(f, "extreme"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Device Credential (wydawany przez serwer)
// ═══════════════════════════════════════════════════════════════════════════════

/// Credential urządzenia - PODPISANY przez serwer (Falcon-512 PQC)
#[derive(Debug, Clone)]
pub struct DeviceCredential {
    /// Unikalny identyfikator urządzenia
    pub device_id: [u8; 16],
    /// Zweryfikowana klasa mocy
    pub power_class: VerifiedPowerClass,
    /// Zmierzony hash rate podczas enrollment (hash/s)
    pub measured_hash_rate: u64,
    /// Timestamp wydania (unix secs)
    pub issued_at: u64,
    /// Czas ważności (sekundy od issued_at)
    pub valid_for_secs: u64,
    /// Podpis serwera - Falcon-512 attached signature (~700 bytes)
    pub server_signature: Vec<u8>,
}

impl DeviceCredential {
    /// Dane do podpisu (bez samego podpisu)
    fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(16 + 1 + 8 + 8 + 8);
        data.extend_from_slice(&self.device_id);
        data.push(self.power_class.to_byte());
        data.extend_from_slice(&self.measured_hash_rate.to_le_bytes());
        data.extend_from_slice(&self.issued_at.to_le_bytes());
        data.extend_from_slice(&self.valid_for_secs.to_le_bytes());
        data
    }
    
    /// Sprawdza czy credential nie wygasł
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now < self.issued_at + self.valid_for_secs
    }
    
    /// Weryfikuje podpis Falcon-512
    pub fn verify_signature(&self, server_key: &ServerSigningKey) -> bool {
        let data = self.signing_data();
        server_key.verify(&data, &self.server_signature)
    }
    
    /// Weryfikuje używając tylko klucza publicznego (client-side)
    pub fn verify_with_public_key(&self, pub_key: &FalconPublicKey) -> bool {
        let data = self.signing_data();
        verify_with_public_key(pub_key, &data, &self.server_signature)
    }
    
    /// Serializacja do bytes
    /// Format: [device_id:16][power_class:1][hash_rate:8][issued_at:8][valid_for:8][sig_len:2][signature:~700]
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_len = self.server_signature.len() as u16;
        let mut bytes = Vec::with_capacity(16 + 1 + 8 + 8 + 8 + 2 + self.server_signature.len());
        bytes.extend_from_slice(&self.device_id);
        bytes.push(self.power_class.to_byte());
        bytes.extend_from_slice(&self.measured_hash_rate.to_le_bytes());
        bytes.extend_from_slice(&self.issued_at.to_le_bytes());
        bytes.extend_from_slice(&self.valid_for_secs.to_le_bytes());
        bytes.extend_from_slice(&sig_len.to_le_bytes());
        bytes.extend_from_slice(&self.server_signature);
        bytes
    }
    
    /// Deserializacja
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // Minimum: header (41 bytes) + sig_len (2) + min signature
        const HEADER_SIZE: usize = 16 + 1 + 8 + 8 + 8 + 2; // 43 bytes
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&bytes[0..16]);
        
        let power_class = VerifiedPowerClass::from_byte(bytes[16])?;
        let measured_hash_rate = u64::from_le_bytes(bytes[17..25].try_into().ok()?);
        let issued_at = u64::from_le_bytes(bytes[25..33].try_into().ok()?);
        let valid_for_secs = u64::from_le_bytes(bytes[33..41].try_into().ok()?);
        let sig_len = u16::from_le_bytes(bytes[41..43].try_into().ok()?) as usize;
        
        // Sprawdź czy mamy wystarczająco danych na podpis
        if bytes.len() != HEADER_SIZE + sig_len {
            return None;
        }
        
        // Falcon signature: ~666-700 bytes
        if sig_len < 600 || sig_len > 1000 {
            return None;
        }
        
        let server_signature = bytes[43..].to_vec();
        
        Some(Self {
            device_id,
            power_class,
            measured_hash_rate,
            issued_at,
            valid_for_secs,
            server_signature,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Enrollment Challenge
// ═══════════════════════════════════════════════════════════════════════════════

/// Challenge do enrollment (serwer → klient)
#[derive(Debug, Clone)]
pub struct EnrollmentChallenge {
    /// Losowe dane challenge
    pub challenge_data: [u8; 32],
    /// Trudność (stała dla enrollment: Medium)
    pub difficulty_bits: u8,
    /// Timestamp utworzenia
    pub created_at: u64,
    /// Czas ważności
    pub valid_for_secs: u64,
    /// Server nonce (do generowania device_id)
    pub server_nonce: [u8; 16],
}

impl EnrollmentChallenge {
    /// Tworzy nowy enrollment challenge
    pub fn new() -> Self {
        let mut challenge_data = [0u8; 32];
        let mut server_nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut challenge_data);
        rand::thread_rng().fill_bytes(&mut server_nonce);
        
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            challenge_data,
            difficulty_bits: 14, // Medium - wystarczające do zmierzenia
            created_at,
            valid_for_secs: 120, // 2 minuty na enrollment
            server_nonce,
        }
    }
    
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now < self.created_at + self.valid_for_secs
    }
    
    /// Serializacja
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 1 + 8 + 8 + 16);
        bytes.extend_from_slice(&self.challenge_data);
        bytes.push(self.difficulty_bits);
        bytes.extend_from_slice(&self.created_at.to_le_bytes());
        bytes.extend_from_slice(&self.valid_for_secs.to_le_bytes());
        bytes.extend_from_slice(&self.server_nonce);
        bytes
    }
    
    /// Deserializacja
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 + 1 + 8 + 8 + 16 {
            return None;
        }
        
        let mut challenge_data = [0u8; 32];
        challenge_data.copy_from_slice(&bytes[0..32]);
        
        let difficulty_bits = bytes[32];
        let created_at = u64::from_le_bytes(bytes[33..41].try_into().ok()?);
        let valid_for_secs = u64::from_le_bytes(bytes[41..49].try_into().ok()?);
        
        let mut server_nonce = [0u8; 16];
        server_nonce.copy_from_slice(&bytes[49..65]);
        
        Some(Self {
            challenge_data,
            difficulty_bits,
            created_at,
            valid_for_secs,
            server_nonce,
        })
    }
}

impl Default for EnrollmentChallenge {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Personalized Challenge (dla zweryfikowanych urządzeń)
// ═══════════════════════════════════════════════════════════════════════════════

/// Challenge spersonalizowany dla konkretnego urządzenia
#[derive(Debug, Clone)]
pub struct PersonalizedChallenge {
    /// Challenge data = hash(device_id || server_random || timestamp)
    pub challenge_data: [u8; 32],
    /// Trudność dopasowana do urządzenia i obciążenia
    pub difficulty_bits: u8,
    /// Device ID dla którego challenge
    pub device_id: [u8; 16],
    /// Timestamp utworzenia
    pub created_at: u64,
    /// Czas ważności
    pub valid_for_secs: u64,
}

impl PersonalizedChallenge {
    /// Tworzy challenge dla konkretnego urządzenia
    pub fn new(
        device_id: [u8; 16],
        power_class: VerifiedPowerClass,
        load_multiplier: f64, // 1.0 = normalny, 2.0 = wysoki load → trudniej
    ) -> Self {
        let mut server_random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut server_random);
        
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Challenge jest PERSONALNY - zawiera device_id
        let mut hasher = Sha3_256::new();
        hasher.update(&device_id);
        hasher.update(&server_random);
        hasher.update(&created_at.to_le_bytes());
        hasher.update(b"TT_PERSONALIZED_CHALLENGE_V1");
        
        let result = hasher.finalize();
        let mut challenge_data = [0u8; 32];
        challenge_data.copy_from_slice(&result);
        
        // Trudność = bazowa + adjustment za load
        let base_diff = power_class.base_difficulty();
        let load_adjustment = ((load_multiplier - 1.0) * 2.0) as u8; // max +4 bits
        let difficulty_bits = base_diff.saturating_add(load_adjustment).min(24);
        
        Self {
            challenge_data,
            difficulty_bits,
            device_id,
            created_at,
            valid_for_secs: 60, // 1 minuta na rozwiązanie
        }
    }
    
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now < self.created_at + self.valid_for_secs
    }
    
    /// Serializacja
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 1 + 16 + 8 + 8);
        bytes.extend_from_slice(&self.challenge_data);
        bytes.push(self.difficulty_bits);
        bytes.extend_from_slice(&self.device_id);
        bytes.extend_from_slice(&self.created_at.to_le_bytes());
        bytes.extend_from_slice(&self.valid_for_secs.to_le_bytes());
        bytes
    }
    
    /// Deserializacja
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 + 1 + 16 + 8 + 8 {
            return None;
        }
        
        let mut challenge_data = [0u8; 32];
        challenge_data.copy_from_slice(&bytes[0..32]);
        
        let difficulty_bits = bytes[32];
        
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&bytes[33..49]);
        
        let created_at = u64::from_le_bytes(bytes[49..57].try_into().ok()?);
        let valid_for_secs = u64::from_le_bytes(bytes[57..65].try_into().ok()?);
        
        Some(Self {
            challenge_data,
            difficulty_bits,
            device_id,
            created_at,
            valid_for_secs,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PoW Solver (client-side, identyczny jak poprzednio)
// ═══════════════════════════════════════════════════════════════════════════════

/// Rozwiązanie PoW
#[derive(Debug, Clone)]
pub struct PowSolution {
    pub nonce: u64,
    pub solve_time_ms: u64,
}

impl PowSolution {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.solve_time_ms.to_le_bytes());
        bytes
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 16 {
            return None;
        }
        let nonce = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let solve_time_ms = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        Some(Self { nonce, solve_time_ms })
    }
}

/// Oblicza hash PoW
fn compute_pow_hash(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(challenge);
    hasher.update(&nonce.to_le_bytes());
    
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Sprawdza trudność
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

/// Rozwiązuje challenge (wywoływane po stronie walleta)
pub fn solve_pow(challenge_data: &[u8; 32], difficulty_bits: u8) -> PowSolution {
    let start = Instant::now();
    let mut nonce: u64 = 0;
    
    loop {
        let hash = compute_pow_hash(challenge_data, nonce);
        
        if check_difficulty(&hash, difficulty_bits) {
            let solve_time_ms = start.elapsed().as_millis() as u64;
            return PowSolution { nonce, solve_time_ms };
        }
        
        nonce = nonce.wrapping_add(1);
        
        if nonce > 10_000_000_000 {
            panic!("PoW solve failed after 10B attempts");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Błędy
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub enum VerifiedPowError {
    /// Credential wygasł
    CredentialExpired,
    /// Nieprawidłowy podpis credential
    InvalidCredentialSignature,
    /// Challenge wygasł
    ChallengeExpired,
    /// Nieprawidłowe rozwiązanie PoW
    InvalidSolution,
    /// Device ID nie zgadza się
    DeviceIdMismatch,
    /// Podejrzenie oszustwa - czas rozwiązania niezgodny z enrollment
    SuspiciousTiming {
        expected_ms: u64,
        actual_ms: u64,
    },
    /// Challenge już użyty (replay)
    ChallengeAlreadyUsed,
    /// Wymagany PoW (brak burst)
    PowRequired,
    /// Enrollment challenge wygasł
    EnrollmentExpired,
    /// Device zbanowany
    DeviceBanned { until_secs: u64 },
}

impl std::fmt::Display for VerifiedPowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CredentialExpired => write!(f, "Device credential expired"),
            Self::InvalidCredentialSignature => write!(f, "Invalid credential signature"),
            Self::ChallengeExpired => write!(f, "Challenge expired"),
            Self::InvalidSolution => write!(f, "Invalid PoW solution"),
            Self::DeviceIdMismatch => write!(f, "Device ID mismatch"),
            Self::SuspiciousTiming { expected_ms, actual_ms } => {
                write!(f, "Suspicious timing: expected ~{}ms, got {}ms", 
                    expected_ms, actual_ms)
            }
            Self::ChallengeAlreadyUsed => write!(f, "Challenge already used"),
            Self::PowRequired => write!(f, "PoW required - burst exhausted"),
            Self::EnrollmentExpired => write!(f, "Enrollment challenge expired"),
            Self::DeviceBanned { until_secs } => write!(f, "Device banned for {} more seconds", until_secs),
        }
    }
}

impl std::error::Error for VerifiedPowError {}

// ═══════════════════════════════════════════════════════════════════════════════
// Verified Device Manager (serwer)
// ═══════════════════════════════════════════════════════════════════════════════

/// Konfiguracja
#[derive(Debug, Clone)]
pub struct VerifiedDeviceConfig {
    /// Początkowe burst tokeny
    pub initial_burst: u32,
    /// Max burst
    pub max_burst: u32,
    /// Regeneracja burst (sekundy na token)
    pub burst_regen_secs: u64,
    /// Czas ważności credential (sekundy)
    pub credential_valid_secs: u64,
    /// Próg podejrzanego czasu (ratio)
    pub suspicion_ratio: f64,
    /// Liczba podejrzanych zachowań do bana
    pub suspicion_to_ban: u32,
    /// Czas bana (sekundy)
    pub ban_duration_secs: u64,
}

impl Default for VerifiedDeviceConfig {
    fn default() -> Self {
        Self {
            initial_burst: 5,
            max_burst: 10,
            burst_regen_secs: 300, // 5 minut
            credential_valid_secs: 86400 * 30, // 30 dni
            suspicion_ratio: 5.0, // 5x szybciej = podejrzane
            suspicion_to_ban: 3,
            ban_duration_secs: 3600, // 1 godzina
        }
    }
}

/// Stan urządzenia na serwerze
#[derive(Debug, Clone)]
struct DeviceState {
    /// Burst tokeny
    burst_tokens: u32,
    /// Ostatnia regeneracja
    last_regen: Instant,
    /// Liczba podejrzanych zachowań
    suspicion_count: u32,
    /// Ban do kiedy
    banned_until: Option<Instant>,
    /// Oczekujące challenge - przechowujemy PEŁNY challenge wraz z Instant!
    /// Klucz: challenge_data, Wartość: (pełny PersonalizedChallenge, Instant wydania)
    /// KRYTYCZNE: dzięki temu klient nie może manipulować difficulty_bits ani timestamps
    /// Instant daje nam precyzję milisekundową dla timing checks
    pending_challenges: HashMap<[u8; 32], (PersonalizedChallenge, Instant)>,
    /// Zmierzony czas podczas enrollment (bazowy)
    enrollment_solve_time_ms: u64,
}

/// Verified Device Manager
pub struct VerifiedDeviceManager {
    config: VerifiedDeviceConfig,
    server_key: ServerSigningKey,
    /// Pending enrollment challenges: challenge_data -> (challenge, issued_at)
    pending_enrollments: RwLock<HashMap<[u8; 32], (EnrollmentChallenge, Instant)>>,
    /// Device states: device_id -> state
    devices: RwLock<HashMap<[u8; 16], DeviceState>>,
    /// Użyte challenge (anti-replay)
    used_challenges: RwLock<HashMap<[u8; 32], Instant>>,
    /// Aktualny load multiplier (1.0 = normalny)
    current_load: RwLock<f64>,
}

impl VerifiedDeviceManager {
    pub fn new() -> Self {
        Self::with_config(VerifiedDeviceConfig::default())
    }
    
    pub fn with_config(config: VerifiedDeviceConfig) -> Self {
        Self {
            config,
            server_key: ServerSigningKey::new(),
            pending_enrollments: RwLock::new(HashMap::new()),
            devices: RwLock::new(HashMap::new()),
            used_challenges: RwLock::new(HashMap::new()),
            current_load: RwLock::new(1.0),
        }
    }
    
    /// Ustawia aktualny load (wpływa na trudność)
    pub fn set_load_multiplier(&self, multiplier: f64) {
        let mut load = self.current_load.write().unwrap();
        *load = multiplier.max(1.0).min(3.0);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // ENROLLMENT FLOW
    // ═══════════════════════════════════════════════════════════════════════
    
    /// Krok 1: Generuje enrollment challenge
    pub fn start_enrollment(&self) -> EnrollmentChallenge {
        let challenge = EnrollmentChallenge::new();
        
        let mut pending = self.pending_enrollments.write().unwrap();
        pending.insert(challenge.challenge_data, (challenge.clone(), Instant::now()));
        
        // Cleanup starych
        pending.retain(|_, (c, _)| c.is_valid());
        
        challenge
    }
    
    /// Krok 2: Finalizuje enrollment po otrzymaniu rozwiązania
    /// 
    /// Serwer MIERZY czas od wysłania challenge do otrzymania odpowiedzi
    /// 
    /// UWAGA: `client_challenge` używamy TYLKO do lookupu po `challenge_data`.
    /// Wszystkie inne pola (difficulty_bits, server_nonce) bierzemy z serwerowej kopii!
    pub fn complete_enrollment(
        &self,
        client_challenge: &EnrollmentChallenge,
        solution: &PowSolution,
    ) -> Result<DeviceCredential, VerifiedPowError> {
        // 1. Pobierz SERWEROWĄ wersję challenge (jedyne źródło prawdy)
        let (original_challenge, issued_at) = {
            let pending = self.pending_enrollments.read().unwrap();
            pending.get(&client_challenge.challenge_data)
                .cloned()
                .ok_or(VerifiedPowError::EnrollmentExpired)?
        };
        
        if !original_challenge.is_valid() {
            return Err(VerifiedPowError::EnrollmentExpired);
        }
        
        // 2. Zmierz czas po stronie serwera
        let server_measured_ms = issued_at.elapsed().as_millis() as u64;
        
        // 3. Zweryfikuj rozwiązanie - używamy TYLKO original_challenge!
        // KRYTYCZNE: difficulty_bits MUSI pochodzić z serwera, nie od klienta!
        let hash = compute_pow_hash(&original_challenge.challenge_data, solution.nonce);
        if !check_difficulty(&hash, original_challenge.difficulty_bits) {
            return Err(VerifiedPowError::InvalidSolution);
        }
        
        // 4. Oblicz hash rate na podstawie SERWERA (nie ufamy klientowi)
        // KRYTYCZNE: difficulty_bits z original_challenge!
        let expected_attempts = 1u64 << original_challenge.difficulty_bits;
        // Odejmij ~50ms na network latency
        let compute_time_ms = server_measured_ms.saturating_sub(50).max(1);
        let estimated_hash_rate = (expected_attempts * 1000) / compute_time_ms;
        
        // 5. Określ power class
        let power_class = VerifiedPowerClass::from_hash_rate(estimated_hash_rate);
        
        // 6. Generuj device_id = hash(solution || server_nonce)
        // KRYTYCZNE: server_nonce MUSI pochodzić z serwera!
        let mut hasher = Sha3_256::new();
        hasher.update(&solution.nonce.to_le_bytes());
        hasher.update(&original_challenge.server_nonce);
        hasher.update(b"TT_DEVICE_ID_V1");
        let result = hasher.finalize();
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&result[..16]);
        
        // 7. Utwórz credential
        let issued_at_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut credential = DeviceCredential {
            device_id,
            power_class,
            measured_hash_rate: estimated_hash_rate,
            issued_at: issued_at_ts,
            valid_for_secs: self.config.credential_valid_secs,
            server_signature: Vec::new(), // Będzie wypełnione podpisem Falcon
        };
        
        // 8. Podpisz Falcon-512 (PQC)
        let signing_data = credential.signing_data();
        credential.server_signature = self.server_key.sign(&signing_data);
        
        // 9. Zapisz device state
        {
            let mut devices = self.devices.write().unwrap();
            devices.insert(device_id, DeviceState {
                burst_tokens: self.config.initial_burst,
                last_regen: Instant::now(),
                suspicion_count: 0,
                banned_until: None,
                pending_challenges: HashMap::new(),
                enrollment_solve_time_ms: server_measured_ms,
            });
        }
        
        // 10. Usuń z pending
        {
            let mut pending = self.pending_enrollments.write().unwrap();
            pending.remove(&client_challenge.challenge_data);
        }
        
        Ok(credential)
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // REQUEST FLOW (dla zweryfikowanych urządzeń)
    // ═══════════════════════════════════════════════════════════════════════
    
    /// Sprawdza czy device może wykonać expensive op
    /// Zwraca Ok(None) jeśli ma burst, Ok(Some(challenge)) jeśli wymaga PoW
    pub fn check_device(
        &self,
        credential: &DeviceCredential,
    ) -> Result<Option<PersonalizedChallenge>, VerifiedPowError> {
        // 1. Zweryfikuj credential
        if !credential.verify_signature(&self.server_key) {
            return Err(VerifiedPowError::InvalidCredentialSignature);
        }
        
        if !credential.is_valid() {
            return Err(VerifiedPowError::CredentialExpired);
        }
        
        // 2. Pobierz/utwórz device state
        let mut devices = self.devices.write().unwrap();
        
        let state = devices.entry(credential.device_id).or_insert_with(|| {
            DeviceState {
                burst_tokens: self.config.initial_burst,
                last_regen: Instant::now(),
                suspicion_count: 0,
                banned_until: None,
                pending_challenges: HashMap::new(), // Pełne challenge, nie tylko hash!
                enrollment_solve_time_ms: 150, // default
            }
        });
        
        // 3. Sprawdź ban
        if let Some(banned_until) = state.banned_until {
            if Instant::now() < banned_until {
                let remaining = banned_until.duration_since(Instant::now()).as_secs();
                return Err(VerifiedPowError::DeviceBanned { until_secs: remaining });
            } else {
                state.banned_until = None;
                state.suspicion_count = 0;
            }
        }
        
        // 4. Regeneruj burst
        let regen_elapsed = state.last_regen.elapsed().as_secs();
        let tokens_to_add = (regen_elapsed / self.config.burst_regen_secs) as u32;
        if tokens_to_add > 0 {
            state.burst_tokens = (state.burst_tokens + tokens_to_add).min(self.config.max_burst);
            state.last_regen = Instant::now();
        }
        
        // 5. Jeśli ma burst - użyj
        if state.burst_tokens > 0 {
            state.burst_tokens -= 1;
            return Ok(None);
        }
        
        // 6. Generuj personalized challenge
        let load = *self.current_load.read().unwrap();
        let challenge = PersonalizedChallenge::new(
            credential.device_id,
            credential.power_class,
            load,
        );
        
        // KRYTYCZNE: zapisujemy PEŁNY challenge wraz z Instant!
        // Dzięki temu klient nie może manipulować difficulty_bits ani timestamps
        // Instant daje nam precyzję milisekundową dla timing checks
        state.pending_challenges.insert(challenge.challenge_data, (challenge.clone(), Instant::now()));
        
        // Cleanup - usuń najstarsze jeśli za dużo
        if state.pending_challenges.len() > 10 {
            // Znajdź najstarszy challenge
            if let Some(oldest_key) = state.pending_challenges
                .iter()
                .min_by_key(|(_, (c, _))| c.created_at)
                .map(|(k, _)| *k)
            {
                state.pending_challenges.remove(&oldest_key);
            }
        }
        
        Ok(Some(challenge))
    }
    
    /// Weryfikuje rozwiązanie PoW
    /// 
    /// UWAGA: `client_challenge` używamy TYLKO do lookupu po `challenge_data`.
    /// Wszystkie inne pola (difficulty_bits, device_id, timestamps) bierzemy z serwerowej kopii!
    /// To jest KRYTYCZNE dla bezpieczeństwa - klient nie może manipulować trudnością!
    pub fn verify_solution(
        &self,
        credential: &DeviceCredential,
        client_challenge: &PersonalizedChallenge,
        solution: &PowSolution,
        server_measured_ms: u64, // Czas zmierzony przez serwer
    ) -> Result<(), VerifiedPowError> {
        // 1. Zweryfikuj credential
        if !credential.verify_signature(&self.server_key) {
            return Err(VerifiedPowError::InvalidCredentialSignature);
        }
        
        // 2. Sprawdź czy credential nie wygasł (dodatkowe zabezpieczenie)
        if !credential.is_valid() {
            return Err(VerifiedPowError::CredentialExpired);
        }
        
        // 3. KRYTYCZNE: Anti-replay PRZED lookup w pending!
        // Sprawdź czy challenge nie był już użyty
        {
            let used = self.used_challenges.read().unwrap();
            if used.contains_key(&client_challenge.challenge_data) {
                return Err(VerifiedPowError::ChallengeAlreadyUsed);
            }
        }
        
        // 4. Pobierz SERWEROWĄ wersję challenge - jedyne źródło prawdy!
        // KRYTYCZNE: używamy client_challenge.challenge_data TYLKO jako klucz lookupu
        // Pobieramy też Instant dla precyzyjnego pomiaru czasu (milisekundy!)
        let (stored_challenge, challenge_issued_at) = {
            let devices = self.devices.read().unwrap();
            let state = devices.get(&credential.device_id)
                .ok_or(VerifiedPowError::DeviceIdMismatch)?;
            state.pending_challenges
                .get(&client_challenge.challenge_data)
                .cloned()
                .ok_or(VerifiedPowError::DeviceIdMismatch)?
        };
        
        // 5. Sprawdź device ID - z SERWEROWEJ kopii
        if credential.device_id != stored_challenge.device_id {
            return Err(VerifiedPowError::DeviceIdMismatch);
        }
        
        // 6. Sprawdź ważność challenge - z SERWEROWEJ kopii
        if !stored_challenge.is_valid() {
            return Err(VerifiedPowError::ChallengeExpired);
        }
        
        // 7. Zweryfikuj hash - używamy SERWEROWEJ trudności!
        // KRYTYCZNE: difficulty_bits MUSI pochodzić z serwera, nie od klienta!
        let hash = compute_pow_hash(&stored_challenge.challenge_data, solution.nonce);
        if !check_difficulty(&hash, stored_challenge.difficulty_bits) {
            return Err(VerifiedPowError::InvalidSolution);
        }
        
        // 8. Sprawdź timing (anti-cheat)
        // Mierzymy czas od wydania challenge do teraz używając Instant (precyzja ms!)
        // To jest spójne z complete_enrollment() które też używa Instant
        let actual_wall_clock_ms = challenge_issued_at.elapsed().as_millis() as u64;
        
        let devices = self.devices.read().unwrap();
        if let Some(state) = devices.get(&credential.device_id) {
            let expected_ms = state.enrollment_solve_time_ms;
            // Użyj WEWNĘTRZNEGO pomiaru wall-clock (spójne z enrollment)
            // server_measured_ms zachowujemy dla logów, ale używamy actual_wall_clock_ms
            let check_ms = if actual_wall_clock_ms > 0 { actual_wall_clock_ms } else { server_measured_ms };
            
            // Dopuszczamy variance, ale nie 5x szybciej
            if check_ms > 0 && expected_ms > 0 {
                let ratio = expected_ms as f64 / check_ms as f64;
                if ratio > self.config.suspicion_ratio {
                    drop(devices);
                    self.report_suspicious(&credential.device_id);
                    return Err(VerifiedPowError::SuspiciousTiming {
                        expected_ms,
                        actual_ms: check_ms,
                    });
                }
            }
        }
        drop(devices);
        
        // 9. Oznacz challenge jako użyty
        {
            let mut used = self.used_challenges.write().unwrap();
            used.insert(stored_challenge.challenge_data, Instant::now());
            used.retain(|_, time| time.elapsed() < Duration::from_secs(600));
        }
        
        // 10. Usuń z pending
        {
            let mut devices = self.devices.write().unwrap();
            if let Some(state) = devices.get_mut(&credential.device_id) {
                state.pending_challenges.remove(&stored_challenge.challenge_data);
            }
        }
        
        Ok(())
    }
    
    /// Raportuje podejrzane zachowanie
    fn report_suspicious(&self, device_id: &[u8; 16]) {
        let mut devices = self.devices.write().unwrap();
        
        if let Some(state) = devices.get_mut(device_id) {
            state.suspicion_count += 1;
            
            if state.suspicion_count >= self.config.suspicion_to_ban {
                state.banned_until = Some(
                    Instant::now() + Duration::from_secs(self.config.ban_duration_secs)
                );
            }
        }
    }
    
    /// Zwraca statystyki device
    pub fn get_device_stats(&self, device_id: &[u8; 16]) -> Option<DeviceStats> {
        let devices = self.devices.read().unwrap();
        
        devices.get(device_id).map(|state| DeviceStats {
            burst_tokens: state.burst_tokens,
            suspicion_count: state.suspicion_count,
            is_banned: state.banned_until.map(|t| Instant::now() < t).unwrap_or(false),
            enrollment_solve_time_ms: state.enrollment_solve_time_ms,
        })
    }
}

impl Default for VerifiedDeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Publiczne statystyki device
#[derive(Debug, Clone)]
pub struct DeviceStats {
    pub burst_tokens: u32,
    pub suspicion_count: u32,
    pub is_banned: bool,
    pub enrollment_solve_time_ms: u64,
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENROLLMENT RATE LIMITER
// ═══════════════════════════════════════════════════════════════════════════════

/// Rate limiter dla enrollment endpoint
/// 
/// Zapobiega:
/// - Spamowaniu enrollment (koszt serwera na generowanie challenge)
/// - Próbom wygenerowania wielu device_id z jednego IP
/// - Amplification attacks
pub struct EnrollmentRateLimiter {
    /// IP -> (count, window_start)
    ip_counts: RwLock<HashMap<IpAddr, (u32, Instant)>>,
    /// Max enrollments per IP per window
    max_per_window: u32,
    /// Window duration
    window_duration: Duration,
    /// Globally blocked IPs (persistent attackers)
    blocked_ips: RwLock<HashMap<IpAddr, Instant>>,
    /// Block duration
    block_duration: Duration,
    /// Threshold to trigger block
    block_threshold: u32,
}

impl EnrollmentRateLimiter {
    pub fn new() -> Self {
        Self {
            ip_counts: RwLock::new(HashMap::new()),
            max_per_window: 5,           // 5 enrollments per window
            window_duration: Duration::from_secs(3600), // 1 hour window
            blocked_ips: RwLock::new(HashMap::new()),
            block_duration: Duration::from_secs(86400), // 24h block
            block_threshold: 20,         // 20 attempts = block
        }
    }
    
    pub fn with_config(
        max_per_window: u32,
        window_secs: u64,
        block_threshold: u32,
        block_duration_secs: u64,
    ) -> Self {
        Self {
            ip_counts: RwLock::new(HashMap::new()),
            max_per_window,
            window_duration: Duration::from_secs(window_secs),
            blocked_ips: RwLock::new(HashMap::new()),
            block_duration: Duration::from_secs(block_duration_secs),
            block_threshold,
        }
    }
    
    /// Sprawdza czy IP może wykonać enrollment
    /// Returns: Ok(remaining) lub Err z czasem do odblokowania
    pub fn check_and_increment(&self, ip: IpAddr) -> Result<u32, Duration> {
        // 1. Sprawdź czy zablokowany
        {
            let blocked = self.blocked_ips.read().unwrap();
            if let Some(blocked_at) = blocked.get(&ip) {
                let elapsed = blocked_at.elapsed();
                if elapsed < self.block_duration {
                    return Err(self.block_duration - elapsed);
                }
            }
        }
        
        // 2. Sprawdź/aktualizuj licznik
        let mut counts = self.ip_counts.write().unwrap();
        
        let (count, window_start) = counts
            .entry(ip)
            .or_insert((0, Instant::now()));
        
        // Reset jeśli nowe okno
        if window_start.elapsed() >= self.window_duration {
            *count = 0;
            *window_start = Instant::now();
        }
        
        *count += 1;
        let current_count = *count;
        
        // 3. Sprawdź czy przekroczył próg blokady
        if current_count > self.block_threshold {
            drop(counts);
            let mut blocked = self.blocked_ips.write().unwrap();
            blocked.insert(ip, Instant::now());
            // Cleanup old blocks
            blocked.retain(|_, t| t.elapsed() < self.block_duration);
            return Err(self.block_duration);
        }
        
        // 4. Sprawdź limit okna
        if current_count > self.max_per_window {
            let remaining = self.window_duration.saturating_sub(window_start.elapsed());
            return Err(remaining);
        }
        
        Ok(self.max_per_window - current_count)
    }
    
    /// Czyści stare wpisy (wywoływać okresowo)
    pub fn cleanup(&self) {
        let mut counts = self.ip_counts.write().unwrap();
        counts.retain(|_, (_, start)| start.elapsed() < self.window_duration * 2);
        
        let mut blocked = self.blocked_ips.write().unwrap();
        blocked.retain(|_, t| t.elapsed() < self.block_duration);
    }
    
    /// Statystyki
    pub fn stats(&self) -> RateLimiterStats {
        let counts = self.ip_counts.read().unwrap();
        let blocked = self.blocked_ips.read().unwrap();
        
        RateLimiterStats {
            tracked_ips: counts.len(),
            blocked_ips: blocked.len(),
        }
    }
}

impl Default for EnrollmentRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub tracked_ips: usize,
    pub blocked_ips: usize,
}

// ═══════════════════════════════════════════════════════════════════════════════
// PERSISTENT STORAGE
// ═══════════════════════════════════════════════════════════════════════════════

/// Format serializacji DeviceState do persystencji
#[derive(Debug, Clone)]
pub struct PersistedDeviceState {
    pub device_id: [u8; 16],
    pub burst_tokens: u32,
    pub suspicion_count: u32,
    pub banned_until_ts: Option<u64>, // Unix timestamp
    pub enrollment_solve_time_ms: u64,
    pub last_seen_ts: u64,
}

impl PersistedDeviceState {
    /// Serializacja do line format (łatwe do debugowania)
    /// Format: hex_device_id:burst:suspicion:banned_ts:solve_time:last_seen
    pub fn to_line(&self) -> String {
        let banned = self.banned_until_ts.unwrap_or(0);
        format!(
            "{}:{}:{}:{}:{}:{}\n",
            hex::encode(self.device_id),
            self.burst_tokens,
            self.suspicion_count,
            banned,
            self.enrollment_solve_time_ms,
            self.last_seen_ts
        )
    }
    
    /// Parsowanie z line
    pub fn from_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        
        let device_id_vec = hex::decode(parts[0]).ok()?;
        if device_id_vec.len() != 16 {
            return None;
        }
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&device_id_vec);
        
        let burst_tokens: u32 = parts[1].parse().ok()?;
        let suspicion_count: u32 = parts[2].parse().ok()?;
        let banned_ts: u64 = parts[3].parse().ok()?;
        let enrollment_solve_time_ms: u64 = parts[4].parse().ok()?;
        let last_seen_ts: u64 = parts[5].parse().ok()?;
        
        Some(Self {
            device_id,
            burst_tokens,
            suspicion_count,
            banned_until_ts: if banned_ts > 0 { Some(banned_ts) } else { None },
            enrollment_solve_time_ms,
            last_seen_ts,
        })
    }
}

/// Manager persystencji dla DeviceState
pub struct DeviceStateStorage {
    path: std::path::PathBuf,
    /// Auto-save interval
    save_interval: Duration,
    /// Last save time
    last_save: RwLock<Instant>,
    /// Dirty flag (needs save)
    dirty: RwLock<bool>,
}

impl DeviceStateStorage {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            save_interval: Duration::from_secs(60), // Save every minute if dirty
            last_save: RwLock::new(Instant::now()),
            dirty: RwLock::new(false),
        }
    }
    
    /// Ładuje wszystkie urządzenia z pliku
    pub fn load(&self) -> io::Result<Vec<PersistedDeviceState>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        
        let file = fs::File::open(&self.path)?;
        let reader = io::BufReader::new(file);
        
        let mut devices = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(state) = PersistedDeviceState::from_line(&line) {
                devices.push(state);
            }
        }
        
        Ok(devices)
    }
    
    /// Zapisuje wszystkie urządzenia do pliku
    pub(crate) fn save(&self, devices: &HashMap<[u8; 16], DeviceState>) -> io::Result<()> {
        // Atomic write: write to temp, then rename
        let temp_path = self.path.with_extension("tmp");
        
        let mut file = fs::File::create(&temp_path)?;
        
        // Header
        writeln!(file, "# TT Device State Storage v1")?;
        writeln!(file, "# Format: device_id:burst:suspicion:banned_ts:solve_time:last_seen")?;
        
        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        for (device_id, state) in devices {
            let banned_ts = state.banned_until.map(|instant| {
                // Convert Instant to approximate Unix timestamp
                let remaining = instant.saturating_duration_since(Instant::now());
                now_ts + remaining.as_secs()
            });
            
            let persisted = PersistedDeviceState {
                device_id: *device_id,
                burst_tokens: state.burst_tokens,
                suspicion_count: state.suspicion_count,
                banned_until_ts: banned_ts,
                enrollment_solve_time_ms: state.enrollment_solve_time_ms,
                last_seen_ts: now_ts,
            };
            
            file.write_all(persisted.to_line().as_bytes())?;
        }
        
        file.sync_all()?;
        drop(file);
        
        // Atomic rename
        fs::rename(&temp_path, &self.path)?;
        
        *self.last_save.write().unwrap() = Instant::now();
        *self.dirty.write().unwrap() = false;
        
        Ok(())
    }
    
    /// Oznacza jako dirty (wymaga zapisu)
    pub fn mark_dirty(&self) {
        *self.dirty.write().unwrap() = true;
    }
    
    /// Zapisuje jeśli dirty i minął interval
    pub(crate) fn maybe_save(&self, devices: &HashMap<[u8; 16], DeviceState>) -> io::Result<bool> {
        let dirty = *self.dirty.read().unwrap();
        let elapsed = self.last_save.read().unwrap().elapsed();
        
        if dirty && elapsed >= self.save_interval {
            self.save(devices)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// Konwertuje PersistedDeviceState do DeviceState
    pub(crate) fn to_device_state(persisted: &PersistedDeviceState) -> DeviceState {
        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let banned_until = persisted.banned_until_ts.and_then(|ts| {
            if ts > now_ts {
                Some(Instant::now() + Duration::from_secs(ts - now_ts))
            } else {
                None
            }
        });
        
        DeviceState {
            burst_tokens: persisted.burst_tokens,
            last_regen: Instant::now(), // Reset - nie możemy persystować Instant
            suspicion_count: persisted.suspicion_count,
            banned_until,
            pending_challenges: HashMap::new(), // Nie persystujemy - i tak wygasną
            enrollment_solve_time_ms: persisted.enrollment_solve_time_ms,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROMETHEUS METRICS
// ═══════════════════════════════════════════════════════════════════════════════

/// Metryki dla Prometheus
/// 
/// Eksportowane jako:
/// ```text
/// # HELP tt_verified_pow_enrollments_total Total enrollment attempts
/// # TYPE tt_verified_pow_enrollments_total counter
/// tt_verified_pow_enrollments_total{status="success"} 1234
/// tt_verified_pow_enrollments_total{status="expired"} 56
/// tt_verified_pow_enrollments_total{status="invalid"} 12
///
/// # HELP tt_verified_pow_challenges_total Total PoW challenges issued
/// # TYPE tt_verified_pow_challenges_total counter
/// tt_verified_pow_challenges_total 5678
///
/// # HELP tt_verified_pow_verifications_total Total PoW verifications
/// # TYPE tt_verified_pow_verifications_total counter
/// tt_verified_pow_verifications_total{status="success"} 4567
/// tt_verified_pow_verifications_total{status="invalid"} 89
/// tt_verified_pow_verifications_total{status="replay"} 12
/// tt_verified_pow_verifications_total{status="suspicious"} 5
///
/// # HELP tt_verified_pow_active_devices Current number of active devices
/// # TYPE tt_verified_pow_active_devices gauge
/// tt_verified_pow_active_devices 890
///
/// # HELP tt_verified_pow_banned_devices Current number of banned devices
/// # TYPE tt_verified_pow_banned_devices gauge
/// tt_verified_pow_banned_devices 23
/// ```
pub struct VerifiedPowMetrics {
    // Counters
    pub enrollments_success: AtomicU64,
    pub enrollments_expired: AtomicU64,
    pub enrollments_invalid: AtomicU64,
    pub enrollments_rate_limited: AtomicU64,
    
    pub challenges_issued: AtomicU64,
    pub burst_used: AtomicU64,
    
    pub verifications_success: AtomicU64,
    pub verifications_invalid: AtomicU64,
    pub verifications_replay: AtomicU64,
    pub verifications_suspicious: AtomicU64,
    pub verifications_expired: AtomicU64,
    
    // Gauges (set externally)
    pub active_devices: AtomicU64,
    pub banned_devices: AtomicU64,
    pub pending_enrollments: AtomicU64,
}

impl VerifiedPowMetrics {
    pub fn new() -> Self {
        Self {
            enrollments_success: AtomicU64::new(0),
            enrollments_expired: AtomicU64::new(0),
            enrollments_invalid: AtomicU64::new(0),
            enrollments_rate_limited: AtomicU64::new(0),
            
            challenges_issued: AtomicU64::new(0),
            burst_used: AtomicU64::new(0),
            
            verifications_success: AtomicU64::new(0),
            verifications_invalid: AtomicU64::new(0),
            verifications_replay: AtomicU64::new(0),
            verifications_suspicious: AtomicU64::new(0),
            verifications_expired: AtomicU64::new(0),
            
            active_devices: AtomicU64::new(0),
            banned_devices: AtomicU64::new(0),
            pending_enrollments: AtomicU64::new(0),
        }
    }
    
    /// Eksportuje metryki w formacie Prometheus
    pub fn export_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);
        
        // Enrollments
        out.push_str("# HELP tt_verified_pow_enrollments_total Total enrollment attempts\n");
        out.push_str("# TYPE tt_verified_pow_enrollments_total counter\n");
        out.push_str(&format!(
            "tt_verified_pow_enrollments_total{{status=\"success\"}} {}\n",
            self.enrollments_success.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tt_verified_pow_enrollments_total{{status=\"expired\"}} {}\n",
            self.enrollments_expired.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tt_verified_pow_enrollments_total{{status=\"invalid\"}} {}\n",
            self.enrollments_invalid.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tt_verified_pow_enrollments_total{{status=\"rate_limited\"}} {}\n",
            self.enrollments_rate_limited.load(Ordering::Relaxed)
        ));
        
        // Challenges
        out.push_str("\n# HELP tt_verified_pow_challenges_total Total PoW challenges issued\n");
        out.push_str("# TYPE tt_verified_pow_challenges_total counter\n");
        out.push_str(&format!(
            "tt_verified_pow_challenges_total {}\n",
            self.challenges_issued.load(Ordering::Relaxed)
        ));
        
        out.push_str("\n# HELP tt_verified_pow_burst_used_total Total burst tokens used\n");
        out.push_str("# TYPE tt_verified_pow_burst_used_total counter\n");
        out.push_str(&format!(
            "tt_verified_pow_burst_used_total {}\n",
            self.burst_used.load(Ordering::Relaxed)
        ));
        
        // Verifications
        out.push_str("\n# HELP tt_verified_pow_verifications_total Total PoW verifications\n");
        out.push_str("# TYPE tt_verified_pow_verifications_total counter\n");
        out.push_str(&format!(
            "tt_verified_pow_verifications_total{{status=\"success\"}} {}\n",
            self.verifications_success.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tt_verified_pow_verifications_total{{status=\"invalid\"}} {}\n",
            self.verifications_invalid.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tt_verified_pow_verifications_total{{status=\"replay\"}} {}\n",
            self.verifications_replay.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tt_verified_pow_verifications_total{{status=\"suspicious\"}} {}\n",
            self.verifications_suspicious.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tt_verified_pow_verifications_total{{status=\"expired\"}} {}\n",
            self.verifications_expired.load(Ordering::Relaxed)
        ));
        
        // Gauges
        out.push_str("\n# HELP tt_verified_pow_active_devices Current number of active devices\n");
        out.push_str("# TYPE tt_verified_pow_active_devices gauge\n");
        out.push_str(&format!(
            "tt_verified_pow_active_devices {}\n",
            self.active_devices.load(Ordering::Relaxed)
        ));
        
        out.push_str("\n# HELP tt_verified_pow_banned_devices Current number of banned devices\n");
        out.push_str("# TYPE tt_verified_pow_banned_devices gauge\n");
        out.push_str(&format!(
            "tt_verified_pow_banned_devices {}\n",
            self.banned_devices.load(Ordering::Relaxed)
        ));
        
        out.push_str("\n# HELP tt_verified_pow_pending_enrollments Current pending enrollment challenges\n");
        out.push_str("# TYPE tt_verified_pow_pending_enrollments gauge\n");
        out.push_str(&format!(
            "tt_verified_pow_pending_enrollments {}\n",
            self.pending_enrollments.load(Ordering::Relaxed)
        ));
        
        out
    }
    
    /// Aktualizuje gauges z aktualnego stanu
    pub fn update_gauges(&self, active: u64, banned: u64, pending: u64) {
        self.active_devices.store(active, Ordering::Relaxed);
        self.banned_devices.store(banned, Ordering::Relaxed);
        self.pending_enrollments.store(pending, Ordering::Relaxed);
    }
}

impl Default for VerifiedPowMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXTENDED VERIFIED DEVICE MANAGER (z wszystkimi feature'ami)
// ═══════════════════════════════════════════════════════════════════════════════

/// Extended manager z rate limiting, persistence i metrics
pub struct VerifiedDeviceManagerExt {
    /// Core manager
    pub core: VerifiedDeviceManager,
    /// Rate limiter dla enrollment
    pub rate_limiter: EnrollmentRateLimiter,
    /// Persistent storage
    pub storage: Option<DeviceStateStorage>,
    /// Prometheus metrics
    pub metrics: VerifiedPowMetrics,
}

impl VerifiedDeviceManagerExt {
    pub fn new() -> Self {
        Self {
            core: VerifiedDeviceManager::new(),
            rate_limiter: EnrollmentRateLimiter::new(),
            storage: None,
            metrics: VerifiedPowMetrics::new(),
        }
    }
    
    pub fn with_storage<P: AsRef<Path>>(mut self, path: P) -> io::Result<Self> {
        let storage = DeviceStateStorage::new(path);
        
        // Load existing devices
        let persisted = storage.load()?;
        {
            let mut devices = self.core.devices.write().unwrap();
            for p in persisted {
                let state = DeviceStateStorage::to_device_state(&p);
                devices.insert(p.device_id, state);
            }
        }
        
        self.storage = Some(storage);
        Ok(self)
    }
    
    /// Start enrollment z rate limiting
    pub fn start_enrollment_limited(
        &self,
        client_ip: IpAddr,
    ) -> Result<EnrollmentChallenge, EnrollmentRateLimitError> {
        // Check rate limit
        match self.rate_limiter.check_and_increment(client_ip) {
            Ok(_remaining) => {
                let challenge = self.core.start_enrollment();
                self.metrics.pending_enrollments.fetch_add(1, Ordering::Relaxed);
                Ok(challenge)
            }
            Err(wait_duration) => {
                self.metrics.enrollments_rate_limited.fetch_add(1, Ordering::Relaxed);
                Err(EnrollmentRateLimitError::TooManyRequests {
                    retry_after_secs: wait_duration.as_secs(),
                })
            }
        }
    }
    
    /// Complete enrollment z metrics
    pub fn complete_enrollment_tracked(
        &self,
        challenge: &EnrollmentChallenge,
        solution: &PowSolution,
    ) -> Result<DeviceCredential, VerifiedPowError> {
        match self.core.complete_enrollment(challenge, solution) {
            Ok(credential) => {
                self.metrics.enrollments_success.fetch_add(1, Ordering::Relaxed);
                self.metrics.pending_enrollments.fetch_sub(1, Ordering::Relaxed);
                self.mark_dirty();
                Ok(credential)
            }
            Err(VerifiedPowError::EnrollmentExpired) => {
                self.metrics.enrollments_expired.fetch_add(1, Ordering::Relaxed);
                Err(VerifiedPowError::EnrollmentExpired)
            }
            Err(VerifiedPowError::InvalidSolution) => {
                self.metrics.enrollments_invalid.fetch_add(1, Ordering::Relaxed);
                Err(VerifiedPowError::InvalidSolution)
            }
            Err(e) => Err(e),
        }
    }
    
    /// Check device z metrics
    pub fn check_device_tracked(
        &self,
        credential: &DeviceCredential,
    ) -> Result<Option<PersonalizedChallenge>, VerifiedPowError> {
        match self.core.check_device(credential) {
            Ok(None) => {
                self.metrics.burst_used.fetch_add(1, Ordering::Relaxed);
                self.mark_dirty();
                Ok(None)
            }
            Ok(Some(challenge)) => {
                self.metrics.challenges_issued.fetch_add(1, Ordering::Relaxed);
                Ok(Some(challenge))
            }
            Err(e) => Err(e),
        }
    }
    
    /// Verify solution z metrics
    pub fn verify_solution_tracked(
        &self,
        credential: &DeviceCredential,
        challenge: &PersonalizedChallenge,
        solution: &PowSolution,
        server_measured_ms: u64,
    ) -> Result<(), VerifiedPowError> {
        match self.core.verify_solution(credential, challenge, solution, server_measured_ms) {
            Ok(()) => {
                self.metrics.verifications_success.fetch_add(1, Ordering::Relaxed);
                self.mark_dirty();
                Ok(())
            }
            Err(VerifiedPowError::InvalidSolution) => {
                self.metrics.verifications_invalid.fetch_add(1, Ordering::Relaxed);
                Err(VerifiedPowError::InvalidSolution)
            }
            Err(VerifiedPowError::ChallengeAlreadyUsed) => {
                self.metrics.verifications_replay.fetch_add(1, Ordering::Relaxed);
                Err(VerifiedPowError::ChallengeAlreadyUsed)
            }
            Err(VerifiedPowError::SuspiciousTiming { expected_ms, actual_ms }) => {
                self.metrics.verifications_suspicious.fetch_add(1, Ordering::Relaxed);
                Err(VerifiedPowError::SuspiciousTiming { expected_ms, actual_ms })
            }
            Err(VerifiedPowError::ChallengeExpired) => {
                self.metrics.verifications_expired.fetch_add(1, Ordering::Relaxed);
                Err(VerifiedPowError::ChallengeExpired)
            }
            Err(e) => Err(e),
        }
    }
    
    /// Oznacza storage jako dirty
    fn mark_dirty(&self) {
        if let Some(ref storage) = self.storage {
            storage.mark_dirty();
        }
    }
    
    /// Okresowy maintenance (wywoływać np. co minutę)
    pub fn maintenance(&self) -> io::Result<()> {
        // Update gauges
        let devices = self.core.devices.read().unwrap();
        let active = devices.len() as u64;
        let banned = devices.values()
            .filter(|s| s.banned_until.map(|t| Instant::now() < t).unwrap_or(false))
            .count() as u64;
        drop(devices);
        
        let pending = self.core.pending_enrollments.read().unwrap().len() as u64;
        
        self.metrics.update_gauges(active, banned, pending);
        
        // Maybe save
        if let Some(ref storage) = self.storage {
            let devices = self.core.devices.read().unwrap();
            storage.maybe_save(&devices)?;
        }
        
        // Cleanup rate limiter
        self.rate_limiter.cleanup();
        
        Ok(())
    }
    
    /// Force save
    pub fn force_save(&self) -> io::Result<()> {
        if let Some(ref storage) = self.storage {
            let devices = self.core.devices.read().unwrap();
            storage.save(&devices)?;
        }
        Ok(())
    }
    
    /// Export metrics
    pub fn export_metrics(&self) -> String {
        self.metrics.export_prometheus()
    }
}

impl Default for VerifiedDeviceManagerExt {
    fn default() -> Self {
        Self::new()
    }
}

/// Błąd rate limiting dla enrollment
#[derive(Debug, Clone, PartialEq)]
pub enum EnrollmentRateLimitError {
    TooManyRequests { retry_after_secs: u64 },
}

impl std::fmt::Display for EnrollmentRateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyRequests { retry_after_secs } => {
                write!(f, "Too many enrollment requests. Retry after {} seconds", retry_after_secs)
            }
        }
    }
}

impl std::error::Error for EnrollmentRateLimitError {}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_server_signing_key() {
        let key = ServerSigningKey::new();
        let data = b"test message";
        
        let sig = key.sign(data);
        assert!(key.verify(data, &sig));
        
        // Zły podpis
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xFF;
        assert!(!key.verify(data, &bad_sig));
        
        // Zła wiadomość
        assert!(!key.verify(b"other message", &sig));
    }
    
    #[test]
    fn test_power_class_from_hash_rate() {
        assert_eq!(VerifiedPowerClass::from_hash_rate(500), VerifiedPowerClass::VeryWeak);
        assert_eq!(VerifiedPowerClass::from_hash_rate(5000), VerifiedPowerClass::Weak);
        assert_eq!(VerifiedPowerClass::from_hash_rate(30000), VerifiedPowerClass::Medium);
        assert_eq!(VerifiedPowerClass::from_hash_rate(100000), VerifiedPowerClass::Fast);
        assert_eq!(VerifiedPowerClass::from_hash_rate(500000), VerifiedPowerClass::VeryFast);
        assert_eq!(VerifiedPowerClass::from_hash_rate(5000000), VerifiedPowerClass::Extreme);
    }
    
    #[test]
    fn test_enrollment_full_flow() {
        let manager = VerifiedDeviceManager::new();
        
        // 1. Start enrollment
        let challenge = manager.start_enrollment();
        println!("Enrollment challenge: difficulty={}", challenge.difficulty_bits);
        
        // 2. Solve (symulacja - w realnym scenariuszu byłby czas sieciowy)
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        println!("Solved in {} ms", solution.solve_time_ms);
        
        // 3. Complete enrollment
        let credential = manager.complete_enrollment(&challenge, &solution)
            .expect("Enrollment should succeed");
        
        println!("Got credential: power_class={}, hash_rate={}",
            credential.power_class, credential.measured_hash_rate);
        
        // 4. Verify credential
        assert!(credential.verify_signature(&manager.server_key));
        assert!(credential.is_valid());
    }
    
    #[test]
    fn test_credential_serialization() {
        let manager = VerifiedDeviceManager::new();
        let challenge = manager.start_enrollment();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let credential = manager.complete_enrollment(&challenge, &solution).unwrap();
        
        let bytes = credential.to_bytes();
        let restored = DeviceCredential::from_bytes(&bytes).expect("Should deserialize");
        
        assert_eq!(credential.device_id, restored.device_id);
        assert_eq!(credential.power_class, restored.power_class);
        assert_eq!(credential.measured_hash_rate, restored.measured_hash_rate);
        assert!(restored.verify_signature(&manager.server_key));
    }
    
    #[test]
    fn test_burst_tokens() {
        let config = VerifiedDeviceConfig {
            initial_burst: 3,
            ..Default::default()
        };
        let manager = VerifiedDeviceManager::with_config(config);
        
        // Enrollment
        let challenge = manager.start_enrollment();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let credential = manager.complete_enrollment(&challenge, &solution).unwrap();
        
        // Pierwsze 3 requesty: burst
        for i in 0..3 {
            let result = manager.check_device(&credential);
            assert!(matches!(result, Ok(None)), "Request {} should use burst", i);
        }
        
        // 4-ty: wymaga PoW
        let result = manager.check_device(&credential);
        assert!(matches!(result, Ok(Some(_))), "4th request should require PoW");
    }
    
    #[test]
    fn test_personalized_challenge_unique() {
        let device1 = [1u8; 16];
        let device2 = [2u8; 16];
        
        let c1 = PersonalizedChallenge::new(device1, VerifiedPowerClass::Medium, 1.0);
        let c2 = PersonalizedChallenge::new(device2, VerifiedPowerClass::Medium, 1.0);
        
        // Różne urządzenia = różne challenge
        assert_ne!(c1.challenge_data, c2.challenge_data);
        assert_ne!(c1.device_id, c2.device_id);
    }
    
    #[test]
    fn test_load_affects_difficulty() {
        let device_id = [1u8; 16];
        
        let c_normal = PersonalizedChallenge::new(device_id, VerifiedPowerClass::Medium, 1.0);
        let c_high = PersonalizedChallenge::new(device_id, VerifiedPowerClass::Medium, 2.0);
        
        // Wyższy load = wyższa trudność
        assert!(c_high.difficulty_bits > c_normal.difficulty_bits,
            "High load should increase difficulty: normal={}, high={}",
            c_normal.difficulty_bits, c_high.difficulty_bits);
    }
    
    #[test]
    fn test_full_verified_flow() {
        // Użyj normalnej konfiguracji - timing check jest teraz spójny
        let manager = VerifiedDeviceManager::new();
        
        // 1. Enrollment
        let enroll_challenge = manager.start_enrollment();
        let enroll_solution = solve_pow(&enroll_challenge.challenge_data, enroll_challenge.difficulty_bits);
        let credential = manager.complete_enrollment(&enroll_challenge, &enroll_solution).unwrap();
        
        // 2. Wyczerpaj burst
        for _ in 0..5 {
            let _ = manager.check_device(&credential);
        }
        
        // 3. Teraz wymaga PoW
        let challenge = manager.check_device(&credential)
            .expect("Should succeed")
            .expect("Should require PoW");
        
        // 4. Solve
        let start = Instant::now();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let server_measured = start.elapsed().as_millis() as u64;
        
        // 5. Verify
        let result = manager.verify_solution(&credential, &challenge, &solution, server_measured);
        assert!(result.is_ok(), "Valid solution should be accepted: {:?}", result);
        
        // 6. Replay powinien być odrzucony
        let replay = manager.verify_solution(&credential, &challenge, &solution, server_measured);
        assert!(matches!(replay, Err(VerifiedPowError::ChallengeAlreadyUsed)));
    }
    
    /// Test że timing check działa poprawnie (wykrywa oszustów)
    #[test]
    fn test_timing_anti_cheat_detects_suspicious() {
        let config = VerifiedDeviceConfig {
            suspicion_ratio: 5.0, // Normalny ratio
            ..Default::default()
        };
        let manager = VerifiedDeviceManager::with_config(config);
        
        // 1. Enrollment - symuluj WOLNE urządzenie
        // Długi sleep ustanawia bazowy czas rozwiązywania
        let enroll_challenge = manager.start_enrollment();
        std::thread::sleep(Duration::from_millis(500)); // Symuluj WOLNE urządzenie
        let enroll_solution = solve_pow(&enroll_challenge.challenge_data, enroll_challenge.difficulty_bits);
        let credential = manager.complete_enrollment(&enroll_challenge, &enroll_solution).unwrap();
        
        // 2. Wyczerpaj burst
        for _ in 0..5 {
            let _ = manager.check_device(&credential);
        }
        
        // 3. Teraz wymaga PoW
        let challenge = manager.check_device(&credential)
            .expect("Should succeed")
            .expect("Should require PoW");
        
        // 4. Solve NATYCHMIAST (bez sleep - oszust z pre-computed solution)
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let fake_fast_time = 1; // Nieistotne - serwer mierzy wewnętrznie
        
        // 5. Verify powinien wykryć suspicious timing
        // enrollment_solve_time ~500ms, actual_wall_clock ~kilka ms
        // ratio = 500 / kilka = ~100x > 5.0 → SUSPICIOUS
        let result = manager.verify_solution(&credential, &challenge, &solution, fake_fast_time);
        assert!(
            matches!(result, Err(VerifiedPowError::SuspiciousTiming { .. })),
            "Should detect suspicious timing, got: {:?}", result
        );
    }
    
    #[test]
    fn test_invalid_credential_rejected() {
        let manager = VerifiedDeviceManager::new();
        
        // Stwórz fake credential z fałszywym podpisem
        let fake_credential = DeviceCredential {
            device_id: [99u8; 16],
            power_class: VerifiedPowerClass::VeryWeak,
            measured_hash_rate: 1000,
            issued_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            valid_for_secs: 3600,
            // Fałszywy podpis - za krótki i nieprawidłowy
            server_signature: vec![0u8; 700], 
        };
        
        let result = manager.check_device(&fake_credential);
        assert!(matches!(result, Err(VerifiedPowError::InvalidCredentialSignature)));
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // RATE LIMITER TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_rate_limiter_allows_initial_requests() {
        let limiter = EnrollmentRateLimiter::with_config(3, 3600, 10, 86400);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        
        // Pierwsze 3 powinny przejść
        assert!(limiter.check_and_increment(ip).is_ok());
        assert!(limiter.check_and_increment(ip).is_ok());
        assert!(limiter.check_and_increment(ip).is_ok());
        
        // 4-te powinno być zablokowane
        assert!(limiter.check_and_increment(ip).is_err());
    }
    
    #[test]
    fn test_rate_limiter_different_ips_independent() {
        let limiter = EnrollmentRateLimiter::with_config(2, 3600, 10, 86400);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        
        // Wyczerpaj limit dla ip1
        assert!(limiter.check_and_increment(ip1).is_ok());
        assert!(limiter.check_and_increment(ip1).is_ok());
        assert!(limiter.check_and_increment(ip1).is_err());
        
        // ip2 nadal ma limit
        assert!(limiter.check_and_increment(ip2).is_ok());
        assert!(limiter.check_and_increment(ip2).is_ok());
    }
    
    #[test]
    fn test_rate_limiter_block_threshold() {
        let limiter = EnrollmentRateLimiter::with_config(2, 3600, 5, 86400);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        
        // Spamuj aż do block_threshold
        for _ in 0..6 {
            let _ = limiter.check_and_increment(ip);
        }
        
        // Powinien być zablokowany na dłużej
        let result = limiter.check_and_increment(ip);
        match result {
            Err(duration) => {
                assert!(duration.as_secs() > 3600, "Should be blocked for > 1 hour");
            }
            Ok(_) => panic!("Should be blocked after threshold"),
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // PERSISTENCE TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_persisted_state_serialization() {
        let state = PersistedDeviceState {
            device_id: [0xAB; 16],
            burst_tokens: 5,
            suspicion_count: 2,
            banned_until_ts: Some(1700000000),
            enrollment_solve_time_ms: 150,
            last_seen_ts: 1699999999,
        };
        
        let line = state.to_line();
        let restored = PersistedDeviceState::from_line(&line).unwrap();
        
        assert_eq!(state.device_id, restored.device_id);
        assert_eq!(state.burst_tokens, restored.burst_tokens);
        assert_eq!(state.suspicion_count, restored.suspicion_count);
        assert_eq!(state.banned_until_ts, restored.banned_until_ts);
        assert_eq!(state.enrollment_solve_time_ms, restored.enrollment_solve_time_ms);
    }
    
    #[test]
    fn test_persisted_state_no_ban() {
        let state = PersistedDeviceState {
            device_id: [0x12; 16],
            burst_tokens: 10,
            suspicion_count: 0,
            banned_until_ts: None,
            enrollment_solve_time_ms: 100,
            last_seen_ts: 1699999999,
        };
        
        let line = state.to_line();
        let restored = PersistedDeviceState::from_line(&line).unwrap();
        
        assert_eq!(restored.banned_until_ts, None);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // METRICS TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_metrics_export() {
        let metrics = VerifiedPowMetrics::new();
        
        // Increment some counters
        metrics.enrollments_success.fetch_add(10, Ordering::Relaxed);
        metrics.verifications_success.fetch_add(100, Ordering::Relaxed);
        metrics.challenges_issued.fetch_add(50, Ordering::Relaxed);
        
        let output = metrics.export_prometheus();
        
        assert!(output.contains("tt_verified_pow_enrollments_total{status=\"success\"} 10"));
        assert!(output.contains("tt_verified_pow_verifications_total{status=\"success\"} 100"));
        assert!(output.contains("tt_verified_pow_challenges_total 50"));
    }
    
    #[test]
    fn test_metrics_gauges() {
        let metrics = VerifiedPowMetrics::new();
        
        metrics.update_gauges(100, 5, 10);
        
        let output = metrics.export_prometheus();
        
        assert!(output.contains("tt_verified_pow_active_devices 100"));
        assert!(output.contains("tt_verified_pow_banned_devices 5"));
        assert!(output.contains("tt_verified_pow_pending_enrollments 10"));
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // EXTENDED MANAGER TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_extended_manager_rate_limiting() {
        let manager = VerifiedDeviceManagerExt::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        
        // Powinno przejść (default: 5 per hour)
        for _ in 0..5 {
            assert!(manager.start_enrollment_limited(ip).is_ok());
        }
        
        // 6-te powinno być rate limited
        let result = manager.start_enrollment_limited(ip);
        assert!(matches!(result, Err(EnrollmentRateLimitError::TooManyRequests { .. })));
        
        // Metrics powinny być zaktualizowane
        assert!(manager.metrics.enrollments_rate_limited.load(Ordering::Relaxed) > 0);
    }
    
    #[test]
    fn test_extended_manager_metrics_tracking() {
        let manager = VerifiedDeviceManagerExt::new();
        
        // Enrollment
        let challenge = manager.core.start_enrollment();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let credential = manager.complete_enrollment_tracked(&challenge, &solution).unwrap();
        
        assert_eq!(manager.metrics.enrollments_success.load(Ordering::Relaxed), 1);
        
        // Burst usage
        for _ in 0..3 {
            let _ = manager.check_device_tracked(&credential);
        }
        
        assert_eq!(manager.metrics.burst_used.load(Ordering::Relaxed), 3);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // SECURITY ATTACK TESTS - Realne wektory ataku
    // ═══════════════════════════════════════════════════════════════════════
    
    /// ATAK: Podmieniony klucz serwera - atakujący generuje własny ServerSigningKey
    #[test]
    fn test_attack_forged_server_key() {
        let legitimate_server = VerifiedDeviceManager::new();
        let attacker_server = ServerSigningKey::new(); // Atakujący tworzy własny klucz
        
        // Atakujący tworzy credential podpisany SWOIM kluczem
        let fake_credential = DeviceCredential {
            device_id: [0xAA; 16],
            power_class: VerifiedPowerClass::VeryFast, // Próbuje być VeryFast
            measured_hash_rate: 1_000_000,
            issued_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            valid_for_secs: 3600 * 24 * 365, // Rok ważności
            server_signature: attacker_server.sign(&{
                let mut data = Vec::new();
                data.extend_from_slice(&[0xAA; 16]);
                data.extend_from_slice(&(VerifiedPowerClass::VeryFast as u8).to_le_bytes());
                data.extend_from_slice(&1_000_000u64.to_le_bytes());
                data.extend_from_slice(&SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_le_bytes());
                data.extend_from_slice(&(3600u64 * 24 * 365).to_le_bytes());
                data
            }),
        };
        
        // Próba użycia na legitnym serwerze - MUSI być odrzucona
        let result = legitimate_server.check_device(&fake_credential);
        assert!(
            matches!(result, Err(VerifiedPowError::InvalidCredentialSignature)),
            "Forged credential should be rejected, got: {:?}", result
        );
    }
    
    /// ATAK: Credential z przyszłości - atakujący ustawia issued_at w przyszłości
    #[test]
    fn test_attack_future_credential() {
        let manager = VerifiedDeviceManager::new();
        
        // Enrollment - zdobądź prawdziwy credential
        let challenge = manager.start_enrollment();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let mut credential = manager.complete_enrollment(&challenge, &solution).unwrap();
        
        // Atakujący modyfikuje issued_at na przyszłość (żeby nigdy nie wygasł)
        credential.issued_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 86400 * 365;
        
        // To powinno być odrzucone bo podpis nie pasuje do zmodyfikowanych danych
        let result = manager.check_device(&credential);
        assert!(
            matches!(result, Err(VerifiedPowError::InvalidCredentialSignature)),
            "Modified credential should fail signature check, got: {:?}", result
        );
    }
    
    /// ATAK: Expired credential - testowanie is_valid()
    #[test]
    fn test_attack_expired_credential() {
        let manager = VerifiedDeviceManager::new();
        
        // Stwórz credential który już wygasł
        let expired_credential = DeviceCredential {
            device_id: [0xBB; 16],
            power_class: VerifiedPowerClass::Medium,
            measured_hash_rate: 50000,
            issued_at: 1000, // Bardzo stary timestamp (1970)
            valid_for_secs: 1, // Wygasł po 1 sekundzie
            server_signature: vec![0u8; 666], // Nieprawidłowy podpis też
        };
        
        // is_valid() powinien zwrócić false
        assert!(!expired_credential.is_valid(), "Expired credential should not be valid");
        
        // check_device powinien odrzucić (najpierw sprawdzi podpis)
        let result = manager.check_device(&expired_credential);
        assert!(result.is_err(), "Expired/invalid credential should be rejected");
    }
    
    /// ATAK: Zmiana rozmiaru credential - truncation attack
    #[test]
    fn test_attack_credential_truncation() {
        let manager = VerifiedDeviceManager::new();
        
        // Enrollment - zdobądź prawdziwy credential
        let challenge = manager.start_enrollment();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let credential = manager.complete_enrollment(&challenge, &solution).unwrap();
        
        // Serializuj
        let bytes = credential.to_bytes();
        
        // Atakujący obcina credential
        let truncated = &bytes[..bytes.len() - 100];
        
        // Deserializacja powinna się nie udać
        let result = DeviceCredential::from_bytes(truncated);
        assert!(result.is_none(), "Truncated credential should fail to deserialize");
        
        // Atakujący wydłuża credential (dopisuje śmieci)
        let mut extended = bytes.clone();
        extended.extend_from_slice(&[0xFF; 100]);
        
        // Deserializacja MOŻE się nie udać (bo mamy strict format)
        // LUB jeśli się uda, podpis nadal musi być prawidłowy
        match DeviceCredential::from_bytes(&extended) {
            Some(restored) => {
                // Jeśli deserializacja się udała, sprawdź podpis
                assert!(restored.verify_signature(&manager.server_key), 
                    "Restored credential should still have valid signature");
            }
            None => {
                // Deserializacja nie ignoruje trailing data - to też jest OK (strict parsing)
                // To jest nawet bezpieczniejsze podejście!
            }
        }
    }
    
    /// ATAK: Replay enrollment challenge
    #[test]
    fn test_attack_enrollment_replay() {
        let manager = VerifiedDeviceManager::new();
        
        // Start enrollment
        let challenge = manager.start_enrollment();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        
        // Pierwszy enrollment - OK
        let credential = manager.complete_enrollment(&challenge, &solution);
        assert!(credential.is_ok(), "First enrollment should succeed");
        
        // Replay tego samego challenge - MUSI być odrzucony
        let replay = manager.complete_enrollment(&challenge, &solution);
        assert!(
            matches!(replay, Err(VerifiedPowError::EnrollmentExpired)),
            "Replay enrollment should be rejected, got: {:?}", replay
        );
    }
    
    /// ATAK: Bit flip w podpisie - zmiana jednego bitu
    #[test]
    fn test_attack_signature_bit_flip() {
        let manager = VerifiedDeviceManager::new();
        
        // Enrollment - zdobądź prawdziwy credential
        let challenge = manager.start_enrollment();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let mut credential = manager.complete_enrollment(&challenge, &solution).unwrap();
        
        // Atakujący zmienia jeden bit w podpisie
        if !credential.server_signature.is_empty() {
            credential.server_signature[0] ^= 0x01;
        }
        
        // Weryfikacja powinna się nie udać
        let result = manager.check_device(&credential);
        assert!(
            matches!(result, Err(VerifiedPowError::InvalidCredentialSignature)),
            "Bit-flipped signature should be rejected, got: {:?}", result
        );
    }
    
    /// ATAK: Zmiana power_class w credential (downgrade attack na difficulty)
    #[test]
    fn test_attack_power_class_downgrade() {
        let manager = VerifiedDeviceManager::new();
        
        // Enrollment
        let challenge = manager.start_enrollment();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let mut credential = manager.complete_enrollment(&challenge, &solution).unwrap();
        
        // Zapisz oryginalny power_class
        let _original_class = credential.power_class;
        
        // Atakujący zmienia power_class na VeryWeak (łatwiejszy PoW)
        credential.power_class = VerifiedPowerClass::VeryWeak;
        
        // To powinno być odrzucone - podpis nie pasuje
        let result = manager.check_device(&credential);
        assert!(
            matches!(result, Err(VerifiedPowError::InvalidCredentialSignature)),
            "Power class manipulation should be rejected, got: {:?}", result
        );
    }
    
    /// ATAK: Zmiana device_id w credential (identity theft)
    #[test]
    fn test_attack_device_id_theft() {
        let manager = VerifiedDeviceManager::new();
        
        // Enrollment
        let challenge = manager.start_enrollment();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let mut credential = manager.complete_enrollment(&challenge, &solution).unwrap();
        
        // Zapisz oryginalne device_id
        let original_id = credential.device_id;
        
        // Atakujący zmienia device_id (próbuje podszywać się pod inne urządzenie)
        credential.device_id = [0xFF; 16];
        
        // To powinno być odrzucone - podpis nie pasuje
        let result = manager.check_device(&credential);
        assert!(
            matches!(result, Err(VerifiedPowError::InvalidCredentialSignature)),
            "Device ID theft should be rejected, got: {:?}", result
        );
        
        // Przywróć oryginalne device_id - powinno działać
        credential.device_id = original_id;
        // Ale nadal nie będzie działać bo credential był już zmodyfikowany w pamięci
        // Musimy pobrać świeży credential
        let challenge2 = manager.start_enrollment();
        let solution2 = solve_pow(&challenge2.challenge_data, challenge2.difficulty_bits);
        let fresh_credential = manager.complete_enrollment(&challenge2, &solution2).unwrap();
        
        let result = manager.check_device(&fresh_credential);
        assert!(result.is_ok(), "Fresh valid credential should work");
    }
    
    /// ATAK: Próba użycia credential przed oficjalnym wydaniem
    #[test]
    fn test_attack_premature_credential_use() {
        let manager = VerifiedDeviceManager::new();
        
        // Start enrollment - ale nie kończymy
        let _challenge = manager.start_enrollment();
        
        // Atakujący próbuje ręcznie stworzyć credential z losowymi danymi
        // (symulacja: atakujący wie jak wygląda credential)
        let fake_credential = DeviceCredential {
            device_id: [0xDE; 16], // Losowe device_id
            power_class: VerifiedPowerClass::Medium,
            measured_hash_rate: 50000,
            issued_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            valid_for_secs: 3600,
            server_signature: vec![0u8; 666], // Losowy podpis
        };
        
        // Musi być odrzucone - podpis nieprawidłowy
        let result = manager.check_device(&fake_credential);
        assert!(
            matches!(result, Err(VerifiedPowError::InvalidCredentialSignature)),
            "Premature credential should be rejected"
        );
    }
    
    /// ATAK: Hash rate manipulation - fałszywy benchmark
    #[test]
    fn test_attack_fake_hash_rate() {
        let manager = VerifiedDeviceManager::new();
        
        // Enrollment
        let challenge = manager.start_enrollment();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let mut credential = manager.complete_enrollment(&challenge, &solution).unwrap();
        
        // Atakujący zmienia measured_hash_rate na bardzo wysoką wartość
        credential.measured_hash_rate = 10_000_000;
        
        // To powinno być odrzucone - podpis nie pasuje
        let result = manager.check_device(&credential);
        assert!(
            matches!(result, Err(VerifiedPowError::InvalidCredentialSignature)),
            "Hash rate manipulation should be rejected, got: {:?}", result
        );
    }
    
    /// Test poprawności: ServerSigningKey używa Falcon-512 PQC
    #[test]
    fn test_server_key_is_pqc() {
        let key = ServerSigningKey::new();
        let data = b"test data for signing";
        let sig = key.sign(data);
        
        // Falcon-512 podpis ma 617-690 bajtów (kompresja zależna od wiadomości)
        // W praktyce może być nawet do ~750 bajtów
        assert!(sig.len() >= 600 && sig.len() <= 750, 
            "Signature should be Falcon-512 sized (600-750 bytes), got {} bytes", sig.len());
        
        // Weryfikacja powinna działać
        assert!(key.verify(data, &sig));
        
        // Falcon używa randomizacji - podpisy dla tej samej wiadomości są RÓŻNE
        // To jest zamierzone (dodatkowe bezpieczeństwo)
        let sig2 = key.sign(data);
        
        // Oba podpisy powinny być prawidłowe
        assert!(key.verify(data, &sig2), "Second signature should also verify");
        
        // Ale podpisy są różne (randomizacja)
        assert_ne!(sig, sig2, "Falcon uses randomized signing - signatures should differ");
    }
}
