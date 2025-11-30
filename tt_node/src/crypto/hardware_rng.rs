//! Hardware RNG Integration - PRAWDZIWA entropia
//!
//! Hierarchia źródeł (Linux-only):
//! 1. /dev/urandom - primary source (kernel miesza RDRAND + inne źródła)
//! 2. rand::rngs::OsRng - fallback (używa getrandom() syscall)
//!
//! UWAGA: RDRAND nie jest używany bezpośrednio ze względu na #![forbid(unsafe_code)].
//! Na nowoczesnych kernelach Linux (4.8+) /dev/urandom już wykorzystuje RDRAND
//! jako jedno ze źródeł entropii, więc pośrednio mamy jego korzyści.

use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

/// Status dostępności źródeł RNG
static URANDOM_AVAILABLE: AtomicBool = AtomicBool::new(false);
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Błędy Hardware RNG
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HwRngError {
    /// Brak dostępnego źródła entropii
    NoEntropySource,
    /// Błąd odczytu z /dev/urandom
    UrandomReadError,
    /// Żądana ilość bajtów przekracza limit
    TooManyBytes { requested: usize, max: usize },
    /// Entropia nie przeszła health check
    HealthCheckFailed,
}

impl std::fmt::Display for HwRngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEntropySource => write!(f, "No hardware entropy source available"),
            Self::UrandomReadError => write!(f, "Failed to read from /dev/urandom"),
            Self::TooManyBytes { requested, max } => {
                write!(f, "Requested {} bytes, max is {}", requested, max)
            }
            Self::HealthCheckFailed => write!(f, "Entropy health check failed"),
        }
    }
}

impl std::error::Error for HwRngError {}

/// Maksymalna ilość bajtów na jedno wywołanie
const MAX_BYTES_PER_CALL: usize = 1024 * 1024; // 1 MB

/// Hardware RNG - bezpieczne źródło entropii
pub struct HardwareRng {
    /// Marker that we're initialized
    _initialized: bool,
}

impl HardwareRng {
    /// Tworzy nowy HardwareRng
    /// 
    /// # Panics
    /// Panikuje jeśli brak dostępnego źródła entropii!
    pub fn new() -> Result<Self, HwRngError> {
        init_entropy_sources();
        
        if !URANDOM_AVAILABLE.load(Ordering::Relaxed) {
            return Err(HwRngError::NoEntropySource);
        }
        
        Ok(Self {
            _initialized: true,
        })
    }
    
    /// Wypełnia bufor losowymi bajtami z hardware RNG
    pub fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HwRngError> {
        if dest.len() > MAX_BYTES_PER_CALL {
            return Err(HwRngError::TooManyBytes {
                requested: dest.len(),
                max: MAX_BYTES_PER_CALL,
            });
        }
        
        // Próbuj /dev/urandom
        if URANDOM_AVAILABLE.load(Ordering::Relaxed) {
            if let Ok(()) = read_urandom(dest) {
                // Health check - sprawdź że nie same zera
                if !health_check(dest) {
                    return Err(HwRngError::HealthCheckFailed);
                }
                return Ok(());
            }
        }
        
        // Fallback do OsRng (używa getrandom syscall)
        use rand::RngCore;
        let mut os_rng = rand::rngs::OsRng;
        os_rng.fill_bytes(dest);
        
        if !health_check(dest) {
            return Err(HwRngError::HealthCheckFailed);
        }
        
        Ok(())
    }
    
    /// Generuje N losowych bajtów
    pub fn generate(&mut self, n: usize) -> Result<Zeroizing<Vec<u8>>, HwRngError> {
        let mut bytes = Zeroizing::new(vec![0u8; n]);
        self.fill_bytes(&mut bytes)?;
        Ok(bytes)
    }
    
    /// Generuje losowy u64
    pub fn generate_u64(&mut self) -> Result<u64, HwRngError> {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    
    /// Generuje losowy u128
    pub fn generate_u128(&mut self) -> Result<u128, HwRngError> {
        let mut bytes = [0u8; 16];
        self.fill_bytes(&mut bytes)?;
        Ok(u128::from_le_bytes(bytes))
    }
    
    /// Generuje seed dla KmacDrbg z prawdziwą entropią
    pub fn generate_seed(&mut self, personalization: &[u8]) -> Result<Zeroizing<Vec<u8>>, HwRngError> {
        // 64 bajty entropii + personalization
        let mut seed = Zeroizing::new(vec![0u8; 64]);
        self.fill_bytes(&mut seed)?;
        
        // Dodaj timestamp dla dodatkowej unikalności
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        
        seed.extend_from_slice(&timestamp.to_le_bytes());
        seed.extend_from_slice(personalization);
        
        Ok(seed)
    }
}

impl Default for HardwareRng {
    fn default() -> Self {
        Self::new().expect("No hardware entropy source available!")
    }
}

/// Implementacja rand_core::RngCore dla kompatybilności
impl rand_core::RngCore for HardwareRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes).expect("HardwareRng failed");
        u32::from_le_bytes(bytes)
    }
    
    fn next_u64(&mut self) -> u64 {
        self.generate_u64().expect("HardwareRng failed")
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        HardwareRng::fill_bytes(self, dest).expect("HardwareRng failed");
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        HardwareRng::fill_bytes(self, dest)
            .map_err(|_| rand_core::Error::new("HardwareRng failed"))
    }
}

impl rand_core::CryptoRng for HardwareRng {}

// ============================================================================
// Wewnętrzne funkcje
// ============================================================================

/// Inicjalizuje dostępne źródła entropii
fn init_entropy_sources() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return; // Już zainicjalizowane
    }
    
    // Sprawdź /dev/urandom
    if std::path::Path::new("/dev/urandom").exists() {
        if let Ok(mut file) = File::open("/dev/urandom") {
            let mut test = [0u8; 8];
            if file.read_exact(&mut test).is_ok() && test != [0u8; 8] {
                URANDOM_AVAILABLE.store(true, Ordering::Relaxed);
            }
        }
    }
}

/// Odczytuje z /dev/urandom
fn read_urandom(dest: &mut [u8]) -> Result<(), HwRngError> {
    let mut file = File::open("/dev/urandom")
        .map_err(|_| HwRngError::UrandomReadError)?;
    
    file.read_exact(dest)
        .map_err(|_| HwRngError::UrandomReadError)?;
    
    Ok(())
}

/// Health check - upewnij się że entropia nie jest zdegenerowana
fn health_check(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    
    // Check 1: Nie same zera
    if data.iter().all(|&b| b == 0) {
        return false;
    }
    
    // Check 2: Nie same jedynki
    if data.iter().all(|&b| b == 0xFF) {
        return false;
    }
    
    // Check 3: Nie powtarzający się pattern (dla >16 bajtów)
    if data.len() >= 16 {
        let first_8 = &data[0..8];
        let all_same = data.chunks(8).all(|chunk| {
            chunk.len() < 8 || chunk == first_8
        });
        if all_same {
            return false;
        }
    }
    
    // Check 4: Podstawowa entropia - co najmniej 25% bitów różnych od 0
    let ones = data.iter().map(|b| b.count_ones()).sum::<u32>();
    let total_bits = (data.len() * 8) as u32;
    let ratio = ones as f64 / total_bits as f64;
    
    // Oczekujemy ~50% jedynek, akceptujemy 25%-75%
    if ratio < 0.25 || ratio > 0.75 {
        return false;
    }
    
    true
}

// ============================================================================
// Bezpieczna kombinacja wielu źródeł
// ============================================================================

/// Łączy entropię z wielu źródeł przez SHAKE256 XOF
/// To jest defensywne - jeśli jedno źródło jest słabe, inne mogą pomóc
pub struct CombinedEntropy {
    hw_rng: HardwareRng,
}

impl CombinedEntropy {
    pub fn new() -> Result<Self, HwRngError> {
        Ok(Self {
            hw_rng: HardwareRng::new()?,
        })
    }
    
    /// Generuje entropię łącząc WSZYSTKIE źródła przez SHAKE256:
    /// 1. Hardware RNG (64 bajty)
    /// 2. Timestamp (nanoseconds)
    /// 3. Thread ID
    /// 4. Process ID
    /// 5. Personalization string
    pub fn generate_combined(
        &mut self, 
        n: usize, 
        personalization: &[u8]
    ) -> Result<Zeroizing<Vec<u8>>, HwRngError> {
        use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
        
        // Źródło 1: Hardware RNG (stały rozmiar 64B)
        let mut hw_bytes = [0u8; 64];
        self.hw_rng.fill_bytes(&mut hw_bytes)?;
        
        // Źródło 2: Timestamp (nanoseconds)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        
        // Źródło 3: Thread ID
        let thread_id = std::thread::current().id();
        let thread_hash = format!("{:?}", thread_id);
        
        // Źródło 4: Process ID
        let pid = std::process::id();
        
        // SHAKE256 jako XOF - miksuje WSZYSTKIE źródła
        let mut shake = Shake256::default();
        shake.update(&hw_bytes);
        shake.update(&timestamp.to_le_bytes());
        shake.update(thread_hash.as_bytes());
        shake.update(&pid.to_le_bytes());
        shake.update(personalization);
        
        // Ekstraktuj dokładnie n bajtów
        let mut xof = shake.finalize_xof();
        let mut output = Zeroizing::new(vec![0u8; n]);
        XofReader::read(&mut xof, &mut output);
        
        Ok(output)
    }
}

impl Default for CombinedEntropy {
    fn default() -> Self {
        Self::new().expect("No hardware entropy source available!")
    }
}

// ============================================================================
// Testy
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hardware_rng_basic() {
        let mut rng = HardwareRng::new().expect("HW RNG should be available");
        
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes).expect("fill_bytes should work");
        
        // Nie powinno być samych zer
        assert!(bytes.iter().any(|&b| b != 0));
    }
    
    #[test]
    fn test_hardware_rng_uniqueness() {
        let mut rng = HardwareRng::new().unwrap();
        
        let a = rng.generate(32).unwrap();
        let b = rng.generate(32).unwrap();
        
        // Dwa wywołania powinny dać różne wyniki
        assert_ne!(a.as_slice(), b.as_slice());
    }
    
    #[test]
    fn test_hardware_rng_distribution() {
        let mut rng = HardwareRng::new().unwrap();
        let mut bytes = vec![0u8; 10000];
        rng.fill_bytes(&mut bytes).unwrap();
        
        // Sprawdź rozkład bitów (powinien być ~50% jedynek)
        let ones: u32 = bytes.iter().map(|b| b.count_ones()).sum();
        let total = (bytes.len() * 8) as f64;
        let ratio = ones as f64 / total;
        
        // Akceptujemy 45%-55% - poluzowane żeby uniknąć rzadkich fali w CI
        // (statystycznie ekstremalnie mało prawdopodobne przy 80k bitów,
        //  ale random to random)
        assert!(ratio > 0.45 && ratio < 0.55, 
            "Bit distribution should be ~50%, got {:.2}%", ratio * 100.0);
    }
    
    #[test]
    fn test_health_check() {
        // Zera - fail
        assert!(!health_check(&[0u8; 32]));
        
        // Jedynki - fail
        assert!(!health_check(&[0xFF; 32]));
        
        // Prawidłowa entropia - pass
        let good = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
            0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        ];
        assert!(health_check(&good));
    }
    
    #[test]
    fn test_combined_entropy() {
        let mut ce = CombinedEntropy::new().unwrap();
        
        let a = ce.generate_combined(64, b"test1").unwrap();
        let b = ce.generate_combined(64, b"test2").unwrap();
        
        // Różna personalizacja = różny output
        assert_ne!(a.as_slice(), b.as_slice());
    }
    
    #[test]
    fn test_rand_core_compatibility() {
        use rand_core::RngCore;
        
        let mut rng = HardwareRng::new().unwrap();
        
        let u32_val = rng.next_u32();
        let u64_val = rng.next_u64();
        
        // Powinny być różne (statystycznie pewne)
        assert_ne!(u32_val as u64, u64_val);
    }
    
    #[test] 
    fn test_zeroizing_seed() {
        let mut rng = HardwareRng::new().unwrap();
        let seed = rng.generate_seed(b"keygen").unwrap();
        
        // Seed powinien mieć co najmniej 64 bajty
        assert!(seed.len() >= 64);
        
        // Powinien zawierać entropię
        assert!(health_check(&seed[..64]));
    }
}
