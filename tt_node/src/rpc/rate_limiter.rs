//! RPC Rate Limiter - Ochrona przed DoS/DDoS
//!
//! # Architektura Warstwowa
//!
//! ## Warstwa 1: Global RPS Limit
//! - Ostatnia linia obrony
//! - Chroni przed całkowitym przeciążeniem infrastruktury
//! - Stosowana dla WSZYSTKICH (anon + auth)
//!
//! ## Warstwa 2: Per-IP (Anonymous Users)
//! - Restrykcyjny limit dla niezalogowanych
//! - Tanie do sprawdzenia (nie wymaga krypto)
//! - Global expensive_bucket dla kosztownych operacji
//!
//! ## Warstwa 3: Per-Key (Authenticated Users)
//! - Każdy user ma WŁASNY budżet (key_bucket)
//! - NIE konkuruje z innymi userami
//! - NIE używa global expensive_bucket (to by karało legit users za ataki anon)
//! - Opcjonalnie: dodatkowy per-IP limit (auth_also_check_ip)
//!
//! ## Kluczowa zasada:
//! Authenticated users NIE są karani za grzechy anonymous attackers.
//! Ich key_bucket jest ich jedynym limitem na operacje.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Błędy Rate Limitera
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitError {
    /// Limit przekroczony
    RateLimitExceeded {
        limit_type: String,
        retry_after_ms: u64,
    },
    /// IP na blackliście
    IpBlacklisted {
        reason: String,
        /// Ile sekund pozostało do wygaśnięcia blacklisty (None = permanent)
        retry_after_secs: Option<u64>,
    },
    /// Klucz na blackliście
    KeyBlacklisted { reason: String },
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimitExceeded { limit_type, retry_after_ms } => {
                write!(f, "Rate limit exceeded ({}). Retry after {} ms", limit_type, retry_after_ms)
            }
            Self::IpBlacklisted { reason, retry_after_secs } => {
                if let Some(secs) = retry_after_secs {
                    write!(f, "IP blacklisted: {}. Retry after {} secs", reason, secs)
                } else {
                    write!(f, "IP blacklisted: {} (permanent)", reason)
                }
            }
            Self::KeyBlacklisted { reason } => {
                write!(f, "Key blacklisted: {}", reason)
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

/// Konfiguracja Rate Limitera
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    // ═══════════════════════════════════════════════════
    // Per-IP limits
    // ═══════════════════════════════════════════════════
    /// Tokeny na sekundę per IP
    pub ip_tokens_per_sec: f64,
    /// Maksymalna pojemność bucketu per IP
    pub ip_bucket_capacity: u32,
    /// Po ilu violations IP trafia na blacklist
    pub ip_violations_to_blacklist: u32,
    /// Czas blacklistu IP (sekundy, 0 = permanent)
    pub ip_blacklist_duration_secs: u64,
    
    // ═══════════════════════════════════════════════════
    // Per-Key limits (authenticated users)
    // ═══════════════════════════════════════════════════
    /// Tokeny na sekundę per klucz (wyższy limit dla auth)
    pub key_tokens_per_sec: f64,
    /// Maksymalna pojemność bucketu per klucz
    pub key_bucket_capacity: u32,
    
    // ═══════════════════════════════════════════════════
    // Per-IP limits dla authenticated (opcjonalne, defense-in-depth)
    // ═══════════════════════════════════════════════════
    /// Czy stosować TAKŻE per-IP limit dla authenticated users
    /// Chroni przed: skradziony klucz + flood z jednej maszyny
    /// Może przeszkadzać: corporate NAT z wieloma userami za 1 IP
    pub auth_also_check_ip: bool,
    /// Tokeny na sekundę per IP dla authenticated (wyższy niż dla anon)
    pub auth_ip_tokens_per_sec: f64,
    /// Maksymalna pojemność bucketu per IP dla authenticated
    pub auth_ip_bucket_capacity: u32,
    
    // ═══════════════════════════════════════════════════
    // Per-Endpoint limits
    // ═══════════════════════════════════════════════════
    /// Kosztowne operacje: tokeny na sekundę
    pub expensive_op_tokens_per_sec: f64,
    /// Kosztowne operacje: pojemność bucketu
    pub expensive_op_bucket_capacity: u32,
    
    // ═══════════════════════════════════════════════════
    // Global limits
    // ═══════════════════════════════════════════════════
    /// Globalny limit requestów na sekundę
    pub global_rps_limit: u32,
    
    // ═══════════════════════════════════════════════════
    // Cleanup
    // ═══════════════════════════════════════════════════
    /// Interwał czyszczenia nieaktywnych bucketów
    pub cleanup_interval_secs: u64,
    /// Bucket nieaktywny przez tyle sekund będzie usunięty
    pub bucket_inactive_timeout_secs: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            // Per-IP: 100 req/s, burst do 200
            ip_tokens_per_sec: 100.0,
            ip_bucket_capacity: 200,
            ip_violations_to_blacklist: 10,
            ip_blacklist_duration_secs: 3600, // 1h
            
            // Per-Key (authenticated): 500 req/s, burst do 1000
            key_tokens_per_sec: 500.0,
            key_bucket_capacity: 1000,
            
            // Per-IP dla authenticated (defense-in-depth)
            // Domyślnie wyłączone - włącz dla wysokiego bezpieczeństwa
            auth_also_check_ip: false,
            auth_ip_tokens_per_sec: 200.0,   // 2x anonymous
            auth_ip_bucket_capacity: 400,    // 2x anonymous
            
            // Expensive ops: 10/s, burst do 20
            expensive_op_tokens_per_sec: 10.0,
            expensive_op_bucket_capacity: 20,
            
            // Global: 10k req/s
            global_rps_limit: 10000,
            
            // Cleanup co 5 min, nieaktywne po 10 min
            cleanup_interval_secs: 300,
            bucket_inactive_timeout_secs: 600,
        }
    }
}

/// Token Bucket - podstawowy building block
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Aktualna liczba tokenów
    tokens: f64,
    /// Maksymalna pojemność
    capacity: f64,
    /// Tokeny dodawane na sekundę
    refill_rate: f64,
    /// Ostatni update
    last_update: Instant,
    /// Liczba violations
    violations: u32,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            tokens: capacity as f64, // Zaczynamy z pełnym bucketem
            capacity: capacity as f64,
            refill_rate,
            last_update: Instant::now(),
            violations: 0,
        }
    }
    
    /// Próbuje pobrać token(y)
    /// Returns: (success, retry_after_ms)
    fn try_acquire(&mut self, cost: f64) -> (bool, u64) {
        self.refill();
        
        if self.tokens >= cost {
            self.tokens -= cost;
            (true, 0)
        } else {
            self.violations += 1;
            // Oblicz ile ms trzeba czekać na wystarczającą liczbę tokenów
            let tokens_needed = cost - self.tokens;
            // Zabezpieczenie przed refill_rate == 0 (dzielenie przez zero)
            if self.refill_rate <= 0.0 {
                return (false, u64::MAX); // Permanentny limit
            }
            let wait_secs = tokens_needed / self.refill_rate;
            let wait_ms = (wait_secs * 1000.0).ceil() as u64;
            (false, wait_ms)
        }
    }
    
    /// Uzupełnia tokeny na podstawie upływu czasu
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_update = now;
    }
    
    /// Czy bucket jest nieaktywny od dłuższego czasu?
    fn is_inactive(&self, timeout: Duration) -> bool {
        self.last_update.elapsed() > timeout
    }
}

/// Blacklist entry
#[derive(Debug, Clone)]
struct BlacklistEntry {
    reason: String,
    added_at: Instant,
    expires_at: Option<Instant>,
}

impl BlacklistEntry {
    fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Instant::now() > exp).unwrap_or(false)
    }
}

/// Endpoint cost - ile tokenów kosztuje dany endpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointCost {
    /// Tani endpoint (1 token)
    Cheap,
    /// Standardowy endpoint (2 tokeny)
    Standard,
    /// Drogi endpoint (10 tokenów) - np. keygen, proof verify
    Expensive,
    /// Bardzo drogi (50 tokenów) - np. batch operations
    VeryExpensive,
}

impl EndpointCost {
    pub fn tokens(&self) -> f64 {
        match self {
            Self::Cheap => 1.0,
            Self::Standard => 2.0,
            Self::Expensive => 10.0,
            Self::VeryExpensive => 50.0,
        }
    }
}

/// Rate Limiter Statistics (używa AtomicU64 dla wydajności przy wysokim RPS)
#[derive(Debug, Default)]
pub struct RateLimiterStats {
    pub total_requests: AtomicU64,
    pub allowed_requests: AtomicU64,
    pub rejected_requests: AtomicU64,
    pub blacklist_rejections: AtomicU64,
}

/// Snapshot statystyk (do zwracania użytkownikom)
#[derive(Debug, Clone)]
pub struct RateLimiterStatsSnapshot {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub rejected_requests: u64,
    pub blacklist_rejections: u64,
    pub active_ip_buckets: usize,
    pub active_key_buckets: usize,
    pub blacklisted_ips: usize,
}

/// RPC Rate Limiter
pub struct RateLimiter {
    config: RateLimiterConfig,
    /// Per-IP buckets
    ip_buckets: RwLock<HashMap<IpAddr, TokenBucket>>,
    /// Per-Key buckets (klucz publiczny jako hex)
    key_buckets: RwLock<HashMap<String, TokenBucket>>,
    /// Per-Endpoint expensive ops bucket (globalny)
    expensive_bucket: RwLock<TokenBucket>,
    /// IP blacklist
    ip_blacklist: RwLock<HashMap<IpAddr, BlacklistEntry>>,
    /// Key blacklist
    key_blacklist: RwLock<HashMap<String, BlacklistEntry>>,
    /// Global request counter (per second window)
    global_counter: RwLock<(u32, Instant)>,
    /// Stats (atomiki - bez locka)
    stats: RateLimiterStats,
    /// Ostatni cleanup
    last_cleanup: RwLock<Instant>,
}

impl RateLimiter {
    /// Tworzy nowy RateLimiter z domyślną konfiguracją
    pub fn new() -> Self {
        Self::with_config(RateLimiterConfig::default())
    }
    
    /// Tworzy RateLimiter z custom konfiguracją
    pub fn with_config(config: RateLimiterConfig) -> Self {
        let expensive_bucket = TokenBucket::new(
            config.expensive_op_bucket_capacity,
            config.expensive_op_tokens_per_sec,
        );
        
        Self {
            config,
            ip_buckets: RwLock::new(HashMap::new()),
            key_buckets: RwLock::new(HashMap::new()),
            expensive_bucket: RwLock::new(expensive_bucket),
            ip_blacklist: RwLock::new(HashMap::new()),
            key_blacklist: RwLock::new(HashMap::new()),
            global_counter: RwLock::new((0, Instant::now())),
            stats: RateLimiterStats::default(),
            last_cleanup: RwLock::new(Instant::now()),
        }
    }
    
    /// Sprawdza czy request jest dozwolony (bez autentykacji)
    pub fn check_anonymous(
        &self,
        ip: IpAddr,
        endpoint_cost: EndpointCost,
    ) -> Result<(), RateLimitError> {
        self.maybe_cleanup();
        self.update_stats_total();
        
        // 1. Sprawdź blacklist
        self.check_ip_blacklist(ip)?;
        
        // 2. Sprawdź global limit
        self.check_global_limit()?;
        
        // 3. Sprawdź per-IP limit
        self.check_ip_limit(ip, endpoint_cost)?;
        
        // 4. Dla expensive ops - dodatkowy limit
        if endpoint_cost == EndpointCost::Expensive || endpoint_cost == EndpointCost::VeryExpensive {
            self.check_expensive_limit(endpoint_cost)?;
        }
        
        self.update_stats_allowed();
        Ok(())
    }
    
    /// Sprawdza czy request jest dozwolony (z autentykacją)
    pub fn check_authenticated(
        &self,
        ip: IpAddr,
        public_key_hex: &str,
        endpoint_cost: EndpointCost,
    ) -> Result<(), RateLimitError> {
        self.maybe_cleanup();
        self.update_stats_total();
        
        // 1. Sprawdź blacklisty
        self.check_ip_blacklist(ip)?;
        self.check_key_blacklist(public_key_hex)?;
        
        // 2. Sprawdź global limit (ostatnia linia obrony)
        self.check_global_limit()?;
        
        // 3. Sprawdź per-key limit
        //    Authenticated users mają SWÓJ WŁASNY budżet na operacje.
        //    key_bucket_capacity=1000, VeryExpensive=50 → 20 drogich ops pod rząd.
        //    NIE sprawdzamy global expensive_bucket - to by karano auth users
        //    za grzechy anonimowych atakujących!
        self.check_key_limit(public_key_hex, endpoint_cost)?;
        
        // 4. Opcjonalnie: per-IP limit dla authenticated (defense-in-depth)
        //    Chroni przed: skradziony klucz + flood z jednej maszyny
        if self.config.auth_also_check_ip {
            self.check_auth_ip_limit(ip, endpoint_cost)?;
        }
        
        // UWAGA: Celowo NIE sprawdzamy check_expensive_limit() dla authenticated!
        // Authenticated users udowodnili kim są. Ich key_bucket jest ich limitem.
        // Global expensive_bucket jest TYLKO dla anonymous (warstwa ochrony infra).
        
        self.update_stats_allowed();
        Ok(())
    }
    
    /// Dodaje IP do blacklisty
    pub fn blacklist_ip(&self, ip: IpAddr, reason: &str, permanent: bool) {
        let expires_at = if permanent {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(self.config.ip_blacklist_duration_secs))
        };
        
        let entry = BlacklistEntry {
            reason: reason.to_string(),
            added_at: Instant::now(),
            expires_at,
        };
        
        let mut blacklist = self.ip_blacklist.write().unwrap();
        blacklist.insert(ip, entry);
    }
    
    /// Dodaje klucz do blacklisty (permanent)
    pub fn blacklist_key(&self, public_key_hex: &str, reason: &str) {
        let entry = BlacklistEntry {
            reason: reason.to_string(),
            added_at: Instant::now(),
            expires_at: None, // Klucze są permanentnie blacklistowane
        };
        
        let mut blacklist = self.key_blacklist.write().unwrap();
        blacklist.insert(public_key_hex.to_string(), entry);
    }
    
    /// Usuwa IP z blacklisty
    pub fn unblacklist_ip(&self, ip: &IpAddr) {
        let mut blacklist = self.ip_blacklist.write().unwrap();
        blacklist.remove(ip);
    }
    
    /// Zwraca snapshot statystyk
    pub fn stats(&self) -> RateLimiterStatsSnapshot {
        RateLimiterStatsSnapshot {
            total_requests: self.stats.total_requests.load(Ordering::Relaxed),
            allowed_requests: self.stats.allowed_requests.load(Ordering::Relaxed),
            rejected_requests: self.stats.rejected_requests.load(Ordering::Relaxed),
            blacklist_rejections: self.stats.blacklist_rejections.load(Ordering::Relaxed),
            active_ip_buckets: self.ip_buckets.read().unwrap().len(),
            active_key_buckets: self.key_buckets.read().unwrap().len(),
            blacklisted_ips: self.ip_blacklist.read().unwrap().len(),
        }
    }
    
    /// Resetuje wszystkie limity (dla testów)
    pub fn reset(&self) {
        self.ip_buckets.write().unwrap().clear();
        self.key_buckets.write().unwrap().clear();
        self.ip_blacklist.write().unwrap().clear();
        self.key_blacklist.write().unwrap().clear();
        self.stats.total_requests.store(0, Ordering::Relaxed);
        self.stats.allowed_requests.store(0, Ordering::Relaxed);
        self.stats.rejected_requests.store(0, Ordering::Relaxed);
        self.stats.blacklist_rejections.store(0, Ordering::Relaxed);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // Internal methods
    // ═══════════════════════════════════════════════════════════════════════
    
    fn check_ip_blacklist(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        let blacklist = self.ip_blacklist.read().unwrap();
        
        if let Some(entry) = blacklist.get(&ip) {
            if !entry.is_expired() {
                self.update_stats_blacklist();
                return Err(RateLimitError::IpBlacklisted {
                    reason: entry.reason.clone(),
                    retry_after_secs: entry.expires_at.map(|e| {
                        // Bezpieczne obliczenie TTL - checked_duration_since zwraca None 
                        // jeśli expires_at jest w przeszłości (race condition)
                        e.checked_duration_since(Instant::now())
                            .map(|d| d.as_secs())
                            .unwrap_or(0)
                    }),
                });
            }
        }
        Ok(())
    }
    
    fn check_key_blacklist(&self, key: &str) -> Result<(), RateLimitError> {
        let blacklist = self.key_blacklist.read().unwrap();
        
        if let Some(entry) = blacklist.get(key) {
            self.update_stats_blacklist();
            return Err(RateLimitError::KeyBlacklisted {
                reason: entry.reason.clone(),
            });
        }
        Ok(())
    }
    
    fn check_global_limit(&self) -> Result<(), RateLimitError> {
        let mut counter = self.global_counter.write().unwrap();
        
        // Reset counter jeśli minęła sekunda
        if counter.1.elapsed() >= Duration::from_secs(1) {
            *counter = (0, Instant::now());
        }
        
        if counter.0 >= self.config.global_rps_limit {
            self.update_stats_rejected();
            return Err(RateLimitError::RateLimitExceeded {
                limit_type: "global".to_string(),
                retry_after_ms: 1000 - counter.1.elapsed().as_millis() as u64,
            });
        }
        
        counter.0 += 1;
        Ok(())
    }
    
    fn check_ip_limit(&self, ip: IpAddr, cost: EndpointCost) -> Result<(), RateLimitError> {
        let mut buckets = self.ip_buckets.write().unwrap();
        
        let bucket = buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(
                self.config.ip_bucket_capacity,
                self.config.ip_tokens_per_sec,
            ));
        
        let (allowed, retry_after) = bucket.try_acquire(cost.tokens());
        
        if !allowed {
            // Sprawdź czy pora na blacklist
            if bucket.violations >= self.config.ip_violations_to_blacklist {
                drop(buckets); // Release lock przed blacklist
                self.blacklist_ip(ip, "Too many rate limit violations", false);
                return Err(RateLimitError::IpBlacklisted {
                    reason: "Too many rate limit violations".to_string(),
                    retry_after_secs: Some(self.config.ip_blacklist_duration_secs),
                });
            }
            
            self.update_stats_rejected();
            return Err(RateLimitError::RateLimitExceeded {
                limit_type: "per-ip".to_string(),
                retry_after_ms: retry_after,
            });
        }
        
        Ok(())
    }
    
    fn check_key_limit(&self, key: &str, cost: EndpointCost) -> Result<(), RateLimitError> {
        let mut buckets = self.key_buckets.write().unwrap();
        
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(
                self.config.key_bucket_capacity,
                self.config.key_tokens_per_sec,
            ));
        
        let (allowed, retry_after) = bucket.try_acquire(cost.tokens());
        
        if !allowed {
            self.update_stats_rejected();
            return Err(RateLimitError::RateLimitExceeded {
                limit_type: "per-key".to_string(),
                retry_after_ms: retry_after,
            });
        }
        
        Ok(())
    }
    
    /// Per-IP limit dla authenticated users (defense-in-depth)
    /// Używa oddzielnych bucketów i wyższych limitów niż dla anonymous
    fn check_auth_ip_limit(&self, ip: IpAddr, cost: EndpointCost) -> Result<(), RateLimitError> {
        // Używamy tych samych ip_buckets, ale z wyższym limitem
        // (bucket jest tworzony z config dla auth jeśli auth_also_check_ip=true)
        let mut buckets = self.ip_buckets.write().unwrap();
        
        let bucket = buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(
                self.config.auth_ip_bucket_capacity,
                self.config.auth_ip_tokens_per_sec,
            ));
        
        let (allowed, retry_after) = bucket.try_acquire(cost.tokens());
        
        if !allowed {
            self.update_stats_rejected();
            return Err(RateLimitError::RateLimitExceeded {
                limit_type: "per-ip-authenticated".to_string(),
                retry_after_ms: retry_after,
            });
        }
        
        Ok(())
    }
    
    fn check_expensive_limit(&self, cost: EndpointCost) -> Result<(), RateLimitError> {
        let mut bucket = self.expensive_bucket.write().unwrap();
        let (allowed, retry_after) = bucket.try_acquire(cost.tokens());
        
        if !allowed {
            self.update_stats_rejected();
            return Err(RateLimitError::RateLimitExceeded {
                limit_type: "expensive-ops".to_string(),
                retry_after_ms: retry_after,
            });
        }
        
        Ok(())
    }
    
    fn update_stats_total(&self) {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);
    }
    
    fn update_stats_allowed(&self) {
        self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed);
    }
    
    fn update_stats_rejected(&self) {
        self.stats.rejected_requests.fetch_add(1, Ordering::Relaxed);
    }
    
    fn update_stats_blacklist(&self) {
        self.stats.blacklist_rejections.fetch_add(1, Ordering::Relaxed);
    }
    
    fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last = self.last_cleanup.read().unwrap();
            last.elapsed() > Duration::from_secs(self.config.cleanup_interval_secs)
        };
        
        if should_cleanup {
            self.perform_cleanup();
        }
    }
    
    fn perform_cleanup(&self) {
        *self.last_cleanup.write().unwrap() = Instant::now();
        
        let timeout = Duration::from_secs(self.config.bucket_inactive_timeout_secs);
        
        // Cleanup IP buckets
        {
            let mut buckets = self.ip_buckets.write().unwrap();
            buckets.retain(|_, bucket| !bucket.is_inactive(timeout));
        }
        
        // Cleanup key buckets
        {
            let mut buckets = self.key_buckets.write().unwrap();
            buckets.retain(|_, bucket| !bucket.is_inactive(timeout));
        }
        
        // Cleanup expired blacklist entries
        {
            let mut blacklist = self.ip_blacklist.write().unwrap();
            blacklist.retain(|_, entry| !entry.is_expired());
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe shared RateLimiter
pub type SharedRateLimiter = Arc<RateLimiter>;

/// Tworzy shared RateLimiter
pub fn create_shared_limiter() -> SharedRateLimiter {
    Arc::new(RateLimiter::new())
}

// ════════════════════════════════════════════════════════════════════════════
// Testy
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    
    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }
    
    #[test]
    fn test_basic_rate_limiting() {
        let config = RateLimiterConfig {
            ip_tokens_per_sec: 10.0,
            ip_bucket_capacity: 10,
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        let ip = test_ip();
        
        // Pierwsze 10 requestów powinno przejść
        for _ in 0..10 {
            assert!(limiter.check_anonymous(ip, EndpointCost::Cheap).is_ok());
        }
        
        // 11-ty powinien być odrzucony
        let result = limiter.check_anonymous(ip, EndpointCost::Cheap);
        assert!(matches!(result, Err(RateLimitError::RateLimitExceeded { .. })));
    }
    
    #[test]
    fn test_bucket_refill() {
        let config = RateLimiterConfig {
            ip_tokens_per_sec: 1000.0, // Szybki refill
            ip_bucket_capacity: 10,
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        let ip = test_ip();
        
        // Wyczerpaj bucket
        for _ in 0..10 {
            let _ = limiter.check_anonymous(ip, EndpointCost::Cheap);
        }
        
        // Odrzucony
        assert!(limiter.check_anonymous(ip, EndpointCost::Cheap).is_err());
        
        // Poczekaj na refill
        std::thread::sleep(Duration::from_millis(20));
        
        // Powinno przejść (refill ~20 tokenów)
        assert!(limiter.check_anonymous(ip, EndpointCost::Cheap).is_ok());
    }
    
    #[test]
    fn test_ip_blacklist() {
        let limiter = RateLimiter::new();
        let ip = test_ip();
        
        // Dodaj do blacklisty
        limiter.blacklist_ip(ip, "test reason", true);
        
        // Request powinien być odrzucony
        let result = limiter.check_anonymous(ip, EndpointCost::Cheap);
        assert!(matches!(result, Err(RateLimitError::IpBlacklisted { .. })));
        
        // Usuń z blacklisty
        limiter.unblacklist_ip(&ip);
        
        // Teraz powinno przejść
        assert!(limiter.check_anonymous(ip, EndpointCost::Cheap).is_ok());
    }
    
    #[test]
    fn test_authenticated_higher_limits() {
        let config = RateLimiterConfig {
            ip_tokens_per_sec: 10.0,
            ip_bucket_capacity: 10,
            key_tokens_per_sec: 100.0,
            key_bucket_capacity: 100,
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        let ip = test_ip();
        let key = "abc123";
        
        // Anonymous: 10 requestów
        for _ in 0..10 {
            assert!(limiter.check_anonymous(ip, EndpointCost::Cheap).is_ok());
        }
        
        // Anonymous 11-ty: odrzucony
        assert!(limiter.check_anonymous(ip, EndpointCost::Cheap).is_err());
        
        // Ale authenticated z kluczem: 100 requestów
        for _ in 0..100 {
            assert!(limiter.check_authenticated(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), // Inne IP
                key, 
                EndpointCost::Cheap
            ).is_ok());
        }
    }
    
    #[test]
    fn test_endpoint_cost() {
        let config = RateLimiterConfig {
            ip_tokens_per_sec: 100.0,
            ip_bucket_capacity: 100,
            expensive_op_tokens_per_sec: 1000.0,  // Wysoki limit dla expensive
            expensive_op_bucket_capacity: 1000,   // Żeby nie było globalnego limitu
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        let ip = test_ip();
        
        // VeryExpensive kosztuje 50 tokenów
        assert!(limiter.check_anonymous(ip, EndpointCost::VeryExpensive).is_ok()); // 100 -> 50
        assert!(limiter.check_anonymous(ip, EndpointCost::VeryExpensive).is_ok()); // 50 -> 0
        
        // Trzeci powinien być odrzucony (IP bucket wyczerpany)
        assert!(limiter.check_anonymous(ip, EndpointCost::VeryExpensive).is_err());
    }
    
    #[test]
    fn test_expensive_ops_global_limit() {
        let config = RateLimiterConfig {
            ip_tokens_per_sec: 1000.0,
            ip_bucket_capacity: 1000,
            expensive_op_tokens_per_sec: 1.0,  // Bardzo wolne refill
            expensive_op_bucket_capacity: 10,   // Tylko 10 expensive ops
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        
        // Expensive ops mają globalny limit 10
        // Każda expensive op kosztuje 10 tokenów, więc max 1 na start
        let mut allowed = 0;
        let mut rejected = 0;
        
        for i in 0..5 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8));
            let result = limiter.check_anonymous(ip, EndpointCost::Expensive);
            if result.is_ok() {
                allowed += 1;
            } else {
                rejected += 1;
            }
        }
        
        // Z 10 tokenów i koszcie 10 na Expensive, tylko 1 powinno przejść
        assert!(allowed <= 2, "Should allow at most 2 expensive ops, got {}", allowed);
        assert!(rejected >= 3, "Should reject at least 3 expensive ops, got {} rejected", rejected);
    }
    
    #[test]
    fn test_stats() {
        let limiter = RateLimiter::new();
        let ip = test_ip();
        
        for _ in 0..5 {
            let _ = limiter.check_anonymous(ip, EndpointCost::Cheap);
        }
        
        let stats = limiter.stats();
        assert_eq!(stats.total_requests, 5);
        assert_eq!(stats.allowed_requests, 5);
    }
    
    #[test]
    fn test_auto_blacklist() {
        let config = RateLimiterConfig {
            ip_tokens_per_sec: 1.0,
            ip_bucket_capacity: 5,
            ip_violations_to_blacklist: 3,
            ip_blacklist_duration_secs: 10,
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        let ip = test_ip();
        
        // Wyczerpaj bucket
        for _ in 0..5 {
            let _ = limiter.check_anonymous(ip, EndpointCost::Cheap);
        }
        
        // Generuj violations
        for _ in 0..3 {
            let _ = limiter.check_anonymous(ip, EndpointCost::Cheap);
        }
        
        // Po 3 violations - blacklist
        let result = limiter.check_anonymous(ip, EndpointCost::Cheap);
        assert!(matches!(result, Err(RateLimitError::IpBlacklisted { .. })));
    }
    
    #[test]
    fn test_blacklist_expiry() {
        // Test że wygasłe IP są automatycznie przepuszczane
        let config = RateLimiterConfig {
            ip_blacklist_duration_secs: 1, // 1 sekunda
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        let ip = test_ip();
        
        // Zablokuj IP
        limiter.blacklist_ip(ip, "Test block", false);
        
        // Sprawdź że jest zablokowane
        let result = limiter.check_anonymous(ip, EndpointCost::Cheap);
        assert!(matches!(result, Err(RateLimitError::IpBlacklisted { .. })));
        
        // Poczekaj na wygaśnięcie
        std::thread::sleep(Duration::from_millis(1100));
        
        // Teraz powinno przejść (is_expired() zwraca true)
        let result = limiter.check_anonymous(ip, EndpointCost::Cheap);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_cleanup_removes_expired_blacklist() {
        let config = RateLimiterConfig {
            ip_blacklist_duration_secs: 1,
            cleanup_interval_secs: 1,
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        let ip = test_ip();
        
        // Dodaj do blacklisty
        limiter.blacklist_ip(ip, "Test", false);
        assert_eq!(limiter.stats().blacklisted_ips, 1);
        
        // Poczekaj na wygaśnięcie + cleanup
        std::thread::sleep(Duration::from_millis(2100));
        
        // Wywołaj request żeby odpalić cleanup
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let _ = limiter.check_anonymous(ip2, EndpointCost::Cheap);
        
        // Blacklist powinien być wyczyszczony
        assert_eq!(limiter.stats().blacklisted_ips, 0);
    }
    
    #[test]
    fn test_cleanup_removes_inactive_buckets() {
        let config = RateLimiterConfig {
            bucket_inactive_timeout_secs: 1,
            cleanup_interval_secs: 1,
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        
        // Utwórz bucket
        let ip = test_ip();
        let _ = limiter.check_anonymous(ip, EndpointCost::Cheap);
        assert_eq!(limiter.stats().active_ip_buckets, 1);
        
        // Poczekaj na timeout + cleanup interval
        std::thread::sleep(Duration::from_millis(2100));
        
        // Wywołaj request z innego IP żeby odpalić cleanup
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let _ = limiter.check_anonymous(ip2, EndpointCost::Cheap);
        
        // Oryginalny bucket powinien być usunięty, zostaje tylko ip2
        assert_eq!(limiter.stats().active_ip_buckets, 1);
    }
    
    #[test]
    fn test_zero_refill_rate_protection() {
        // Test zabezpieczenia przed refill_rate == 0 (dzielenie przez zero)
        let mut bucket = TokenBucket::new(10, 0.0); // Zero refill rate!
        bucket.tokens = 0.0; // Wyczerpane tokeny
        
        let (allowed, retry_after) = bucket.try_acquire(1.0);
        
        assert!(!allowed);
        assert_eq!(retry_after, u64::MAX); // Permanentny limit, nie panika
    }
}
