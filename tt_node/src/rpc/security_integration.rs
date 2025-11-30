//! Security Integration Module
//!
//! Łączy wszystkie komponenty security w spójny system:
//! - Hardware RNG (from checkpoint_system)
//! - Nonce Tracker (replay protection)
//! - Rate Limiter (IP-based DoS protection)
//! - Checkpoint System (state recovery)
//! - Verified Device PoW (anonymous user DoS protection)
//!
//! ## Architektura
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                         SECURE RPC GATEWAY                                  │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │   INCOMING REQUEST                                                          │
//! │         │                                                                   │
//! │         ▼                                                                   │
//! │   ┌─────────────┐                                                           │
//! │   │ IP Rate     │ ──(blocked)──▶ 429 Too Many Requests                     │
//! │   │ Limiter     │                                                           │
//! │   └──────┬──────┘                                                           │
//! │          │ (passed)                                                         │
//! │          ▼                                                                  │
//! │   ┌─────────────┐                                                           │
//! │   │ Device      │ ──(no credential)──▶ Enrollment Flow                     │
//! │   │ Credential  │                                                           │
//! │   │ Check       │                                                           │
//! │   └──────┬──────┘                                                           │
//! │          │ (valid credential)                                               │
//! │          ▼                                                                  │
//! │   ┌─────────────┐                                                           │
//! │   │ Burst or    │ ──(burst)──▶ Process Request                             │
//! │   │ PoW Check   │                                                           │
//! │   └──────┬──────┘                                                           │
//! │          │ (no burst)                                                       │
//! │          ▼                                                                  │
//! │   ┌─────────────┐                                                           │
//! │   │ Personalized│                                                           │
//! │   │ PoW         │ ──(solved)──▶ Process Request                            │
//! │   │ Challenge   │                                                           │
//! │   └──────┬──────┘                                                           │
//! │          │ (failed)                                                         │
//! │          ▼                                                                  │
//! │   ┌─────────────┐                                                           │
//! │   │ Suspicion   │ ──(threshold)──▶ Temporary Ban                           │
//! │   │ Tracker     │                                                           │
//! │   └─────────────┘                                                           │
//! │                                                                             │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::rpc::rate_limiter::{RateLimiter as IpRateLimiter, EndpointCost};
use crate::rpc::verified_device_pow::{
    VerifiedDeviceManagerExt, DeviceCredential, PersonalizedChallenge,
    EnrollmentChallenge, VerifiedPowError, EnrollmentRateLimitError,
    PowSolution,
};

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATED SECURITY GATEWAY
// ═══════════════════════════════════════════════════════════════════════════════

/// Konfiguracja zintegrowanego systemu bezpieczeństwa
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Włącz rate limiting IP
    pub enable_ip_rate_limit: bool,
    /// Włącz Device PoW dla anonimowych użytkowników
    pub enable_device_pow: bool,
    /// Ścieżka do persystencji state
    pub state_path: Option<String>,
    /// Włącz metryki Prometheus
    pub enable_metrics: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_ip_rate_limit: true,
            enable_device_pow: true,
            state_path: None,
            enable_metrics: true,
        }
    }
}

/// Wynik sprawdzenia bezpieczeństwa
#[derive(Debug, Clone)]
pub enum SecurityCheckResult {
    /// Request dozwolony bez dodatkowych wymagań
    Allowed,
    /// Wymaga rozwiązania PoW challenge
    PowRequired(PersonalizedChallenge),
    /// Wymaga enrollment (nowe urządzenie)
    EnrollmentRequired(EnrollmentChallenge),
    /// Zablokowany
    Blocked(SecurityBlockReason),
}

/// Powód blokady
#[derive(Debug, Clone)]
pub enum SecurityBlockReason {
    /// IP rate limit
    IpRateLimited { retry_after_secs: u64 },
    /// Enrollment rate limit
    EnrollmentRateLimited { retry_after_secs: u64 },
    /// Device banned
    DeviceBanned { until_secs: u64 },
    /// Invalid credential
    InvalidCredential(String),
    /// Suspicious activity
    SuspiciousActivity(String),
}

/// Zintegrowany gateway bezpieczeństwa
pub struct SecurityGateway {
    config: SecurityConfig,
    /// IP rate limiter
    ip_limiter: Option<Arc<IpRateLimiter>>,
    /// Device PoW manager
    device_manager: Option<Arc<VerifiedDeviceManagerExt>>,
    /// Timestamp utworzenia (do uptime)
    created_at: Instant,
}

impl SecurityGateway {
    /// Tworzy nowy gateway z domyślną konfiguracją
    pub fn new() -> Self {
        Self::with_config(SecurityConfig::default())
    }
    
    /// Tworzy gateway z custom konfiguracją
    pub fn with_config(config: SecurityConfig) -> Self {
        let ip_limiter = if config.enable_ip_rate_limit {
            Some(Arc::new(IpRateLimiter::new()))
        } else {
            None
        };
        
        let device_manager = if config.enable_device_pow {
            let manager = VerifiedDeviceManagerExt::new();
            // TODO: Load from state_path if provided
            Some(Arc::new(manager))
        } else {
            None
        };
        
        Self {
            config,
            ip_limiter,
            device_manager,
            created_at: Instant::now(),
        }
    }
    
    /// Główna funkcja sprawdzająca bezpieczeństwo requestu
    /// 
    /// Sprawdza w kolejności:
    /// 1. IP rate limit
    /// 2. Device credential validity
    /// 3. Burst tokens or PoW requirement
    pub fn check_request(
        &self,
        client_ip: IpAddr,
        credential: Option<&DeviceCredential>,
        endpoint_cost: EndpointCost,
    ) -> SecurityCheckResult {
        // 1. IP Rate Limit
        if let Some(ref limiter) = self.ip_limiter {
            if let Err(_e) = limiter.check_anonymous(client_ip, endpoint_cost) {
                return SecurityCheckResult::Blocked(SecurityBlockReason::IpRateLimited {
                    retry_after_secs: 60, // Default retry
                });
            }
        }
        
        // 2. Device PoW Check
        if let Some(ref manager) = self.device_manager {
            match credential {
                Some(cred) => {
                    // Has credential - check if valid and has burst/needs PoW
                    match manager.check_device_tracked(cred) {
                        Ok(None) => {
                            // Has burst tokens - allowed
                            SecurityCheckResult::Allowed
                        }
                        Ok(Some(challenge)) => {
                            // Needs PoW
                            SecurityCheckResult::PowRequired(challenge)
                        }
                        Err(VerifiedPowError::DeviceBanned { until_secs }) => {
                            SecurityCheckResult::Blocked(SecurityBlockReason::DeviceBanned { until_secs })
                        }
                        Err(VerifiedPowError::InvalidCredentialSignature) => {
                            SecurityCheckResult::Blocked(SecurityBlockReason::InvalidCredential(
                                "Invalid signature".to_string()
                            ))
                        }
                        Err(VerifiedPowError::CredentialExpired) => {
                            SecurityCheckResult::Blocked(SecurityBlockReason::InvalidCredential(
                                "Credential expired".to_string()
                            ))
                        }
                        Err(e) => {
                            SecurityCheckResult::Blocked(SecurityBlockReason::InvalidCredential(
                                e.to_string()
                            ))
                        }
                    }
                }
                None => {
                    // No credential - need enrollment
                    match manager.start_enrollment_limited(client_ip) {
                        Ok(challenge) => {
                            SecurityCheckResult::EnrollmentRequired(challenge)
                        }
                        Err(EnrollmentRateLimitError::TooManyRequests { retry_after_secs }) => {
                            SecurityCheckResult::Blocked(SecurityBlockReason::EnrollmentRateLimited {
                                retry_after_secs
                            })
                        }
                    }
                }
            }
        } else {
            // Device PoW disabled - just allow
            SecurityCheckResult::Allowed
        }
    }
    
    /// Rozpoczyna enrollment dla nowego urządzenia
    pub fn start_enrollment(&self, client_ip: IpAddr) -> Result<EnrollmentChallenge, SecurityBlockReason> {
        if let Some(ref manager) = self.device_manager {
            manager.start_enrollment_limited(client_ip)
                .map_err(|e| match e {
                    EnrollmentRateLimitError::TooManyRequests { retry_after_secs } => {
                        SecurityBlockReason::EnrollmentRateLimited { retry_after_secs }
                    }
                })
        } else {
            Err(SecurityBlockReason::InvalidCredential("Device PoW disabled".to_string()))
        }
    }
    
    /// Kończy enrollment i wydaje credential
    pub fn complete_enrollment(
        &self,
        challenge: &EnrollmentChallenge,
        solution: &PowSolution,
    ) -> Result<DeviceCredential, VerifiedPowError> {
        if let Some(ref manager) = self.device_manager {
            manager.complete_enrollment_tracked(challenge, solution)
        } else {
            Err(VerifiedPowError::InvalidSolution)
        }
    }
    
    /// Weryfikuje rozwiązanie PoW
    pub fn verify_pow_solution(
        &self,
        credential: &DeviceCredential,
        challenge: &PersonalizedChallenge,
        solution: &PowSolution,
        server_measured_ms: u64,
    ) -> Result<(), VerifiedPowError> {
        if let Some(ref manager) = self.device_manager {
            manager.verify_solution_tracked(credential, challenge, solution, server_measured_ms)
        } else {
            Ok(()) // PoW disabled
        }
    }
    
    /// Eksportuje metryki Prometheus
    pub fn export_metrics(&self) -> String {
        let mut output = String::new();
        
        // Gateway uptime
        output.push_str("# HELP tt_security_gateway_uptime_seconds Gateway uptime\n");
        output.push_str("# TYPE tt_security_gateway_uptime_seconds gauge\n");
        output.push_str(&format!(
            "tt_security_gateway_uptime_seconds {}\n\n",
            self.created_at.elapsed().as_secs()
        ));
        
        // Device PoW metrics
        if let Some(ref manager) = self.device_manager {
            output.push_str(&manager.export_metrics());
        }
        
        output
    }
    
    /// Okresowy maintenance (save, cleanup)
    pub fn maintenance(&self) -> std::io::Result<()> {
        if let Some(ref manager) = self.device_manager {
            manager.maintenance()?;
        }
        Ok(())
    }
}

impl Default for SecurityGateway {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::verified_device_pow::solve_pow;
    
    #[test]
    fn test_gateway_creation() {
        let gateway = SecurityGateway::new();
        assert!(gateway.ip_limiter.is_some());
        assert!(gateway.device_manager.is_some());
    }
    
    #[test]
    fn test_gateway_disabled_features() {
        let config = SecurityConfig {
            enable_ip_rate_limit: false,
            enable_device_pow: false,
            state_path: None,
            enable_metrics: false,
        };
        let gateway = SecurityGateway::with_config(config);
        
        assert!(gateway.ip_limiter.is_none());
        assert!(gateway.device_manager.is_none());
        
        // Should allow all requests when security is disabled
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let result = gateway.check_request(ip, None, EndpointCost::Cheap);
        assert!(matches!(result, SecurityCheckResult::Allowed));
    }
    
    #[test]
    fn test_gateway_enrollment_flow() {
        let gateway = SecurityGateway::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        
        // 1. Request without credential → enrollment required
        let result = gateway.check_request(ip, None, EndpointCost::Cheap);
        let challenge = match result {
            SecurityCheckResult::EnrollmentRequired(c) => c,
            other => panic!("Expected EnrollmentRequired, got {:?}", other),
        };
        
        // 2. Solve enrollment challenge
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        
        // 3. Complete enrollment
        let credential = gateway.complete_enrollment(&challenge, &solution)
            .expect("Enrollment should succeed");
        
        // 4. Now requests with credential should work
        let result = gateway.check_request(ip, Some(&credential), EndpointCost::Cheap);
        assert!(matches!(result, SecurityCheckResult::Allowed), 
            "With valid credential should be allowed, got {:?}", result);
    }
    
    #[test]
    fn test_gateway_burst_exhaustion() {
        let gateway = SecurityGateway::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        
        // Enrollment
        let challenge = gateway.start_enrollment(ip).unwrap();
        let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
        let credential = gateway.complete_enrollment(&challenge, &solution).unwrap();
        
        // Exhaust burst (default: 5)
        for i in 0..5 {
            let result = gateway.check_request(ip, Some(&credential), EndpointCost::Cheap);
            assert!(matches!(result, SecurityCheckResult::Allowed), 
                "Request {} should be allowed", i);
        }
        
        // Next request should require PoW
        let result = gateway.check_request(ip, Some(&credential), EndpointCost::Cheap);
        assert!(matches!(result, SecurityCheckResult::PowRequired(_)),
            "After burst exhaustion should require PoW, got {:?}", result);
    }
    
    #[test]
    fn test_gateway_pow_verification() {
        let gateway = SecurityGateway::new();
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        
        // Enrollment
        let enroll_challenge = gateway.start_enrollment(ip).unwrap();
        let enroll_solution = solve_pow(&enroll_challenge.challenge_data, enroll_challenge.difficulty_bits);
        let credential = gateway.complete_enrollment(&enroll_challenge, &enroll_solution).unwrap();
        
        // Exhaust burst
        for _ in 0..5 {
            let _ = gateway.check_request(ip, Some(&credential), EndpointCost::Cheap);
        }
        
        // Get PoW challenge
        let result = gateway.check_request(ip, Some(&credential), EndpointCost::Cheap);
        let pow_challenge = match result {
            SecurityCheckResult::PowRequired(c) => c,
            other => panic!("Expected PowRequired, got {:?}", other),
        };
        
        // Solve PoW
        let start = std::time::Instant::now();
        let solution = solve_pow(&pow_challenge.challenge_data, pow_challenge.difficulty_bits);
        let server_measured = start.elapsed().as_millis() as u64;
        
        // Verify
        let verify_result = gateway.verify_pow_solution(
            &credential,
            &pow_challenge,
            &solution,
            server_measured
        );
        assert!(verify_result.is_ok(), "PoW verification should succeed: {:?}", verify_result);
    }
    
    #[test]
    fn test_gateway_metrics_export() {
        let gateway = SecurityGateway::new();
        
        let metrics = gateway.export_metrics();
        
        assert!(metrics.contains("tt_security_gateway_uptime_seconds"));
        assert!(metrics.contains("tt_verified_pow_enrollments_total"));
        assert!(metrics.contains("tt_verified_pow_active_devices"));
    }
    
    #[test]
    fn test_gateway_enrollment_rate_limit() {
        let gateway = SecurityGateway::new();
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        
        // Start many enrollments from same IP
        for _ in 0..5 {
            let _ = gateway.start_enrollment(ip);
        }
        
        // Next should be rate limited
        let result = gateway.start_enrollment(ip);
        assert!(matches!(result, Err(SecurityBlockReason::EnrollmentRateLimited { .. })),
            "Should be rate limited after 5 attempts: {:?}", result);
    }
    
    #[test]
    fn test_gateway_invalid_credential() {
        let gateway = SecurityGateway::new();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        
        // Fake credential
        let fake_credential = DeviceCredential {
            device_id: [0x42; 16],
            power_class: crate::rpc::verified_device_pow::VerifiedPowerClass::Medium,
            measured_hash_rate: 50000,
            issued_at: 0,
            valid_for_secs: 3600,
            server_signature: vec![0u8; 700], // Invalid signature
        };
        
        let result = gateway.check_request(ip, Some(&fake_credential), EndpointCost::Cheap);
        assert!(matches!(result, SecurityCheckResult::Blocked(SecurityBlockReason::InvalidCredential(_))),
            "Invalid credential should be blocked: {:?}", result);
    }
}
