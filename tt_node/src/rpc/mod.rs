#![forbid(unsafe_code)]

// Stary/nowszy kod z SecureRpcServer / SecureRpcClient
pub mod rpc_secure;

// Rate limiter - DoS/DDoS protection
pub mod rate_limiter;

// Adaptive PoW - Device-based rate limiting for anonymous users
pub mod adaptive_pow;

// Verified Device PoW - Server-verified enrollment, niepodrabialne credentials
pub mod verified_device_pow;

// Security Integration - unified security gateway
pub mod security_integration;

// Re-exporty, żeby można było pisać crate::rpc::{...}
pub use rpc_secure::{SecureRpcClient, RpcRequest, RpcResponse, PrivacyMode, ProxyConfig};
pub use rate_limiter::{RateLimiter, RateLimiterConfig, EndpointCost, RateLimitError};
pub use adaptive_pow::{
    AdaptivePowManager, AdaptivePowConfig, DevicePowerClass,
    PowChallenge, PowSolution, PowError,
    benchmark_device, generate_device_id, solve_challenge,
};
pub use verified_device_pow::{
    VerifiedDeviceManager, VerifiedDeviceManagerExt, VerifiedDeviceConfig, VerifiedPowerClass,
    DeviceCredential, EnrollmentChallenge, PersonalizedChallenge,
    VerifiedPowError, EnrollmentRateLimitError, VerifiedPowMetrics,
    DeviceStateStorage, PersistedDeviceState, EnrollmentRateLimiter,
    solve_pow,
};
pub use security_integration::{
    SecurityGateway, SecurityConfig, SecurityCheckResult, SecurityBlockReason,
};
