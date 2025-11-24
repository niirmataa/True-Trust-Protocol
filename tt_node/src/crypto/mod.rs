//! Crypto primitives for tt_node
//!
//! This module exposes only the pieces we actually use in the node:
//! - KMAC256-based primitives (key derivation, XOF, MAC)
//! - KMAC-DRBG (deterministic RNG)
//! - Deterministic Falcon integration (via falcon_seeded)
//! - Kyber-768 KEM helpers
//! - Poseidon hash (CPU) + Poseidon STARK AIR (Winterfell v0.13)

pub mod kmac;
pub mod kmac_drbg;
pub mod seeded;
pub mod kyber_kem;
pub mod poseidon_hash_cpu;
pub mod zk_range_poseidon;
pub mod randomx_pow;

// Uwaga: poseidon_params.rs jest AUTOGENEROWANY przez poseidon_param_gen
// i nie powinien być edytowany ręcznie.
pub mod poseidon_params;
