//! Crypto primitives for tt_node
//!
//! This module exposes only the pieces we actually use in the node:
//! - KMAC256-based primitives (key derivation, XOF, MAC)
//! - KMAC-DRBG (deterministic RNG)
//! - Hardware RNG (true entropy from /dev/urandom + RDRAND)
//! - Deterministic Falcon integration (via falcon_seeded)
//! - Deterministic Kyber-768 keypair (via pqc_kyber)
//! - Kyber-768 KEM helpers
//! - Poseidon hash (CPU) + Poseidon STARK AIR (Winterfell v0.13)

pub mod kmac;
pub mod kmac_drbg;
pub mod hardware_rng;
pub mod nonce_tracker;
pub mod seeded;
#[cfg(feature = "seeded_kyber")]
pub mod seeded_kyber;
pub mod kyber_kem;
pub mod poseidon_hash_cpu;
#[cfg(feature = "winterfell_v2")]
pub mod zk_range_poseidon;
pub mod randomx_pow;

// Uwaga: poseidon_params.rs jest AUTOGENEROWANY przez poseidon_param_gen
// i nie powinien być edytowany ręcznie.
pub mod poseidon_params;
