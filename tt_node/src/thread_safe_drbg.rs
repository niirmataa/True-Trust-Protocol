#![forbid(unsafe_code)]

//! Legacy shim: stary moduł `crate::thread_safe_drbg`.
//!
//! Prawdziwa implementacja DRBG jest w `crate::crypto::thread_safe_drbg`,
//! opartej na KMAC-DRBG z pliku `crypto/kmac_drbg.rs`.
//!
//! Ten plik istnieje tylko po to, żeby stary import `crate::thread_safe_drbg`
//! nie generował błędów kompilacji i nie używał już tiny-keccak::Kmac.

pub use crate::crypto::thread_safe_drbg::*;
