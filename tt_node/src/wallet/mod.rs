#![forbid(unsafe_code)]

//! Wallet module

pub mod api;
#[cfg(feature = "wallet")]
pub mod wallet_cli;
