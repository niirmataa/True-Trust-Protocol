#![forbid(unsafe_code)]

//! Public API for wallet operations
//!
//! This module provides functions to work with encrypted wallet files
//! created by tt_wallet CLI.

use anyhow::{Context, Result};
use rpassword::prompt_password;
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::falcon_sigs::{FalconPublicKey, FalconSecretKey};
use crate::kyber_kem::{KyberPublicKey, KyberSecretKey};
use crate::node_id::node_id_from_falcon_pk;
use crate::node_id::NodeId;
use crate::wallet::wallet_cli::{decrypt_wallet_v3, load_wallet_file, Keyset, WalletHeader};

/// Load keyset from encrypted wallet file
pub fn load_wallet_keyset(
    wallet_path: &PathBuf,
    password: Option<String>,
) -> Result<(Keyset, WalletHeader)> {
    let wf = load_wallet_file(wallet_path).context("Failed to load wallet file")?;

    let pw = if let Some(pwd) = password {
        Zeroizing::new(pwd)
    } else {
        Zeroizing::new(prompt_password("Wallet password: ")?)
    };

    let secret = decrypt_wallet_v3(&wf.enc, pw.as_str(), &wf.header)
        .context("Failed to decrypt wallet (wrong password?)")?;

    let ks = Keyset::from_payload_v3(&secret).context("Failed to parse wallet keys")?;

    Ok((ks, wf.header))
}

/// Get Falcon keys from wallet
pub fn get_falcon_keys_from_wallet(
    wallet_path: &PathBuf,
    password: Option<String>,
) -> Result<(FalconPublicKey, FalconSecretKey)> {
    let (keyset, _) = load_wallet_keyset(wallet_path, password)?;
    Ok((keyset.falcon_pk, keyset.falcon_sk))
}

/// Get Kyber keys from wallet
pub fn get_kyber_keys_from_wallet(
    wallet_path: &PathBuf,
    password: Option<String>,
) -> Result<(KyberPublicKey, KyberSecretKey)> {
    let (keyset, _) = load_wallet_keyset(wallet_path, password)?;
    Ok((keyset.mlkem_pk, keyset.mlkem_sk))
}

/// Get all keys from wallet
pub fn get_all_keys_from_wallet(
    wallet_path: &PathBuf,
    password: Option<String>,
) -> Result<(
    FalconPublicKey,
    FalconSecretKey,
    KyberPublicKey,
    KyberSecretKey,
    NodeId,
)> {
    let (keyset, _) = load_wallet_keyset(wallet_path, password)?;
    let node_id = node_id_from_falcon_pk(&keyset.falcon_pk);
    Ok((
        keyset.falcon_pk,
        keyset.falcon_sk,
        keyset.mlkem_pk,
        keyset.mlkem_sk,
        node_id,
    ))
}

/// Get wallet address (NodeId) from wallet
pub fn get_wallet_address(wallet_path: &PathBuf, password: Option<String>) -> Result<NodeId> {
    let (keyset, _) = load_wallet_keyset(wallet_path, password)?;
    Ok(node_id_from_falcon_pk(&keyset.falcon_pk))
}

/// Wallet info structure
pub struct WalletInfo {
    pub address: NodeId,
    pub falcon_pk: FalconPublicKey,
    pub kyber_pk: KyberPublicKey,
    pub wallet_id: [u8; 16],
}

/// Get wallet info (requires password to decrypt and get public keys)
pub fn get_wallet_info(wallet_path: &PathBuf, password: Option<String>) -> Result<WalletInfo> {
    let wf = load_wallet_file(wallet_path)?;
    // To get full info with public keys, we need password
    let (keyset, _) = load_wallet_keyset(wallet_path, password)?;
    Ok(WalletInfo {
        address: node_id_from_falcon_pk(&keyset.falcon_pk),
        falcon_pk: keyset.falcon_pk,
        kyber_pk: keyset.mlkem_pk,
        wallet_id: wf.header.wallet_id,
    })
}
