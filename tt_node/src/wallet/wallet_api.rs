#![forbid(unsafe_code)]

//! Public API for wallet operations
//!
//! Ten moduł udostępnia funkcje do pracy z zaszyfrowanymi plikami portfela
//! tworzonymi przez CLI w tt_node (PQ-only: Falcon512 + Kyber768).

use anyhow::{Context, Result};
use rpassword::prompt_password;
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::falcon_sigs::{FalconPublicKey, FalconSecretKey};
use crate::kyber_kem::{KyberPublicKey, KyberSecretKey};
use crate::node_id::{NodeId, node_id_from_falcon_pk};
use crate::wallet::wallet_cli::{
    decrypt_wallet_file_to_keyset,
    load_wallet_file,
    Keyset,
    WalletHeader,
};

/// Ładuje Keyset + nagłówek z zaszyfrowanego pliku portfela.
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

    let ks = decrypt_wallet_file_to_keyset(&wf, pw.as_str())
        .context("Failed to decrypt wallet (wrong password?)")?;

    Ok((ks, wf.header))
}

/// Zwraca klucze Falcon z portfela.
pub fn get_falcon_keys_from_wallet(
    wallet_path: &PathBuf,
    password: Option<String>,
) -> Result<(FalconPublicKey, FalconSecretKey)> {
    let (keyset, _) = load_wallet_keyset(wallet_path, password)?;
    Ok((keyset.falcon_pk, keyset.falcon_sk))
}

/// Zwraca klucze Kyber z portfela.
pub fn get_kyber_keys_from_wallet(
    wallet_path: &PathBuf,
    password: Option<String>,
) -> Result<(KyberPublicKey, KyberSecretKey)> {
    let (keyset, _) = load_wallet_keyset(wallet_path, password)?;
    Ok((keyset.mlkem_pk, keyset.mlkem_sk))
}

/// Zwraca wszystkie klucze + NodeId.
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

/// Zwraca sam adres (NodeId) z portfela.
pub fn get_wallet_address(wallet_path: &PathBuf, password: Option<String>) -> Result<NodeId> {
    let (keyset, _) = load_wallet_keyset(wallet_path, password)?;
    Ok(node_id_from_falcon_pk(&keyset.falcon_pk))
}

/// Informacje o portfelu.
pub struct WalletInfo {
    pub address: NodeId,
    pub falcon_pk: FalconPublicKey,
    pub kyber_pk: KyberPublicKey,
    pub wallet_id: [u8; 16],
}

/// Pełne info o portfelu (wymaga hasła).
pub fn get_wallet_info(wallet_path: &PathBuf, password: Option<String>) -> Result<WalletInfo> {
    let wf = load_wallet_file(wallet_path)?;
    let (keyset, _) = load_wallet_keyset(wallet_path, password)?;
    Ok(WalletInfo {
        address: node_id_from_falcon_pk(&keyset.falcon_pk),
        falcon_pk: keyset.falcon_pk,
        kyber_pk: keyset.mlkem_pk,
        wallet_id: wf.header.wallet_id,
    })
}
