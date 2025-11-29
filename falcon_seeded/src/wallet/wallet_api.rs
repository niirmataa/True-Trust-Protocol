#![forbid(unsafe_code)]

//! Public API for wallet operations
//!
//! Ten moduł łączy TT wallet v5 (zaszyfrowane pliki portfeli)
//! z nodem TRUE_TRUST. Wszystkie adresy / NodeId są liczone
//! z pary kluczy PQ (Falcon512 + Kyber768), dokładnie tak samo
//! jak w `tt_priv_cli` (ttq-adres).
//!
//! Adres / NodeId = SHAKE256(Falcon_PK || Kyber_PK)[0..32].

use anyhow::{Context, Result};
use rpassword::prompt_password;
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::falcon_sigs::{FalconPublicKey, FalconSecretKey};
use crate::kyber_kem::{KyberPublicKey, KyberSecretKey};
use crate::node_id::{NodeId, node_id_from_pq_keys};
use crate::wallet::wallet_cli::{decrypt_wallet_v3, load_wallet_file, Keyset, WalletHeader};

/// Load keyset from encrypted wallet file
///
/// Zwraca:
/// - `Keyset` (master32 + klucze PQ),
/// - `WalletHeader` (meta: KDF, AEAD, wallet_id, itp.).
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

/// Get Falcon keys from wallet (public + secret)
pub fn get_falcon_keys_from_wallet(
    wallet_path: &PathBuf,
    password: Option<String>,
) -> Result<(FalconPublicKey, FalconSecretKey)> {
    let (keyset, _) = load_wallet_keyset(wallet_path, password)?;
    Ok((keyset.falcon_pk, keyset.falcon_sk))
}

/// Get Kyber keys from wallet (public + secret)
pub fn get_kyber_keys_from_wallet(
    wallet_path: &PathBuf,
    password: Option<String>,
) -> Result<(KyberPublicKey, KyberSecretKey)> {
    let (keyset, _) = load_wallet_keyset(wallet_path, password)?;
    Ok((keyset.mlkem_pk, keyset.mlkem_sk))
}

/// Get all keys from wallet + NodeId (z Falcon+Kyber)
///
/// Zwraca:
/// - Falcon PK / SK,
/// - Kyber PK / SK,
/// - NodeId (32B hash, zgodny z ttq-adresem).
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
    let (keyset, _hdr) = load_wallet_keyset(wallet_path, password)?;
    let node_id = node_id_from_pq_keys(&keyset.falcon_pk, &keyset.mlkem_pk);

    Ok((
        keyset.falcon_pk,
        keyset.falcon_sk,
        keyset.mlkem_pk,
        keyset.mlkem_sk,
        node_id,
    ))
}

/// Get wallet address (NodeId) from wallet
///
/// To jest *surowy* 32-bajtowy identyfikator adresu,
/// ten sam który trafia do payloadu Bech32m `ttq1...`.
pub fn get_wallet_address(wallet_path: &PathBuf, password: Option<String>) -> Result<NodeId> {
    let (keyset, _hdr) = load_wallet_keyset(wallet_path, password)?;
    Ok(node_id_from_pq_keys(&keyset.falcon_pk, &keyset.mlkem_pk))
}

/// Wallet info structure (public-only)
///
/// Używane do wyświetlania informacji o portfelu w CLI / RPC.
pub struct WalletInfo {
    /// Surowy NodeId (32B) = SHAKE256(Falcon_PK || Kyber_PK)
    pub address: NodeId,
    /// Publiczny klucz Falcon-512
    pub falcon_pk: FalconPublicKey,
    /// Publiczny klucz Kyber-768 (ML-KEM)
    pub kyber_pk: KyberPublicKey,
    /// Losowy 128-bit ID portfela (z nagłówka)
    pub wallet_id: [u8; 16],
}

/// Get wallet info (requires password to decrypt and get public keys)
pub fn get_wallet_info(wallet_path: &PathBuf, password: Option<String>) -> Result<WalletInfo> {
    let wf = load_wallet_file(wallet_path).context("Failed to load wallet file")?;
    let (keyset, _hdr) = load_wallet_keyset(wallet_path, password)?;

    Ok(WalletInfo {
        address: node_id_from_pq_keys(&keyset.falcon_pk, &keyset.mlkem_pk),
        falcon_pk: keyset.falcon_pk,
        kyber_pk: keyset.mlkem_pk,
        wallet_id: wf.header.wallet_id,
    })
}
