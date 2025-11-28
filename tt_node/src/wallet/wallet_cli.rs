//! TT Private CLI - Quantum wallet v7 (PQ-only, hardmode)
//!
//! - PQC ONLY: Falcon512 + ML-KEM (Kyber768)
//! - Brak Ed25519 / X25519 (zero ECC).
//! - AEAD: AES-GCM-SIV / XChaCha20-Poly1305
//! - KDF: Argon2id z lokalnym pepperem + KMAC post-KDF
//! - Shamir M-of-N secret sharing na *samym* master32
//! - PQ klucze DETERMINISTYCZNE z master32 (hardmode v7)
//! - Stealth PQ: wysyłanie i odbieranie zaszyfrowanych hintów
//!
//! Adresy:
//!   - ttq: SHAKE256(Falcon_PK || MLKEM_PK)[0..32] → Bech32m "ttq"
//!
//! Feature `wallet` automatycznie włącza `seeded_falcon` i `seeded_kyber`.

#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, ensure, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use bincode::Options;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use aes_gcm_siv::{Aes256GcmSiv, Nonce as Nonce12Siv};
use chacha20poly1305::{XChaCha20Poly1305, XNonce as Nonce24};
use argon2::{Algorithm, Argon2, Params, Version};

use pqcrypto_falcon::falcon512;
use pqcrypto_kyber::kyber768 as mlkem;
use pqcrypto_traits::sign::PublicKey as PQSignPublicKey;
use pqcrypto_traits::sign::SecretKey as PQSignSecretKey;
use pqcrypto_traits::kem::PublicKey as PQKemPublicKey;
use pqcrypto_traits::kem::SecretKey as PQKemSecretKey;

use sharks::{Sharks, Share};

use crate::crypto::kmac as ck;

// Deterministyczne moduły PQ - WYMAGANE dla wallet v7
use crate::crypto::seeded::falcon_keypair_deterministic;
use crate::crypto::seeded_kyber::{kyber_keypair_deterministic, to_pqcrypto_kyber_keys};

use bech32::{Bech32m, Hrp};
use std::net::SocketAddr;
use crate::rpc::{SecureRpcClient, RpcRequest, RpcResponse};
use crate::p2p::secure::NodeIdentity;

// Stealth PQ imports (legacy)
use crate::stealth_pq::{
    StealthAddressPQ,
    StealthSecretsPQ,
    StealthHint,
    StealthHintBuilder,
    ScanResult,
    decrypt_stealth_hint,
};

// STARK transaction imports (legacy)
use crate::tx_stark::{TxOutputStark, TransactionStark};
use crate::core::{now_ts, BlockV2};

// Private STARK TX v2 imports (full privacy)
use crate::private_stark_tx::{
    PrivateStarkTx,
    ViewKey as PrivateViewKey,
};

/* ========================================================================================= */

const WALLET_VERSION: u32 = 7;
const WALLET_MAX_SIZE: u64 = 1 << 20;
const BECH32_HRP_TTQ: &str = "ttq";

// Argon2 defaults are now CLI parameters with these defaults:
// --argon2-mem-mib 256 (256 MiB, min 64 MiB for weak devices)
// --argon2-time 3
// --argon2-lanes 1

/// MasterSeed wrapper z automatyczną zeroizacją w Drop.
/// Paranoidalne podejście - żadne kopie master seed nie zostają w pamięci.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MasterSeed([u8; 32]);

impl MasterSeed {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_inner(mut self) -> Zeroizing<[u8; 32]> {
        let bytes = self.0;
        self.0.zeroize(); // zeroize before move
        Zeroizing::new(bytes)
    }
}

impl Zeroize for MasterSeed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for MasterSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl AsRef<[u8; 32]> for MasterSeed {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::ops::Deref for MasterSeed {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/* =========================================================================================
 * DERIVACJE Z MASTER32
 * ====================================================================================== */

fn derive_wallet_id(master: &MasterSeed) -> [u8; 16] {
    let full = ck::kmac256_derive_key(
        master.as_bytes(),
        b"TT.v7.WALLET.id",
        b"",
    );
    let mut wid = [0u8; 16];
    wid.copy_from_slice(&full[..16]);
    wid
}

/// Deterministyczne generowanie kluczy Falcon-512 z master seed.
/// TWARDA WERSJA - zero fallbacków, wymaga `seeded_falcon` feature.
fn derive_falcon_keypair(master: &MasterSeed) -> Result<(falcon512::PublicKey, falcon512::SecretKey)> {
    // 1) Deterministyczny keygen z master32 + domain separation
    let (pk_bytes, sk_bytes) = falcon_keypair_deterministic(
        *master.as_bytes(),
        b"TT.v7.FALCON512.keygen"
    ).map_err(|e| anyhow!("falcon_keypair_deterministic failed: {e}"))?;

    // 2) Konwersja bajtów na typy z pqcrypto_falcon
    let pk = falcon512::PublicKey::from_bytes(&pk_bytes)
        .map_err(|_| anyhow!("invalid falcon pk bytes from deterministic keygen"))?;
    let sk = falcon512::SecretKey::from_bytes(&sk_bytes)
        .map_err(|_| anyhow!("invalid falcon sk bytes from deterministic keygen"))?;

    Ok((pk, sk))
}

/// Deterministyczne generowanie kluczy Kyber-768 z master seed.
/// TWARDA WERSJA - zero fallbacków, wymaga `seeded_kyber` feature.
fn derive_mlkem_keypair(master: &MasterSeed) -> Result<(mlkem::PublicKey, mlkem::SecretKey)> {
    // 1) Deterministyczny Kyber z master32 + osobną domeną
    let (pk_bytes, sk_bytes) = kyber_keypair_deterministic(
        *master.as_bytes(),
        b"TT.v7.KYBER768.keygen"
    ).map_err(|e| anyhow!("kyber_keypair_deterministic failed: {e}"))?;

    // 2) Konwersja bajtów na typy z pqcrypto_kyber::kyber768
    let (pk, sk) = to_pqcrypto_kyber_keys(&pk_bytes, &sk_bytes)
        .map_err(|e| anyhow!("kyber key conversion failed: {e}"))?;

    Ok((pk, sk))
}

/* =========================================================================================
 * ADRES BECH32 (ttq)
 * ====================================================================================== */

pub fn raw_addr_from_keys(
    falcon_pk: &falcon512::PublicKey,
    mlkem_pk: &mlkem::PublicKey,
) -> [u8; 32] {
    // Adres oparty na OBU kluczach: Falcon + Kyber
    // Oba klucze są teraz deterministyczne z master seed!
    let mut h = Shake256::default();
    h.update(falcon_pk.as_bytes());
    h.update(mlkem_pk.as_bytes());
    let mut rdr = h.finalize_xof();
    let mut d = [0u8; 32];
    rdr.read(&mut d);
    d
}

fn bech32_addr_quantum_short(
    falcon_pk: &falcon512::PublicKey,
    mlkem_pk: &mlkem::PublicKey,
) -> Result<String> {
    let d = raw_addr_from_keys(falcon_pk, mlkem_pk);
    let mut payload = Vec::with_capacity(33);
    payload.push(0x03); // typ adresu PQ
    payload.extend_from_slice(&d);

    let hrp = Hrp::parse(BECH32_HRP_TTQ)?;
    // bech32 v0.11 encode takes 8-bit data directly
    Ok(bech32::encode::<Bech32m>(hrp, &payload)?)
}

/* =========================================================================================
 * CLI
 * ====================================================================================== */

#[derive(Parser, Debug)]
#[command(name = "tt_priv_cli", version, author)]
#[command(about = "TRUE_TRUST wallet CLI v7 (PQ-only: Falcon512 + Kyber768, hardmode + stealth)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(ValueEnum, Clone, Debug)]
enum AeadFlag {
    GcmSiv,
    XChaCha20,
}

#[derive(ValueEnum, Clone, Debug)]
enum PepperFlag {
    None,
    OsLocal,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Initialize new PQ wallet
    WalletInit {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value_t = true)]
        argon2: bool,
        /// Argon2 memory in MiB (default: 256, min: 64, use lower for weak devices)
        #[arg(long, default_value_t = 256)]
        argon2_mem_mib: u32,
        /// Argon2 time cost / iterations (default: 3)
        #[arg(long, default_value_t = 3)]
        argon2_time: u32,
        /// Argon2 parallelism lanes (default: 1)
        #[arg(long, default_value_t = 1)]
        argon2_lanes: u32,
        #[arg(long, value_enum, default_value_t = AeadFlag::GcmSiv)]
        aead: AeadFlag,
        #[arg(long, value_enum, default_value_t = PepperFlag::OsLocal)]
        pepper: PepperFlag,
        #[arg(long, default_value_t = 1024)]
        pad_block: u16,
    },

    /// Show wallet address
    WalletAddr {
        #[arg(long)]
        file: PathBuf,
    },

    /// Export wallet (public or secret)
    WalletExport {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        secret: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Change wallet password/encryption
    WalletRekey {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value_t = true)]
        argon2: bool,
        /// Argon2 memory in MiB (default: 256, min: 64, use lower for weak devices)
        #[arg(long, default_value_t = 256)]
        argon2_mem_mib: u32,
        /// Argon2 time cost / iterations (default: 3)
        #[arg(long, default_value_t = 3)]
        argon2_time: u32,
        /// Argon2 parallelism lanes (default: 1)
        #[arg(long, default_value_t = 1)]
        argon2_lanes: u32,
        #[arg(long, value_enum, default_value_t = AeadFlag::GcmSiv)]
        aead: AeadFlag,
        #[arg(long, value_enum, default_value_t = PepperFlag::OsLocal)]
        pepper: PepperFlag,
        #[arg(long, default_value_t = 1024)]
        pad_block: u16,
    },

    /// Create Shamir M-of-N backup shards
    ShardsCreate {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long)]
        m: u8,
        #[arg(long)]
        n: u8,
        #[arg(long, default_value_t = false)]
        per_share_pass: bool,
    },

    /// Recover wallet from Shamir shards
    ShardsRecover {
        #[arg(long, value_delimiter = ',')]
        input: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = true)]
        argon2: bool,
        /// Argon2 memory in MiB (default: 256, min: 64, use lower for weak devices)
        #[arg(long, default_value_t = 256)]
        argon2_mem_mib: u32,
        /// Argon2 time cost / iterations (default: 3)
        #[arg(long, default_value_t = 3)]
        argon2_time: u32,
        /// Argon2 parallelism lanes (default: 1)
        #[arg(long, default_value_t = 1)]
        argon2_lanes: u32,
        #[arg(long, value_enum, default_value_t = AeadFlag::GcmSiv)]
        aead: AeadFlag,
        #[arg(long, value_enum, default_value_t = PepperFlag::OsLocal)]
        pepper: PepperFlag,
        #[arg(long, default_value_t = 1024)]
        pad_block: u16,
    },

    /// Check balance via secure RPC
    WalletBalance {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8080")]
        rpc: String,
        /// Disable ProPrivacy mode (use --no-privacy for debug only)
        #[arg(long = "no-privacy", default_value_t = false)]
        no_privacy: bool,
        /// Use Tor (SOCKS5 proxy, e.g. 127.0.0.1:9050)
        #[arg(long)]
        tor: Option<String>,
    },

    /// Send funds to another wallet (normal transfer via RPC)
    Send {
        /// Your wallet file
        #[arg(long)]
        file: PathBuf,
        /// Recipient address (ttq... bech32 or 32-byte hex)
        #[arg(long)]
        to: String,
        /// Amount to send
        #[arg(long)]
        amount: u128,
        /// Transaction fee (default: 100)
        #[arg(long, default_value_t = 100)]
        fee: u128,
        /// RPC server address
        #[arg(long, default_value = "127.0.0.1:8080")]
        rpc: String,
        /// Disable ProPrivacy mode (use --no-privacy for debug only)
        #[arg(long = "no-privacy", default_value_t = false)]
        no_privacy: bool,
        /// Use Tor (SOCKS5 proxy, e.g. 127.0.0.1:9050)
        #[arg(long)]
        tor: Option<String>,
    },

    /// Credit/mint tokens to your wallet (faucet for testing)
    Credit {
        /// Your wallet file (to get address)
        #[arg(long)]
        file: PathBuf,
        /// Amount to credit
        #[arg(long)]
        amount: u128,
        /// RPC server address
        #[arg(long, default_value = "127.0.0.1:8080")]
        rpc: String,
        /// Disable ProPrivacy mode (use --no-privacy for debug only)
        #[arg(long = "no-privacy", default_value_t = false)]
        no_privacy: bool,
        /// Use Tor (SOCKS5 proxy, e.g. 127.0.0.1:9050)
        #[arg(long)]
        tor: Option<String>,
    },

    /// Create stealth hint for recipient (send)
    StealthSend {
        /// Your wallet file (for context/AAD)
        #[arg(long)]
        file: PathBuf,
        /// Recipient's Falcon-512 public key (hex)
        #[arg(long)]
        recipient_falcon_pk: String,
        /// Recipient's Kyber-768 public key (hex)
        #[arg(long)]
        recipient_kyber_pk: String,
        /// Value to send
        #[arg(long)]
        value: u64,
        /// Optional memo message
        #[arg(long, default_value = "")]
        memo: String,
        /// Output file for the stealth hint (local save)
        #[arg(long)]
        out: Option<PathBuf>,
        /// RPC server to broadcast hint through (e.g. 127.0.0.1:9999)
        #[arg(long)]
        rpc: Option<String>,
        /// Disable ProPrivacy mode (use --no-privacy for debug only)
        #[arg(long = "no-privacy", default_value_t = false)]
        no_privacy: bool,
    },

    /// Try to decrypt a stealth hint (receive)
    StealthReceive {
        /// Your wallet file (contains secret keys)
        #[arg(long)]
        file: PathBuf,
        /// Path to the stealth hint file
        #[arg(long)]
        hint: PathBuf,
    },

    /// Scan multiple stealth hints to find ones addressed to you
    StealthScan {
        /// Your wallet file
        #[arg(long)]
        file: PathBuf,
        /// Directory containing hint files
        #[arg(long)]
        hints_dir: PathBuf,
    },

    /// Scan stealth hints from RPC server
    StealthScanRpc {
        /// Your wallet file
        #[arg(long)]
        file: PathBuf,
        /// RPC server address (e.g. 127.0.0.1:9999)
        #[arg(long)]
        rpc: String,
        /// Disable ProPrivacy mode (use --no-privacy for debug only)
        #[arg(long = "no-privacy", default_value_t = false)]
        no_privacy: bool,
        /// Maximum hints to fetch
        #[arg(long, default_value = "100")]
        limit: usize,
    },

    /// Send STARK transaction with full privacy (hidden value + stealth recipient)
    /// Combines STARK range proof (value hidden) + Stealth hint (recipient hidden)
    #[command(name = "stark-send")]
    StarkSend {
        /// Your wallet file
        #[arg(long)]
        file: PathBuf,
        /// Recipient's Falcon-512 public key (hex)
        #[arg(long)]
        recipient_falcon_pk: String,
        /// Recipient's Kyber-768 public key (hex)
        #[arg(long)]
        recipient_kyber_pk: String,
        /// Amount to send
        #[arg(long)]
        amount: u64,
        /// Optional memo message (max 200 bytes)
        #[arg(long, default_value = "")]
        memo: String,
        /// RPC server to submit transaction
        #[arg(long)]
        rpc: String,
        /// Disable ProPrivacy mode (use --no-privacy for debug only)
        #[arg(long = "no-privacy", default_value_t = false)]
        no_privacy: bool,
        /// Optional Tor SOCKS5 proxy (e.g. 127.0.0.1:9050)
        #[arg(long)]
        tor: Option<String>,
    },

    /// Receive and decrypt STARK transaction outputs addressed to you
    #[command(name = "stark-receive")]
    StarkReceive {
        /// Your wallet file
        #[arg(long)]
        file: PathBuf,
        /// RPC server to query transactions
        #[arg(long)]
        rpc: String,
        /// Disable ProPrivacy mode (use --no-privacy for debug only)
        #[arg(long = "no-privacy", default_value_t = false)]
        no_privacy: bool,
    },

    /// Scan blockchain blocks for stealth hints (Monero-style)
    /// This is the recommended way to receive - hints persist in blockchain
    #[command(name = "stark-scan-blocks")]
    StarkScanBlocks {
        /// Your wallet file
        #[arg(long)]
        file: PathBuf,
        /// RPC server address
        #[arg(long)]
        rpc: String,
        /// Starting block height (default: 0)
        #[arg(long, default_value = "0")]
        from_height: u64,
        /// Disable ProPrivacy mode (use --no-privacy for debug only)
        #[arg(long = "no-privacy", default_value_t = false)]
        no_privacy: bool,
    },

    /// [V2] Send private STARK transaction with FULL privacy
    /// - Sender: HIDDEN (stealth + encrypted master_key_id)
    /// - Recipient: HIDDEN (stealth address)
    /// - Amount: HIDDEN (Poseidon commitment + STARK range proof)
    #[command(name = "private-stark-send")]
    PrivateStarkSend {
        /// Your wallet file
        #[arg(long)]
        file: PathBuf,
        /// Recipient's Kyber-768 public key (hex)
        #[arg(long)]
        recipient_kyber_pk: String,
        /// Amount to send (hidden with STARK proof)
        #[arg(long)]
        amount: u64,
        /// Fee (plaintext for validators)
        #[arg(long, default_value = "10")]
        fee: u64,
        /// RPC server to submit transaction
        #[arg(long)]
        rpc: String,
        /// Disable ProPrivacy mode (use --no-privacy for debug only)
        #[arg(long = "no-privacy", default_value_t = false)]
        no_privacy: bool,
        /// Optional Tor SOCKS5 proxy (e.g. 127.0.0.1:9050)
        #[arg(long)]
        tor: Option<String>,
    },

    /// [V2] Receive private STARK transactions with full verification
    /// Scans, decrypts, and verifies STARK range proofs
    #[command(name = "private-stark-receive")]
    PrivateStarkReceive {
        /// Your wallet file
        #[arg(long)]
        file: PathBuf,
        /// Transaction data (hex) - from sender out-of-band
        #[arg(long)]
        tx_hex: String,
    },
}

/* =========================================================================================
 * TYPY PORTFELA
 * ====================================================================================== */

#[derive(Clone, Debug, Serialize, Deserialize)]
enum AeadKind {
    AesGcmSiv,
    XChaCha20,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum PepperPolicy {
    None,
    OsLocal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct WalletHeader {
    version: u32,
    kdf: KdfHeader,
    aead: AeadKind,
    nonce12: [u8; 12],
    nonce24_opt: Option<[u8; 24]>,
    padding_block: u16,
    pepper: PepperPolicy,
    pub(crate) wallet_id: [u8; 16],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct KdfHeader {
    kind: KdfKind,
    info: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum KdfKind {
    Kmac256V1 { salt32: [u8; 32] },
    Argon2idV1 {
        mem_kib: u32,
        time_cost: u32,
        lanes: u32,
        salt32: [u8; 32],
    },
}

/// Sekretny payload v7 – tylko master32.
/// Oba klucze (Falcon + Kyber) są deterministycznie generowane z master seed.
#[derive(Clone, Serialize, Deserialize)]
struct WalletSecretPayloadV7 {
    master32: MasterSeed,
}

impl Drop for WalletSecretPayloadV7 {
    fn drop(&mut self) {
        self.master32.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct WalletFile {
    pub(crate) header: WalletHeader,
    pub(crate) enc: Vec<u8>,
}

/// To jest to, czego oczekuje też stealth_pq: klucze PQ + master32 + wallet_id.
#[derive(Clone)]
pub struct Keyset {
    pub master32: MasterSeed,
    pub wallet_id: [u8; 16],
    pub falcon_sk: falcon512::SecretKey,
    pub falcon_pk: falcon512::PublicKey,
    pub mlkem_sk: mlkem::SecretKey,
    pub mlkem_pk: mlkem::PublicKey,
}

impl Keyset {
    /// Tworzy Keyset w pełni deterministycznie z master seed
    /// Oba klucze (Falcon + Kyber) są generowane z master seed
    pub fn from_master(master: &MasterSeed) -> Result<Self> {
        let wallet_id = derive_wallet_id(master);
        let (falcon_pk, falcon_sk) = derive_falcon_keypair(master)?;
        let (mlkem_pk, mlkem_sk) = derive_mlkem_keypair(master)?;
        Ok(Self {
            master32: master.clone(),
            wallet_id,
            falcon_sk,
            falcon_pk,
            mlkem_sk,
            mlkem_pk,
        })
    }
}

impl Drop for Keyset {
    fn drop(&mut self) {
        self.master32.zeroize();
    }
}

/* =========================================================================================
 * PEPPER
 * ====================================================================================== */

trait PepperProvider {
    fn get(&self, wallet_id: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>>;
}

struct NoPepper;
impl PepperProvider for NoPepper {
    fn get(&self, _id: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(Vec::new()))
    }
}

struct OsLocalPepper;
impl OsLocalPepper {
    fn path_for(id: &[u8; 16]) -> Result<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            let base = std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            Ok(base.join("TT").join("pepper").join(hex::encode(id)))
        }
        #[cfg(not(target_os = "windows"))]
        {
            let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
            Ok(base.join("tt").join("pepper").join(hex::encode(id)))
        }
    }
}

impl PepperProvider for OsLocalPepper {
    fn get(&self, wallet_id: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>> {
        let path = Self::path_for(wallet_id)?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        if path.exists() {
            let v = fs::read(&path)?;
            ensure!(v.len() == 32, "pepper file size invalid");
            return Ok(Zeroizing::new(v));
        }
        let mut p = [0u8; 32];
        OsRng.fill_bytes(&mut p);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = OpenOptions::new();
            opts.create_new(true).write(true).mode(0o600);
            let mut f = opts.open(&path)?;
            f.write_all(&p)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            let mut opts = OpenOptions::new();
            opts.create_new(true).write(true);
            let mut f = opts.open(&path)?;
            f.write_all(&p)?;
            f.sync_all()?;
        }
        Ok(Zeroizing::new(p.to_vec()))
    }
}

fn pepper_provider(pol: &PepperPolicy) -> Box<dyn PepperProvider> {
    match pol {
        PepperPolicy::None => Box::new(NoPepper),
        PepperPolicy::OsLocal => Box::new(OsLocalPepper),
    }
}

/* =========================================================================================
 * KDF / AEAD / PADDING
 * ====================================================================================== */

fn derive_kdf_key(password: &str, hdr: &KdfHeader, pepper: &[u8]) -> [u8; 32] {
    match &hdr.kind {
        KdfKind::Kmac256V1 { salt32 } => {
            let k1 =
                ck::kmac256_derive_key(password.as_bytes(), b"TT-KDF.v7.kmac.pre", salt32);
            ck::kmac256_derive_key(&k1, b"TT-KDF.v7.kmac.post", pepper)
        }
        KdfKind::Argon2idV1 {
            mem_kib,
            time_cost,
            lanes,
            salt32,
        } => {
            let params =
                Params::new(*mem_kib, *time_cost, *lanes, Some(32)).expect("argon2 params");
            let a2 = Argon2::new_with_secret(
                pepper,
                Algorithm::Argon2id,
                Version::V0x13,
                params,
            )
            .expect("argon2 new_with_secret");
            let mut out = [0u8; 32];
            a2.hash_password_into(password.as_bytes(), salt32, &mut out)
                .expect("argon2");
            ck::kmac256_derive_key(&out, b"TT-KDF.v7.post", salt32)
        }
    }
}

fn aad_for_header(h: &WalletHeader) -> Vec<u8> {
    bincode::options()
        .with_limit(WALLET_MAX_SIZE)
        .serialize(h)
        .expect("serialize header AAD")
}

fn pad(mut v: Vec<u8>, block: usize) -> Vec<u8> {
    let len = v.len();
    let pad_len = (block - ((len + 8) % block)) % block;
    v.extend(std::iter::repeat(0u8).take(pad_len));
    v.extend_from_slice(&(len as u64).to_le_bytes());
    v
}

fn unpad(mut v: Vec<u8>) -> Result<Vec<u8>> {
    ensure!(v.len() >= 8, "bad padded len");
    let len = u64::from_le_bytes(v[v.len() - 8..].try_into().unwrap()) as usize;
    ensure!(len <= v.len() - 8, "bad pad marker");
    v.truncate(len);
    Ok(v)
}

fn encrypt_wallet<T: Serialize>(
    payload: &T,
    password: &str,
    hdr: &WalletHeader,
) -> Result<Vec<u8>> {
    let prov = pepper_provider(&hdr.pepper);
    let pepper = prov.get(&hdr.wallet_id)?;
    let key = Zeroizing::new(derive_kdf_key(password, &hdr.kdf, &pepper));
    let aad = aad_for_header(hdr);
    let pt_ser = bincode::options()
        .with_limit(WALLET_MAX_SIZE)
        .serialize(payload)?;
    let pt_pad = Zeroizing::new(pad(pt_ser, hdr.padding_block as usize));

    match hdr.aead {
        AeadKind::AesGcmSiv => {
            use aes_gcm_siv::aead::{Aead, KeyInit};
            let cipher = Aes256GcmSiv::new_from_slice(&*key)
                .map_err(|_| anyhow!("bad AES-256 key"))?;
            let nonce = Nonce12Siv::from_slice(&hdr.nonce12);
            Ok(cipher
                .encrypt(
                    nonce,
                    aes_gcm_siv::aead::Payload {
                        msg: pt_pad.as_ref(),
                        aad: &aad,
                    },
                )
                .map_err(|e| anyhow!("encrypt: {e}"))?)
        }
        AeadKind::XChaCha20 => {
            use chacha20poly1305::aead::{Aead, KeyInit};
            let n24 =
                hdr.nonce24_opt
                    .ok_or_else(|| anyhow!("missing 24B nonce"))?;
            let cipher = XChaCha20Poly1305::new_from_slice(&*key)
                .map_err(|_| anyhow!("bad XChaCha key"))?;
            let nonce = Nonce24::from_slice(&n24);
            Ok(cipher
                .encrypt(
                    nonce,
                    chacha20poly1305::aead::Payload {
                        msg: pt_pad.as_ref(),
                        aad: &aad,
                    },
                )
                .map_err(|e| anyhow!("encrypt: {e}"))?)
        }
    }
}

fn decrypt_wallet_v7(
    enc: &[u8],
    password: &str,
    hdr: &WalletHeader,
) -> Result<WalletSecretPayloadV7> {
    let prov = pepper_provider(&hdr.pepper);
    let pepper = prov.get(&hdr.wallet_id)?;
    let key = Zeroizing::new(derive_kdf_key(password, &hdr.kdf, &pepper));
    let aad = aad_for_header(hdr);

    let pt = match hdr.aead {
        AeadKind::AesGcmSiv => {
            use aes_gcm_siv::aead::{Aead, KeyInit};
            let cipher = Aes256GcmSiv::new_from_slice(&*key)
                .map_err(|_| anyhow!("bad AES-256 key"))?;
            let nonce = Nonce12Siv::from_slice(&hdr.nonce12);
            Zeroizing::new(
                cipher
                    .decrypt(
                        nonce,
                        aes_gcm_siv::aead::Payload {
                            msg: enc,
                            aad: &aad,
                        },
                    )
                    .map_err(|e| anyhow!("decrypt: {e}"))?,
            )
        }
        AeadKind::XChaCha20 => {
            use chacha20poly1305::aead::{Aead, KeyInit};
            let n24 =
                hdr.nonce24_opt
                    .ok_or_else(|| anyhow!("missing 24B nonce"))?;
            let cipher = XChaCha20Poly1305::new_from_slice(&*key)
                .map_err(|_| anyhow!("bad XChaCha key"))?;
            let nonce = Nonce24::from_slice(&n24);
            Zeroizing::new(
                cipher
                    .decrypt(
                        nonce,
                        chacha20poly1305::aead::Payload {
                            msg: enc,
                            aad: &aad,
                        },
                    )
                    .map_err(|e| anyhow!("decrypt: {e}"))?,
            )
        }
    };

    let unpadded = unpad(pt.to_vec())?;
    let w: WalletSecretPayloadV7 = bincode::options()
        .with_limit(WALLET_MAX_SIZE)
        .deserialize(&unpadded)?;
    Ok(w)
}

pub(crate) fn decrypt_wallet_file_to_keyset(
    wf: &WalletFile,
    password: &str,
) -> Result<Keyset> {
    let secret = decrypt_wallet_v7(&wf.enc, password, &wf.header)?;
    Keyset::from_master(&secret.master32)
}

/* =========================================================================================
 * WALLET FILE I I/O
 * ====================================================================================== */

pub(crate) fn load_wallet_file(path: &PathBuf) -> Result<WalletFile> {
    let meta = fs::metadata(path)?;
    ensure!(meta.len() <= WALLET_MAX_SIZE, "wallet file too large");
    let buf = fs::read(path)?;
    let wf: WalletFile = bincode::options()
        .with_limit(WALLET_MAX_SIZE)
        .deserialize(&buf)?;
    ensure!(
        wf.header.version == WALLET_VERSION,
        "wallet version unsupported (have {}, want {})",
        wf.header.version,
        WALLET_VERSION
    );
    Ok(wf)
}

/// Pobierz hasło z TT_WALLET_PASSWORD env lub interaktywnie
fn get_password_auto(prompt_msg: &str) -> Result<Zeroizing<String>> {
    if let Ok(pw) = std::env::var("TT_WALLET_PASSWORD") {
        return Ok(Zeroizing::new(pw));
    }
    Ok(Zeroizing::new(prompt_password(prompt_msg)?))
}

fn load_keyset(path: PathBuf) -> Result<(Keyset, WalletHeader)> {
    let wf = load_wallet_file(&path)?;
    let pw = get_password_auto("Password: ")?;
    let secret = decrypt_wallet_v7(&wf.enc, pw.as_str(), &wf.header)?;
    let ks = Keyset::from_master(&secret.master32)?;
    Ok((ks, wf.header))
}

/* =========================================================================================
 * ATOMIC FILES
 * ====================================================================================== */

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = path.with_extension("tmp");
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }

    let mut f = match opts.open(&tmp) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(&tmp)?;
            opts.open(&tmp)?
        }
        Err(e) => return Err(e.into()),
    };

    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);

    match fs::rename(&tmp, path) {
        Ok(()) => {
            fsync_parent_dir(path)?;
            Ok(())
        }
        Err(_) => {
            let _ = fs::remove_file(path);
            fs::rename(&tmp, path)?;
            fsync_parent_dir(path)?;
            Ok(())
        }
    }
}

#[cfg(unix)]
fn fsync_parent_dir(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let dirf = std::fs::File::open(parent)?;
    dirf.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn fsync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}

/* =========================================================================================
 * SHAMIR NA MASTER32 (v7)
 * ====================================================================================== */

#[derive(Clone, Serialize, Deserialize)]
struct ShardHeader {
    version: u32,
    scheme: String,
    wallet_id: [u8; 16],
    m: u8,
    n: u8,
    idx: u8,
    salt32: [u8; 32],
    info: String,
    has_pw: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct ShardFile {
    hdr: ShardHeader,
    share_ct: Vec<u8>,
    mac32: [u8; 32],
}

fn shard_mac_key(wallet_id: &[u8; 16], salt32: &[u8; 32]) -> [u8; 32] {
    ck::kmac256_derive_key(wallet_id, b"TT-SHARD.v7.mac.key", salt32)
}

fn shard_mask(share: &[u8], pw: &str, salt32: &[u8; 32]) -> Vec<u8> {
    let mask =
        ck::kmac256_xof(pw.as_bytes(), b"TT-SHARD.v7.mask", salt32, share.len());
    share.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect()
}

fn seal_share(
    wallet_id: [u8; 16],
    idx: u8,
    m: u8,
    n: u8,
    share: &[u8],
    salt32: [u8; 32],
    pw_opt: Option<&str>,
) -> Result<ShardFile> {
    let has_pw = pw_opt.is_some();
    let share_ct = if let Some(pw) = pw_opt {
        shard_mask(share, pw, &salt32)
    } else {
        share.to_vec()
    };

    let hdr = ShardHeader {
        version: 1,
        scheme: "shamir-gf256.v7.master32".to_string(),
        wallet_id,
        m,
        n,
        idx,
        salt32,
        info: "TT-SHARD.v7".into(),
        has_pw,
    };

    let hdr_bytes = bincode::serialize(&hdr)?;
    let mut mac_input = hdr_bytes.clone();
    mac_input.extend(&share_ct);
    let mac32 = ck::kmac256_tag(
        &shard_mac_key(&wallet_id, &salt32),
        b"TT-SHARD.v7.mac",
        &mac_input,
    );

    Ok(ShardFile { hdr, share_ct, mac32 })
}

fn shards_create(
    master32: MasterSeed,
    m: u8,
    n: u8,
    pw_opt: Option<&str>,
) -> Result<Vec<ShardFile>> {
    ensure!(m >= 2 && n >= m && n <= 8, "m-of-n out of range");
    let sharks = Sharks(m);
    let dealer = sharks.dealer(master32.as_bytes());
    let shares: Vec<Share> = dealer.take(n as usize).collect();

    let wallet_id = derive_wallet_id(&master32);

    let mut out = Vec::with_capacity(n as usize);
    for (i, sh) in shares.into_iter().enumerate() {
        let mut salt32 = [0u8; 32];
        OsRng.fill_bytes(&mut salt32);
        let share_bytes: Vec<u8> = Vec::from(&sh);
        let sf = seal_share(
            wallet_id,
            (i + 1) as u8,
            m,
            n,
            &share_bytes,
            salt32,
            pw_opt,
        )?;
        out.push(sf);
    }
    Ok(out)
}

fn shards_recover(paths: &[PathBuf]) -> Result<MasterSeed> {
    ensure!(paths.len() >= 2, "need at least 2 shards");
    let mut shards: Vec<(ShardHeader, Vec<u8>)> = Vec::new();

    for p in paths {
        let bytes = fs::read(p)?;
        let sf: ShardFile = serde_json::from_slice(&bytes)
            .or_else(|_| bincode::deserialize(&bytes))?;

        // MAC
        let hdr_bytes = bincode::serialize(&sf.hdr)?;
        let mut mac_input = hdr_bytes.clone();
        mac_input.extend(&sf.share_ct);
        let mac_chk = ck::kmac256_tag(
            &shard_mac_key(&sf.hdr.wallet_id, &sf.hdr.salt32),
            b"TT-SHARD.v7.mac",
            &mac_input,
        );
        ensure!(mac_chk == sf.mac32, "shard MAC mismatch: {}", p.display());
        shards.push((sf.hdr, sf.share_ct));
    }

    let (wid, m, n) = (shards[0].0.wallet_id, shards[0].0.m, shards[0].0.n);
    ensure!(
        paths.len() as u8 >= m,
        "need at least {} shards, got {}",
        m,
        paths.len()
    );

    let mut seen = HashSet::new();
    for (h, _) in &shards {
        ensure!(
            h.wallet_id == wid && h.m == m && h.n == n,
            "shard set mismatch"
        );
        ensure!(seen.insert(h.idx), "duplicate shard index: {}", h.idx);
    }

    let mut rec: Vec<(u8, Vec<u8>)> = Vec::new();
    for (h, ct) in shards {
        let pt = if h.has_pw {
            let pw = Zeroizing::new(prompt_password(format!(
                "Password for shard #{}: ",
                h.idx
            ))?);
            shard_mask(&ct, pw.as_str(), &h.salt32)
        } else {
            ct
        };
        rec.push((h.idx, pt));
    }

    let sharks = Sharks(m);
    let shares_iter = rec
        .into_iter()
        .map(|(_, bytes)| Share::try_from(bytes.as_slice()));
    let shares_vec: Result<Vec<_>> = shares_iter
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("share parse error: {}", e));
    let shares_vec = shares_vec?;

    let secret = sharks
        .recover(shares_vec.iter())
        .map_err(|e| anyhow!("sharks recover: {}", e))?;

    let mut out = [0u8; 32];
    out.copy_from_slice(&secret);
    Ok(MasterSeed::new(out))
}

/* =========================================================================================
 * KOMENDY WALLET
 * ====================================================================================== */

fn cmd_wallet_init(
    path: PathBuf,
    use_argon2: bool,
    argon2_mem_mib: u32,
    argon2_time: u32,
    argon2_lanes: u32,
    aead_flag: AeadFlag,
    pepper_flag: PepperFlag,
    pad_block: u16,
) -> Result<()> {
    if path.exists() {
        bail!("file exists: {}", path.display());
    }

    // Validate Argon2 parameters
    ensure!(argon2_mem_mib >= 64, "argon2_mem_mib must be at least 64 MiB");
    ensure!(argon2_time >= 1, "argon2_time must be at least 1");
    ensure!(argon2_lanes >= 1, "argon2_lanes must be at least 1");

    // Dla automatyzacji: hasło z env TT_WALLET_PASSWORD
    let pw1 = if let Ok(pw) = std::env::var("TT_WALLET_PASSWORD") {
        Zeroizing::new(pw)
    } else {
        let p1 = Zeroizing::new(prompt_password("New password (min 12 chars): ")?);
        ensure!(p1.len() >= 12, "password too short");
        let p2 = Zeroizing::new(prompt_password("Repeat password: ")?);
        ensure!(p1.as_str() == p2.as_str(), "password mismatch");
        p1
    };
    ensure!(pw1.len() >= 12, "password too short (min 12 chars)");

    let mut nonce12 = [0u8; 12];
    OsRng.fill_bytes(&mut nonce12);
    let nonce24_opt = match aead_flag {
        AeadFlag::XChaCha20 => {
            let mut n = [0u8; 24];
            OsRng.fill_bytes(&mut n);
            Some(n)
        }
        _ => None,
    };

    let kdf = if use_argon2 {
        let mut salt32 = [0u8; 32];
        OsRng.fill_bytes(&mut salt32);
        let mem_kib = argon2_mem_mib * 1024;
        let time_cost = argon2_time;
        let lanes = argon2_lanes;
        KdfHeader {
            kind: KdfKind::Argon2idV1 {
                mem_kib,
                time_cost,
                lanes,
                salt32,
            },
            info: format!(
                "TT-KDF.v7.argon2id.t{time_cost}.m{}MiB.l{lanes}",
                mem_kib / 1024
            ),
        }
    } else {
        let mut salt32 = [0u8; 32];
        OsRng.fill_bytes(&mut salt32);
        KdfHeader {
            kind: KdfKind::Kmac256V1 { salt32 },
            info: "TT-KDF.v7.kmac".into(),
        }
    };

    let master32 = MasterSeed::generate();
    let wallet_id = derive_wallet_id(&master32);

    let hdr = WalletHeader {
        version: WALLET_VERSION,
        kdf,
        aead: match aead_flag {
            AeadFlag::GcmSiv => AeadKind::AesGcmSiv,
            AeadFlag::XChaCha20 => AeadKind::XChaCha20,
        },
        nonce12,
        nonce24_opt,
        padding_block: pad_block,
        pepper: match pepper_flag {
            PepperFlag::None => PepperPolicy::None,
            PepperFlag::OsLocal => PepperPolicy::OsLocal,
        },
        wallet_id,
    };

    // Teraz klucze są deterministyczne - tylko master32 w payload
    let payload = WalletSecretPayloadV7 { master32 };
    let enc = encrypt_wallet(&payload, pw1.as_str(), &hdr)?;
    let wf = WalletFile { header: hdr, enc };
    let bytes = bincode::options()
        .with_limit(WALLET_MAX_SIZE)
        .serialize(&wf)?;

    atomic_write(&path, &bytes)?;
    eprintln!(
        "✅ created PQ wallet v{} (hardmode) → {}",
        WALLET_VERSION,
        path.display()
    );
    Ok(())
}

fn cmd_wallet_addr(path: PathBuf) -> Result<()> {
    let (ks, _hdr) = load_keyset(path)?;
    let addr = bech32_addr_quantum_short(&ks.falcon_pk, &ks.mlkem_pk)?;
    println!("address(ttq): {}", addr);
    println!("falcon_pk: {}", hex::encode(ks.falcon_pk.as_bytes()));
    println!("mlkem_pk : {}", hex::encode(ks.mlkem_pk.as_bytes()));
    Ok(())
}

fn cmd_wallet_export(
    path: PathBuf,
    secret: bool,
    out: Option<PathBuf>,
) -> Result<()> {
    let wf = load_wallet_file(&path)?;
    let pw = get_password_auto("Password: ")?;
    let secret_payload = decrypt_wallet_v7(&wf.enc, pw.as_str(), &wf.header)?;
    let ks = Keyset::from_master(&secret_payload.master32)?;

    if secret {
        let outp =
            out.ok_or_else(|| anyhow!("secret export requires --out <file>"))?;
        let confirm =
            Zeroizing::new(prompt_password("Type wallet password again to CONFIRM: ")?);
        let _ = decrypt_wallet_v7(&wf.enc, confirm.as_str(), &wf.header)?;

        let txt = format!(
            "{{\"version\":{},\"master32\":\"{}\",\"falcon_sk\":\"{}\",\"mlkem_sk\":\"{}\"}}\n",
            WALLET_VERSION,
            hex::encode(secret_payload.master32.as_bytes()),
            hex::encode(ks.falcon_sk.as_bytes()),
            hex::encode(ks.mlkem_sk.as_bytes())
        );
        atomic_write(&outp, txt.as_bytes())?;
        eprintln!("🔒 secrets written → {}", outp.display());
    } else {
        let addr = bech32_addr_quantum_short(&ks.falcon_pk, &ks.mlkem_pk)?;
        println!("address(ttq): {}", addr);
        println!("falcon_pk: {}", hex::encode(ks.falcon_pk.as_bytes()));
        println!("mlkem_pk : {}", hex::encode(ks.mlkem_pk.as_bytes()));
    }
    Ok(())
}

fn cmd_wallet_rekey(
    path: PathBuf,
    use_argon2: bool,
    argon2_mem_mib: u32,
    argon2_time: u32,
    argon2_lanes: u32,
    aead_flag: AeadFlag,
    pepper_flag: PepperFlag,
    pad_block: u16,
) -> Result<()> {
    // Validate Argon2 parameters
    ensure!(argon2_mem_mib >= 64, "argon2_mem_mib must be at least 64 MiB");
    ensure!(argon2_time >= 1, "argon2_time must be at least 1");
    ensure!(argon2_lanes >= 1, "argon2_lanes must be at least 1");

    let wf = load_wallet_file(&path)?;
    let old_pw = Zeroizing::new(prompt_password("Old password: ")?);
    let secret = decrypt_wallet_v7(&wf.enc, old_pw.as_str(), &wf.header)?;

    let pw1 = Zeroizing::new(prompt_password("New password (min 12 chars): ")?);
    ensure!(pw1.len() >= 12, "password too short");
    let pw2 = Zeroizing::new(prompt_password("Repeat password: ")?);
    ensure!(pw1.as_str() == pw2.as_str(), "password mismatch");

    let mut nonce12 = [0u8; 12];
    OsRng.fill_bytes(&mut nonce12);
    let nonce24_opt = match aead_flag {
        AeadFlag::XChaCha20 => {
            let mut n = [0u8; 24];
            OsRng.fill_bytes(&mut n);
            Some(n)
        }
        _ => None,
    };

    let kdf = if use_argon2 {
        let mut salt32 = [0u8; 32];
        OsRng.fill_bytes(&mut salt32);
        let mem_kib = argon2_mem_mib * 1024;
        let time_cost = argon2_time;
        let lanes = argon2_lanes;
        KdfHeader {
            kind: KdfKind::Argon2idV1 {
                mem_kib,
                time_cost,
                lanes,
                salt32,
            },
            info: format!(
                "TT-KDF.v7.argon2id.t{time_cost}.m{}MiB.l{lanes}",
                mem_kib / 1024
            ),
        }
    } else {
        let mut salt32 = [0u8; 32];
        OsRng.fill_bytes(&mut salt32);
        KdfHeader {
            kind: KdfKind::Kmac256V1 { salt32 },
            info: "TT-KDF.v7.kmac".into(),
        }
    };

    let wallet_id = derive_wallet_id(&secret.master32);

    let hdr = WalletHeader {
        version: WALLET_VERSION,
        kdf,
        aead: match aead_flag {
            AeadFlag::GcmSiv => AeadKind::AesGcmSiv,
            AeadFlag::XChaCha20 => AeadKind::XChaCha20,
        },
        nonce12,
        nonce24_opt,
        padding_block: pad_block,
        pepper: match pepper_flag {
            PepperFlag::None => PepperPolicy::None,
            PepperFlag::OsLocal => PepperPolicy::OsLocal,
        },
        wallet_id,
    };

    let enc = encrypt_wallet(&secret, pw1.as_str(), &hdr)?;
    let wf2 = WalletFile { header: hdr, enc };
    let bytes = bincode::options()
        .with_limit(WALLET_MAX_SIZE)
        .serialize(&wf2)?;

    atomic_replace(&path, &bytes)?;
    eprintln!("🔐 rekeyed PQ wallet (v7 hardmode) → {}", path.display());
    Ok(())
}

fn create_encrypted_wallet_from_master(
    master32: MasterSeed,
    use_argon2: bool,
    argon2_mem_mib: u32,
    argon2_time: u32,
    argon2_lanes: u32,
    aead_flag: AeadFlag,
    pepper_flag: PepperFlag,
    pad_block: u16,
) -> Result<(WalletHeader, Vec<u8>)> {
    let pw = Zeroizing::new(
        prompt_password("Set new wallet password (min 12 chars): ")?,
    );
    ensure!(pw.len() >= 12, "password too short");
    let pw2 = Zeroizing::new(prompt_password("Repeat password: ")?);
    ensure!(pw.as_str() == pw2.as_str(), "password mismatch");

    let mut nonce12 = [0u8; 12];
    OsRng.fill_bytes(&mut nonce12);
    let nonce24_opt = match aead_flag {
        AeadFlag::XChaCha20 => {
            let mut n = [0u8; 24];
            OsRng.fill_bytes(&mut n);
            Some(n)
        }
        _ => None,
    };

    let kdf = if use_argon2 {
        let mut salt32 = [0u8; 32];
        OsRng.fill_bytes(&mut salt32);
        let mem_kib = argon2_mem_mib * 1024;
        let time_cost = argon2_time;
        let lanes = argon2_lanes;
        KdfHeader {
            kind: KdfKind::Argon2idV1 {
                mem_kib,
                time_cost,
                lanes,
                salt32,
            },
            info: format!(
                "TT-KDF.v7.argon2id.t{time_cost}.m{}MiB.l{lanes}",
                mem_kib / 1024
            ),
        }
    } else {
        let mut salt32 = [0u8; 32];
        OsRng.fill_bytes(&mut salt32);
        KdfHeader {
            kind: KdfKind::Kmac256V1 { salt32 },
            info: "TT-KDF.v7.kmac".into(),
        }
    };

    let wallet_id = derive_wallet_id(&master32);

    let hdr = WalletHeader {
        version: WALLET_VERSION,
        kdf,
        aead: match aead_flag {
            AeadFlag::GcmSiv => AeadKind::AesGcmSiv,
            AeadFlag::XChaCha20 => AeadKind::XChaCha20,
        },
        nonce12,
        nonce24_opt,
        padding_block: pad_block,
        pepper: match pepper_flag {
            PepperFlag::None => PepperPolicy::None,
            PepperFlag::OsLocal => PepperPolicy::OsLocal,
        },
        wallet_id,
    };

    // Klucze są deterministyczne - tylko master32 w payload
    let payload = WalletSecretPayloadV7 { master32 };
    let enc = encrypt_wallet(&payload, pw.as_str(), &hdr)?;
    Ok((hdr, enc))
}

fn cmd_shards_create(
    file: PathBuf,
    out_dir: PathBuf,
    m: u8,
    n: u8,
    per_share_pass: bool,
) -> Result<()> {
    let wf = load_wallet_file(&file)?;
    let pw = get_password_auto("Wallet password: ")?;
    let secret = decrypt_wallet_v7(&wf.enc, pw.as_str(), &wf.header)?;

    // Klucze są deterministyczne z master32 - recovery odtworzy ten sam adres!

    let share_pw = if per_share_pass {
        Some(Zeroizing::new(prompt_password(
            "Password for all shards: ",
        )?))
    } else {
        None
    };

    let shards = shards_create(
        secret.master32.clone(),
        m,
        n,
        share_pw.as_deref().map(String::as_str),
    )?;

    fs::create_dir_all(&out_dir)?;

    for (i, sf) in shards.iter().enumerate() {
        let name = format!("shard-{}-of-{}.json", i + 1, n);
        let path = out_dir.join(name);
        let bytes = serde_json::to_vec_pretty(&sf)?;
        atomic_write(&path, &bytes)?;
        eprintln!("✅ wrote shard {} → {}", i + 1, path.display());
    }

    eprintln!(
        "🔐 created {}-of-{} Shamir shards (v7, master32) in {}",
        m,
        n,
        out_dir.display()
    );
    Ok(())
}

fn cmd_shards_recover(
    input: Vec<PathBuf>,
    out: PathBuf,
    use_argon2: bool,
    argon2_mem_mib: u32,
    argon2_time: u32,
    argon2_lanes: u32,
    aead_flag: AeadFlag,
    pepper_flag: PepperFlag,
    pad_block: u16,
) -> Result<()> {
    eprintln!("🔍 recovering master32 from {} shards (v7)...", input.len());
    let master32 = shards_recover(&input)?;

    eprintln!("✅ master32 recovered, creating new PQ wallet (same address)...");
    let (hdr, enc) = create_encrypted_wallet_from_master(
        master32,
        use_argon2,
        argon2_mem_mib,
        argon2_time,
        argon2_lanes,
        aead_flag,
        pepper_flag,
        pad_block,
    )?;

    let wf = WalletFile { header: hdr, enc };
    let bytes = bincode::options()
        .with_limit(WALLET_MAX_SIZE)
        .serialize(&wf)?;

    atomic_write(&out, &bytes)?;
    eprintln!("✅ recovered wallet (v7 hardmode) → {}", out.display());
    Ok(())
}

fn cmd_wallet_balance(path: PathBuf, rpc: String, privacy: bool, tor: Option<String>) -> Result<()> {
    let (ks, _hdr) = load_keyset(path)?;
    let addr_ttq = bech32_addr_quantum_short(&ks.falcon_pk, &ks.mlkem_pk)?;
    let raw = raw_addr_from_keys(&ks.falcon_pk, &ks.mlkem_pk);
    let addr_hex = hex::encode(raw);

    let server_addr: SocketAddr = rpc
        .parse()
        .map_err(|e| anyhow!("Invalid --rpc address '{}': {}", rpc, e))?;

    // Privacy i Tor są niezależne
    if privacy {
        println!("🔒 ProPrivacy mode: ephemeral identity (unlinkable sessions)");
    } else {
        println!("⚠️  WARNING: Privacy disabled (--no-privacy) - identity may be linked across sessions");
    }
    if tor.is_some() {
        println!("🧅 Tor mode: routing through SOCKS5 proxy (IP hidden)");
    }

    let rt = tokio::runtime::Runtime::new()?;;
    rt.block_on(async move {
        let mut client = create_rpc_client(server_addr, privacy, &tor, &ks)?;
        client.connect().await?;

        let resp = client
            .request(RpcRequest::GetBalance {
                address_hex: addr_hex.clone(),
            })
            .await?;

        match resp {
            RpcResponse::Balance {
                address_hex,
                confirmed,
                pending,
            } => {
                println!("address(ttq): {}", addr_ttq);
                println!("address_hex : {}", address_hex);
                println!("confirmed   : {}", confirmed);
                println!("pending     : {}", pending);
            }
            RpcResponse::Error { code, message, data } => {
                eprintln!("RPC error {}: {}", code, message);
                if let Some(d) = data {
                    eprintln!("  data: {}", d);
                }
            }
            other => {
                eprintln!("Unexpected RPC response: {:?}", other);
            }
        }

        client.close().await?;
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

/* =========================================================================================
 * SEND / CREDIT COMMANDS (normal transfers)
 * ====================================================================================== */

/// Create RPC client with optional privacy mode and/or Tor proxy
/// - `--privacy` = ephemeral PQ identity (unlinkable sessions)
/// - `--tor` = SOCKS5 proxy for IP hiding (works with or without --privacy)
/// - Both can be combined for maximum anonymity
#[cfg(feature = "tor_proxy")]
fn create_rpc_client(
    server_addr: SocketAddr,
    use_privacy: bool,
    tor: &Option<String>,
    ks: &Keyset,
) -> Result<SecureRpcClient> {
    let tor_addr: Option<SocketAddr> = if let Some(t) = tor {
        Some(t.parse().map_err(|e| anyhow!("Invalid --tor address '{}': {}", t, e))?)
    } else {
        None
    };

    match (use_privacy, tor_addr) {
        // ProPrivacy + Tor = maksymalna anonimowość
        (true, Some(socks5)) => {
            SecureRpcClient::new_pro_privacy_tor(server_addr, socks5)
        }
        // Tylko Tor (normalna tożsamość, ukryte IP)
        (false, Some(socks5)) => {
            let id = NodeIdentity::from_keys(
                ks.falcon_pk.clone(),
                ks.falcon_sk.clone(),
                ks.mlkem_pk.clone(),
                ks.mlkem_sk.clone(),
            );
            let mut client = SecureRpcClient::new(server_addr, id);
            client.set_proxy(socks5);
            Ok(client)
        }
        // Tylko ProPrivacy (efemeryczna tożsamość, bezpośrednie IP)
        (true, None) => {
            SecureRpcClient::new_pro_privacy(server_addr)
        }
        // Normal mode (stała tożsamość, bezpośrednie IP)
        (false, None) => {
            let id = NodeIdentity::from_keys(
                ks.falcon_pk.clone(),
                ks.falcon_sk.clone(),
                ks.mlkem_pk.clone(),
                ks.mlkem_sk.clone(),
            );
            Ok(SecureRpcClient::new(server_addr, id))
        }
    }
}

#[cfg(not(feature = "tor_proxy"))]
fn create_rpc_client(
    server_addr: SocketAddr,
    use_privacy: bool,
    tor: &Option<String>,
    ks: &Keyset,
) -> Result<SecureRpcClient> {
    if tor.is_some() {
        bail!("Tor support requires 'tor_proxy' feature. Recompile with: --features tor_proxy");
    }
    if use_privacy {
        SecureRpcClient::new_pro_privacy(server_addr)
    } else {
        let id = NodeIdentity::from_keys(
            ks.falcon_pk.clone(),
            ks.falcon_sk.clone(),
            ks.mlkem_pk.clone(),
            ks.mlkem_sk.clone(),
        );
        Ok(SecureRpcClient::new(server_addr, id))
    }
}

fn parse_recipient_address(to: &str) -> Result<[u8; 32]> {
    // Try hex first
    if let Ok(bytes) = hex::decode(to) {
        if bytes.len() == 32 {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&bytes);
            return Ok(addr);
        }
    }

    // Try bech32 ttq...
    if to.starts_with("ttq") {
        let (hrp, payload) = bech32::decode(to)
            .map_err(|e| anyhow!("invalid bech32 address: {e}"))?;
        if hrp.as_str() != BECH32_HRP_TTQ {
            bail!("invalid HRP, expected 'ttq', got '{}'", hrp);
        }
        // bech32 v0.11 decode returns 8-bit data directly
        if payload.len() < 33 || payload[0] != 0x03 {
            bail!("invalid ttq payload (len={}, prefix={:02x})", payload.len(), payload.get(0).copied().unwrap_or(0));
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&payload[1..33]);
        return Ok(addr);
    }

    bail!("invalid recipient address format (expected 32-byte hex or ttq... bech32)");
}

fn cmd_send(
    file: PathBuf,
    to: String,
    amount: u128,
    fee: u128,
    rpc: String,
    privacy: bool,
    tor: Option<String>,
) -> Result<()> {
    use crate::falcon_sigs::falcon_sign;

    // 1. Load wallet
    let (ks, _hdr) = load_keyset(file)?;
    let from = raw_addr_from_keys(&ks.falcon_pk, &ks.mlkem_pk);
    let from_ttq = bech32_addr_quantum_short(&ks.falcon_pk, &ks.mlkem_pk)?;

    // 2. Parse recipient
    let to_addr = parse_recipient_address(&to)?;

    if from == to_addr {
        bail!("cannot send to yourself");
    }

    // 3. Generate nonce (timestamp-based)
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // 4. Build message to sign: from || to || amount || fee || nonce
    let mut msg = Vec::new();
    msg.extend_from_slice(&from);
    msg.extend_from_slice(&to_addr);
    msg.extend_from_slice(&amount.to_le_bytes());
    msg.extend_from_slice(&fee.to_le_bytes());
    msg.extend_from_slice(&nonce.to_le_bytes());

    // 5. Sign with Falcon
    let signed = falcon_sign(&msg, &ks.falcon_sk)
        .map_err(|e| anyhow!("Falcon sign failed: {e}"))?;

    // Privacy i Tor są niezależne
    if privacy {
        println!("🔒 ProPrivacy mode: ephemeral identity (unlinkable sessions)");
    } else {
        println!("⚠️  WARNING: Privacy disabled (--no-privacy) - identity may be linked across sessions");
    }
    if tor.is_some() {
        println!("🧅 Tor mode: routing through SOCKS5 proxy (IP hidden)");
    }

    println!("📤 Sending {} (+ {} fee) from {} to {}...",
             amount, fee, &from_ttq[..16], &to[..16.min(to.len())]);

    // 6. Connect and send via RPC
    let server_addr: SocketAddr = rpc
        .parse()
        .map_err(|e| anyhow!("Invalid --rpc address '{}': {}", rpc, e))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let mut client = create_rpc_client(server_addr, privacy, &tor, &ks)?;
        client.connect().await?;

        let resp = client
            .request(RpcRequest::SubmitSimplePqTx {
                from_hex: hex::encode(from),
                to_hex: hex::encode(to_addr),
                amount,
                fee,
                nonce,
                falcon_pk_hex: hex::encode(ks.falcon_pk.as_bytes()),
                falcon_sig_hex: hex::encode(&signed.signed_message_bytes),
            })
            .await?;

        match resp {
            RpcResponse::SimplePqTxSubmitted {
                tx_id,
                accepted,
                new_sender_balance,
                new_recipient_balance,
            } => {
                if accepted {
                    println!("✅ Transaction accepted!");
                    println!("   tx_id: {}", tx_id);
                    println!("   your new balance: {}", new_sender_balance);
                    println!("   recipient balance: {}", new_recipient_balance);
                } else {
                    eprintln!("❌ Transaction rejected (tx_id: {})", tx_id);
                }
            }
            RpcResponse::Error { code, message, data } => {
                eprintln!("❌ RPC error {}: {}", code, message);
                if let Some(d) = data {
                    eprintln!("   data: {}", d);
                }
            }
            other => {
                eprintln!("Unexpected RPC response: {:?}", other);
            }
        }

        client.close().await?;
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

fn cmd_credit(file: PathBuf, amount: u128, rpc: String, privacy: bool, tor: Option<String>) -> Result<()> {
    // 1. Load wallet to get address
    let (ks, _hdr) = load_keyset(file)?;
    let addr = raw_addr_from_keys(&ks.falcon_pk, &ks.mlkem_pk);
    let addr_ttq = bech32_addr_quantum_short(&ks.falcon_pk, &ks.mlkem_pk)?;

    // Privacy i Tor są niezależne
    if privacy {
        println!("🔒 ProPrivacy mode: ephemeral identity (unlinkable sessions)");
    } else {
        println!("⚠️  WARNING: Privacy disabled (--no-privacy) - identity may be linked across sessions");
    }
    if tor.is_some() {
        println!("🧅 Tor mode: routing through SOCKS5 proxy (IP hidden)");
    }

    println!("💰 Requesting {} tokens for {}...", amount, addr_ttq);

    // 2. Connect and request credit
    let server_addr: SocketAddr = rpc
        .parse()
        .map_err(|e| anyhow!("Invalid --rpc address '{}': {}", rpc, e))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let mut client = create_rpc_client(server_addr, privacy, &tor, &ks)?;
        client.connect().await?;

        let resp = client
            .request(RpcRequest::Credit {
                address_hex: hex::encode(addr),
                amount,
            })
            .await?;

        match resp {
            RpcResponse::Credited {
                address_hex: _,
                new_balance,
            } => {
                println!("✅ Credited!");
                println!("   new balance: {}", new_balance);
            }
            RpcResponse::Error { code, message, data } => {
                eprintln!("❌ RPC error {}: {}", code, message);
                if let Some(d) = data {
                    eprintln!("   data: {}", d);
                }
            }
            other => {
                eprintln!("Unexpected RPC response: {:?}", other);
            }
        }

        client.close().await?;
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

/* =========================================================================================
 * STEALTH PQ COMMANDS
 * ====================================================================================== */

fn cmd_stealth_send(
    file: PathBuf,
    recipient_falcon_pk_hex: String,
    recipient_kyber_pk_hex: String,
    value: u64,
    memo: String,
    out: Option<PathBuf>,
    rpc: Option<String>,
    privacy: bool,
) -> Result<()> {
    // 1. Otwórz własny portfel (wymusi hasło, sprawdzi integralność)
    let (ks, _hdr) = load_keyset(file)?;

    // 2. Parsowanie PK odbiorcy
    let falcon_pk_bytes = hex::decode(&recipient_falcon_pk_hex)
        .map_err(|e| anyhow!("invalid falcon_pk hex: {e}"))?;
    let kyber_pk_bytes = hex::decode(&recipient_kyber_pk_hex)
        .map_err(|e| anyhow!("invalid kyber_pk hex: {e}"))?;

    let falcon_pk = falcon512::PublicKey::from_bytes(&falcon_pk_bytes)
        .map_err(|_| anyhow!("invalid Falcon-512 public key bytes"))?;
    let kyber_pk = mlkem::PublicKey::from_bytes(&kyber_pk_bytes)
        .map_err(|_| anyhow!("invalid Kyber-768 public key bytes"))?;

    let recipient_addr = StealthAddressPQ::from_pks(falcon_pk, kyber_pk);

    // 3. Losowy r_blind (chcemy go wypisać, więc generujemy ręcznie)
    let mut r_blind = [0u8; 32];
    OsRng.fill_bytes(&mut r_blind);

    // 4. Budowa stealth hint przez builder v2
    let builder = StealthHintBuilder::new(value)
        .memo(memo.clone())?   // String -> Vec<u8>, clone bo jeszcze go logujemy
        .r_blind(r_blind);

    let hint = builder.build(&recipient_addr)?;
    let hint_bytes = hint.to_bytes();

    println!("✅ Stealth hint created:");
    println!("   recipient addr_id: {}", hex::encode(recipient_addr.id()));
    println!("   value: {}", value);
    println!("   memo: \"{}\"", memo);
    println!("   r_blind: {}", hex::encode(&r_blind));

    // 5a. Opcjonalny zapis do pliku
    if let Some(ref out_path) = out {
        if out_path.exists() {
            bail!("output file already exists: {}", out_path.display());
        }
        atomic_write(out_path, &hint_bytes)?;
        println!("   saved to: {}", out_path.display());
    }

    // 5b. Opcjonalny broadcast przez RPC
    if let Some(ref rpc_addr) = rpc {
        println!();
        println!("📡 Broadcasting hint through RPC {}...", rpc_addr);

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let addr: std::net::SocketAddr = rpc_addr.parse()
                .map_err(|e| anyhow!("Invalid RPC address: {e}"))?;

            let mut client = if privacy {
                SecureRpcClient::new_pro_privacy(addr)
                    .map_err(|e| anyhow!("Failed to create ProPrivacy client: {e}"))?
            } else {
                let identity = crate::p2p::secure::NodeIdentity::from_keys(
                    ks.falcon_pk.clone(),
                    ks.falcon_sk.clone(),
                    ks.mlkem_pk.clone(),
                    ks.mlkem_sk.clone(),
                );
                SecureRpcClient::new(addr, identity)
            };
            
            client.connect().await?;

            let resp = client
                .request(RpcRequest::SubmitStealthHint {
                    hint_hex: hex::encode(&hint_bytes),
                })
                .await?;

            match resp {
                RpcResponse::StealthHintSubmitted { hint_id, broadcast_peers } => {
                    println!("   ✅ Hint broadcast successful!");
                    println!("   hint_id: {}", hint_id);
                    println!("   broadcast to {} peers", broadcast_peers);
                }
                RpcResponse::Error { code, message, .. } => {
                    bail!("RPC error {}: {}", code, message);
                }
                _ => bail!("Unexpected RPC response"),
            }

            Ok::<(), anyhow::Error>(())
        })?;
    }

    // 6. Jeśli nie podano ani --out ani --rpc, wyświetl ostrzeżenie
    if out.is_none() && rpc.is_none() {
        println!();
        println!("⚠️  Hint not saved or broadcast. Use --out or --rpc to send it.");
        println!("   Hint hex: {}", hex::encode(&hint_bytes));
    } else if out.is_some() && rpc.is_none() {
        println!();
        println!("📤 Send this hint file to the recipient via any channel.");
    }

    Ok(())
}

fn cmd_stealth_receive(file: PathBuf, hint_path: PathBuf) -> Result<()> {
    // 1. Portfel odbiorcy
    let (ks, _hdr) = load_keyset(file)?;

    // 2. Wczytaj hint
    let hint_bytes = fs::read(&hint_path)
        .map_err(|e| anyhow!("failed to read hint file '{}': {e}", hint_path.display()))?;
    let hint = StealthHint::from_bytes(&hint_bytes)?;

    println!("🔍 Attempting to decrypt stealth hint...");
    println!("   scan_tag: {}", hex::encode(&hint.scan_tag));

    // 3. Sekrety stealth z walleta (v2 wymaga też PK do addr_id)
    let secrets = StealthSecretsPQ::from_sks(
        ks.falcon_sk.clone(),
        ks.mlkem_sk.clone(),
        &ks.falcon_pk,
        &ks.mlkem_pk,
    );

    // 4. Pełne odszyfrowanie + walidacje
    match decrypt_stealth_hint(&secrets, &hint) {
        ScanResult::Match(payload) => {
            println!();
            println!("✅ Stealth hint decrypted successfully!");
            println!("   value: {}", payload.value);
            println!("   memo: \"{}\"", String::from_utf8_lossy(&payload.memo));
            println!("   r_blind: {}", hex::encode(&payload.r_blind));
            println!("   hint_id: {}", hex::encode(&payload.hint_id));
            println!("   timestamp: {}", payload.timestamp);
            println!();
            println!("💰 This payment is addressed to you.");
        }
        ScanResult::NotForUs => {
            println!();
            println!("ℹ️ Hint is not addressed to this wallet (scan_tag mismatch).");
        }
        ScanResult::ReplayDetected(reason) => {
            println!();
            println!("⚠️ Hint looks like a replay: {}", reason);
        }
        ScanResult::DecryptionFailed(reason) => {
            println!();
            println!("❌ Cannot decrypt stealth hint: {}", reason);
            println!();
            println!("   Possible reasons:");
            println!("   - This hint is not addressed to your wallet");
            println!("   - The hint file is corrupted");
        }
        ScanResult::DuplicateHint => {
            // Nie wystąpi tutaj (tylko przy scan_hints_dedup), ale obsługujemy na wszelki.
            println!();
            println!("⚠️ Hint marked as duplicate");
        }
    }

    Ok(())
}

fn cmd_stealth_scan(file: PathBuf, hints_dir: PathBuf) -> Result<()> {
    // 1. Portfel
    let (ks, _hdr) = load_keyset(file)?;

    println!("🔍 Scanning directory for stealth hints: {}", hints_dir.display());

    // 2. Sekrety stealth (v2)
    let secrets = StealthSecretsPQ::from_sks(
        ks.falcon_sk.clone(),
        ks.mlkem_sk.clone(),
        &ks.falcon_pk,
        &ks.mlkem_pk,
    );

    let mut found = 0u32;
    let mut scanned = 0u32;
    let mut total_value = 0u64;
    let mut seen_hint_ids: HashSet<[u8; 32]> = HashSet::new();

    for entry in fs::read_dir(&hints_dir)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let hint_bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let hint = match StealthHint::from_bytes(&hint_bytes) {
            Ok(h) => h,
            Err(_) => continue, // nieprawidłowy plik
        };

        scanned += 1;

        match decrypt_stealth_hint(&secrets, &hint) {
            ScanResult::Match(payload) => {
                // dedup po hint_id
                if !seen_hint_ids.insert(payload.hint_id) {
                    // duplikat – ignorujemy
                    continue;
                }

                found += 1;
                total_value += payload.value;

                println!();
                println!("  ✅ Found: {}", path.display());
                println!("     value: {}", payload.value);
                println!("     memo: \"{}\"", String::from_utf8_lossy(&payload.memo));
            }
            _ => {}
        }
    }

    println!();
    println!("📊 Scan complete:");
    println!("   files scanned: {}", scanned);
    println!("   hints for you: {}", found);
    println!("   total value: {}", total_value);

    Ok(())
}

fn cmd_stealth_scan_rpc(file: PathBuf, rpc_addr: String, privacy: bool, limit: usize) -> Result<()> {
    // 1. Portfel
    let (ks, _hdr) = load_keyset(file)?;

    println!("🔍 Fetching stealth hints from RPC {}...", rpc_addr);

    // 2. Sekrety stealth (v2)
    let secrets = StealthSecretsPQ::from_sks(
        ks.falcon_sk.clone(),
        ks.mlkem_sk.clone(),
        &ks.falcon_pk,
        &ks.mlkem_pk,
    );

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let addr: std::net::SocketAddr = rpc_addr.parse()
            .map_err(|e| anyhow!("Invalid RPC address: {e}"))?;

        let mut client = if privacy {
            SecureRpcClient::new_pro_privacy(addr)
                .map_err(|e| anyhow!("Failed to create ProPrivacy client: {e}"))?
        } else {
            let identity = crate::p2p::secure::NodeIdentity::from_keys(
                ks.falcon_pk.clone(),
                ks.falcon_sk.clone(),
                ks.mlkem_pk.clone(),
                ks.mlkem_sk.clone(),
            );
            SecureRpcClient::new(addr, identity)
        };

        client.connect().await?;

        let resp = client
            .request(RpcRequest::GetStealthHints {
                limit: Some(limit),
                offset: None,
            })
            .await?;

        let hints_hex = match resp {
            RpcResponse::StealthHints { hints, total_count } => {
                println!("   📥 Fetched {} hints (total on server: {})", hints.len(), total_count);
                hints
            }
            RpcResponse::Error { code, message, .. } => {
                bail!("RPC error {}: {}", code, message);
            }
            _ => bail!("Unexpected RPC response"),
        };

        let mut found = 0u32;
        let mut total_value = 0u64;
        let mut seen_hint_ids: HashSet<[u8; 32]> = HashSet::new();

        for (idx, hint_hex) in hints_hex.iter().enumerate() {
            let hint_bytes = match hex::decode(hint_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let hint = match StealthHint::from_bytes(&hint_bytes) {
                Ok(h) => h,
                Err(_) => continue,
            };

            match decrypt_stealth_hint(&secrets, &hint) {
                ScanResult::Match(payload) => {
                    if !seen_hint_ids.insert(payload.hint_id) {
                        continue; // duplikat
                    }

                    found += 1;
                    total_value += payload.value;

                    println!();
                    println!("  ✅ Found hint #{}", idx);
                    println!("     value: {}", payload.value);
                    println!("     memo: \"{}\"", String::from_utf8_lossy(&payload.memo));
                    println!("     hint_id: {}", hex::encode(&payload.hint_id[..16]));
                }
                _ => {}
            }
        }

        println!();
        println!("📊 Scan complete:");
        println!("   hints fetched: {}", hints_hex.len());
        println!("   hints for you: {}", found);
        println!("   total value: {}", total_value);

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

/* =========================================================================================
 * STARK TRANSACTION COMMANDS
 * ====================================================================================== */

fn cmd_stark_send(
    file: PathBuf,
    recipient_falcon_pk_hex: String,
    recipient_kyber_pk_hex: String,
    amount: u64,
    memo: String,
    rpc: String,
    privacy: bool,
    tor: Option<String>,
) -> Result<()> {
    // 1. Load sender wallet
    let (ks, _hdr) = load_keyset(file)?;
    let from_addr = raw_addr_from_keys(&ks.falcon_pk, &ks.mlkem_pk);
    let from_ttq = bech32_addr_quantum_short(&ks.falcon_pk, &ks.mlkem_pk)?;

    // 2. Parse recipient keys
    let falcon_pk_bytes = hex::decode(&recipient_falcon_pk_hex)
        .map_err(|e| anyhow!("invalid falcon_pk hex: {e}"))?;
    let kyber_pk_bytes = hex::decode(&recipient_kyber_pk_hex)
        .map_err(|e| anyhow!("invalid kyber_pk hex: {e}"))?;

    let recipient_falcon_pk = falcon512::PublicKey::from_bytes(&falcon_pk_bytes)
        .map_err(|_| anyhow!("invalid Falcon-512 public key bytes"))?;
    let recipient_kyber_pk = mlkem::PublicKey::from_bytes(&kyber_pk_bytes)
        .map_err(|_| anyhow!("invalid Kyber-768 public key bytes"))?;

    // 3. Derive recipient address and stealth address
    let recipient_addr = raw_addr_from_keys(&recipient_falcon_pk, &recipient_kyber_pk);
    let recipient_stealth = StealthAddressPQ::from_pks(
        recipient_falcon_pk.clone(),
        recipient_kyber_pk.clone(),
    );

    // 4. Generate random blinding factor
    let mut blinding = [0u8; 32];
    OsRng.fill_bytes(&mut blinding);

    println!("🔐 Creating STARK transaction with full privacy...");
    println!("   from: {}", &from_ttq[..20]);
    println!("   amount: {} (hidden in STARK proof)", amount);
    println!("   memo: \"{}\"", memo);

    // 5. Create TxOutputStark with STARK proof + stealth hint
    // Uses recipient's Kyber key for encryption so only they can decrypt
    let output = TxOutputStark::new_with_stealth(
        amount,
        &blinding,
        recipient_addr,
        &recipient_kyber_pk,  // recipient's key for encrypted value
        &recipient_stealth,   // recipient's stealth address for hint
        &memo,
    );

    // Verify the STARK proof locally before sending
    if !output.verify() {
        bail!("STARK proof verification failed locally!");
    }
    println!("   ✅ STARK range proof verified locally");
    println!("   ✅ Stealth hint embedded (recipient can scan)");

    // 6. Build transaction
    let tx = TransactionStark {
        inputs: vec![], // For now, no inputs (coinbase-like)
        outputs: vec![output],
        fee: 0,
        nonce: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        timestamp: now_ts(),
    };

    let tx_id = tx.id();
    let tx_bytes = bincode::serialize(&tx)?;

    println!("   tx_id: {}", hex::encode(&tx_id[..16]));
    println!("   tx_size: {} bytes", tx_bytes.len());

    // Privacy mode info
    if privacy {
        println!("🔒 ProPrivacy mode: ephemeral identity");
    } else {
        println!("⚠️  WARNING: Privacy disabled (--no-privacy) - identity may be linked across sessions");
    }
    if tor.is_some() {
        println!("🧅 Tor mode: IP hidden");
    }

    // 7. Submit via RPC
    let server_addr: SocketAddr = rpc
        .parse()
        .map_err(|e| anyhow!("Invalid --rpc address '{}': {}", rpc, e))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let mut client = create_rpc_client(server_addr, privacy, &tor, &ks)?;
        client.connect().await?;

        let resp = client
            .request(RpcRequest::SubmitStarkTx {
                tx_hex: hex::encode(&tx_bytes),
            })
            .await?;

        match resp {
            RpcResponse::StarkTxSubmitted { tx_id, accepted, message } => {
                if accepted {
                    println!();
                    println!("✅ STARK transaction accepted!");
                    println!("   tx_id: {}", tx_id);
                    if let Some(msg) = message {
                        println!("   message: {}", msg);
                    }
                } else {
                    eprintln!("❌ Transaction rejected: {:?}", message);
                }
            }
            RpcResponse::Error { code, message, data } => {
                eprintln!("❌ RPC error {}: {}", code, message);
                if let Some(d) = data {
                    eprintln!("   data: {}", d);
                }
            }
            other => {
                eprintln!("Unexpected RPC response: {:?}", other);
            }
        }

        client.close().await?;
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

/// Receive STARK transactions.
/// 
/// NOTE: Pool is now properly typed with StarkTxPoolEntry enum:
/// - GetStarkTxs returns only Public transactions (TransactionStark)
/// - GetPrivateStarkTxs returns only Private transactions (PrivateStarkTx)
fn cmd_stark_receive(
    file: PathBuf,
    rpc: String,
    privacy: bool,
) -> Result<()> {
    // 1. Load wallet
    let (ks, _hdr) = load_keyset(file)?;
    let my_addr = raw_addr_from_keys(&ks.falcon_pk, &ks.mlkem_pk);
    let my_ttq = bech32_addr_quantum_short(&ks.falcon_pk, &ks.mlkem_pk)?;

    println!("🔍 Scanning for STARK transactions addressed to you...");
    println!("   wallet: {}", &my_ttq[..20]);

    // 2. Build stealth secrets for scanning
    let secrets = StealthSecretsPQ::from_sks(
        ks.falcon_sk.clone(),
        ks.mlkem_sk.clone(),
        &ks.falcon_pk,
        &ks.mlkem_pk,
    );

    let server_addr: SocketAddr = rpc
        .parse()
        .map_err(|e| anyhow!("Invalid --rpc address '{}': {}", rpc, e))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let mut client = if privacy {
            SecureRpcClient::new_pro_privacy(server_addr)
                .map_err(|e| anyhow!("Failed to create ProPrivacy client: {e}"))?
        } else {
            let identity = NodeIdentity::from_keys(
                ks.falcon_pk.clone(),
                ks.falcon_sk.clone(),
                ks.mlkem_pk.clone(),
                ks.mlkem_sk.clone(),
            );
            SecureRpcClient::new(server_addr, identity)
        };

        client.connect().await?;

        // Request STARK transactions for our address
        let resp = client
            .request(RpcRequest::GetStarkTxs {
                address_hex: Some(hex::encode(my_addr)),
                limit: Some(50),
            })
            .await?;

        let txs_hex = match resp {
            RpcResponse::StarkTxs { txs, total_count } => {
                println!("   📥 Fetched {} transactions (total: {})", txs.len(), total_count);
                txs
            }
            RpcResponse::Error { code, message, .. } => {
                bail!("RPC error {}: {}", code, message);
            }
            _ => bail!("Unexpected RPC response"),
        };

        let mut found = 0u32;
        let mut total_value = 0u64;

        for (idx, tx_hex) in txs_hex.iter().enumerate() {
            let tx_bytes = match hex::decode(tx_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let tx: TransactionStark = match bincode::deserialize(&tx_bytes) {
                Ok(t) => t,
                Err(_) => continue,
            };

            // Check each output
            for (out_idx, output) in tx.outputs.iter().enumerate() {
                // First try to decrypt the value
                if let Some((value, _blinding)) = output.decrypt_value(&ks.mlkem_sk) {
                    // Verify STARK proof
                    if !output.verify() {
                        println!("  ⚠️ TX #{} output #{}: STARK proof invalid!", idx, out_idx);
                        continue;
                    }

                    found += 1;
                    total_value += value;

                    println!();
                    println!("  ✅ Found TX #{} output #{}", idx, out_idx);
                    println!("     value: {}", value);
                    println!("     tx_id: {}", hex::encode(&tx.id()[..16]));

                    // Check for stealth hint
                    if let Some(ref stealth_data) = output.stealth_hint {
                        let hint = stealth_data.to_hint();
                        if let ScanResult::Match(payload) = decrypt_stealth_hint(&secrets, &hint) {
                            println!("     memo: \"{}\"", String::from_utf8_lossy(&payload.memo));
                        }
                    }
                }
            }
        }

        println!();
        println!("📊 Scan complete:");
        println!("   transactions scanned: {}", txs_hex.len());
        println!("   outputs for you: {}", found);
        println!("   total value: {}", total_value);

        client.close().await?;
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

fn cmd_stark_scan_blocks(
    file: PathBuf,
    rpc: String,
    from_height: u64,
    privacy: bool,
) -> Result<()> {
    // 1. Load wallet
    let (ks, _hdr) = load_keyset(file)?;
    let my_ttq = bech32_addr_quantum_short(&ks.falcon_pk, &ks.mlkem_pk)?;

    println!("🔍 Scanning blockchain for stealth hints (Monero-style)...");
    println!("   wallet: {}", &my_ttq[..20]);
    println!("   starting from block: {}", from_height);

    // 2. Build stealth secrets for scanning
    let secrets = StealthSecretsPQ::from_sks(
        ks.falcon_sk.clone(),
        ks.mlkem_sk.clone(),
        &ks.falcon_pk,
        &ks.mlkem_pk,
    );

    let server_addr: SocketAddr = rpc
        .parse()
        .map_err(|e| anyhow!("Invalid --rpc address '{}': {}", rpc, e))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let mut client = if privacy {
            SecureRpcClient::new_pro_privacy(server_addr)
                .map_err(|e| anyhow!("Failed to create ProPrivacy client: {e}"))?
        } else {
            let identity = NodeIdentity::from_keys(
                ks.falcon_pk.clone(),
                ks.falcon_sk.clone(),
                ks.mlkem_pk.clone(),
                ks.mlkem_sk.clone(),
            );
            SecureRpcClient::new(server_addr, identity)
        };

        client.connect().await?;

        // Request blocks with stealth hints (Monero-style)
        let resp = client
            .request(RpcRequest::GetBlocksWithHints {
                from_height,
                limit: Some(100),
            })
            .await?;

        let (blocks_hex, chain_height) = match resp {
            RpcResponse::BlocksWithHints { blocks, latest_height, chain_height } => {
                println!("   📦 Fetched {} blocks (chain height: {})", blocks.len(), chain_height);
                println!("   scanning blocks {} to {}", from_height, latest_height);
                (blocks, chain_height)
            }
            RpcResponse::Error { code, message, .. } => {
                bail!("RPC error {}: {}", code, message);
            }
            _ => bail!("Unexpected RPC response"),
        };

        let mut found = 0u32;
        let mut total_value = 0u64;
        let mut blocks_scanned = 0u32;

        for block_hex in blocks_hex.iter() {
            let block_bytes = match hex::decode(block_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let block: BlockV2 = match BlockV2::from_bytes(&block_bytes) {
                Ok(b) => b,
                Err(_) => continue,
            };

            blocks_scanned += 1;

            // Collect stealth hints from this block (Monero-style)
            let hints = block.collect_stealth_hints();
            
            for hint_data in hints {
                let hint = hint_data.to_hint();
                
                match decrypt_stealth_hint(&secrets, &hint) {
                    ScanResult::Match(payload) => {
                        found += 1;
                        total_value += payload.value;

                        println!();
                        println!("  ✅ Found payment in block #{}", block.header.height);
                        println!("     value: {}", payload.value);
                        println!("     memo: \"{}\"", String::from_utf8_lossy(&payload.memo));
                        println!("     hint_id: {}", hex::encode(&payload.hint_id[..8]));
                    }
                    _ => {} // Not for us
                }
            }

            // Also check transaction outputs directly
            for tx in &block.stark_transactions {
                for output in &tx.outputs {
                    // Try to decrypt with our Kyber key
                    if let Some((value, _)) = output.decrypt_value(&ks.mlkem_sk) {
                        if output.verify() {
                            // Only count if not already found via stealth hint
                            if output.stealth_hint.is_none() {
                                found += 1;
                                total_value += value;
                                println!();
                                println!("  ✅ Found direct output in block #{}", block.header.height);
                                println!("     value: {}", value);
                            }
                        }
                    }
                }
            }
        }

        println!();
        println!("📊 Blockchain scan complete:");
        println!("   blocks scanned: {}", blocks_scanned);
        println!("   chain height: {}", chain_height);
        println!("   payments found: {}", found);
        println!("   total value: {}", total_value);
        println!();
        println!("💡 Tip: Run again with --from-height {} to continue syncing", from_height + blocks_scanned as u64);

        client.close().await?;
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

/* =========================================================================================
 * PRIVATE STARK V2 COMMANDS (full privacy: stealth + encrypted sender + STARK amounts)
 * ====================================================================================== */

fn cmd_private_stark_send(
    file: PathBuf,
    recipient_kyber_pk_hex: String,
    amount: u64,
    fee: u64,
    rpc: String,
    privacy: bool,
    tor: Option<String>,
) -> Result<()> {
    // 1. Load sender wallet
    let (ks, _hdr) = load_keyset(file)?;
    let from_ttq = bech32_addr_quantum_short(&ks.falcon_pk, &ks.mlkem_pk)?;

    // 2. Parse recipient Kyber key
    let kyber_pk_bytes = hex::decode(&recipient_kyber_pk_hex)
        .map_err(|e| anyhow!("invalid kyber_pk hex: {e}"))?;
    let recipient_kyber_pk = mlkem::PublicKey::from_bytes(&kyber_pk_bytes)
        .map_err(|_| anyhow!("invalid Kyber-768 public key bytes"))?;

    // 3. Derive recipient address (from Kyber key only - we don't need Falcon for privacy TX)
    // NOTE: For STARK verification, we use first 8 bytes as recipient address binding
    let mut recipient_addr = [0u8; 32];
    {
        use sha3::{Sha3_256, Digest};
        let hash = Sha3_256::digest(&kyber_pk_bytes);
        recipient_addr.copy_from_slice(&hash);
    }

    // 4. Get sender's master_key_id (from wallet_id)
    let sender_master_key_id = {
        let full = ck::kmac256_derive_key(
            ks.falcon_pk.as_bytes(),
            b"TT.v7.MASTER_KEY_ID",
            b"",
        );
        full
    };

    // 5. Generate change nonce
    let change_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    println!("🔐 Creating Private STARK transaction (V2 - full privacy)...");
    println!("   from: {}", &from_ttq[..20]);
    println!("   amount: {} (hidden in STARK proof)", amount);
    println!("   fee: {} (plaintext)", fee);

    // 6. Create PrivateStarkTx
    let tx = PrivateStarkTx::create(
        &ks.falcon_sk,
        &ks.mlkem_sk,
        sender_master_key_id,
        &recipient_kyber_pk,
        &recipient_addr,
        amount,
        fee,
        change_nonce,
    ).map_err(|e| anyhow!("Failed to create PrivateStarkTx: {e}"))?;

    // 7. Verify STARK proof locally
    if !tx.verify_range_proof(&recipient_addr) {
        bail!("STARK proof verification failed locally!");
    }
    println!("   ✅ STARK range proof verified locally");
    println!("   ✅ Sender stealth output (48B)");
    println!("   ✅ Encrypted sender_id (60B)");
    println!("   ✅ Recipient stealth output (1128B)");

    let tx_id = tx.tx_id();
    
    // Use zstd compression for smaller hex output
    let compressed_hex = tx.to_compressed_hex()?;
    let uncompressed_size = bincode::serialize(&tx)?.len();
    let compressed_size = compressed_hex.len() / 2;

    println!("   tx_id: {}", hex::encode(&tx_id[..16]));
    println!("   tx_size: {} bytes (uncompressed)", uncompressed_size);
    println!("   compressed: {} bytes ({:.0}% reduction)", compressed_size,
             100.0 * (1.0 - compressed_size as f64 / uncompressed_size as f64));

    // Privacy mode info
    if privacy {
        println!("🔒 ProPrivacy mode: ephemeral identity");
    } else {
        println!("⚠️  WARNING: Privacy disabled (--no-privacy) - identity may be linked across sessions");
    }
    if tor.is_some() {
        println!("🧅 Tor mode: IP hidden");
    }

    // 8. Submit via RPC (use SubmitPrivateStarkTx)
    let server_addr: SocketAddr = rpc
        .parse()
        .map_err(|e| anyhow!("Invalid --rpc address '{}': {}", rpc, e))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let mut client = create_rpc_client(server_addr, privacy, &tor, &ks)?;
        client.connect().await?;

        let resp = client
            .request(RpcRequest::SubmitPrivateStarkTx {
                tx_hex: compressed_hex.clone(),
            })
            .await?;

        match resp {
            RpcResponse::PrivateStarkTxSubmitted { tx_id, accepted, message } => {
                if accepted {
                    println!();
                    println!("✅ Private STARK transaction accepted!");
                    println!("   tx_id: {}", tx_id);
                    if let Some(msg) = message {
                        println!("   message: {}", msg);
                    }
                    println!();
                    println!("📤 Compressed TX hex for recipient (out-of-band):");
                    println!("{}", &compressed_hex);
                } else {
                    eprintln!("❌ Transaction rejected: {:?}", message);
                }
            }
            // Fallback for older nodes without PrivateStarkTx support
            RpcResponse::StarkTxSubmitted { tx_id, accepted, message } => {
                if accepted {
                    println!();
                    println!("✅ Transaction accepted (legacy response)!");
                    println!("   tx_id: {}", tx_id);
                    if let Some(msg) = message {
                        println!("   message: {}", msg);
                    }
                    println!();
                    println!("📤 Compressed TX hex for recipient (out-of-band):");
                    println!("{}", &compressed_hex);
                } else {
                    eprintln!("❌ Transaction rejected: {:?}", message);
                }
            }
            RpcResponse::Error { code, message, data } => {
                eprintln!("❌ RPC error {}: {}", code, message);
                if let Some(d) = data {
                    eprintln!("   data: {}", d);
                }
            }
            other => {
                eprintln!("Unexpected RPC response: {:?}", other);
            }
        }

        client.close().await?;
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

fn cmd_private_stark_receive(
    file: PathBuf,
    tx_hex: String,
) -> Result<()> {
    // 1. Load recipient wallet
    let (ks, _hdr) = load_keyset(file)?;
    let my_ttq = bech32_addr_quantum_short(&ks.falcon_pk, &ks.mlkem_pk)?;

    // 2. Derive our address (same method as sender)
    let my_addr = {
        use sha3::{Sha3_256, Digest};
        let kyber_pk_bytes = ks.mlkem_pk.as_bytes();
        let hash = Sha3_256::digest(kyber_pk_bytes);
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&hash);
        addr
    };

    // 3. Parse TX (supports both compressed PSTX and legacy bincode)
    let tx: PrivateStarkTx = if tx_hex.starts_with("50535458") {
        // PSTX magic header (hex: "PSTX") - compressed format
        PrivateStarkTx::from_compressed_hex(&tx_hex)
            .map_err(|e| anyhow!("invalid compressed PrivateStarkTx: {e}"))?
    } else {
        // Legacy bincode format
        let tx_bytes = hex::decode(&tx_hex)
            .map_err(|e| anyhow!("invalid tx_hex: {e}"))?;
        bincode::deserialize(&tx_bytes)
            .map_err(|e| anyhow!("invalid PrivateStarkTx: {e}"))?
    };

    println!("🔍 Scanning Private STARK transaction...");
    println!("   wallet: {}", &my_ttq[..20]);
    println!("   tx_id: {}", hex::encode(&tx.tx_id()[..16]));

    // 4. Get our master_key_id (for sender identification)
    let my_master_key_id = {
        let full = ck::kmac256_derive_key(
            ks.falcon_pk.as_bytes(),
            b"TT.v7.MASTER_KEY_ID",
            b"",
        );
        full
    };

    // 5. Create ViewKey and scan (now requires kyber_pk for fingerprint verification)
    let view_key = PrivateViewKey::from_secrets(&ks.mlkem_sk, &ks.mlkem_pk, my_master_key_id);
    
    println!("   our_fingerprint: {}", hex::encode(view_key.our_fingerprint()));

    match view_key.scan_as_recipient(&tx, &my_addr) {
        Some(result) => {
            println!();
            println!("✅ Transaction is for you!");
            println!("   amount: {} (STARK verified: {})", result.amount, result.stark_verified);
            println!("   stealth_key: {}", hex::encode(&result.stealth_key[..8]));
            println!("   sender_master_key_id: {}", hex::encode(&result.sender_master_key_id[..8]));
            println!();
            println!("🔒 Privacy achieved:");
            println!("   ├─ Sender: HIDDEN (only you know sender_master_key_id)");
            println!("   ├─ Recipient: HIDDEN (stealth address)");
            println!("   └─ Amount: HIDDEN (STARK range proof verified)");
        }
        None => {
            println!();
            println!("❌ Transaction is NOT for you (or data corrupted)");
            println!("   Possible reasons:");
            println!("   - TX was sent to different Kyber key");
            println!("   - TX data was modified in transit");
            println!("   - STARK proof is invalid");
        }
    }

    // Also check if we're the sender (change output)
    if let Some(_fee) = view_key.scan_as_sender(&tx) {
        println!();
        println!("💡 You are the SENDER of this transaction");
        println!("   (change output detected)");
    }

    Ok(())
}

/* =========================================================================================
 * MAIN
 * ====================================================================================== */

pub fn run_cli() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::WalletInit {
            file,
            argon2,
            argon2_mem_mib,
            argon2_time,
            argon2_lanes,
            aead,
            pepper,
            pad_block,
        } => cmd_wallet_init(file, argon2, argon2_mem_mib, argon2_time, argon2_lanes, aead, pepper, pad_block),

        Cmd::WalletAddr { file } => cmd_wallet_addr(file),

        Cmd::WalletExport { file, secret, out } => {
            cmd_wallet_export(file, secret, out)
        }

        Cmd::WalletRekey {
            file,
            argon2,
            argon2_mem_mib,
            argon2_time,
            argon2_lanes,
            aead,
            pepper,
            pad_block,
        } => cmd_wallet_rekey(file, argon2, argon2_mem_mib, argon2_time, argon2_lanes, aead, pepper, pad_block),

        Cmd::ShardsCreate {
            file,
            out_dir,
            m,
            n,
            per_share_pass,
        } => cmd_shards_create(file, out_dir, m, n, per_share_pass),

        Cmd::ShardsRecover {
            input,
            out,
            argon2,
            argon2_mem_mib,
            argon2_time,
            argon2_lanes,
            aead,
            pepper,
            pad_block,
        } => cmd_shards_recover(input, out, argon2, argon2_mem_mib, argon2_time, argon2_lanes, aead, pepper, pad_block),

        Cmd::WalletBalance { file, rpc, no_privacy, tor } => cmd_wallet_balance(file, rpc, !no_privacy, tor),

        // === TRANSFER COMMANDS ===
        Cmd::Send {
            file,
            to,
            amount,
            fee,
            rpc,
            no_privacy,
            tor,
        } => cmd_send(file, to, amount, fee, rpc, !no_privacy, tor),

        Cmd::Credit { file, amount, rpc, no_privacy, tor } => cmd_credit(file, amount, rpc, !no_privacy, tor),

        // === STEALTH COMMANDS ===
        Cmd::StealthSend {
            file,
            recipient_falcon_pk,
            recipient_kyber_pk,
            value,
            memo,
            out,
            rpc,
            no_privacy,
        } => cmd_stealth_send(file, recipient_falcon_pk, recipient_kyber_pk, value, memo, out, rpc, !no_privacy),

        Cmd::StealthReceive { file, hint } => cmd_stealth_receive(file, hint),

        Cmd::StealthScan { file, hints_dir } => cmd_stealth_scan(file, hints_dir),

        Cmd::StealthScanRpc { file, rpc, no_privacy, limit } => cmd_stealth_scan_rpc(file, rpc, !no_privacy, limit),

        // === STARK COMMANDS (full privacy: hidden value + stealth recipient) ===
        Cmd::StarkSend {
            file,
            recipient_falcon_pk,
            recipient_kyber_pk,
            amount,
            memo,
            rpc,
            no_privacy,
            tor,
        } => cmd_stark_send(file, recipient_falcon_pk, recipient_kyber_pk, amount, memo, rpc, !no_privacy, tor),

        Cmd::StarkReceive { file, rpc, no_privacy } => cmd_stark_receive(file, rpc, !no_privacy),

        Cmd::StarkScanBlocks { file, rpc, from_height, no_privacy } => 
            cmd_stark_scan_blocks(file, rpc, from_height, !no_privacy),

        // === PRIVATE STARK V2 COMMANDS (full privacy: stealth + encrypted sender + STARK amounts) ===
        Cmd::PrivateStarkSend {
            file,
            recipient_kyber_pk,
            amount,
            fee,
            rpc,
            no_privacy,
            tor,
        } => cmd_private_stark_send(file, recipient_kyber_pk, amount, fee, rpc, !no_privacy, tor),

        Cmd::PrivateStarkReceive { file, tx_hex } => cmd_private_stark_receive(file, tx_hex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        let data = b"hello world".to_vec();
        let padded = pad(data.clone(), 256);
        assert!(padded.len() >= data.len() + 8);
        assert_eq!(padded.len() % 256, 0);
        let unpadded = unpad(padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_shard_mask_roundtrip() {
        let share = b"secret share data";
        let pw = "password123";
        let salt = [0x42u8; 32];
        let masked = shard_mask(share, pw, &salt);
        let unmasked = shard_mask(&masked, pw, &salt);
        assert_eq!(unmasked, share);
    }
}
