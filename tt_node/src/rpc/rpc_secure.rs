#![forbid(unsafe_code)]

//! Secure PQ RPC using PRO P2P (Falcon + Kyber + XChaCha20-Poly1305)
//!
//! Security features:
//! - Handshake: SignedChallenge → ClientHello(Falcon+Kyber+PoW) → ServerHello → ClientFinished
//! - PoW: SHA3-256 with nonce replay protection
//! - Channel: XChaCha20-Poly1305 with session-bound AAD (derived from PQ session keys)
//! - Rate limiting + connection limits per IP
//!
//! Privacy modes:
//! - Normal: pseudonymous client labels (linkable across sessions)
//! - ProPrivacy: ephemeral PQ identity per connection (unlinkable)
//!
//! NOTE: ProPrivacy mode generates ephemeral PQ identity per connection,
//! but client IP is still visible to server. Use Tor/I2P for full anonymity.

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};

use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::PublicKey as _;

use crate::node_core::{NodeCore, SimplePqTx};
use crate::node_id::NodeId;
use crate::p2p::secure::{
    build_client_finished, build_client_hello, handle_client_hello, handle_server_hello,
    verify_client_finished, ClientFinished, ClientHello, NodeIdentity, ServerHello,
    TranscriptHasher, PROTOCOL_VERSION,
};
use crate::p2p::channel::SecureChannel;
use crate::p2p::P2PNetwork;
use crate::tx_stark::{SignedStarkTx, TransactionStark};
use crate::falcon_sigs::{falcon_sign, falcon_verify, falcon_pk_from_bytes, SignedNullifier};
use crate::private_stark_tx::PrivateStarkTx;

/* ============================================================================ */
/* STARK TX Pool Entry (public vs private)                                      */
/* ============================================================================ */

/// Unified STARK transaction pool entry.
/// Separates public (TransactionStark) from private (PrivateStarkTx) transactions.
#[derive(Clone, Serialize, Deserialize)]
pub enum StarkTxPoolEntry {
    /// Public STARK TX - visible amounts, stealth recipient
    Public(TransactionStark),
    /// Private STARK TX - hidden amounts + stealth recipient + encrypted sender
    Private(PrivateStarkTx),
}

impl StarkTxPoolEntry {
    /// Check if this entry matches a recipient address (for filtering)
    pub fn matches_recipient(&self, addr: &[u8; 32]) -> bool {
        match self {
            StarkTxPoolEntry::Public(tx) => {
                tx.outputs.iter().any(|o| o.recipient == *addr)
            }
            StarkTxPoolEntry::Private(tx) => {
                // PrivateStarkTx has stealth recipient - caller must scan
                // For now, return true (let client-side scanning handle it)
                // In practice, we'd check stealth hint
                true
            }
        }
    }

    /// Get transaction timestamp
    pub fn timestamp(&self) -> u64 {
        match self {
            StarkTxPoolEntry::Public(tx) => tx.timestamp,
            StarkTxPoolEntry::Private(_tx) => {
                // PrivateStarkTx doesn't have explicit timestamp (privacy)
                // Return current time or 0 (caller should handle this case)
                0
            }
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("StarkTxPoolEntry deserialize: {e}"))
    }
}

/* ============================================================================ */
/* Security constants                                                           */
/* ============================================================================ */

/// Maximum RPC message size (1 MB — sufficient for RPC, prevents DoS)
const MAX_MESSAGE_SIZE: usize = 1 * 1024 * 1024;

/// Session timeout (30 minutes)
const SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Maximum connections per IP
const MAX_CONNECTIONS_PER_IP: usize = 10;

/// Rate limit: requests per second
const MAX_REQUESTS_PER_SECOND: u32 = 100;

/// PoW difficulty (leading zero bits required)
const POW_DIFFICULTY: u32 = 20;

/// PoW timestamp validity window (seconds)
const POW_TIMESTAMP_WINDOW: u64 = 300;

/// PoW nonce cache cleanup interval
const POW_CACHE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Key rotation interval (24 hours)
const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Minimum interval between renegotiations
const MIN_RENEGOTIATION_INTERVAL: Duration = Duration::from_secs(60);

/// ProPrivacy: hard session lifetime (5 minutes)
const PRO_PRIVACY_SESSION_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// ProPrivacy: max requests per session
const PRO_PRIVACY_MAX_REQUESTS: u64 = 100;

/* ============================================================================ */
/* Privacy mode                                                                 */
/* ============================================================================ */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyMode {
    /// Pseudonymous: client label derived from NodeId (linkable across sessions)
    Normal,
    /// Ephemeral identity per connection (unlinkable, but IP still visible)
    ProPrivacy,
}

/* ============================================================================ */
/* PoW with replay protection                                                   */
/* ============================================================================ */

/// Signed PoW challenge from server (prevents MITM challenge substitution)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedChallenge {
    pub challenge: [u8; 32],
    pub server_falcon_pk: Vec<u8>,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl SignedChallenge {
    /// Create and sign a new challenge
    pub fn new(falcon_pk: &falcon512::PublicKey, falcon_sk: &falcon512::SecretKey) -> Self {
        use rand::RngCore;

        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Sign: challenge || timestamp
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(&challenge);
        msg.extend_from_slice(&timestamp.to_le_bytes());

        let sig = falcon_sign(&msg, falcon_sk)
            .expect("Falcon sign failed in SignedChallenge::new");
        let signature = sig.signed_message_bytes.clone();

        Self {
            challenge,
            server_falcon_pk: falcon_pk.as_bytes().to_vec(),
            timestamp,
            signature,
        }
    }

    /// Verify challenge signature
    pub fn verify(&self) -> Result<falcon512::PublicKey> {
        let falcon_pk = falcon512::PublicKey::from_bytes(&self.server_falcon_pk)
            .map_err(|_| anyhow!("invalid server Falcon PK"))?;

        // Check timestamp freshness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if (now as i64 - self.timestamp as i64).abs() > POW_TIMESTAMP_WINDOW as i64 {
            bail!("challenge timestamp expired");
        }

        // Verify signature
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(&self.challenge);
        msg.extend_from_slice(&self.timestamp.to_le_bytes());

        let signed = crate::falcon_sigs::SignedNullifier { signed_message_bytes: self.signature.clone() };
        if falcon_verify(&msg, &signed, &falcon_pk).is_err() {
            bail!("invalid challenge signature");
        }

        Ok(falcon_pk)
    }
}

/// Client's proof of work solution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfWork {
    pub challenge: [u8; 32],
    pub nonce: u64,
    pub timestamp: u64,
}

impl ProofOfWork {
    /// Verify PoW (leading zero bits >= difficulty)
    pub fn verify(&self, difficulty: u32) -> bool {
        use sha3::{Digest, Sha3_256};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if (now as i64 - self.timestamp as i64).abs() > POW_TIMESTAMP_WINDOW as i64 {
            return false;
        }

        let mut hasher = Sha3_256::new();
        hasher.update(&self.challenge);
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        let hash = hasher.finalize();

        let mut leading_bits: u32 = 0;
        for &byte in hash.iter() {
            if byte == 0 {
                leading_bits += 8;
            } else {
                leading_bits += byte.leading_zeros();
                break;
            }
        }

        leading_bits >= difficulty
    }

    /// Unique key for replay detection
    pub fn cache_key(&self) -> [u8; 40] {
        let mut key = [0u8; 40];
        key[..32].copy_from_slice(&self.challenge);
        key[32..].copy_from_slice(&self.nonce.to_le_bytes());
        key
    }
}

/// PoW nonce cache for replay protection
pub struct PowCache {
    used: HashSet<[u8; 40]>,
    timestamps: HashMap<[u8; 40], Instant>,
}

impl PowCache {
    pub fn new() -> Self {
        Self {
            used: HashSet::new(),
            timestamps: HashMap::new(),
        }
    }

    /// Check if PoW was already used (returns false if replay)
    pub fn check_and_insert(&mut self, pow: &ProofOfWork) -> bool {
        let key = pow.cache_key();
        if self.used.contains(&key) {
            return false;
        }
        self.used.insert(key);
        self.timestamps.insert(key, Instant::now());
        true
    }

    /// Remove expired entries
    pub fn cleanup(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(POW_TIMESTAMP_WINDOW);
        self.timestamps.retain(|key, ts| {
            if *ts < cutoff {
                self.used.remove(key);
                false
            } else {
                true
            }
        });
    }
}

impl Default for PowCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined message: ClientHello + PoW
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientHelloWithPow {
    ch: ClientHello,
    pow: ProofOfWork,
}

/* ============================================================================ */
/* Rate limiter                                                                 */
/* ============================================================================ */

pub struct RateLimiter {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_rate: f64,
}

impl RateLimiter {
    pub fn new(capacity: u32, per_second: u32) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: Instant::now(),
            capacity: capacity as f64,
            refill_rate: per_second as f64,
        }
    }

    pub fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }
}

/* ============================================================================ */
/* RPC messages                                                                 */
/* ============================================================================ */

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcRequest {
    GetStatus,
    GetChainInfo,
    GetPeerCount,
    SubmitTransaction { tx_hex: String, priority: TransactionPriority },
    GetBlockByHeight { height: u64 },
    GetBlockByHash { hash: String },
    GetMempool { limit: Option<usize> },
    GetNodeMetrics,
    SubscribeEvents { filter: EventFilter },
    UnsubscribeEvents { subscription_id: String },
    GetBalance { address_hex: String },
    SubmitSignedStarkTx { tx_hex: String },
    /// Submit a simple PQ transaction (account-based transfer)
    SubmitSimplePqTx {
        /// Sender address (32-byte hex)
        from_hex: String,
        /// Recipient address (32-byte hex)
        to_hex: String,
        /// Amount to transfer
        amount: u128,
        /// Transaction fee
        fee: u128,
        /// Nonce (anti-replay)
        nonce: u64,
        /// Falcon-512 public key of sender (hex)
        falcon_pk_hex: String,
        /// Falcon-512 signature over tx data (hex)
        falcon_sig_hex: String,
    },
    /// Credit/mint tokens to an address (faucet/testing)
    Credit {
        /// Address to credit (32-byte hex)
        address_hex: String,
        /// Amount to credit
        amount: u128,
    },
    /// Submit stealth hint for broadcast through P2P network
    SubmitStealthHint {
        /// Stealth hint bytes (hex-encoded)
        hint_hex: String,
    },
    /// Get pending stealth hints (for scanning)
    GetStealthHints {
        /// Maximum number of hints to return
        limit: Option<usize>,
        /// Offset for pagination (hint index)
        offset: Option<usize>,
    },
    /// Submit STARK transaction (with range proof + optional stealth)
    SubmitStarkTx {
        /// Serialized TransactionStark (hex-encoded)
        tx_hex: String,
    },
    /// Get STARK transactions for an address
    GetStarkTxs {
        /// Filter by recipient address (optional, hex)
        address_hex: Option<String>,
        /// Maximum transactions to return
        limit: Option<usize>,
    },
    /// Get blocks with stealth hints (Monero-style blockchain scan)
    GetBlocksWithHints {
        /// Starting block height
        from_height: u64,
        /// Maximum blocks to return
        limit: Option<usize>,
    },
    /// Submit Private STARK transaction v2 (full privacy: stealth + encrypted sender + STARK amounts)
    SubmitPrivateStarkTx {
        /// Serialized PrivateStarkTx (hex-encoded)
        tx_hex: String,
    },
    /// Get Private STARK transactions (for scanning by recipient)
    GetPrivateStarkTxs {
        /// Maximum transactions to return
        limit: Option<usize>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionPriority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventFilter {
    pub event_types: Vec<String>,
    pub addresses: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcResponse {
    Status {
        node_id: String,
        is_validator: bool,
        height: u64,
        sync_status: SyncStatus,
        uptime: u64,
    },
    ChainInfo {
        height: u64,
        best_block_hash: String,
        finalized_height: u64,
        network_difficulty: String,
    },
    PeerCount {
        connected: usize,
        inbound: usize,
        outbound: usize,
    },
    TxSubmitted {
        tx_id: String,
        accepted: bool,
        fee_paid: u64,
    },
    Block {
        height: u64,
        hash: String,
        timestamp: u64,
        transactions: Vec<String>,
    },
    Mempool {
        pending: usize,
        queued: usize,
        transactions: Vec<MempoolTx>,
    },
    NodeMetrics {
        cpu_usage: f32,
        memory_usage: f32,
        disk_usage: f32,
        network_in: u64,
        network_out: u64,
    },
    Subscription {
        subscription_id: String,
        status: String,
    },
    Error {
        code: i32,
        message: String,
        data: Option<String>,
    },
    Balance {
        address_hex: String,
        confirmed: u128,
        pending: u128,
    },
    /// Response for simple PQ transaction submission
    SimplePqTxSubmitted {
        tx_id: String,
        accepted: bool,
        new_sender_balance: u128,
        new_recipient_balance: u128,
    },
    /// Response for credit/faucet operation
    Credited {
        address_hex: String,
        new_balance: u128,
    },
    /// Response for stealth hint submission
    StealthHintSubmitted {
        hint_id: String,
        broadcast_peers: usize,
    },
    /// Response for getting stealth hints
    StealthHints {
        hints: Vec<String>,  // hex-encoded hint bytes
        total_count: usize,
    },
    /// Response for STARK transaction submission
    StarkTxSubmitted {
        tx_id: String,
        accepted: bool,
        message: Option<String>,
    },
    /// Response for getting STARK transactions
    StarkTxs {
        txs: Vec<String>,  // hex-encoded TransactionStark bytes
        total_count: usize,
    },
    /// Response for blocks with stealth hints (Monero-style)
    BlocksWithHints {
        /// Serialized BlockV2 bytes (hex)
        blocks: Vec<String>,
        /// Latest block height in response
        latest_height: u64,
        /// Total chain height
        chain_height: u64,
    },
    /// Response for Private STARK transaction v2 submission
    PrivateStarkTxSubmitted {
        tx_id: String,
        accepted: bool,
        message: Option<String>,
    },
    /// Response for GetPrivateStarkTxs - list of private STARK transactions
    PrivateStarkTxs {
        /// Serialized PrivateStarkTx entries (hex-encoded)
        txs: Vec<String>,
        /// Total count in pool
        total_count: usize,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncStatus {
    pub is_syncing: bool,
    pub current_block: u64,
    pub target_block: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MempoolTx {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value: u64,
    pub gas_price: u64,
    pub timestamp: u64,
}

/* ============================================================================ */
/* Trusted servers (TOFU + pinning)                                             */
/* ============================================================================ */

/// Trusted server entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedServer {
    pub address: SocketAddr,
    pub falcon_pk: Vec<u8>,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Trust store for server verification (TOFU model)
pub struct TrustStore {
    servers: HashMap<SocketAddr, TrustedServer>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self {
            servers: HashMap::new(),
        }
    }

    /// Add hardcoded trusted server
    pub fn add_pinned(&mut self, address: SocketAddr, falcon_pk: Vec<u8>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.servers.insert(
            address,
            TrustedServer {
                address,
                falcon_pk,
                first_seen: now,
                last_seen: now,
            },
        );
    }

    /// Check if server is trusted (TOFU: trust on first use)
    pub fn verify_or_trust(&mut self, address: SocketAddr, falcon_pk: &[u8]) -> Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(existing) = self.servers.get_mut(&address) {
            // Server known — verify PK matches
            if existing.falcon_pk != falcon_pk {
                bail!(
                    "SERVER KEY CHANGED! Expected: {}..., Got: {}... \
                     This could be a MITM attack!",
                    hex::encode(&existing.falcon_pk[..16]),
                    hex::encode(&falcon_pk[..16])
                );
            }
            existing.last_seen = now;
            Ok(false) // Not first time
        } else {
            // First contact — trust on first use
            self.servers.insert(
                address,
                TrustedServer {
                    address,
                    falcon_pk: falcon_pk.to_vec(),
                    first_seen: now,
                    last_seen: now,
                },
            );
            Ok(true) // First time
        }
    }
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

/* ============================================================================ */
/* Server                                                                       */
/* ============================================================================ */

#[derive(Debug, Clone)]
struct SessionState {
    session_id: [u8; 32],
    created_at: Instant,
    last_activity: Instant,
    request_count: u64,
    bytes_transferred: u64,
    client_label: Option<[u8; 32]>,
}

#[derive(Default, Debug, Clone)]
struct ServerMetrics {
    total_connections: u64,
    active_connections: u64,
    total_requests: u64,
    failed_authentications: u64,
    rate_limit_hits: u64,
}

pub struct SecureRpcServer {
    address: SocketAddr,
    identity: Arc<RwLock<NodeIdentity>>,
    is_validator: bool,
    node: Arc<NodeCore>,
    sessions: Arc<RwLock<HashMap<[u8; 32], SessionState>>>,
    connection_limiter: Arc<RwLock<HashMap<IpAddr, usize>>>,
    rate_limiters: Arc<RwLock<HashMap<IpAddr, RateLimiter>>>,
    connection_semaphore: Arc<Semaphore>,
    metrics: Arc<RwLock<ServerMetrics>>,
    last_key_rotation: Arc<RwLock<Instant>>,
    pow_cache: Arc<RwLock<PowCache>>,
    privacy_mode: PrivacyMode,
    server_salt: [u8; 32],
    /// Optional P2P network for broadcasting stealth hints
    p2p: Option<Arc<P2PNetwork>>,
    /// Stealth hint pool (raw hint bytes)
    hint_pool: Arc<RwLock<Vec<Vec<u8>>>>,
    /// STARK transaction pool (typed: public + private)
    stark_tx_pool: Arc<RwLock<Vec<StarkTxPoolEntry>>>,
}

impl SecureRpcServer {
    pub fn new(
        rpc_port: u16,
        identity: NodeIdentity,
        is_validator: bool,
        node: Arc<NodeCore>,
    ) -> Self {
        Self::new_with_options(rpc_port, identity, is_validator, node, PrivacyMode::Normal, None)
    }

    pub fn new_with_privacy(
        rpc_port: u16,
        identity: NodeIdentity,
        is_validator: bool,
        node: Arc<NodeCore>,
        privacy_mode: PrivacyMode,
    ) -> Self {
        Self::new_with_options(rpc_port, identity, is_validator, node, privacy_mode, None)
    }

    pub fn new_with_p2p(
        rpc_port: u16,
        identity: NodeIdentity,
        is_validator: bool,
        node: Arc<NodeCore>,
        privacy_mode: PrivacyMode,
        p2p: Arc<P2PNetwork>,
    ) -> Self {
        Self::new_with_options(rpc_port, identity, is_validator, node, privacy_mode, Some(p2p))
    }

    fn new_with_options(
        rpc_port: u16,
        identity: NodeIdentity,
        is_validator: bool,
        node: Arc<NodeCore>,
        privacy_mode: PrivacyMode,
        p2p: Option<Arc<P2PNetwork>>,
    ) -> Self {
        use rand::RngCore;

        let address = SocketAddr::from(([0, 0, 0, 0], rpc_port));
        let mut server_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut server_salt);

        Self {
            address,
            identity: Arc::new(RwLock::new(identity)),
            is_validator,
            node,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            connection_limiter: Arc::new(RwLock::new(HashMap::new())),
            rate_limiters: Arc::new(RwLock::new(HashMap::new())),
            connection_semaphore: Arc::new(Semaphore::new(1000)),
            metrics: Arc::new(RwLock::new(ServerMetrics::default())),
            last_key_rotation: Arc::new(RwLock::new(Instant::now())),
            pow_cache: Arc::new(RwLock::new(PowCache::new())),
            privacy_mode,
            server_salt,
            p2p,
            hint_pool: Arc::new(RwLock::new(Vec::new())),
            stark_tx_pool: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn generate_session_id(&self) -> [u8; 32] {
        use rand::RngCore;
        let mut id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    fn derive_client_label(&self, node_id: &NodeId) -> Option<[u8; 32]> {
        match self.privacy_mode {
            PrivacyMode::Normal => {
                use blake3::Hasher;
                let mut hasher = Hasher::new();
                hasher.update(&self.server_salt);
                hasher.update(node_id);
                let hash = hasher.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(hash.as_bytes());
                Some(out)
            }
            PrivacyMode::ProPrivacy => None,
        }
    }

    fn short_id(id: &[u8]) -> String {
        let hex = hex::encode(id);
        if hex.len() > 16 {
            format!("{}…", &hex[..16])
        } else {
            hex
        }
    }

    pub async fn start(self) -> Result<()> {
        let listener = TcpListener::bind(self.address)
            .await
            .context("Failed to bind RPC port")?;
        println!("🔐 Secure PQ RPC listening on {}", self.address);

        let identity = self.identity.read().await;
        println!("   Node ID: {}", Self::short_id(&identity.node_id));
        drop(identity);

        let server = Arc::new(self);

        // Background tasks
        {
            let s = Arc::clone(&server);
            tokio::spawn(async move {
                cleanup_sessions_task(s).await;
            });
        }
        {
            let s = Arc::clone(&server);
            tokio::spawn(async move {
                key_rotation_task(s).await;
            });
        }
        {
            let s = Arc::clone(&server);
            tokio::spawn(async move {
                pow_cache_cleanup_task(s).await;
            });
        }

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    if !server.check_connection_limit(addr.ip()).await {
                        eprintln!("Connection limit exceeded for {}", addr.ip());
                        continue;
                    }
                    let permit = server.connection_semaphore.clone().acquire_owned().await?;
                    let s = Arc::clone(&server);
                    tokio::spawn(async move {
                        if let Err(e) = s.handle_connection(stream, addr).await {
                            if !e.to_string().contains("Connection reset") {
                                eprintln!("RPC connection error from {}: {}", addr, e);
                            }
                        }
                        drop(permit);
                        s.release_connection(addr.ip()).await;
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept RPC connection: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn check_connection_limit(&self, ip: IpAddr) -> bool {
        let mut limiter = self.connection_limiter.write().await;
        let count = limiter.entry(ip).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_IP {
            self.metrics.write().await.rate_limit_hits += 1;
            return false;
        }
        *count += 1;
        let mut metrics = self.metrics.write().await;
        metrics.total_connections += 1;
        metrics.active_connections += 1;
        true
    }

    async fn release_connection(&self, ip: IpAddr) {
        let mut limiter = self.connection_limiter.write().await;
        if let Some(count) = limiter.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                limiter.remove(&ip);
            }
        }
        let mut metrics = self.metrics.write().await;
        metrics.active_connections = metrics.active_connections.saturating_sub(1);
    }

    async fn handle_connection(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        println!("🔗 New RPC connection from {}", addr);
        stream.set_nodelay(true)?;

        // Rate limit per IP
        {
            let mut rls = self.rate_limiters.write().await;
            let rl = rls
                .entry(addr.ip())
                .or_insert_with(|| RateLimiter::new(MAX_REQUESTS_PER_SECOND * 2, MAX_REQUESTS_PER_SECOND));
            if !rl.try_consume(1.0) {
                bail!("Rate limit exceeded");
            }
        }

        // === Send SIGNED PoW challenge ===
        let signed_challenge = {
            let identity = self.identity.read().await;
            SignedChallenge::new(&identity.falcon_pk, identity.falcon_sk())
        };
        let challenge_bytes = bincode::serialize(&signed_challenge)?;
        write_message(&mut stream, &challenge_bytes).await?;

        // Receive ClientHello + PoW
        let ch_pow_bytes =
            read_message_with_timeout(&mut stream, Duration::from_secs(30)).await?;
        let ch_pow: ClientHelloWithPow =
            bincode::deserialize(&ch_pow_bytes).context("Failed to deserialize ClientHelloWithPow")?;

        // Verify PoW challenge matches
        ensure!(
            ch_pow.pow.challenge == signed_challenge.challenge,
            "PoW challenge mismatch"
        );

        // Verify PoW difficulty
        if !ch_pow.pow.verify(POW_DIFFICULTY) {
            self.metrics.write().await.failed_authentications += 1;
            bail!("Invalid proof-of-work");
        }

        // Check PoW replay
        {
            let mut cache = self.pow_cache.write().await;
            if !cache.check_and_insert(&ch_pow.pow) {
                self.metrics.write().await.failed_authentications += 1;
                bail!("PoW replay detected");
            }
        }

        let ch = ch_pow.ch;
        println!("   ClientHello from {}", Self::short_id(&ch.node_id));

        // === PQ handshake ===
        let identity = self.identity.read().await;
        let transcript = TranscriptHasher::new();
        let (sh, session_keys, transcript) =
            handle_client_hello(&identity, &ch, PROTOCOL_VERSION, transcript, None)
                .context("ClientHello validation failed")?;
        drop(identity);

        // ServerHello
        let sh_bytes = bincode::serialize(&sh)?;
        write_message(&mut stream, &sh_bytes).await?;

        // ClientFinished
        let cf_bytes =
            read_message_with_timeout(&mut stream, Duration::from_secs(10)).await?;
        let cf: ClientFinished =
            bincode::deserialize(&cf_bytes).context("Failed to deserialize ClientFinished")?;
        let _transcript =
            verify_client_finished(&ch.falcon_pk, transcript, &cf)
                .context("ClientFinished verification failed")?;

        // Channel AAD derived from session keys (both sides can compute identically)
        let channel_aad = derive_channel_aad(&session_keys);

        // Server-local session ID (for metrics / management only, never sent)
        let session_id = self.generate_session_id();
        let client_label = self.derive_client_label(&ch.node_id);

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(
                session_id,
                SessionState {
                    session_id,
                    created_at: Instant::now(),
                    last_activity: Instant::now(),
                    request_count: 0,
                    bytes_transferred: 0,
                    client_label,
                },
            );
        }

        let mut channel = SecureChannel::new_server(&session_keys);
        let mut last_renegotiation = Instant::now();

        loop {
            // Session timeout check
            {
                let sessions = self.sessions.read().await;
                if let Some(st) = sessions.get(&session_id) {
                    if st.created_at.elapsed() > SESSION_TIMEOUT {
                        println!("   Session timeout for {}", addr);
                        break;
                    }
                } else {
                    break;
                }
            }

            // ProPrivacy limits
            if self.privacy_mode == PrivacyMode::ProPrivacy {
                let sessions = self.sessions.read().await;
                if let Some(st) = sessions.get(&session_id) {
                    if st.created_at.elapsed() > PRO_PRIVACY_SESSION_LIFETIME {
                        println!("   ProPrivacy: hard session lifetime reached for {}", addr);
                        break;
                    }
                    if st.request_count >= PRO_PRIVACY_MAX_REQUESTS {
                        println!("   ProPrivacy: max requests per session reached for {}", addr);
                        break;
                    }
                } else {
                    break;
                }
            }

            // Key renegotiation check
            if last_renegotiation.elapsed() > MIN_RENEGOTIATION_INTERVAL
                && channel.should_renegotiate()
            {
                // TODO: key renegotiation
                last_renegotiation = Instant::now();
            }

            let req_bytes = match read_secure_message_with_timeout(
                &mut stream,
                &mut channel,
                Duration::from_secs(60),
                &channel_aad,
            )
            .await
            {
                Ok(b) => b,
                Err(e) => {
                    println!("   Connection closed: {}", e);
                    break;
                }
            };

            self.update_session_metrics(&session_id, req_bytes.len()).await;

            // Per-request rate limit
            {
                let mut rls = self.rate_limiters.write().await;
                let rl = rls.get_mut(&addr.ip()).unwrap();
                if !rl.try_consume(1.0) {
                    let err = RpcResponse::Error {
                        code: 429,
                        message: "Rate limit exceeded".to_string(),
                        data: None,
                    };
                    let resp_bytes = bincode::serialize(&err)?;
                    write_secure_message(&mut stream, &mut channel, &resp_bytes, &channel_aad).await?;
                    continue;
                }
            }

            // Deserialize request
            let request: RpcRequest = match bincode::deserialize(&req_bytes) {
                Ok(r) => r,
                Err(e) => {
                    let err = RpcResponse::Error {
                        code: 400,
                        message: format!("Invalid request: {}", e),
                        data: None,
                    };
                    let resp_bytes = bincode::serialize(&err)?;
                    write_secure_message(&mut stream, &mut channel, &resp_bytes, &channel_aad).await?;
                    continue;
                }
            };

            let response = tokio::time::timeout(
                Duration::from_secs(30),
                self.process_request(request),
            )
            .await
            .unwrap_or_else(|_| RpcResponse::Error {
                code: 408,
                message: "Request timeout".to_string(),
                data: None,
            });

            let resp_bytes = bincode::serialize(&response)?;
            write_secure_message(&mut stream, &mut channel, &resp_bytes, &channel_aad).await?;
            self.update_session_metrics(&session_id, resp_bytes.len()).await;
        }

        self.sessions.write().await.remove(&session_id);
        Ok(())
    }

    async fn update_session_metrics(&self, session_id: &[u8; 32], bytes: usize) {
        {
            let mut sessions = self.sessions.write().await;
            if let Some(st) = sessions.get_mut(session_id) {
                st.last_activity = Instant::now();
                st.request_count += 1;
                st.bytes_transferred += bytes as u64;
            }
        }
        let mut metrics = self.metrics.write().await;
        metrics.total_requests += 1;
    }

    async fn process_request(&self, request: RpcRequest) -> RpcResponse {
        match request {
            RpcRequest::GetStatus => {
                let height = self.node.get_chain_height().await;
                let uptime = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let identity = self.identity.read().await;
                RpcResponse::Status {
                    node_id: hex::encode(&identity.node_id),
                    is_validator: self.is_validator,
                    height,
                    sync_status: SyncStatus {
                        is_syncing: false,
                        current_block: height,
                        target_block: height,
                    },
                    uptime,
                }
            }
            RpcRequest::GetChainInfo => {
                let height = self.node.get_chain_height().await;
                let best = self.node.get_best_block_hash().await;
                RpcResponse::ChainInfo {
                    height,
                    best_block_hash: hex::encode(best),
                    finalized_height: height.saturating_sub(6),
                    network_difficulty: "1000000".to_string(),
                }
            }
            RpcRequest::GetPeerCount => {
                let count = self.node.get_peer_count().await;
                RpcResponse::PeerCount {
                    connected: count,
                    inbound: count / 2,
                    outbound: count / 2,
                }
            }
            RpcRequest::SubmitTransaction { tx_hex, priority } => {
                match hex::decode(&tx_hex) {
                    Ok(tx_bytes) => {
                        let fee_mult = match priority {
                            TransactionPriority::Low => 1,
                            TransactionPriority::Normal => 2,
                            TransactionPriority::High => 3,
                            TransactionPriority::Critical => 5,
                        };
                        match self.node.submit_transaction(&tx_bytes).await {
                            Ok(tx_id) => RpcResponse::TxSubmitted {
                                tx_id: hex::encode(tx_id),
                                accepted: true,
                                fee_paid: 1000 * fee_mult,
                            },
                            Err(e) => RpcResponse::Error {
                                code: 500,
                                message: format!("TX rejected: {}", e),
                                data: None,
                            },
                        }
                    }
                    Err(_) => RpcResponse::Error {
                        code: 400,
                        message: "Invalid hex encoding".into(),
                        data: None,
                    },
                }
            }
            RpcRequest::GetBalance { address_hex } => {
                match hex::decode(&address_hex) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&bytes);
                        let bal = self.node.get_balance(&id).await;
                        RpcResponse::Balance {
                            address_hex,
                            confirmed: bal,
                            pending: 0,
                        }
                    }
                    _ => RpcResponse::Error {
                        code: 400,
                        message: "Invalid address (must be 32-byte hex)".into(),
                        data: None,
                    },
                }
            }
            RpcRequest::SubmitSignedStarkTx { tx_hex } => {
                match hex::decode(&tx_hex) {
                    Ok(bytes) => {
                        match bincode::deserialize::<SignedStarkTx>(&bytes) {
                            Ok(stx) => {
                                match self.node.submit_signed_stark_tx(&stx).await {
                                    Ok(tx_id) => RpcResponse::StarkTxSubmitted {
                                        tx_id: hex::encode(tx_id),
                                        accepted: true,
                                        message: None,
                                    },
                                    Err(e) => RpcResponse::Error {
                                        code: 500,
                                        message: format!("TX rejected: {e}"),
                                        data: None,
                                    },
                                }
                            }
                            Err(e) => RpcResponse::Error {
                                code: 400,
                                message: format!("Invalid SignedStarkTx encoding: {e}"),
                                data: None,
                            },
                        }
                    }
                    Err(_) => RpcResponse::Error {
                        code: 400,
                        message: "Invalid hex encoding".into(),
                        data: None,
                    },
                }
            }
            RpcRequest::SubmitSimplePqTx {
                from_hex,
                to_hex,
                amount,
                fee,
                nonce,
                falcon_pk_hex,
                falcon_sig_hex,
            } => {
                // 1. Decode addresses
                let from_bytes = match hex::decode(&from_hex) {
                    Ok(b) if b.len() == 32 => b,
                    _ => return RpcResponse::Error {
                        code: 400,
                        message: "Invalid 'from' address (must be 32-byte hex)".into(),
                        data: None,
                    },
                };
                let to_bytes = match hex::decode(&to_hex) {
                    Ok(b) if b.len() == 32 => b,
                    _ => return RpcResponse::Error {
                        code: 400,
                        message: "Invalid 'to' address (must be 32-byte hex)".into(),
                        data: None,
                    },
                };

                let mut from: NodeId = [0u8; 32];
                let mut to: NodeId = [0u8; 32];
                from.copy_from_slice(&from_bytes);
                to.copy_from_slice(&to_bytes);

                // 2. Decode Falcon PK and signature
                let falcon_pk_bytes = match hex::decode(&falcon_pk_hex) {
                    Ok(b) => b,
                    Err(_) => return RpcResponse::Error {
                        code: 400,
                        message: "Invalid falcon_pk hex".into(),
                        data: None,
                    },
                };
                let falcon_sig_bytes = match hex::decode(&falcon_sig_hex) {
                    Ok(b) => b,
                    Err(_) => return RpcResponse::Error {
                        code: 400,
                        message: "Invalid falcon_sig hex".into(),
                        data: None,
                    },
                };

                // 3. Verify Falcon signature
                let falcon_pk = match falcon_pk_from_bytes(&falcon_pk_bytes) {
                    Ok(pk) => pk,
                    Err(_) => return RpcResponse::Error {
                        code: 400,
                        message: "Invalid Falcon-512 public key".into(),
                        data: None,
                    },
                };

                // Build the message to verify (same as client signs)
                let mut msg_to_sign = Vec::new();
                msg_to_sign.extend_from_slice(&from);
                msg_to_sign.extend_from_slice(&to);
                msg_to_sign.extend_from_slice(&amount.to_le_bytes());
                msg_to_sign.extend_from_slice(&fee.to_le_bytes());
                msg_to_sign.extend_from_slice(&nonce.to_le_bytes());

                let signed_nullifier = SignedNullifier {
                    signed_message_bytes: falcon_sig_bytes.clone(),
                };

                if falcon_verify(&msg_to_sign, &signed_nullifier, &falcon_pk).is_err() {
                    return RpcResponse::Error {
                        code: 401,
                        message: "Invalid Falcon signature".into(),
                        data: None,
                    };
                }

                // 4. Build SimplePqTx and apply
                let tx = SimplePqTx {
                    from,
                    to,
                    amount,
                    fee,
                    nonce,
                    falcon_pk: falcon_pk_bytes,
                    falcon_sig: falcon_sig_bytes,
                };

                match self.node.apply_simple_pq_tx(&tx).await {
                    Ok(tx_id) => {
                        // Get updated balances
                        let new_sender_balance = self.node.get_balance(&from).await;
                        let new_recipient_balance = self.node.get_balance(&to).await;

                        RpcResponse::SimplePqTxSubmitted {
                            tx_id: hex::encode(tx_id),
                            accepted: true,
                            new_sender_balance,
                            new_recipient_balance,
                        }
                    }
                    Err(e) => RpcResponse::Error {
                        code: 500,
                        message: format!("TX rejected: {e}"),
                        data: None,
                    },
                }
            }
            RpcRequest::Credit { address_hex, amount } => {
                // Faucet/testing: credit tokens to address
                let addr_bytes = match hex::decode(&address_hex) {
                    Ok(b) if b.len() == 32 => b,
                    _ => return RpcResponse::Error {
                        code: 400,
                        message: "Invalid address (must be 32-byte hex)".into(),
                        data: None,
                    },
                };

                let mut addr: NodeId = [0u8; 32];
                addr.copy_from_slice(&addr_bytes);

                // Credit the account
                {
                    let mut ledger = self.node.ledger.write().await;
                    ledger.credit(&addr, amount);
                }

                let new_balance = self.node.get_balance(&addr).await;

                println!(
                    "[RPC] Credit {} to {} → new balance: {}",
                    amount,
                    hex::encode(&addr[..8]),
                    new_balance
                );

                RpcResponse::Credited {
                    address_hex,
                    new_balance,
                }
            }
            RpcRequest::SubmitStealthHint { hint_hex } => {
                // Decode hint bytes
                let hint_bytes = match hex::decode(&hint_hex) {
                    Ok(b) => b,
                    Err(e) => return RpcResponse::Error {
                        code: 400,
                        message: format!("Invalid hint hex: {e}"),
                        data: None,
                    },
                };

                // Compute hint_id for logging (hash of hint)
                let hint_id = {
                    use blake3::Hasher;
                    let mut h = Hasher::new();
                    h.update(&hint_bytes);
                    hex::encode(&h.finalize().as_bytes()[..16])
                };

                // Add to hint pool
                {
                    let mut pool = self.hint_pool.write().await;
                    // Limit pool size (prevent DoS)
                    const MAX_POOL_SIZE: usize = 10000;
                    if pool.len() >= MAX_POOL_SIZE {
                        pool.remove(0); // Remove oldest
                    }
                    pool.push(hint_bytes.clone());
                }

                // Broadcast through P2P if available
                let broadcast_peers = if let Some(ref p2p) = self.p2p {
                    match p2p.broadcast_stealth_hint(&hint_bytes).await {
                        Ok(count) => count,
                        Err(e) => {
                            log::warn!("[RPC] P2P broadcast failed: {e}");
                            0
                        }
                    }
                } else {
                    0
                };

                println!(
                    "[RPC] 🔐 Stealth hint submitted: {} ({} bytes, broadcast to {} peers)",
                    hint_id,
                    hint_bytes.len(),
                    broadcast_peers
                );

                RpcResponse::StealthHintSubmitted {
                    hint_id,
                    broadcast_peers,
                }
            }
            RpcRequest::GetStealthHints { limit, offset } => {
                let pool = self.hint_pool.read().await;
                let total_count = pool.len();
                
                let offset = offset.unwrap_or(0);
                let limit = limit.unwrap_or(100).min(1000); // Max 1000 at once
                
                let hints: Vec<String> = pool
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|h| hex::encode(h))
                    .collect();

                RpcResponse::StealthHints {
                    hints,
                    total_count,
                }
            }
            RpcRequest::SubmitStarkTx { tx_hex } => {
                use crate::tx_stark::TransactionStark;
                
                let tx_bytes = match hex::decode(&tx_hex) {
                    Ok(b) => b,
                    Err(e) => return RpcResponse::Error {
                        code: 400,
                        message: format!("Invalid hex: {}", e),
                        data: None,
                    },
                };

                let tx: TransactionStark = match bincode::deserialize(&tx_bytes) {
                    Ok(t) => t,
                    Err(e) => return RpcResponse::Error {
                        code: 400,
                        message: format!("Invalid TransactionStark: {}", e),
                        data: None,
                    },
                };

                // Verify all STARK proofs
                let (valid, total) = tx.verify_all_proofs();
                if valid != total {
                    return RpcResponse::StarkTxSubmitted {
                        tx_id: hex::encode(tx.id()),
                        accepted: false,
                        message: Some(format!("STARK proof verification failed: {}/{} valid", valid, total)),
                    };
                }

                let tx_id = tx.id();
                
                // Store in STARK tx pool as Public entry
                {
                    let mut pool = self.stark_tx_pool.write().await;
                    pool.push(StarkTxPoolEntry::Public(tx.clone()));
                    // Keep pool bounded
                    if pool.len() > 10000 {
                        pool.remove(0);
                    }
                }

                // Broadcast through P2P if available
                if let Some(ref p2p) = self.p2p {
                    let _ = p2p.broadcast_stark_tx(&tx).await;
                }

                RpcResponse::StarkTxSubmitted {
                    tx_id: hex::encode(tx_id),
                    accepted: true,
                    message: Some(format!("{} outputs with valid STARK proofs", total)),
                }
            }
            RpcRequest::GetStarkTxs { address_hex, limit } => {
                let pool = self.stark_tx_pool.read().await;
                let total_count = pool.len();
                let limit = limit.unwrap_or(50).min(200);

                let filter_addr: Option<[u8; 32]> = address_hex.and_then(|h| {
                    hex::decode(&h).ok().and_then(|b| {
                        if b.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&b);
                            Some(arr)
                        } else {
                            None
                        }
                    })
                });

                // Return only Public transactions (typed properly now)
                let txs: Vec<String> = pool
                    .iter()
                    .filter(|entry| {
                        if let Some(ref addr) = filter_addr {
                            entry.matches_recipient(addr)
                        } else {
                            true
                        }
                    })
                    .filter_map(|entry| {
                        // Only return Public entries for this endpoint
                        match entry {
                            StarkTxPoolEntry::Public(tx) => {
                                Some(hex::encode(bincode::serialize(tx).ok()?))
                            }
                            StarkTxPoolEntry::Private(_) => None, // Use GetPrivateStarkTxs
                        }
                    })
                    .take(limit)
                    .collect();

                RpcResponse::StarkTxs {
                    txs,
                    total_count,
                }
            }
            RpcRequest::GetBlocksWithHints { from_height, limit } => {
                // For now, return STARK txs from pool wrapped as "blocks"
                // TODO: Integrate with ChainStore for actual blockchain persistence
                let pool = self.stark_tx_pool.read().await;
                let limit = limit.unwrap_or(10).min(100);
                
                // Simulate blocks from tx pool (each Public tx = 1 block for now)
                // In production, this would query ChainStore for BlockV2
                let mut blocks_hex = Vec::new();
                let mut height = from_height;
                
                for entry in pool.iter().skip(from_height as usize).take(limit) {
                    if let StarkTxPoolEntry::Public(tx) = entry {
                        // Create a simple BlockV2 wrapper
                        let block = crate::core::BlockV2 {
                            header: crate::core::BlockHeader {
                                parent: [0u8; 32],
                                height,
                                author: [0u8; 32],
                                task_seed: [0u8; 32],
                                timestamp: tx.timestamp,
                                parent_state_hash: [0u8; 32],
                                result_state_hash: [0u8; 32],
                            },
                            author_sig: vec![],
                            zk_receipt_bincode: vec![],
                            stark_transactions: vec![tx.clone()],
                            legacy_transactions: vec![],
                        };
                        blocks_hex.push(hex::encode(block.to_bytes()));
                        height += 1;
                    }
                }

                let latest_height = if blocks_hex.is_empty() { 
                    from_height 
                } else { 
                    from_height + blocks_hex.len() as u64 - 1 
                };

                RpcResponse::BlocksWithHints {
                    blocks: blocks_hex,
                    latest_height,
                    chain_height: pool.len() as u64,
                }
            }
            RpcRequest::SubmitPrivateStarkTx { tx_hex } => {
                // Support both compressed (PSTX) and legacy bincode formats
                let tx: PrivateStarkTx = if tx_hex.starts_with("50535458") {
                    // PSTX magic header (hex: "PSTX") - compressed zstd format
                    match PrivateStarkTx::from_compressed_hex(&tx_hex) {
                        Ok(t) => t,
                        Err(e) => return RpcResponse::Error {
                            code: 400,
                            message: format!("Invalid compressed PrivateStarkTx: {}", e),
                            data: None,
                        },
                    }
                } else {
                    // Legacy bincode format
                    let tx_bytes = match hex::decode(&tx_hex) {
                        Ok(b) => b,
                        Err(e) => return RpcResponse::Error {
                            code: 400,
                            message: format!("Invalid hex: {}", e),
                            data: None,
                        },
                    };
                    match bincode::deserialize(&tx_bytes) {
                        Ok(t) => t,
                        Err(e) => return RpcResponse::Error {
                            code: 400,
                            message: format!("Invalid PrivateStarkTx: {}", e),
                            data: None,
                        },
                    }
                };

                let tx_id = tx.tx_id();

                // Note: We cannot verify the STARK proof without knowing the recipient address
                // The proof is bound to the recipient, so only they can fully verify
                // We can at least check signature is present
                if tx.falcon_sig.is_empty() {
                    return RpcResponse::PrivateStarkTxSubmitted {
                        tx_id: hex::encode(tx_id),
                        accepted: false,
                        message: Some("Missing Falcon signature".to_string()),
                    };
                }

                // Store in STARK tx pool as Private entry
                {
                    let mut pool = self.stark_tx_pool.write().await;
                    pool.push(StarkTxPoolEntry::Private(tx));
                    // Keep pool bounded
                    if pool.len() > 10000 {
                        pool.remove(0);
                    }
                }

                // Note: P2P broadcast would need to be updated for PrivateStarkTx
                // For now, we just store it

                RpcResponse::PrivateStarkTxSubmitted {
                    tx_id: hex::encode(tx_id),
                    accepted: true,
                    message: Some("PrivateStarkTx accepted (full privacy TX)".to_string()),
                }
            }
            RpcRequest::GetPrivateStarkTxs { limit } => {
                let pool = self.stark_tx_pool.read().await;
                let total_count = pool.iter().filter(|e| matches!(e, StarkTxPoolEntry::Private(_))).count();
                let limit = limit.unwrap_or(50).min(200);

                // Return only Private transactions
                let txs: Vec<String> = pool
                    .iter()
                    .filter_map(|entry| {
                        match entry {
                            StarkTxPoolEntry::Private(tx) => {
                                Some(hex::encode(bincode::serialize(tx).ok()?))
                            }
                            StarkTxPoolEntry::Public(_) => None,
                        }
                    })
                    .take(limit)
                    .collect();

                RpcResponse::PrivateStarkTxs {
                    txs,
                    total_count,
                }
            }
            _ => RpcResponse::Error {
                code: 501,
                message: "Not implemented".into(),
                data: None,
            },
        }
    }
}

/* ============================================================================ */
/* Channel AAD derivation (shared client/server)                                */
/* ============================================================================ */

fn derive_channel_aad<S: Serialize>(session_keys: &S) -> [u8; 32] {
    use blake3::Hasher;
    let encoded = bincode::serialize(session_keys)
        .expect("Session keys must be serializable for channel AAD derivation");
    let mut h = Hasher::new();
    h.update(b"RPC_CHANNEL_AAD_V1");
    h.update(&encoded);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

/* ============================================================================ */
/* Client                                                                       */
/* ============================================================================ */

/// SOCKS5 proxy configuration for Tor support
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// SOCKS5 proxy address (e.g., "127.0.0.1:9050" for Tor)
    pub socks5_addr: SocketAddr,
}

pub struct SecureRpcClient {
    server_addr: SocketAddr,
    identity: NodeIdentity,
    channel: Option<SecureChannel>,
    stream: Option<TcpStream>,
    channel_aad: Option<[u8; 32]>,
    request_count: u64,
    last_activity: Instant,
    privacy_mode: PrivacyMode,
    trust_store: TrustStore,
    proxy: Option<ProxyConfig>,
}

impl SecureRpcClient {
    pub fn new(server_addr: SocketAddr, identity: NodeIdentity) -> Self {
        Self {
            server_addr,
            identity,
            channel: None,
            stream: None,
            channel_aad: None,
            request_count: 0,
            last_activity: Instant::now(),
            privacy_mode: PrivacyMode::Normal,
            trust_store: TrustStore::new(),
            proxy: None,
        }
    }

    /// ProPrivacy: ephemeral PQ identity per connection (unlinkable)
    /// NOTE: Client IP is still visible to server. Use Tor/I2P for full anonymity.
    pub fn new_pro_privacy(server_addr: SocketAddr) -> Result<Self> {
        let identity = create_secure_rpc_identity()?;
        Ok(Self {
            server_addr,
            identity,
            channel: None,
            stream: None,
            channel_aad: None,
            request_count: 0,
            last_activity: Instant::now(),
            privacy_mode: PrivacyMode::ProPrivacy,
            trust_store: TrustStore::new(),
            proxy: None,
        })
    }

    /// ProPrivacy + Tor: ephemeral identity AND hidden IP via SOCKS5 proxy
    /// Usage: `new_pro_privacy_tor(server, "127.0.0.1:9050".parse()?)?`
    #[cfg(feature = "tor_proxy")]
    pub fn new_pro_privacy_tor(server_addr: SocketAddr, socks5_addr: SocketAddr) -> Result<Self> {
        let identity = create_secure_rpc_identity()?;
        Ok(Self {
            server_addr,
            identity,
            channel: None,
            stream: None,
            channel_aad: None,
            request_count: 0,
            last_activity: Instant::now(),
            privacy_mode: PrivacyMode::ProPrivacy,
            trust_store: TrustStore::new(),
            proxy: Some(ProxyConfig { socks5_addr }),
        })
    }

    /// Set SOCKS5 proxy (for Tor)
    #[cfg(feature = "tor_proxy")]
    pub fn set_proxy(&mut self, socks5_addr: SocketAddr) {
        self.proxy = Some(ProxyConfig { socks5_addr });
    }

    /// Add pinned server (known trusted server)
    pub fn add_pinned_server(&mut self, address: SocketAddr, falcon_pk: Vec<u8>) {
        self.trust_store.add_pinned(address, falcon_pk);
    }

    pub async fn connect(&mut self) -> Result<()> {
        let proxy_info = match &self.proxy {
            Some(p) => format!(" via SOCKS5 proxy {}", p.socks5_addr),
            None => String::new(),
        };
        
        // ProPrivacy w czerwonym kolorze (bold red)
        let mode_str = match self.privacy_mode {
            PrivacyMode::ProPrivacy => "\x1b[1;31mProPrivacy\x1b[0m".to_string(),
            PrivacyMode::Normal => "Normal".to_string(),
        };
        
        println!(
            "🔐 Connecting to secure RPC at {} (mode: {}){}",
            self.server_addr, mode_str, proxy_info
        );

        // Connect: direct or via SOCKS5 proxy
        let mut stream = self.establish_connection().await?;
        stream.set_nodelay(true)?;

        // Receive SIGNED PoW challenge
        let challenge_bytes =
            read_message_with_timeout(&mut stream, Duration::from_secs(10)).await?;
        let signed_challenge: SignedChallenge =
            bincode::deserialize(&challenge_bytes)
                .context("Failed to deserialize SignedChallenge")?;

        // Verify challenge signature
        let server_falcon_pk = signed_challenge
            .verify()
            .context("Invalid server challenge signature")?;

        // TOFU: verify or trust server
        let first_contact = self
            .trust_store
            .verify_or_trust(self.server_addr, server_falcon_pk.as_bytes())?;

        if first_contact {
            println!("   ⚠️  First contact with server — trusting on first use");
            println!(
                "   Server Falcon PK: {}...",
                hex::encode(&server_falcon_pk.as_bytes()[..32])
            );
        }

        // Solve PoW
        let pow = self.solve_pow(signed_challenge.challenge, POW_DIFFICULTY).await?;

        // ClientHello + transcript
        let (ch, transcript) = build_client_hello(&self.identity, PROTOCOL_VERSION)?;
        let ch_pow = ClientHelloWithPow { ch: ch.clone(), pow };
        let ch_pow_bytes = bincode::serialize(&ch_pow)?;
        write_message(&mut stream, &ch_pow_bytes).await?;

        // ServerHello
        let sh_bytes =
            read_message_with_timeout(&mut stream, Duration::from_secs(10)).await?;
        let sh: ServerHello =
            bincode::deserialize(&sh_bytes).context("Failed to deserialize ServerHello")?;

        let (session_keys, transcript) = handle_server_hello(
            &self.identity,
            &ch,
            &sh,
            transcript,
            PROTOCOL_VERSION,
        )
        .context("ServerHello verification failed")?;

        // ClientFinished
        let (cf, _transcript) = build_client_finished(&self.identity, transcript)?;
        let cf_bytes = bincode::serialize(&cf)?;
        write_message(&mut stream, &cf_bytes).await?;

        // ProPrivacy w czerwonym kolorze (bold red)
        let mode_str = match self.privacy_mode {
            PrivacyMode::ProPrivacy => "\x1b[1;31mProPrivacy\x1b[0m".to_string(),
            PrivacyMode::Normal => "Normal".to_string(),
        };
        println!("   ✅ PQ handshake complete! (mode: {})", mode_str);

        let channel_aad = derive_channel_aad(&session_keys);

        self.channel = Some(SecureChannel::new_client(&session_keys));
        self.channel_aad = Some(channel_aad);
        self.stream = Some(stream);
        self.last_activity = Instant::now();

        Ok(())
    }

    /// Establish TCP connection (direct or via SOCKS5 proxy)
    async fn establish_connection(&self) -> Result<TcpStream> {
        #[cfg(feature = "tor_proxy")]
        if let Some(proxy) = &self.proxy {
            use tokio_socks::tcp::Socks5Stream;

            println!("   🧅 Connecting via Tor (SOCKS5 proxy at {})...", proxy.socks5_addr);

            let stream = Socks5Stream::connect(
                proxy.socks5_addr,
                self.server_addr,
            )
            .await
            .context("Failed to connect via SOCKS5 proxy (is Tor running?)")?;

            println!("   🧅 Tor circuit established!");
            return Ok(stream.into_inner());
        }

        // Direct connection
        TcpStream::connect(self.server_addr)
            .await
            .context("Failed to connect to RPC server")
    }

    async fn solve_pow(&self, challenge: [u8; 32], difficulty: u32) -> Result<ProofOfWork> {
        use sha3::{Digest, Sha3_256};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut nonce = 0u64;
        loop {
            let mut hasher = Sha3_256::new();
            hasher.update(&challenge);
            hasher.update(&nonce.to_le_bytes());
            hasher.update(&timestamp.to_le_bytes());
            let hash = hasher.finalize();

            let mut leading_bits = 0u32;
            for &byte in hash.iter() {
                if byte == 0 {
                    leading_bits += 8;
                } else {
                    leading_bits += byte.leading_zeros();
                    break;
                }
            }

            if leading_bits >= difficulty {
                return Ok(ProofOfWork {
                    challenge,
                    nonce,
                    timestamp,
                });
            }

            nonce = nonce.wrapping_add(1);
            if nonce % 10_000 == 0 {
                tokio::task::yield_now().await;
            }
        }
    }

    pub async fn request(&mut self, req: RpcRequest) -> Result<RpcResponse> {
        if self.last_activity.elapsed() > SESSION_TIMEOUT {
            self.reconnect().await?;
        }

        let aad = self
            .channel_aad
            .ok_or_else(|| anyhow!("No channel AAD (not connected)"))?;
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| anyhow!("Not connected"))?;
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow!("No secure channel"))?;

        let req_bytes = bincode::serialize(&req)?;
        write_secure_message(stream, channel, &req_bytes, &aad).await?;

        let resp_bytes =
            read_secure_message_with_timeout(stream, channel, Duration::from_secs(30), &aad)
                .await?;
        let resp: RpcResponse =
            bincode::deserialize(&resp_bytes).context("Failed to deserialize RPC response")?;

        self.request_count += 1;
        self.last_activity = Instant::now();

        Ok(resp)
    }

    async fn reconnect(&mut self) -> Result<()> {
        self.close().await?;

        if self.privacy_mode == PrivacyMode::ProPrivacy {
            let new_identity = create_secure_rpc_identity()?;
            self.identity = new_identity;
        }

        self.connect().await
    }

    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
        }
        self.channel = None;
        self.channel_aad = None;
        Ok(())
    }
}

/* ============================================================================ */
/* Message framing + secure wrapper                                             */
/* ============================================================================ */

async fn read_message_with_timeout(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<Vec<u8>> {
    tokio::time::timeout(timeout, read_message(stream))
        .await
        .context("Read timeout")?
}

async fn read_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read message length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    ensure!(len <= MAX_MESSAGE_SIZE, "Message too large: {} bytes", len);
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("Failed to read message body")?;
    Ok(buf)
}

async fn write_message(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    ensure!(
        data.len() <= MAX_MESSAGE_SIZE,
        "Message too large: {} bytes",
        data.len()
    );
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_secure_message_with_timeout(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    timeout: Duration,
    aad: &[u8; 32],
) -> Result<Vec<u8>> {
    let ciphertext = read_message_with_timeout(stream, timeout).await?;
    let plaintext = channel
        .decrypt(&ciphertext, aad)
        .context("AEAD decryption failed")?;
    Ok(plaintext)
}

async fn write_secure_message(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    plaintext: &[u8],
    aad: &[u8; 32],
) -> Result<()> {
    let ciphertext = channel
        .encrypt(plaintext, aad)
        .context("AEAD encryption failed")?;
    write_message(stream, &ciphertext).await
}

/* ============================================================================ */
/* Helper: create RPC identity from PQ keys                                     */
/* ============================================================================ */

pub fn create_secure_rpc_identity() -> Result<NodeIdentity> {
    let (falcon_pk, falcon_sk) = crate::falcon_sigs::falcon_keypair();
    let (kyber_pk, kyber_sk) = crate::kyber_kem::kyber_keypair();
    Ok(NodeIdentity::from_keys(
        falcon_pk, falcon_sk, kyber_pk, kyber_sk,
    ))
}

/* ============================================================================ */
/* Background tasks                                                             */
/* ============================================================================ */

async fn cleanup_sessions_task(server: Arc<SecureRpcServer>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        let mut sessions = server.sessions.write().await;
        let now = Instant::now();
        sessions.retain(|_, st| now.duration_since(st.last_activity) < SESSION_TIMEOUT);
    }
}

async fn key_rotation_task(server: Arc<SecureRpcServer>) {
    let mut interval = tokio::time::interval(KEY_ROTATION_INTERVAL);
    loop {
        interval.tick().await;
        let mut last = server.last_key_rotation.write().await;
        if last.elapsed() >= KEY_ROTATION_INTERVAL {
            // TODO: key rotation logic
            *last = Instant::now();
        }
    }
}

async fn pow_cache_cleanup_task(server: Arc<SecureRpcServer>) {
    let mut interval = tokio::time::interval(POW_CACHE_CLEANUP_INTERVAL);
    loop {
        interval.tick().await;
        let mut cache = server.pow_cache.write().await;
        cache.cleanup();
    }
}

/* ============================================================================ */
/* Tests                                                                        */
/* ============================================================================ */

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Lokalny sync solver PoW (bez async), mała trudność, tylko do testów.
    fn solve_pow_sync(challenge: [u8; 32], difficulty: u32, timestamp: u64) -> ProofOfWork {
        use sha3::{Digest, Sha3_256};

        let mut nonce = 0u64;
        loop {
            let mut hasher = Sha3_256::new();
            hasher.update(&challenge);
            hasher.update(&nonce.to_le_bytes());
            hasher.update(&timestamp.to_le_bytes());
            let hash = hasher.finalize();

            let mut leading_bits = 0u32;
            for &byte in hash.iter() {
                if byte == 0 {
                    leading_bits += 8;
                } else {
                    leading_bits += byte.leading_zeros();
                    break;
                }
            }

            if leading_bits >= difficulty {
                return ProofOfWork {
                    challenge,
                    nonce,
                    timestamp,
                };
            }

            nonce = nonce.wrapping_add(1);
        }
    }

    #[test]
    fn pow_accepts_fresh_and_rejects_stale() {
        use rand::RngCore;

        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // niska trudność żeby test był szybki
        let pow = solve_pow_sync(challenge, 8, now);

        assert!(pow.verify(8), "świeży PoW powinien przejść");

        // przeterminowany timestamp
        let stale_pow = ProofOfWork {
            timestamp: now - (POW_TIMESTAMP_WINDOW + 10),
            ..pow
        };

        assert!(
            !stale_pow.verify(8),
            "stary PoW powinien zostać odrzucony przez okno czasowe"
        );
    }

    #[test]
    fn pow_cache_detects_replay_and_cleans_up() {
        use rand::RngCore;

        let mut cache = PowCache::new();

        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let pow = solve_pow_sync(challenge, 4, now);

        // pierwsze użycie – OK
        assert!(cache.check_and_insert(&pow));

        // drugie użycie – replay
        assert!(!cache.check_and_insert(&pow));

        // sztucznie "postarzamy" wpis
        {
            let key = pow.cache_key();
            if let Some(ts) = cache.timestamps.get_mut(&key) {
                *ts -= Duration::from_secs(POW_TIMESTAMP_WINDOW + 10);
            }
        }
        cache.cleanup();

        // po cleanupie cache zapomina o starym wpisie (ale samo PoW jest i tak przeterminowane)
        assert!(
            cache.check_and_insert(&pow),
            "po cleanupie cache powinien zapomnieć o starym wpisie"
        );
    }

    #[test]
    fn signed_challenge_roundtrip() {
        // generujemy klucze FALCON-512 z pqcrypto
        let (pk, sk) = pqcrypto_falcon::falcon512::keypair();

        let sc = SignedChallenge::new(&pk, &sk);
        let verified_pk = sc.verify().expect("challenge verify failed");

        assert_eq!(
            pk.as_bytes(),
            verified_pk.as_bytes(),
            "zweryfikowany klucz publiczny musi się zgadzać"
        );
    }

    #[test]
    fn trust_store_tofu_and_pinning() {
        use rand::RngCore;

        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut pk1 = vec![0u8; 32];
        let mut pk2 = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut pk1);
        rand::thread_rng().fill_bytes(&mut pk2);

        let mut store = TrustStore::new();

        // pierwsze użycie – TOFU
        let first = store.verify_or_trust(addr, &pk1).expect("verify_or_trust failed");
        assert!(first, "pierwsze użycie powinno być traktowane jako TOFU");

        // drugie użycie z tym samym PK – OK
        let first2 = store.verify_or_trust(addr, &pk1).expect("verify_or_trust failed");
        assert!(!first2, "kolejne użycie znanego klucza nie jest TOFU");

        // próba z innym PK – powinna się wywalić (podejrzenie MITM)
        let err = store.verify_or_trust(addr, &pk2).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SERVER KEY CHANGED"),
            "zmiana klucza serwera powinna być traktowana jako błąd bezpieczeństwa"
        );
    }

    #[test]
    fn rate_limiter_basic_behavior() {
        let mut rl = RateLimiter::new(2, 10);

        assert!(rl.try_consume(1.0));
        assert!(rl.try_consume(1.0));
        assert!(
            !rl.try_consume(1.0),
            "po zużyciu capacity nie powinno być tokenów"
        );

        std::thread::sleep(Duration::from_millis(150));
        assert!(
            rl.try_consume(1.0),
            "po chwili część tokenów powinna się odnowić"
        );
    }

    /// Lokalna implementacja derive_client_label niezależna od NodeId,
    /// testuje jedynie semantykę PrivacyMode.
    fn derive_client_label_local(
        mode: PrivacyMode,
        server_salt: &[u8; 32],
        client_id: &[u8],
    ) -> Option<[u8; 32]> {
        match mode {
            PrivacyMode::Normal => {
                use blake3::Hasher;
                let mut hasher = Hasher::new();
                hasher.update(server_salt);
                hasher.update(client_id);
                let hash = hasher.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(hash.as_bytes());
                Some(out)
            }
            PrivacyMode::ProPrivacy => None,
        }
    }

    #[test]
    fn privacy_mode_affects_client_label() {
        use rand::RngCore;

        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let client_a = b"client-a-unique-id-AAAAAAAA";
        let client_b = b"client-b-unique-id-BBBBBBBB";

        let la1 = derive_client_label_local(PrivacyMode::Normal, &salt, client_a).unwrap();
        let la2 = derive_client_label_local(PrivacyMode::Normal, &salt, client_a).unwrap();
        let lb = derive_client_label_local(PrivacyMode::Normal, &salt, client_b).unwrap();

        assert_eq!(
            la1, la2,
            "ten sam klient musi mieć ten sam label w trybie Normal"
        );
        assert_ne!(
            la1, lb,
            "różni klienci powinni mieć różne labele (z dużym prawdopodobieństwem)"
        );

        assert!(
            derive_client_label_local(PrivacyMode::ProPrivacy, &salt, client_a).is_none(),
            "w ProPrivacy nie powinno być żadnego labela do linkowania sesji"
        );
    }

    /// Testuje, że klient i serwer, po pełnym PQ handshaku, wyprowadzają identyczne AAD.
    #[test]
    fn channel_aad_is_symmetric_for_handshake() {
        // serwer i klient dostają swoje NodeIdentity
        let server_id = create_secure_rpc_identity().expect("server_id");
        let client_id = create_secure_rpc_identity().expect("client_id");

        // klient: ClientHello
        let (ch, transcript_client) =
            build_client_hello(&client_id, PROTOCOL_VERSION).expect("build_client_hello");

        // serwer: handle_client_hello
        let transcript_server = TranscriptHasher::new();
        let (sh, session_keys_server, transcript_server2) =
            handle_client_hello(&server_id, &ch, PROTOCOL_VERSION, transcript_server, None)
                .expect("handle_client_hello");

        // klient: handle_server_hello
        let (session_keys_client, transcript_client2) = handle_server_hello(
            &client_id,
            &ch,
            &sh,
            transcript_client,
            PROTOCOL_VERSION,
        )
        .expect("handle_server_hello");

        // klient: ClientFinished
        let (cf, _transcript_client3) =
            build_client_finished(&client_id, transcript_client2).expect("build_client_finished");

        // serwer: verify_client_finished
        let _transcript_server3 =
            verify_client_finished(&ch.falcon_pk, transcript_server2, &cf)
                .expect("verify_client_finished");

        // teraz obie strony mają swoje session_keys_*,
        // więc powinny wyprowadzić identyczne AAD
        let aad_server = super::derive_channel_aad(&session_keys_server);
        let aad_client = super::derive_channel_aad(&session_keys_client);

        assert_eq!(
            aad_server, aad_client,
            "channel AAD musi być identyczny po obu stronach"
        );

        // sanity check: inne session_keys → inne AAD
        let other_id = create_secure_rpc_identity().expect("other_id");
        let (ch2, _t2) =
            build_client_hello(&other_id, PROTOCOL_VERSION).expect("build_client_hello 2");
        let ts2 = TranscriptHasher::new();
        let (_sh2, session_keys_other, _ts2) =
            handle_client_hello(&server_id, &ch2, PROTOCOL_VERSION, ts2, None)
                .expect("handle_client_hello 2");

        let aad_other = super::derive_channel_aad(&session_keys_other);
        assert_ne!(aad_server, aad_other, "inne session_keys → inne AAD");
    }
}
