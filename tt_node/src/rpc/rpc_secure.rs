#![forbid(unsafe_code)]

//! Secure PQ RPC using PRO P2P (Falcon + Kyber + XChaCha20-Poly1305)
//!
//! - Handshake: ClientHello (Falcon+Kyber+PoW) → ServerHello(Falcon sig, Kyber CT) → ClientFinished(Falcon sig)
//! - PoW: lekki SHA3-256 (anti-DDoS dla RPC, NIE konsensus – tam RandomX)
//! - Kanał: XChaCha20-Poly1305, dwa klucze kierunkowe
//! - Rate limiting + limit połączeń per IP.

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};

use crate::node_core::NodeCore;
use crate::node_id::NodeId;
use crate::p2p::secure::{
    build_client_finished, build_client_hello, handle_client_hello, handle_server_hello,
    verify_client_finished, ClientFinished, ClientHello, NodeIdentity, ServerHello,
    TranscriptHasher, PROTOCOL_VERSION,
};
use crate::p2p::channel::SecureChannel;
use crate::tx_stark::SignedStarkTx;

/* ============================================================================ */
/* Security constants                                                           */
/* ============================================================================ */

const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
const SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_CONNECTIONS_PER_IP: usize = 10;
const MAX_REQUESTS_PER_SECOND: u32 = 100;
const POW_DIFFICULTY: u32 = 20; // do testów obniż np. do 10
const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const MIN_RENEGOTIATION_INTERVAL: Duration = Duration::from_secs(60);

/* ============================================================================ */
/* PoW                                                                          */
/* ============================================================================ */

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfWork {
    pub challenge: [u8; 32],
    pub nonce: u64,
    pub timestamp: u64,
}

impl ProofOfWork {
    /// Nowe wyzwanie (tylko 32-bajtowy challenge).
    pub fn new_challenge() -> [u8; 32] {
        let mut challenge = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut challenge);
        challenge
    }

    /// Weryfikacja PoW (leading zero bits >= difficulty).
    pub fn verify(&self, difficulty: u32) -> bool {
        use sha3::{Digest, Sha3_256};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if (now as i64 - self.timestamp as i64).abs() > 300 {
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
}

/// Połączony komunikat: ClientHello + PoW.
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
    StarkTxSubmitted {
        tx_id: String,
        accepted: bool,
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
/* Server                                                                      */
/* ============================================================================ */

#[derive(Debug, Clone)]
struct SessionState {
    session_id: [u8; 32],
    created_at: Instant,
    last_activity: Instant,
    request_count: u64,
    bytes_transferred: u64,
    client_id: NodeId,
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
}

impl SecureRpcServer {
    pub fn new(
        rpc_port: u16,
        identity: NodeIdentity,
        is_validator: bool,
        node: Arc<NodeCore>,
    ) -> Self {
        let address = SocketAddr::from(([0, 0, 0, 0], rpc_port));
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
        }
    }

    pub async fn start(self) -> Result<()> {
        let listener = TcpListener::bind(self.address)
            .await
            .context("Failed to bind RPC port")?;
        println!("🔐 Secure PQ RPC listening on {}", self.address);

        let identity = self.identity.read().await;
        println!("   Node ID: {}", hex::encode(&identity.node_id));
        drop(identity);

        let server = Arc::new(self);

        // background tasks
        {
            let s = Arc::clone(&server);
            tokio::spawn(async move { s.cleanup_sessions_task().await });
        }
        {
            let s = Arc::clone(&server);
            tokio::spawn(async move { s.key_rotation_task().await });
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

        // rate limit per IP
        {
            let mut rls = self.rate_limiters.write().await;
            let rl = rls
                .entry(addr.ip())
                .or_insert_with(|| RateLimiter::new(MAX_REQUESTS_PER_SECOND * 2, MAX_REQUESTS_PER_SECOND));
            if !rl.try_consume(1.0) {
                bail!("Rate limit exceeded");
            }
        }

        // === PoW challenge ===
        let pow_challenge = ProofOfWork::new_challenge();
        write_message(&mut stream, &pow_challenge).await?;

        // ClientHello + PoW
        let ch_pow_bytes =
            read_message_with_timeout(&mut stream, Duration::from_secs(30)).await?;
        let ch_pow: ClientHelloWithPow =
            bincode::deserialize(&ch_pow_bytes).context("Failed to deserialize ClientHelloWithPow")?;

        // verify PoW
        ensure!(
            ch_pow.pow.challenge == pow_challenge,
            "PoW challenge mismatch"
        );
        if !ch_pow.pow.verify(POW_DIFFICULTY) {
            self.metrics.write().await.failed_authentications += 1;
            bail!("Invalid proof-of-work");
        }

        let ch = ch_pow.ch;
        println!("   ClientHello from {}", hex::encode(&ch.node_id));

        // === PQ handshake ===
        let identity = self.identity.read().await;
        let transcript = TranscriptHasher::new();
        let (sh, session_keys, transcript) =
            handle_client_hello(&identity, &ch, PROTOCOL_VERSION, transcript)
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

        println!("   ✅ PQ handshake complete!");

        let session_id = self.generate_session_id(&ch.node_id);
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
                    client_id: ch.node_id,
                },
            );
        }

        let mut channel = SecureChannel::new_server(&session_keys);
        let mut last_renegotiation = Instant::now();

        loop {
            // session timeout
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

            if last_renegotiation.elapsed() > MIN_RENEGOTIATION_INTERVAL
                && channel.should_renegotiate()
            {
                // TODO: renegocjacja kluczy
                last_renegotiation = Instant::now();
            }

            let req_bytes = match read_secure_message_with_timeout(
                &mut stream,
                &mut channel,
                Duration::from_secs(60),
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

            // per-request rate limit
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
                    write_secure_message(&mut stream, &mut channel, &resp_bytes).await?;
                    continue;
                }
            }

            // deserializacja requestu
            let request: RpcRequest = match bincode::deserialize(&req_bytes) {
                Ok(r) => r,
                Err(e) => {
                    let err = RpcResponse::Error {
                        code: 400,
                        message: format!("Invalid request: {}", e),
                        data: None,
                    };
                    let resp_bytes = bincode::serialize(&err)?;
                    write_secure_message(&mut stream, &mut channel, &resp_bytes).await?;
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
            write_secure_message(&mut stream, &mut channel, &resp_bytes).await?;
            self.update_session_metrics(&session_id, resp_bytes.len()).await;
        }

        self.sessions.write().await.remove(&session_id);
        Ok(())
    }

    fn generate_session_id(&self, client_id: &NodeId) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(client_id);
        h.update(&Instant::now().elapsed().as_nanos().to_le_bytes());
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
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
            _ => RpcResponse::Error {
                code: 501,
                message: "Not implemented".into(),
                data: None,
            },
        }
    }

/* ============================================================================ */
/* Client                                                                       */
/* ============================================================================ */

pub struct SecureRpcClient {
    server_addr: SocketAddr,
    identity: NodeIdentity,
    channel: Option<SecureChannel>,
    stream: Option<TcpStream>,
    session_id: Option<[u8; 32]>,
    request_count: u64,
    last_activity: Instant,
}

impl SecureRpcClient {
    pub fn new(server_addr: SocketAddr, identity: NodeIdentity) -> Self {
        Self {
            server_addr,
            identity,
            channel: None,
            stream: None,
            session_id: None,
            request_count: 0,
            last_activity: Instant::now(),
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        println!("🔐 Connecting to secure RPC at {}", self.server_addr);
        let mut stream = TcpStream::connect(self.server_addr)
            .await
            .context("Failed to connect to RPC server")?;
        stream.set_nodelay(true)?;

        // PoW challenge
        let pow_challenge_bytes =
            read_message_with_timeout(&mut stream, Duration::from_secs(10)).await?;
        let pow_challenge: [u8; 32] = pow_challenge_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Invalid PoW challenge length"))?;

        let pow = self.solve_pow(pow_challenge, POW_DIFFICULTY).await?;

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

        println!("   ✅ PQ handshake complete!");

        self.channel = Some(SecureChannel::new_client(&session_keys));
        self.stream = Some(stream);
        self.session_id = Some(self.generate_session_id());
        self.last_activity = Instant::now();

        Ok(())
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

    fn generate_session_id(&self) -> [u8; 32] {
        use rand::RngCore;
        let mut id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    pub async fn request(&mut self, req: RpcRequest) -> Result<RpcResponse> {
        if self.last_activity.elapsed() > SESSION_TIMEOUT {
            self.reconnect().await?;
        }

        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| anyhow!("Not connected"))?;
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow!("No secure channel"))?;

        let req_bytes = bincode::serialize(&req)?;
        write_secure_message(stream, channel, &req_bytes).await?;

        let resp_bytes =
            read_secure_message_with_timeout(stream, channel, Duration::from_secs(30)).await?;
        let resp: RpcResponse =
            bincode::deserialize(&resp_bytes).context("Failed to deserialize RPC response")?;

        self.request_count += 1;
        self.last_activity = Instant::now();

        Ok(resp)
    }

    async fn reconnect(&mut self) -> Result<()> {
        self.close().await?;
        self.connect().await
    }

    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.shutdown().await?;
        }
        self.channel = None;
        self.session_id = None;
        Ok(())
    }
}

/* ============================================================================ */
/* Message framing + secure wrapper                                            */
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
    ensure!(len <= MAX_MESSAGE_SIZE, "Message too large");
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("Failed to read message body")?;
    Ok(buf)
}

async fn write_message(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    ensure!(data.len() <= MAX_MESSAGE_SIZE, "Message too large");
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
) -> Result<Vec<u8>> {
    let ciphertext = read_message_with_timeout(stream, timeout).await?;
    let plaintext = channel
        .decrypt(&ciphertext, b"")
        .context("AEAD decryption failed")?;
    Ok(plaintext)
}

async fn write_secure_message(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    plaintext: &[u8],
) -> Result<()> {
    let ciphertext = channel
        .encrypt(plaintext, b"")
        .context("AEAD encryption failed")?;
    write_message(stream, &ciphertext).await
}

/* ============================================================================ */
/* Helper: create RPC identity from PQ keys                                    */
/* ============================================================================ */

/// Buduje RPC identity z losowych PQ kluczy.
pub fn create_secure_rpc_identity() -> Result<NodeIdentity> {
    let (falcon_pk, falcon_sk) = crate::falcon_sigs::falcon_keypair();
    let (kyber_pk, kyber_sk) = crate::kyber_kem::kyber_keypair();
    Ok(NodeIdentity::from_keys(falcon_pk, falcon_sk, kyber_pk, kyber_sk))
}
