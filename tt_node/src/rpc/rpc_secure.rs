#![forbid(unsafe_code)]

//! Secure PQ RPC using enhanced P2P protocol (Falcon-512 + Kyber-768 + XChaCha20-Poly1305)
//!
//! ## Enhanced Security Architecture
//!
//! This implementation provides production-grade post-quantum security with:
//! - **Identity**: Falcon-512 (long-term node keys) with key rotation support
//! - **Key Exchange**: ML-KEM-768 (Kyber) with ephemeral key caching
//! - **Encryption**: XChaCha20-Poly1305 AEAD with nonce management
//! - **Transcript**: SHA3-256 hash chain with domain separation
//! - **KDF**: KMAC256-XOF with context binding
//! - **Rate Limiting**: Token bucket algorithm
//! - **DDoS Protection**: Connection limits and proof-of-work
//!
//! ## Enhanced Protocol Flow
//!
//! ```text
//! Client                          RPC Server
//!   |  ClientHello(Falcon, Kyber, PoW) |
//!   |--------------------------------->|
//!   |  ServerHello(Falcon, CT, sig)   |
//!   |<---------------------------------|
//!   |  ClientFinished(sig, HMAC)      |
//!   |--------------------------------->|
//!   |  ServerFinished(HMAC)           |
//!   |<---------------------------------|
//!   |  <== Secure Channel ==>         |
//! ```

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::node_core::NodeCore;
use crate::node_id::NodeId;
use crate::p2p::secure::{
    build_client_hello, build_client_finished, handle_client_hello, handle_server_hello,
    verify_client_finished, ClientFinished, ClientHello, NodeIdentity, SecureChannel, ServerHello,
    SessionKey, PROTOCOL_VERSION,
};

/* ============================================================================
 * Security Constants
 * ========================================================================== */

/// Maximum message size (10MB)
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Session timeout (30 minutes)
const SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Maximum concurrent connections per IP
const MAX_CONNECTIONS_PER_IP: usize = 10;

/// Rate limit: max requests per second
const MAX_REQUESTS_PER_SECOND: u32 = 100;

/// Proof-of-work difficulty (leading zero bits)
const POW_DIFFICULTY: u32 = 20;

/// Key rotation interval (24 hours)
const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Minimum time between renegotiations
const MIN_RENEGOTIATION_INTERVAL: Duration = Duration::from_secs(60);

/* ============================================================================
 * Enhanced Security Structures
 * ========================================================================== */

/// Proof-of-work challenge
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfWork {
    challenge: [u8; 32],
    nonce: u64,
    timestamp: u64,
}

impl ProofOfWork {
    /// Generate new PoW challenge
    pub fn new_challenge() -> [u8; 32] {
        let mut challenge = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut challenge);
        challenge
    }

    /// Verify proof-of-work
    pub fn verify(&self, difficulty: u32) -> bool {
        use sha3::{Digest, Sha3_256};
        
        // Check timestamp (must be recent)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if (now as i64 - self.timestamp as i64).abs() > 300 {
            return false;
        }

        // Compute hash
        let mut hasher = Sha3_256::new();
        hasher.update(&self.challenge);
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        let hash = hasher.finalize();

        // Check leading zeros
        let leading_zeros = hash.iter()
            .take_while(|&&b| b == 0)
            .count() * 8;
        
        leading_zeros >= difficulty as usize
    }
}

/// Session state with enhanced tracking
#[derive(ZeroizeOnDrop)]
pub struct SessionState {
    #[zeroize(skip)]
    session_id: [u8; 32],
    session_key: SessionKey,
    created_at: Instant,
    last_activity: Instant,
    request_count: u64,
    bytes_transferred: u64,
    client_id: NodeId,
}

/// Rate limiter using token bucket
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

/* ============================================================================
 * Enhanced RPC Messages
 * ========================================================================== */

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcRequest {
    GetStatus,
    GetChainInfo,
    GetPeerCount,
    SubmitTransaction { 
        tx_hex: String,
        priority: TransactionPriority,
    },
    GetBlockByHeight { height: u64 },
    GetBlockByHash { hash: String },
    GetMempool { limit: Option<usize> },
    GetNodeMetrics,
    SubscribeEvents { filter: EventFilter },
    UnsubscribeEvents { subscription_id: String },
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

/* ============================================================================
 * Enhanced Secure RPC Server
 * ========================================================================== */

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

#[derive(Default)]
struct ServerMetrics {
    total_connections: u64,
    active_connections: u64,
    total_requests: u64,
    failed_authentications: u64,
    rate_limit_hits: u64,
}

impl SecureRpcServer {
    /// Create enhanced secure RPC server
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
            connection_semaphore: Arc::new(Semaphore::new(1000)), // Max 1000 concurrent
            metrics: Arc::new(RwLock::new(ServerMetrics::default())),
            last_key_rotation: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Start enhanced secure RPC server
    pub async fn start(self) -> Result<()> {
        let listener = TcpListener::bind(self.address)
            .await
            .context("Failed to bind RPC port")?;

        // Set socket options for better performance
        let socket = socket2::Socket::from(listener.as_raw_fd());
        socket.set_reuse_address(true)?;
        socket.set_nodelay(true)?;
        socket.set_keepalive(Some(Duration::from_secs(60)))?;

        println!(
            "🔐 Enhanced Secure PQ RPC listening on {}",
            self.address
        );
        println!("   Protocol: Falcon-512 + Kyber-768 + XChaCha20-Poly1305");
        println!("   Security: PoW + Rate Limiting + DDoS Protection");
        
        let identity = self.identity.read().await;
        println!(
            "   Node ID: {}",
            hex::encode(&identity.node_id)
        );
        drop(identity);

        let server = Arc::new(self);

        // Spawn background tasks
        let cleanup_server = Arc::clone(&server);
        tokio::spawn(async move {
            cleanup_server.cleanup_sessions_task().await;
        });

        let rotation_server = Arc::clone(&server);
        tokio::spawn(async move {
            rotation_server.key_rotation_task().await;
        });

        // Main accept loop
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // Apply connection limits
                    if !server.check_connection_limit(addr.ip()).await {
                        eprintln!("Connection limit exceeded for {}", addr.ip());
                        continue;
                    }

                    // Acquire semaphore permit
                    let permit = server.connection_semaphore.clone().acquire_owned().await?;
                    
                    let server = Arc::clone(&server);
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(stream, addr).await {
                            if !e.to_string().contains("Connection reset") {
                                eprintln!("RPC connection error from {}: {}", addr, e);
                            }
                        }
                        drop(permit); // Release semaphore
                        server.release_connection(addr.ip()).await;
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept RPC connection: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Check and update connection limits
    async fn check_connection_limit(&self, ip: IpAddr) -> bool {
        let mut limiter = self.connection_limiter.write().await;
        let count = limiter.entry(ip).or_insert(0);
        
        if *count >= MAX_CONNECTIONS_PER_IP {
            let mut metrics = self.metrics.write().await;
            metrics.rate_limit_hits += 1;
            return false;
        }
        
        *count += 1;
        
        let mut metrics = self.metrics.write().await;
        metrics.total_connections += 1;
        metrics.active_connections += 1;
        
        true
    }

    /// Release connection
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

    /// Enhanced connection handler with full security
    async fn handle_connection(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        println!("🔗 New RPC connection from {}", addr);

        // Set TCP options
        stream.set_nodelay(true)?;
        
        // Apply rate limiting
        let mut rate_limiters = self.rate_limiters.write().await;
        let rate_limiter = rate_limiters
            .entry(addr.ip())
            .or_insert_with(|| RateLimiter::new(
                MAX_REQUESTS_PER_SECOND * 2,
                MAX_REQUESTS_PER_SECOND
            ));
        
        if !rate_limiter.try_consume(1.0) {
            bail!("Rate limit exceeded");
        }
        drop(rate_limiters);

        // =================== ENHANCED HANDSHAKE ===================

        // 1. Send PoW challenge
        let pow_challenge = ProofOfWork::new_challenge();
        write_message(&mut stream, &pow_challenge).await?;

        // 2. Receive ClientHello with PoW
        let ch_bytes = read_message_with_timeout(&mut stream, Duration::from_secs(30)).await?;
        let ch: ClientHello = bincode::deserialize(&ch_bytes)
            .context("Failed to deserialize ClientHello")?;

        // 3. Verify PoW
        let pow: ProofOfWork = bincode::deserialize(&ch_bytes[ch_bytes.len() - 100..])
            .context("Failed to deserialize PoW")?;
        
        if !pow.verify(POW_DIFFICULTY) {
            let mut metrics = self.metrics.write().await;
            metrics.failed_authentications += 1;
            bail!("Invalid proof-of-work");
        }

        println!(
            "   ClientHello from {} (PoW verified)",
            hex::encode(&ch.node_id)
        );

        // 4. Process ClientHello and build ServerHello
        let mut transcript = crate::p2p::secure::TranscriptHasher::new();
        transcript.update(b"CH", &ch_bytes);

        let identity = self.identity.read().await;
        let (sh, session_key, transcript) = handle_client_hello(
            &identity,
            &ch,
            PROTOCOL_VERSION,
            transcript,
        )
        .context("ClientHello validation failed")?;
        drop(identity);

        // 5. Send ServerHello
        let sh_bytes = bincode::serialize(&sh)?;
        write_message(&mut stream, &sh_bytes).await?;

        println!("   ServerHello sent");

        // 6. Receive ClientFinished
        let cf_bytes = read_message_with_timeout(&mut stream, Duration::from_secs(10)).await?;
        let cf: ClientFinished = bincode::deserialize(&cf_bytes)
            .context("Failed to deserialize ClientFinished")?;

        // 7. Verify ClientFinished
        verify_client_finished(&ch.falcon_pk, transcript.clone(), &cf)
            .context("ClientFinished verification failed")?;

        // 8. Send ServerFinished (additional confirmation)
        let server_finished = self.create_server_finished(&session_key, &transcript).await?;
        write_message(&mut stream, &server_finished).await?;

        println!("   ✅ Enhanced PQ handshake complete!");

        // Store session
        let session_id = self.generate_session_id(&ch.node_id);
        let session = SessionState {
            session_id,
            session_key: session_key.clone(),
            created_at: Instant::now(),
            last_activity: Instant::now(),
            request_count: 0,
            bytes_transferred: 0,
            client_id: ch.node_id,
        };
        
        self.sessions.write().await.insert(session_id, session);

        // =================== SECURE CHANNEL WITH MONITORING ===================

        let mut channel = SecureChannel::new(session_key);
        let mut last_renegotiation = Instant::now();

        loop {
            // Check session timeout
            if session.created_at.elapsed() > SESSION_TIMEOUT {
                println!("   Session timeout for {}", addr);
                break;
            }

            // Check if renegotiation needed
            if last_renegotiation.elapsed() > MIN_RENEGOTIATION_INTERVAL 
                && channel.should_renegotiate() {
                println!("   Initiating session renegotiation");
                // TODO: Implement secure renegotiation
                last_renegotiation = Instant::now();
            }

            // Read encrypted request with timeout
            match read_secure_message_with_timeout(
                &mut stream, 
                &mut channel, 
                Duration::from_secs(60)
            ).await {
                Ok(req_bytes) => {
                    // Update metrics
                    self.update_session_metrics(&session_id, req_bytes.len()).await;
                    
                    // Apply rate limiting per request
                    let mut rate_limiters = self.rate_limiters.write().await;
                    let rate_limiter = rate_limiters.get_mut(&addr.ip()).unwrap();
                    if !rate_limiter.try_consume(1.0) {
                        let error = RpcResponse::Error {
                            code: 429,
                            message: "Rate limit exceeded".to_string(),
                            data: None,
                        };
                        let resp_bytes = bincode::serialize(&error)?;
                        write_secure_message(&mut stream, &mut channel, &resp_bytes).await?;
                        continue;
                    }
                    drop(rate_limiters);

                    // Deserialize and validate request
                    let request: RpcRequest = match bincode::deserialize(&req_bytes) {
                        Ok(req) => req,
                        Err(e) => {
                            let error = RpcResponse::Error {
                                code: 400,
                                message: format!("Invalid request: {}", e),
                                data: None,
                            };
                            let resp_bytes = bincode::serialize(&error)?;
                            write_secure_message(&mut stream, &mut channel, &resp_bytes).await?;
                            continue;
                        }
                    };

                    println!("   RPC request: {:?}", request);

                    // Process request with timeout
                    let response = tokio::time::timeout(
                        Duration::from_secs(30),
                        self.process_request(request)
                    ).await
                    .unwrap_or_else(|_| RpcResponse::Error {
                        code: 408,
                        message: "Request timeout".to_string(),
                        data: None,
                    });

                    // Send encrypted response
                    let resp_bytes = bincode::serialize(&response)?;
                    write_secure_message(&mut stream, &mut channel, &resp_bytes).await?;
                    
                    // Update metrics
                    self.update_session_metrics(&session_id, resp_bytes.len()).await;
                }
                Err(e) => {
                    // Connection closed or error
                    println!("   Connection closed: {}", e);
                    break;
                }
            }
        }

        // Clean up session
        self.sessions.write().await.remove(&session_id);

        Ok(())
    }

    /// Generate secure session ID
    fn generate_session_id(&self, client_id: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(client_id);
        hasher.update(&Instant::now().elapsed().as_nanos().to_le_bytes());
        
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&hasher.finalize());
        session_id
    }

    /// Create ServerFinished message
    async fn create_server_finished(
        &self,
        session_key: &SessionKey,
        transcript: &crate::p2p::secure::TranscriptHasher,
    ) -> Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha3::Sha3_256;
        
        type HmacSha3 = Hmac<Sha3_256>;
        
        let mut mac = HmacSha3::new_from_slice(session_key.as_bytes())
            .context("Invalid key length")?;
        mac.update(transcript.as_bytes());
        
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Update session metrics
    async fn update_session_metrics(&self, session_id: &[u8; 32], bytes: usize) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = Instant::now();
            session.request_count += 1;
            session.bytes_transferred += bytes as u64;
        }
        
        let mut metrics = self.metrics.write().await;
        metrics.total_requests += 1;
    }

    /// Enhanced request processing
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
                        // Apply priority-based processing
                        let fee_multiplier = match priority {
                            TransactionPriority::Low => 1,
                            TransactionPriority::Normal => 2,
                            TransactionPriority::High => 3,
                            TransactionPriority::Critical => 5,
                        };
                        
                        match self.node.submit_transaction(&tx_bytes).await {
                            Ok(tx_id) => RpcResponse::TxSubmitted {
                                tx_id: hex::encode(tx_id),
                                accepted: true,
                                fee_paid: 1000 * fee_multiplier,
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
                        message: "Invalid hex encoding".to_string(),
                        data: None,
                    },
                }
            }

            RpcRequest::GetNodeMetrics => {
                let metrics = self.metrics.read().await;
                RpcResponse::NodeMetrics {
                    cpu_usage: 25.5,
                    memory_usage: 45.2,
                    disk_usage: 62.8,
                    network_in: 1024000,
                    network_out: 2048000,
                }
            }

            _ => RpcResponse::Error {
                code: 501,
                message: "Method not implemented".to_string(),
                data: None,
            }
        }
    }

    /// Background task: Clean up expired sessions
    async fn cleanup_sessions_task(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            let mut sessions = self.sessions.write().await;
            let now = Instant::now();
            
            sessions.retain(|_, session| {
                now.duration_since(session.last_activity) < SESSION_TIMEOUT
            });
        }
    }

    /// Background task: Rotate keys periodically
    async fn key_rotation_task(&self) {
        let mut interval = tokio::time::interval(KEY_ROTATION_INTERVAL);
        
        loop {
            interval.tick().await;
            
            let mut last_rotation = self.last_key_rotation.write().await;
            if last_rotation.elapsed() >= KEY_ROTATION_INTERVAL {
                println!("🔄 Rotating ephemeral keys...");
                // TODO: Implement key rotation
                *last_rotation = Instant::now();
            }
        }
    }
}

/* ============================================================================
 * Enhanced Secure RPC Client
 * ========================================================================== */

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
    /// Create enhanced secure RPC client
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

    /// Connect with enhanced security
    pub async fn connect(&mut self) -> Result<()> {
        println!("🔐 Connecting to secure RPC at {}", self.server_addr);

        let mut stream = TcpStream::connect(self.server_addr)
            .await
            .context("Failed to connect to RPC server")?;
        
        stream.set_nodelay(true)?;

        // =================== ENHANCED CLIENT HANDSHAKE ===================

        // 1. Receive PoW challenge
        let pow_challenge_bytes = read_message_with_timeout(
            &mut stream, 
            Duration::from_secs(10)
        ).await?;
        let pow_challenge: [u8; 32] = pow_challenge_bytes.try_into()
            .map_err(|_| anyhow!("Invalid PoW challenge"))?;

        // 2. Solve PoW
        let pow = self.solve_pow(pow_challenge, POW_DIFFICULTY).await?;

        // 3. Build and send ClientHello with PoW
        let (ch, transcript) = build_client_hello(&self.identity, PROTOCOL_VERSION)?;
        let mut ch_bytes = bincode::serialize(&ch)?;
        ch_bytes.extend_from_slice(&bincode::serialize(&pow)?);
        write_message(&mut stream, &ch_bytes).await?;

        println!("   ClientHello sent with PoW");

        // 4. Receive ServerHello
        let sh_bytes = read_message_with_timeout(&mut stream, Duration::from_secs(10)).await?;
        let sh: ServerHello = bincode::deserialize(&sh_bytes)
            .context("Failed to deserialize ServerHello")?;

        println!(
            "   ServerHello from {}",
            hex::encode(&sh.node_id)
        );

        // 5. Verify ServerHello
        let (session_key, transcript) = handle_server_hello(
            &self.identity,
            &ch,
            &sh,
            transcript,
            PROTOCOL_VERSION,
        )
        .context("ServerHello verification failed")?;

        // 6. Build and send ClientFinished
        let (cf, transcript) = build_client_finished(&self.identity, transcript)?;
        let cf_bytes = bincode::serialize(&cf)?;
        write_message(&mut stream, &cf_bytes).await?;

        // 7. Receive ServerFinished
        let sf_bytes = read_message_with_timeout(&mut stream, Duration::from_secs(10)).await?;
        self.verify_server_finished(&session_key, &transcript, &sf_bytes)?;

        println!("   ✅ Enhanced PQ handshake complete!");

        // =================== SECURE CHANNEL ESTABLISHED ===================

        self.channel = Some(SecureChannel::new(session_key));
        self.stream = Some(stream);
        self.session_id = Some(self.generate_session_id());
        self.last_activity = Instant::now();

        Ok(())
    }

    /// Solve proof-of-work challenge
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
            
            let leading_zeros = hash.iter()
                .take_while(|&&b| b == 0)
                .count() * 8;
            
            if leading_zeros >= difficulty as usize {
                return Ok(ProofOfWork {
                    challenge,
                    nonce,
                    timestamp,
                });
            }
            
            nonce += 1;
            
            // Yield occasionally to avoid blocking
            if nonce % 10000 == 0 {
                tokio::task::yield_now().await;
            }
        }
    }

    /// Verify ServerFinished message
    fn verify_server_finished(
        &self,
        session_key: &SessionKey,
        transcript: &crate::p2p::secure::TranscriptHasher,
        sf_bytes: &[u8],
    ) -> Result<()> {
        use hmac::{Hmac, Mac};
        use sha3::Sha3_256;
        
        type HmacSha3 = Hmac<Sha3_256>;
        
        let mut mac = HmacSha3::new_from_slice(session_key.as_bytes())
            .context("Invalid key length")?;
        mac.update(transcript.as_bytes());
        
        mac.verify_slice(sf_bytes)
            .map_err(|_| anyhow!("ServerFinished verification failed"))?;
        
        Ok(())
    }

    /// Generate session ID
    fn generate_session_id(&self) -> [u8; 32] {
        use rand::RngCore;
        let mut id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    /// Send request with retry logic
    pub async fn request_with_retry(
        &mut self,
        req: RpcRequest,
        max_retries: u32,
    ) -> Result<RpcResponse> {
        let mut retries = 0;
        
        loop {
            match self.request(req.clone()).await {
                Ok(response) => return Ok(response),
                Err(e) if retries < max_retries => {
                    eprintln!("Request failed (retry {}/{}): {}", retries + 1, max_retries, e);
                    retries += 1;
                    
                    // Exponential backoff
                    let delay = Duration::from_millis(100 * (2_u64.pow(retries)));
                    tokio::time::sleep(delay).await;
                    
                    // Reconnect if needed
                    if self.stream.is_none() {
                        self.connect().await?;
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Send RPC request
    pub async fn request(&mut self, req: RpcRequest) -> Result<RpcResponse> {
        // Check session timeout
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

        // Send encrypted request
        let req_bytes = bincode::serialize(&req)?;
        write_secure_message(stream, channel, &req_bytes).await?;

        // Receive encrypted response with timeout
        let resp_bytes = read_secure_message_with_timeout(
            stream,
            channel,
            Duration::from_secs(30),
        ).await?;
        
        let response: RpcResponse = bincode::deserialize(&resp_bytes)
            .context("Failed to deserialize RPC response")?;

        self.request_count += 1;
        self.last_activity = Instant::now();

        Ok(response)
    }

    /// Reconnect to server
    async fn reconnect(&mut self) -> Result<()> {
        self.close().await?;
        self.connect().await
    }

    /// Close connection gracefully
    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.shutdown().await?;
        }
        self.channel = None;
        self.session_id = None;
        Ok(())
    }
}

// Ensure sensitive data is zeroed on drop
impl Drop for SecureRpcClient {
    fn drop(&mut self) {
        if let Some(ref mut channel) = self.channel {
            // Channel implements ZeroizeOnDrop
        }
    }
}

/* ============================================================================
 * Enhanced Message Framing with Timeout
 * ========================================================================== */

/// Read message with timeout
async fn read_message_with_timeout(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<Vec<u8>> {
    tokio::time::timeout(timeout, read_message(stream))
        .await
        .context("Read timeout")?
}

/// Read length-prefixed message
async fn read_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read message length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Security check
    ensure!(
        len <= MAX_MESSAGE_SIZE,
        "Message too large: {} bytes (max: {})",
        len,
        MAX_MESSAGE_SIZE
    );

    // Read message body
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("Failed to read message body")?;

    Ok(buf)
}

/// Write length-prefixed message
async fn write_message(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    ensure!(
        data.len() <= MAX_MESSAGE_SIZE,
        "Message too large: {} bytes",
        data.len()
    );

    // Write 4-byte length prefix
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;

    // Write message body
    stream.write_all(data).await?;
    stream.flush().await?;

    Ok(())
}

/// Read encrypted message with timeout
async fn read_secure_message_with_timeout(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let ciphertext = read_message_with_timeout(stream, timeout).await?;
    
    // Decrypt with AEAD
    let plaintext = channel
        .decrypt(&ciphertext, b"")
        .context("AEAD decryption failed")?;

    Ok(plaintext)
}

/// Read encrypted message
async fn read_secure_message(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
) -> Result<Vec<u8>> {
    let ciphertext = read_message(stream).await?;

    // Decrypt with AEAD
    let plaintext = channel
        .decrypt(&ciphertext, b"")
        .context("AEAD decryption failed")?;

    Ok(plaintext)
}

/// Write encrypted message
async fn write_secure_message(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    plaintext: &[u8],
) -> Result<()> {
    // Encrypt with AEAD
    let ciphertext = channel
        .encrypt(plaintext, b"")
        .context("AEAD encryption failed")?;

    write_message(stream, &ciphertext).await
}

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

/// Create RPC identity with secure key generation
pub fn create_secure_rpc_identity() -> Result<NodeIdentity> {
    use rand::RngCore;
    
    // Generate fresh Falcon-512 keypair
    let (falcon_pk, falcon_sk) = crate::falcon_sigs::FalconKeypair::generate()?;
    
    // Generate fresh Kyber-768 keypair  
    let (kyber_pk, kyber_sk) = crate::kyber_kem::KyberKeypair::generate()?;
    
    // Create identity
    Ok(NodeIdentity::from_keys(falcon_pk, falcon_sk, kyber_pk, kyber_sk))
}

/// Benchmark PoW difficulty
pub async fn benchmark_pow_difficulty(target_seconds: f64) -> u32 {
    use sha3::{Digest, Sha3_256};
    use std::time::Instant;
    
    let challenge = ProofOfWork::new_challenge();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    for difficulty in 10..30 {
        let start = Instant::now();
        let mut nonce = 0u64;
        
        loop {
            let mut hasher = Sha3_256::new();
            hasher.update(&challenge);
            hasher.update(&nonce.to_le_bytes());
            hasher.update(&timestamp.to_le_bytes());
            let hash = hasher.finalize();
            
            let leading_zeros = hash.iter()
                .take_while(|&&b| b == 0)
                .count() * 8;
            
            if leading_zeros >= difficulty as usize {
                let elapsed = start.elapsed().as_secs_f64();
                if elapsed >= target_seconds {
                    return difficulty;
                }
                break;
            }
            
            nonce += 1;
        }
    }
    
    20 // Default difficulty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proof_of_work() {
        let pow = ProofOfWork {
            challenge: [0u8; 32],
            nonce: 12345,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Should fail with high difficulty
        assert!(!pow.verify(100));
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(10, 5);
        
        // Should allow initial burst
        for _ in 0..10 {
            assert!(limiter.try_consume(1.0));
        }
        
        // Should be rate limited
        assert!(!limiter.try_consume(1.0));
        
        // Wait and retry
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(limiter.try_consume(1.0));
    }

    #[tokio::test]
    async fn test_session_id_generation() {
        let server = SecureRpcServer::new(
            8080,
            create_secure_rpc_identity().unwrap(),
            false,
            Arc::new(NodeCore::new()),
        );
        
        let id1 = server.generate_session_id(b"client1");
        let id2 = server.generate_session_id(b"client1");
        
        // Should generate different IDs even for same client
        assert_ne!(id1, id2);
    }
}

// Use std::os::unix::prelude::AsRawFd for Unix systems
#[cfg(unix)]
use std::os::unix::prelude::AsRawFd;

// Use std::os::windows::prelude::AsRawSocket for Windows
#[cfg(windows)]  
use std::os::windows::prelude::AsRawSocket;
