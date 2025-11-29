#![forbid(unsafe_code)]

//! PQ-secure P2P dla TrueTrust:
//! - tożsamość: Falcon-512 + Kyber-768 (NodeId = PQC fingerprint),
//! - handshake jak w RPC: ClientHello / ServerHello / ClientFinished,
//! - kanał: XChaCha20-Poly1305 (osobne klucze w obie strony),
//! - proste API: connect(), start(), broadcast().

pub mod channel;
pub mod secure;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock, mpsc},
    time::timeout,
};

use crate::{
    node_id::NodeId,
    p2p::{
        channel::SecureChannel,
        secure::{
            build_client_finished, build_client_hello, handle_client_hello,
            handle_server_hello, verify_client_finished, ClientFinished, ClientHello,
            NodeIdentity, ServerHello, TranscriptHasher, PROTOCOL_VERSION,
        },
    },
    tx_stark::TransactionStark,
};

const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of concurrent peer connections (DoS protection).
const MAX_PEERS: usize = 128;

/// Cooldown between connection attempts from same IP (seconds).
const CONNECTION_COOLDOWN_SECS: u64 = 5;

/// Timeout for handshake operations (seconds).
const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// Timeout for reading messages (seconds).
const READ_TIMEOUT_SECS: u64 = 60;

/// Anti-replay nonce cache TTL (seconds).
const NONCE_CACHE_TTL_SECS: u64 = 300;

/// Channel buffer size for incoming messages.
const MESSAGE_CHANNEL_SIZE: usize = 1000;

/// Received P2P message with sender info.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// NodeId of the sender.
    pub from: NodeId,
    /// The message content.
    pub message: P2PMessage,
}

/// Prosty typ wiadomości P2P – ping, STARK TX, Stealth Hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    Ping { nonce: u64 },
    StarkTx { tx_bytes: Vec<u8> },
    /// Encrypted stealth hint (for private payments)
    StealthHint { hint_bytes: Vec<u8> },
}

/// Połączenie z peerm – strumień TCP + zaszyfrowany kanał.
pub struct PeerConnection {
    pub stream: TcpStream,
    pub channel: SecureChannel,
}

/// Informacje o peerze (identyfikator + połączenie).
pub struct Peer {
    pub node_id: NodeId,
    pub address: SocketAddr,
    pub connected_at: Instant,
    pub conn: Arc<Mutex<PeerConnection>>,
}

/// Rate limiter for connection attempts (per IP).
struct ConnectionRateLimiter {
    last_attempt: HashMap<std::net::IpAddr, Instant>,
}

impl ConnectionRateLimiter {
    fn new() -> Self {
        Self {
            last_attempt: HashMap::new(),
        }
    }

    fn check_and_update(&mut self, ip: std::net::IpAddr) -> bool {
        let now = Instant::now();
        if let Some(last) = self.last_attempt.get(&ip) {
            if now.duration_since(*last).as_secs() < CONNECTION_COOLDOWN_SECS {
                return false; // Rate limited
            }
        }
        self.last_attempt.insert(ip, now);
        // Cleanup old entries (older than 1 minute)
        self.last_attempt.retain(|_, v| now.duration_since(*v).as_secs() < 60);
        true
    }
}

/// Anti-replay nonce cache to prevent ClientHello replay attacks.
struct AntiReplayCache {
    /// Set of seen nonces with their timestamps.
    seen: HashMap<[u8; 32], Instant>,
}

impl AntiReplayCache {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// Check if nonce was seen before. Returns false if replay detected.
    fn check_and_insert(&mut self, nonce: [u8; 32]) -> bool {
        let now = Instant::now();
        
        // Cleanup expired entries
        self.seen.retain(|_, ts| now.duration_since(*ts).as_secs() < NONCE_CACHE_TTL_SECS);
        
        // Check if already seen
        if self.seen.contains_key(&nonce) {
            return false; // Replay detected
        }
        
        self.seen.insert(nonce, now);
        true
    }
}

/// PQ-secure P2P network.
pub struct P2PNetwork {
    /// Nasz NodeId (PQC fingerprint).
    pub node_id: NodeId,
    /// Port P2P.
    pub port: u16,
    /// Pełna tożsamość PQ (Falcon+Kyber) tego noda.
    pub identity: Arc<RwLock<NodeIdentity>>,
    /// Aktualnie podłączeni peerzy.
    pub peers: Arc<RwLock<HashMap<NodeId, Peer>>>,
    /// Rate limiter for incoming connections (DoS protection).
    rate_limiter: Arc<Mutex<ConnectionRateLimiter>>,
    /// Anti-replay nonce cache (DoS protection).
    nonce_cache: Arc<Mutex<AntiReplayCache>>,
    /// Channel sender for received messages (STARK TX, Stealth Hints).
    /// Clone this sender for each peer reader loop.
    message_tx: mpsc::Sender<ReceivedMessage>,
}

/// Receiver for incoming P2P messages.
/// Use this to process STARK transactions and stealth hints.
pub type MessageReceiver = mpsc::Receiver<ReceivedMessage>;

impl P2PNetwork {
    /// Tworzy nową sieć P2P z PQC tożsamością.
    /// Zwraca (P2PNetwork, MessageReceiver) - receiver do odbierania wiadomości.
    pub async fn new(port: u16, identity: NodeIdentity) -> Result<(Self, MessageReceiver)> {
        let node_id = identity.node_id;
        let (message_tx, message_rx) = mpsc::channel(MESSAGE_CHANNEL_SIZE);
        
        let network = Self {
            node_id,
            port,
            identity: Arc::new(RwLock::new(identity)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(ConnectionRateLimiter::new())),
            nonce_cache: Arc::new(Mutex::new(AntiReplayCache::new())),
            message_tx,
        };
        
        Ok((network, message_rx))
    }

    /// Startuje listener P2P na podanym porcie.
    ///
    /// Uwaga: oczekuje, że wołasz to na Arc:
    /// `let p2p = Arc::new(P2PNetwork::new(...).await?);
    ///  tokio::spawn(async move { p2p.start().await.unwrap(); });`
    pub async fn start(self: Arc<Self>) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(&addr)
            .await
            .context("Failed to bind P2P port")?;

        println!("📡 P2P listening on {}", addr);

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            
            // DoS protection: check peer limit
            {
                let peers = self.peers.read().await;
                if peers.len() >= MAX_PEERS {
                    log::warn!("[P2P] Max peers ({}) reached, rejecting {}", MAX_PEERS, remote_addr);
                    drop(stream);
                    continue;
                }
            }

            // DoS protection: rate limit per IP
            {
                let mut limiter = self.rate_limiter.lock().await;
                if !limiter.check_and_update(remote_addr.ip()) {
                    log::warn!("[P2P] Rate limited connection from {}", remote_addr);
                    drop(stream);
                    continue;
                }
            }

            let this = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = this.handle_incoming_peer(stream, remote_addr).await {
                    eprintln!("[P2P] incoming connection error from {}: {}", remote_addr, e);
                }
            });
        }
    }

    /// Nawiązuje PQ-secure połączenie do innego noda (rola klienta).
    pub async fn connect(&self, address: &str) -> Result<()> {
        let addr: SocketAddr = address
            .parse()
            .with_context(|| format!("Invalid peer address: {address}"))?;

        println!("[P2P] Connecting to peer {} ...", addr);

        let mut stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("Failed to connect to {addr}"))?;
        stream.set_nodelay(true)?;

        // === PQ handshake (klient) ===

        let identity = self.identity.read().await;
        let (ch, transcript) = build_client_hello(&identity, PROTOCOL_VERSION)?;
        let ch_bytes = bincode::serialize(&ch)?;
        write_message(&mut stream, &ch_bytes).await?;

        let sh_bytes = read_message(&mut stream)
            .await
            .context("Failed to read ServerHello")?;
        let sh: ServerHello =
            bincode::deserialize(&sh_bytes).context("Failed to decode ServerHello")?;

        let (session_keys, transcript) = handle_server_hello(
            &identity,
            &ch,
            &sh,
            transcript,
            PROTOCOL_VERSION,
        )
        .context("ServerHello verification failed")?;

        let (cf, _transcript) = build_client_finished(&identity, transcript)?;
        drop(identity);

        let cf_bytes = bincode::serialize(&cf)?;
        write_message(&mut stream, &cf_bytes).await?;

        println!(
            "[P2P] ✅ PQ handshake complete with {}",
            hex::encode(&sh.node_id)
        );

        // Kanał szyfrowany (klient)
        let channel = SecureChannel::new_client(&session_keys);
        let conn = Arc::new(Mutex::new(PeerConnection { stream, channel }));

        let peer = Peer {
            node_id: sh.node_id,
            address: addr,
            connected_at: Instant::now(),
            conn: Arc::clone(&conn),
        };

        {
            let mut peers = self.peers.write().await;
            peers.insert(sh.node_id, peer);
        }

        // Reader loop dla tego peer-a
        let node_id = sh.node_id;
        let message_tx = self.message_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = peer_reader_loop(node_id, conn, message_tx).await {
                eprintln!(
                    "[P2P] peer {} closed: {}",
                    hex::encode(node_id),
                    e
                );
            }
        });

        Ok(())
    }

    /// Prosty broadcast: wysyła bajty do wszystkich peerów (zaszyfrowane).
    pub async fn broadcast(&self, payload: &[u8]) -> Result<()> {
        // no longer need AsyncWriteExt here (we use helper write_secure_message)

        let peers = self.peers.read().await;

        for (node_id, peer) in peers.iter() {
            let mut conn_guard = peer.conn.lock().await;

            // Use helper to frame + encrypt + write the payload
            let PeerConnection { stream, channel } = &mut *conn_guard;
            if let Err(e) = write_secure_message(stream, channel, payload).await {
                log::error!(
                    "[P2P] send to {} failed: {}",
                    hex::encode(node_id),
                    e
                );
            }
        }

        Ok(())
    }

    /// Wygodna funkcja: broadcast STARK transakcji (bincode + AES).
    pub async fn broadcast_stark_tx(&self, tx: &TransactionStark) -> Result<usize> {
        let tx_bytes = tx.to_bytes();
        let msg = P2PMessage::StarkTx { tx_bytes };
        let payload = bincode::serialize(&msg)?;
        let peers = self.peers.read().await;
        let count = peers.len();
        drop(peers);

        self.broadcast(&payload).await?;
        println!(
            "[P2P] Broadcasting STARK tx to {} peers",
            count
        );
        Ok(count)
    }

    /// Broadcast stealth hint (encrypted, PQ-secure).
    /// 
    /// Hint jest zaszyfrowany Kyber → tylko odbiorca może odszyfrować.
    /// Broadcast przez P2P → każdy node może skanować czy hint jest dla niego.
    pub async fn broadcast_stealth_hint(&self, hint_bytes: &[u8]) -> Result<usize> {
        let msg = P2PMessage::StealthHint {
            hint_bytes: hint_bytes.to_vec(),
        };
        let payload = bincode::serialize(&msg)?;
        let peers = self.peers.read().await;
        let count = peers.len();
        drop(peers);

        self.broadcast(&payload).await?;
        println!(
            "[P2P] 🔒 Broadcasting stealth hint to {} peers ({} bytes)",
            count,
            hint_bytes.len()
        );
        Ok(count)
    }

    /// Ile peerów jest aktualnie podłączonych.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Obsługa połączenia przychodzącego (rola serwera).
    async fn handle_incoming_peer(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        stream.set_nodelay(true)?;
        println!("[P2P] Incoming connection from {}", addr);

        // === PQ handshake (serwer) z timeout ===

        let ch_bytes = timeout(
            Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            read_message(&mut stream)
        )
        .await
        .context("ClientHello read timeout")?
        .context("Failed to read ClientHello")?;
        
        let ch: ClientHello =
            bincode::deserialize(&ch_bytes).context("Failed to decode ClientHello")?;

        // Anti-replay protection: check if nonce was seen before
        {
            let mut cache = self.nonce_cache.lock().await;
            if !cache.check_and_insert(ch.anti_replay_nonce) {
                log::warn!("[P2P] Replay attack detected from {} (duplicate nonce)", addr);
                return Err(anyhow::anyhow!("Replay attack: duplicate anti_replay_nonce"));
            }
        }

        println!(
            "[P2P] ClientHello from {}",
            hex::encode(&ch.node_id)
        );

        let identity = self.identity.read().await;
        let transcript = TranscriptHasher::new();
        let (sh, session_keys, transcript) =
            handle_client_hello(&identity, &ch, PROTOCOL_VERSION, transcript, None)
                .context("ClientHello validation failed")?;
        drop(identity);

        let sh_bytes = bincode::serialize(&sh)?;
        write_message(&mut stream, &sh_bytes).await?;

        let cf_bytes = timeout(
            Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            read_message(&mut stream)
        )
        .await
        .context("ClientFinished read timeout")?
        .context("Failed to read ClientFinished")?;
        
        let cf: ClientFinished =
            bincode::deserialize(&cf_bytes).context("Failed to decode ClientFinished")?;
        verify_client_finished(&ch.falcon_pk, transcript, &cf)
            .context("ClientFinished verification failed")?;

        println!(
            "[P2P] ✅ PQ handshake complete with {}",
            hex::encode(&ch.node_id)
        );

        // Kanał szyfrowany (serwer)
        let channel = SecureChannel::new_server(&session_keys);
        let conn = Arc::new(Mutex::new(PeerConnection { stream, channel }));

        let peer = Peer {
            node_id: ch.node_id,
            address: addr,
            connected_at: Instant::now(),
            conn: Arc::clone(&conn),
        };

        {
            let mut peers = self.peers.write().await;
            peers.insert(ch.node_id, peer);
        }

        // Reader loop dla tego peer-a
        let node_id = ch.node_id;
        let message_tx = self.message_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = peer_reader_loop(node_id, conn, message_tx).await {
                eprintln!(
                    "[P2P] peer {} closed: {}",
                    hex::encode(node_id),
                    e
                );
            }
        });

        Ok(())
    }
}

/// Reader loop: odbiera zaszyfrowane wiadomości od jednego peer-a.
async fn peer_reader_loop(
    node_id: NodeId,
    conn: Arc<Mutex<PeerConnection>>,
    message_tx: mpsc::Sender<ReceivedMessage>,
) -> Result<()> {
    loop {
        let mut guard = conn.lock().await;
        let PeerConnection { stream, channel } = &mut *guard;
        
        // Timeout protection against slow-read attacks
        let plaintext = timeout(
            Duration::from_secs(READ_TIMEOUT_SECS),
            read_secure_message(stream, channel)
        )
        .await
        .context("Message read timeout")?
        .context("Failed to read secure message")?;
        
        drop(guard);

        match bincode::deserialize::<P2PMessage>(&plaintext) {
            Ok(P2PMessage::Ping { nonce }) => {
                log::info!(
                    "[P2P] 🏓 ping {} from {}",
                    nonce,
                    hex::encode(node_id)
                );
                // Ping jest tylko heartbeat, nie przekazujemy dalej
            }
            Ok(msg @ P2PMessage::StarkTx { .. }) => {
                if let P2PMessage::StarkTx { ref tx_bytes } = msg {
                    log::info!(
                        "[P2P] 💸 STARK tx ({} bytes) from {}",
                        tx_bytes.len(),
                        hex::encode(node_id)
                    );
                }
                // Przekaż do NodeCore / mempoolu przez channel
                if message_tx.send(ReceivedMessage { from: node_id, message: msg }).await.is_err() {
                    log::warn!("[P2P] Message channel closed, dropping STARK tx");
                }
            }
            Ok(msg @ P2PMessage::StealthHint { .. }) => {
                if let P2PMessage::StealthHint { ref hint_bytes } = msg {
                    log::info!(
                        "[P2P] 🔒 Stealth hint ({} bytes) from {}",
                        hint_bytes.len(),
                        hex::encode(node_id)
                    );
                }
                // Przekaż do hint pool przez channel
                if message_tx.send(ReceivedMessage { from: node_id, message: msg }).await.is_err() {
                    log::warn!("[P2P] Message channel closed, dropping stealth hint");
                }
            }
            Err(e) => {
                println!(
                    "[P2P] 📥 unknown msg from {} ({} bytes): {}",
                    hex::encode(node_id),
                    plaintext.len(),
                    e
                );
            }
        }
    }
}

/* ===================== Framing + AEAD wrapper ===================== */

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
    ensure!(data.len() <= MAX_MESSAGE_SIZE, "Message too large");
    let len = (data.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .context("Failed to write message length")?;
    stream
        .write_all(data)
        .await
        .context("Failed to write message body")?;
    stream.flush().await.context("Failed to flush")?;
    Ok(())
}

async fn read_secure_message(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
) -> Result<Vec<u8>> {
    let ciphertext = read_message(stream).await?;
    let plaintext = channel
        .decrypt(&ciphertext, b"p2p")
        .context("AEAD decryption failed")?;
    Ok(plaintext)
}

async fn write_secure_message(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    plaintext: &[u8],
) -> Result<()> {
    let ciphertext = channel
        .encrypt(plaintext, b"p2p")
        .context("AEAD encryption failed")?;
    write_message(stream, &ciphertext).await
}
