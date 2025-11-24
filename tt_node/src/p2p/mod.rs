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
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock},
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

/// Prosty typ wiadomości P2P – na razie ping + STARK TX.
#[derive(Debug, Serialize, Deserialize)]
pub enum P2PMessage {
    Ping { nonce: u64 },
    StarkTx { tx_bytes: Vec<u8> },
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
}

impl P2PNetwork {
    /// Tworzy nową sieć P2P z PQC tożsamością.
    pub async fn new(port: u16, identity: NodeIdentity) -> Result<Self> {
        let node_id = identity.node_id;
        Ok(Self {
            node_id,
            port,
            identity: Arc::new(RwLock::new(identity)),
            peers: Arc::new(RwLock::new(HashMap::new())),
        })
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
        tokio::spawn(async move {
            if let Err(e) = peer_reader_loop(node_id, conn).await {
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
        use tokio::io::AsyncWriteExt;

        let peers = self.peers.read().await;

        for (node_id, peer) in peers.iter() {
            let mut conn_guard = peer.conn.lock().await;

            // 1. Najpierw szyfrujemy wiadomość, używając tylko channel
            let ciphertext = match conn_guard.channel.encrypt(payload, &[]) {
                Ok(ct) => ct,
                Err(e) => {
                    eprintln!(
                        "[P2P] encrypt for {} failed: {}",
                        hex::encode(node_id),
                        e
                    );
                    continue;
                }
            };

            // 2. Dopiero potem bierzemy stream i wysyłamy ciphertext
            if let Err(e) = conn_guard.stream.write_all(&ciphertext).await {
                eprintln!(
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

    /// Ile peerów jest aktualnie podłączonych.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Obsługa połączenia przychodzącego (rola serwera).
    async fn handle_incoming_peer(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        stream.set_nodelay(true)?;
        println!("[P2P] Incoming connection from {}", addr);

        // === PQ handshake (serwer) ===

        let ch_bytes = read_message(&mut stream)
            .await
            .context("Failed to read ClientHello")?;
        let ch: ClientHello =
            bincode::deserialize(&ch_bytes).context("Failed to decode ClientHello")?;

        println!(
            "[P2P] ClientHello from {}",
            hex::encode(&ch.node_id)
        );

        let identity = self.identity.read().await;
        let transcript = TranscriptHasher::new();
        let (sh, session_keys, transcript) =
            handle_client_hello(&identity, &ch, PROTOCOL_VERSION, transcript)
                .context("ClientHello validation failed")?;
        drop(identity);

        let sh_bytes = bincode::serialize(&sh)?;
        write_message(&mut stream, &sh_bytes).await?;

        let cf_bytes = read_message(&mut stream)
            .await
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
        tokio::spawn(async move {
            if let Err(e) = peer_reader_loop(node_id, conn).await {
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
) -> Result<()> {
    loop {
        let mut guard = conn.lock().await;
        let PeerConnection { stream, channel } = &mut *guard;
        let plaintext = read_secure_message(stream, channel).await?;
        drop(guard);

        match bincode::deserialize::<P2PMessage>(&plaintext) {
            Ok(P2PMessage::Ping { nonce }) => {
                println!(
                    "[P2P] 🏓 ping {} from {}",
                    nonce,
                    hex::encode(node_id)
                );
            }
            Ok(P2PMessage::StarkTx { tx_bytes }) => {
                println!(
                    "[P2P] 💸 STARK tx ({} bytes) from {}",
                    tx_bytes.len(),
                    hex::encode(node_id)
                );
                // TODO: przekazać do NodeCore / mempoolu
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
