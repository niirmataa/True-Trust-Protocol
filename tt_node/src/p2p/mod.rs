//! P2P networking module

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::node_id::NodeId;

pub mod channel;
pub mod secure;

use secure::{build_client_hello, handle_client_hello, handle_server_hello,
             verify_client_finished, build_client_finished, NodeIdentity, PROTOCOL_VERSION};
use channel::SecureChannel;

/// P2P network implementation
pub struct P2PNetwork {
    /// Our node ID
    pub node_id: NodeId,

    /// Listening port
    pub port: u16,

    /// Connected peers
    pub peers: Arc<RwLock<HashMap<NodeId, PeerConnection>>>,

    /// Our node identity for PQ handshakes
    pub identity: Arc<RwLock<NodeIdentity>>,
}

/// Connected peer information with secure channel
pub struct PeerConnection {
    pub node_id: NodeId,
    pub address: SocketAddr,
    pub connected_at: std::time::Instant,
    pub channel: SecureChannel,
}

/// Legacy peer struct for compatibility
pub struct Peer {
    pub node_id: NodeId,
    pub address: SocketAddr,
    pub connected_at: std::time::Instant,
}

impl P2PNetwork {
    /// Create new P2P network with node identity
    pub async fn new(port: u16, node_id: NodeId, identity: NodeIdentity) -> Result<Self> {
        Ok(Self {
            node_id,
            port,
            peers: Arc::new(RwLock::new(HashMap::new())),
            identity: Arc::new(RwLock::new(identity)),
        })
    }

    /// Start listening for connections
    pub async fn start(self: Arc<Self>) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr)
            .await
            .context("Failed to bind P2P port")?;

        println!("🌐 P2P listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let network = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = network.handle_incoming_connection(stream, peer_addr).await {
                            eprintln!("P2P connection error from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept P2P connection: {}", e);
                }
            }
        }
    }

    /// Handle incoming connection (server side)
    async fn handle_incoming_connection(&self, mut stream: TcpStream, peer_addr: SocketAddr) -> Result<()> {
        println!("📥 Incoming P2P connection from {}", peer_addr);

        // Receive ClientHello
        let ch_bytes = read_length_prefixed(&mut stream).await?;
        let ch: secure::ClientHello = bincode::deserialize(&ch_bytes)
            .context("Failed to deserialize ClientHello")?;

        println!("   Peer ID: {}", hex::encode(&ch.node_id));

        // Process handshake
        let identity = self.identity.read().await;
        let transcript = secure::TranscriptHasher::new();
        let (sh, session_key, transcript) = handle_client_hello(&identity, &ch, PROTOCOL_VERSION, transcript)
            .context("ClientHello validation failed")?;
        drop(identity);

        // Send ServerHello
        let sh_bytes = bincode::serialize(&sh)?;
        write_length_prefixed(&mut stream, &sh_bytes).await?;

        // Receive ClientFinished
        let cf_bytes = read_length_prefixed(&mut stream).await?;
        let cf: secure::ClientFinished = bincode::deserialize(&cf_bytes)
            .context("Failed to deserialize ClientFinished")?;

        verify_client_finished(&ch.falcon_pk, transcript, &cf)
            .context("ClientFinished verification failed")?;

        println!("   ✅ P2P handshake complete with {}", hex::encode(&ch.node_id));

        // Create secure channel
        let channel = SecureChannel::new_server(&session_key);

        // Store peer connection
        let peer_conn = PeerConnection {
            node_id: ch.node_id,
            address: peer_addr,
            connected_at: std::time::Instant::now(),
            channel,
        };

        self.peers.write().await.insert(ch.node_id, peer_conn);

        // Keep connection alive and handle messages
        self.handle_peer_messages(stream, ch.node_id).await
    }

    /// Connect to a peer (client side)
    pub async fn connect(&self, address: &str) -> Result<()> {
        println!("📤 Connecting to peer at {}", address);

        let mut stream = TcpStream::connect(address)
            .await
            .context("Failed to connect to peer")?;

        // Build and send ClientHello
        let identity = self.identity.read().await;
        let (ch, transcript) = build_client_hello(&identity, PROTOCOL_VERSION)?;
        drop(identity);

        let ch_bytes = bincode::serialize(&ch)?;
        write_length_prefixed(&mut stream, &ch_bytes).await?;

        // Receive ServerHello
        let sh_bytes = read_length_prefixed(&mut stream).await?;
        let sh: secure::ServerHello = bincode::deserialize(&sh_bytes)
            .context("Failed to deserialize ServerHello")?;

        println!("   Server ID: {}", hex::encode(&sh.node_id));

        // Verify ServerHello
        let identity = self.identity.read().await;
        let (session_key, transcript) = handle_server_hello(&identity, &ch, &sh, transcript, PROTOCOL_VERSION)
            .context("ServerHello verification failed")?;
        drop(identity);

        // Build and send ClientFinished
        let identity = self.identity.read().await;
        let (cf, _transcript) = build_client_finished(&identity, transcript)?;
        drop(identity);

        let cf_bytes = bincode::serialize(&cf)?;
        write_length_prefixed(&mut stream, &cf_bytes).await?;

        println!("   ✅ P2P handshake complete with {}", hex::encode(&sh.node_id));

        // Create secure channel
        let channel = SecureChannel::new_client(&session_key);

        // Store peer connection
        let peer_conn = PeerConnection {
            node_id: sh.node_id,
            address: stream.peer_addr()?,
            connected_at: std::time::Instant::now(),
            channel,
        };

        self.peers.write().await.insert(sh.node_id, peer_conn);

        // Keep connection alive and handle messages
        self.handle_peer_messages(stream, sh.node_id).await
    }

    /// Handle messages from a connected peer
    async fn handle_peer_messages(&self, mut _stream: TcpStream, peer_id: NodeId) -> Result<()> {
        // TODO: Implement message protocol
        // For now, just keep connection alive
        println!("   📡 Message handling loop started for {}", hex::encode(&peer_id));

        // Wait indefinitely (in production, implement proper message handling)
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;

        Ok(())
    }

    /// Broadcast message to all peers
    pub async fn broadcast(&self, message: &[u8]) -> Result<()> {
        let mut peers = self.peers.write().await;

        for (node_id, peer_conn) in peers.iter_mut() {
            match peer_conn.channel.encrypt(message, b"") {
                Ok(ciphertext) => {
                    println!("   📤 Broadcasting to {}", hex::encode(node_id));
                    // TODO: Actually send over network (need to store TcpStream)
                    // For now, just encrypt successfully
                }
                Err(e) => {
                    eprintln!("   ❌ Failed to encrypt for {}: {}", hex::encode(node_id), e);
                }
            }
        }

        Ok(())
    }

    /// Get count of connected peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }
}

/// Read length-prefixed message (4-byte big-endian length + data)
async fn read_length_prefixed(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    anyhow::ensure!(len <= 10_000_000, "Message too large: {} bytes", len);

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write length-prefixed message (4-byte big-endian length + data)
async fn write_length_prefixed(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}
