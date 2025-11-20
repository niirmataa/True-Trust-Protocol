//! P2P networking module

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{RwLock, mpsc};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::node_id::NodeId;

pub mod channel;
pub mod secure;
pub mod message;

pub use message::P2PMessage;

/// P2P network implementation
pub struct P2PNetwork {
    /// Our node ID
    pub node_id: NodeId,
    
    /// Listening port
    pub port: u16,
    
    /// Connected peers
    pub peers: Arc<RwLock<HashMap<NodeId, PeerConnection>>>,
    
    /// Message receiver
    pub message_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<(NodeId, P2PMessage)>>>>,
    
    /// Message sender
    message_tx: mpsc::UnboundedSender<(NodeId, P2PMessage)>,
}

/// Connected peer connection
pub struct PeerConnection {
    pub node_id: NodeId,
    pub address: SocketAddr,
    pub connected_at: std::time::Instant,
    pub tx: mpsc::UnboundedSender<P2PMessage>,
}

impl P2PNetwork {
    /// Create new P2P network
    pub async fn new(port: u16, node_id: NodeId) -> Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        
        Ok(Self {
            node_id,
            port,
            peers: Arc::new(RwLock::new(HashMap::new())),
            message_rx: Arc::new(RwLock::new(Some(rx))),
            message_tx: tx,
        })
    }
    
    /// Start listening for connections
    pub async fn start(self: Arc<Self>) -> Result<()> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr)
            .await
            .context("Failed to bind P2P port")?;
        
        println!("[P2P] Listening on {}", addr);
        
        // Accept connections in background
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let network = Arc::clone(&self);
                        tokio::spawn(async move {
                            if let Err(e) = network.handle_connection(stream, addr).await {
                                eprintln!("[P2P] Connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[P2P] Accept error: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Handle incoming connection
    async fn handle_connection(self: Arc<Self>, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        println!("[P2P] New connection from {}", addr);
        
        // Read handshake
        let mut buffer = vec![0u8; 8192];
        let n = stream.read(&mut buffer).await?;
        buffer.truncate(n);
        
        if let Some((data, _)) = message::read_framed_message(&buffer) {
            let msg = P2PMessage::from_bytes(&data)?;
            
            match msg {
                P2PMessage::Handshake { node_id, version, .. } => {
                    println!("[P2P] Handshake from node {}", hex::encode(&node_id[..8]));
                    
                    // Send handshake ack
                    let ack = P2PMessage::HandshakeAck {
                        node_id: self.node_id,
                        version: 1,
                    };
                    let ack_bytes = message::frame_message(&ack.to_bytes());
                    stream.write_all(&ack_bytes).await?;
                    
                    // Create peer connection
                    let (tx, mut rx) = mpsc::unbounded_channel();
                    
                    let peer = PeerConnection {
                        node_id,
                        address: addr,
                        connected_at: std::time::Instant::now(),
                        tx: tx.clone(),
                    };
                    
                    self.peers.write().await.insert(node_id, peer);
                    
                    // Handle messages in background
                    let network_tx = self.message_tx.clone();
                    let network_peers = Arc::clone(&self.peers);
                    let peer_node_id = node_id;
                    
                    tokio::spawn(async move {
                        let mut buffer = vec![0u8; 8192];
                        loop {
                            tokio::select! {
                                // Receive from peer
                                result = stream.read(&mut buffer) => {
                                    match result {
                                        Ok(0) => break, // Connection closed
                                        Ok(n) => {
                                            buffer.truncate(n);
                                            if let Some((data, _)) = message::read_framed_message(&buffer) {
                                                if let Ok(msg) = P2PMessage::from_bytes(&data) {
                                                    let _ = network_tx.send((peer_node_id, msg));
                                                }
                                            }
                                            // Reset buffer for next read
                                            buffer.resize(8192, 0);
                                        }
                                        Err(_) => break,
                                    }
                                }
                                // Send to peer
                                Some(msg) = rx.recv() => {
                                    let framed = message::frame_message(&msg.to_bytes());
                                    if stream.write_all(&framed).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        
                        // Remove peer on disconnect
                        network_peers.write().await.remove(&peer_node_id);
                        println!("[P2P] Disconnected from node {}", hex::encode(&peer_node_id[..8]));
                    });
                }
                _ => {}
            }
        }
        
        Ok(())
    }
    
    /// Connect to a peer
    pub async fn connect(&self, address: &str) -> Result<()> {
        let mut stream = TcpStream::connect(address)
            .await
            .context("Failed to connect to peer")?;
        
        println!("[P2P] Connecting to {}", address);
        
        // Send handshake
        let handshake = P2PMessage::Handshake {
            node_id: self.node_id,
            version: 1,
            chain_height: 0,
            best_block: [0u8; 32],
        };
        
        let handshake_bytes = message::frame_message(&handshake.to_bytes());
        stream.write_all(&handshake_bytes).await?;
        
        // Read handshake ack
        let mut buffer = vec![0u8; 8192];
        let n = stream.read(&mut buffer).await?;
        buffer.truncate(n);
        
        if let Some((data, _)) = message::read_framed_message(&buffer) {
            let msg = P2PMessage::from_bytes(&data)?;
            
            match msg {
                P2PMessage::HandshakeAck { node_id, .. } => {
                    println!("[P2P] Connected to node {}", hex::encode(&node_id[..8]));
                    
                    // Create peer connection
                    let (tx, mut rx) = mpsc::unbounded_channel();
                    
                    let peer_addr = stream.peer_addr()?;
                    let peer = PeerConnection {
                        node_id,
                        address: peer_addr,
                        connected_at: std::time::Instant::now(),
                        tx: tx.clone(),
                    };
                    
                    self.peers.write().await.insert(node_id, peer);
                    
                    // Handle messages in background
                    let network_tx = self.message_tx.clone();
                    let network_peers = self.peers.clone();
                    let peer_node_id = node_id;
                    
                    tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                // Receive from peer
                                result = stream.read(&mut buffer) => {
                                    match result {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            if n > 0 {
                                                buffer.resize(n, 0);
                                                if let Some((data, _)) = message::read_framed_message(&buffer[..n]) {
                                                    if let Ok(msg) = P2PMessage::from_bytes(&data) {
                                                        let _ = network_tx.send((peer_node_id, msg));
                                                    }
                                                }
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                                // Send to peer
                                Some(msg) = rx.recv() => {
                                    let framed = message::frame_message(&msg.to_bytes());
                                    if stream.write_all(&framed).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        
                        network_peers.write().await.remove(&peer_node_id);
                        println!("[P2P] Disconnected from node {}", hex::encode(&peer_node_id[..8]));
                    });
                }
                _ => {}
            }
        }
        
        Ok(())
    }
    
    /// Send message to specific peer
    pub async fn send_to(&self, peer_id: &NodeId, message: P2PMessage) -> Result<()> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(peer_id) {
            peer.tx.send(message).context("Failed to send message")?;
        }
        Ok(())
    }
    
    /// Broadcast message to all peers
    pub async fn broadcast(&self, message: P2PMessage) -> Result<()> {
        let peers = self.peers.read().await;
        for (node_id, peer) in peers.iter() {
            if let Err(e) = peer.tx.send(message.clone()) {
                eprintln!("[P2P] Failed to send to {}: {}", hex::encode(&node_id[..4]), e);
            }
        }
        Ok(())
    }
    
    /// Get number of connected peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }
    
    /// Get all peer IDs
    pub async fn get_peer_ids(&self) -> Vec<NodeId> {
        self.peers.read().await.keys().copied().collect()
    }
}
