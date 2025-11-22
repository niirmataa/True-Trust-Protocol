#![forbid(unsafe_code)]

//! Secure PQ RPC using the P2P protocol (Falcon-512 + Kyber-768 + XChaCha20-Poly1305)
//!
//! ## Architecture
//!
//! This RPC server uses the SAME cryptographic protocol as P2P:
//! - **Identity**: Falcon-512 (long-term node keys)
//! - **Key Exchange**: ML-KEM-768 (Kyber) ephemeral
//! - **Encryption**: XChaCha20-Poly1305 AEAD
//! - **Transcript**: SHA3-256 hash chain
//! - **KDF**: KMAC256-XOF
//!
//! ## Protocol Flow
//!
//! ```text
//! Client                          RPC Server
//!   |  ClientHello(Falcon, Kyber)     |
//!   |--------------------------------->|
//!   |  ServerHello(Falcon, CT, sig)   |
//!   |<---------------------------------|
//!   |  ClientFinished(sig)             |
//!   |--------------------------------->|
//!   |  <== Secure Channel ==>         |
//!   |  RPC Request (encrypted)        |
//!   |--------------------------------->|
//!   |  RPC Response (encrypted)       |
//!   |<---------------------------------|
//! ```
//!
//! ## Security Properties
//!
//! - ✅ Post-quantum security (Kyber768 + Falcon512)
//! - ✅ Forward secrecy (ephemeral KEM)
//! - ✅ Mutual authentication
//! - ✅ Replay protection
//! - ✅ AEAD confidentiality + authenticity

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::node_core::NodeCore;
use crate::node_id::NodeId;
use crate::p2p::secure::{
    build_client_hello, build_client_finished, handle_client_hello, handle_server_hello,
    verify_client_finished, ClientFinished, ClientHello, NodeIdentity, SecureChannel, ServerHello,
    SessionKey, PROTOCOL_VERSION,
};

/* ============================================================================
 * RPC Message Types
 * ========================================================================== */

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcRequest {
    GetStatus,
    GetChainInfo,
    GetPeerCount,
    SubmitTransaction { tx_hex: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcResponse {
    Status {
        node_id: String,
        is_validator: bool,
        height: u64,
    },
    ChainInfo {
        height: u64,
        best_block_hash: String,
    },
    PeerCount {
        count: usize,
    },
    TxSubmitted {
        tx_id: String,
        accepted: bool,
    },
    Error {
        message: String,
    },
}

/* ============================================================================
 * Secure RPC Server
 * ========================================================================== */

pub struct SecureRpcServer {
    address: SocketAddr,
    identity: NodeIdentity,
    is_validator: bool,
    node: Arc<NodeCore>,
}

impl SecureRpcServer {
    /// Create new secure RPC server
    ///
    /// # Arguments
    /// - `rpc_port`: Port to bind on
    /// - `identity`: Node's PQ identity (Falcon + Kyber keys)
    /// - `is_validator`: Whether this node is a validator
    /// - `node`: Reference to NodeCore
    pub fn new(
        rpc_port: u16,
        identity: NodeIdentity,
        is_validator: bool,
        node: Arc<NodeCore>,
    ) -> Self {
        let address = SocketAddr::from(([0, 0, 0, 0], rpc_port));
        Self {
            address,
            identity,
            is_validator,
            node,
        }
    }

    /// Start secure RPC server
    pub async fn start(self) -> Result<()> {
        let listener = TcpListener::bind(self.address)
            .await
            .context("Failed to bind RPC port")?;

        println!(
            "🔐 Secure PQ RPC listening on {}",
            self.address
        );
        println!("   Protocol: Falcon-512 + Kyber-768 + XChaCha20-Poly1305");
        println!(
            "   Node ID: {}",
            hex::encode(&self.identity.node_id)
        );

        let server = Arc::new(self);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let server = Arc::clone(&server);
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(stream, addr).await {
                            eprintln!("RPC connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept RPC connection: {}", e);
                }
            }
        }
    }

    /// Handle single RPC connection with full PQ handshake
    async fn handle_connection(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        println!("🔗 New RPC connection from {}", addr);

        // =================== SERVER-SIDE HANDSHAKE ===================

        // 1. Receive ClientHello
        let ch_bytes = read_message(&mut stream).await?;
        let ch: ClientHello = bincode::deserialize(&ch_bytes)
            .context("Failed to deserialize ClientHello")?;

        println!(
            "   ClientHello from {}",
            hex::encode(&ch.node_id)
        );

        // 2. Process ClientHello and build ServerHello
        let mut transcript = crate::p2p::secure::TranscriptHasher::new();
        let ch_ser = bincode::serialize(&ch)?;
        transcript.update(b"CH", &ch_ser);

        let (sh, session_key, transcript) = handle_client_hello(
            &self.identity,
            &ch,
            PROTOCOL_VERSION,
            transcript,
        )
        .context("ClientHello validation failed")?;

        // 3. Send ServerHello
        let sh_bytes = bincode::serialize(&sh)?;
        write_message(&mut stream, &sh_bytes).await?;

        println!("   ServerHello sent");

        // 4. Receive ClientFinished
        let cf_bytes = read_message(&mut stream).await?;
        let cf: ClientFinished = bincode::deserialize(&cf_bytes)
            .context("Failed to deserialize ClientFinished")?;

        // 5. Verify ClientFinished
        verify_client_finished(&ch.falcon_pk, transcript, &cf)
            .context("ClientFinished verification failed")?;

        println!("   ✅ PQ handshake complete!");

        // =================== SECURE CHANNEL ESTABLISHED ===================

        let mut channel = SecureChannel::new(session_key);

        // Handle RPC requests over secure channel
        loop {
            // Check if session should be renegotiated
            if channel.should_renegotiate() {
                println!("   Session expired, closing connection");
                break;
            }

            // Read encrypted request
            match read_secure_message(&mut stream, &mut channel).await {
                Ok(req_bytes) => {
                    let request: RpcRequest = bincode::deserialize(&req_bytes)
                        .context("Failed to deserialize RPC request")?;

                    println!("   RPC request: {:?}", request);

                    // Process request
                    let response = self.process_request(request).await;

                    // Send encrypted response
                    let resp_bytes = bincode::serialize(&response)?;
                    write_secure_message(&mut stream, &mut channel, &resp_bytes).await?;
                }
                Err(e) => {
                    // Client disconnected or error
                    println!("   Connection closed: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process RPC request
    async fn process_request(&self, request: RpcRequest) -> RpcResponse {
        match request {
            RpcRequest::GetStatus => {
                let height = self.node.get_chain_height().await;
                RpcResponse::Status {
                    node_id: hex::encode(&self.identity.node_id),
                    is_validator: self.is_validator,
                    height,
                }
            }

            RpcRequest::GetChainInfo => {
                let height = self.node.get_chain_height().await;
                let best = self.node.get_best_block_hash().await;
                RpcResponse::ChainInfo {
                    height,
                    best_block_hash: hex::encode(best),
                }
            }

            RpcRequest::GetPeerCount => {
                let count = self.node.get_peer_count().await;
                RpcResponse::PeerCount { count }
            }

            RpcRequest::SubmitTransaction { tx_hex } => {
                match hex::decode(&tx_hex) {
                    Ok(tx_bytes) => match self.node.submit_transaction(&tx_bytes).await {
                        Ok(tx_id) => RpcResponse::TxSubmitted {
                            tx_id: hex::encode(tx_id),
                            accepted: true,
                        },
                        Err(e) => RpcResponse::Error {
                            message: format!("TX rejected: {}", e),
                        },
                    },
                    Err(_) => RpcResponse::Error {
                        message: "Invalid hex encoding".to_string(),
                    },
                }
            }
        }
    }
}

/* ============================================================================
 * Secure RPC Client
 * ========================================================================== */

pub struct SecureRpcClient {
    server_addr: SocketAddr,
    identity: NodeIdentity,
    channel: Option<SecureChannel>,
    stream: Option<TcpStream>,
}

impl SecureRpcClient {
    /// Create new secure RPC client
    pub fn new(server_addr: SocketAddr, identity: NodeIdentity) -> Self {
        Self {
            server_addr,
            identity,
            channel: None,
            stream: None,
        }
    }

    /// Connect to server with PQ handshake
    pub async fn connect(&mut self) -> Result<()> {
        println!("🔐 Connecting to secure RPC at {}", self.server_addr);

        let mut stream = TcpStream::connect(self.server_addr)
            .await
            .context("Failed to connect to RPC server")?;

        // =================== CLIENT-SIDE HANDSHAKE ===================

        // 1. Build and send ClientHello
        let (ch, transcript) = build_client_hello(&self.identity, PROTOCOL_VERSION)?;
        let ch_bytes = bincode::serialize(&ch)?;
        write_message(&mut stream, &ch_bytes).await?;

        println!("   ClientHello sent");

        // 2. Receive ServerHello
        let sh_bytes = read_message(&mut stream).await?;
        let sh: ServerHello = bincode::deserialize(&sh_bytes)
            .context("Failed to deserialize ServerHello")?;

        println!(
            "   ServerHello from {}",
            hex::encode(&sh.node_id)
        );

        // 3. Verify ServerHello
        let (session_key, transcript) = handle_server_hello(
            &self.identity,
            &ch,
            &sh,
            transcript,
            PROTOCOL_VERSION,
        )
        .context("ServerHello verification failed")?;

        // 4. Build and send ClientFinished
        let (cf, _transcript) = build_client_finished(&self.identity, transcript)?;
        let cf_bytes = bincode::serialize(&cf)?;
        write_message(&mut stream, &cf_bytes).await?;

        println!("   ✅ PQ handshake complete!");

        // =================== SECURE CHANNEL ESTABLISHED ===================

        self.channel = Some(SecureChannel::new(session_key));
        self.stream = Some(stream);

        Ok(())
    }

    /// Send RPC request and receive response
    pub async fn request(&mut self, req: RpcRequest) -> Result<RpcResponse> {
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

        // Receive encrypted response
        let resp_bytes = read_secure_message(stream, channel).await?;
        let response: RpcResponse = bincode::deserialize(&resp_bytes)
            .context("Failed to deserialize RPC response")?;

        Ok(response)
    }

    /// Close connection
    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.shutdown().await?;
        }
        self.channel = None;
        Ok(())
    }
}

/* ============================================================================
 * Message Framing (Length-Prefixed)
 * ========================================================================== */

/// Read length-prefixed message
async fn read_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read message length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Sanity check
    ensure!(len <= 10_000_000, "Message too large: {} bytes", len);

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
    // Write 4-byte length prefix
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;

    // Write message body
    stream.write_all(data).await?;
    stream.flush().await?;

    Ok(())
}

/// Read encrypted message from secure channel
async fn read_secure_message(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
) -> Result<Vec<u8>> {
    let ciphertext = read_message(stream).await?;

    // Decrypt with AEAD (no additional AAD)
    let plaintext = channel
        .decrypt(&ciphertext, b"")
        .context("AEAD decryption failed")?;

    Ok(plaintext)
}

/// Write encrypted message to secure channel
async fn write_secure_message(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    plaintext: &[u8],
) -> Result<()> {
    // Encrypt with AEAD (no additional AAD)
    let ciphertext = channel
        .encrypt(plaintext, b"")
        .context("AEAD encryption failed")?;

    write_message(stream, &ciphertext).await
}

/* ============================================================================
 * Helper: Create RPC identity from existing node keys
 * ========================================================================== */

/// Create RPC identity from Falcon + Kyber keypairs
pub fn rpc_identity_from_keys(
    falcon_pk: crate::falcon_sigs::FalconPublicKey,
    falcon_sk: crate::falcon_sigs::FalconSecretKey,
    kyber_pk: crate::kyber_kem::KyberPublicKey,
    kyber_sk: crate::kyber_kem::KyberSecretKey,
) -> NodeIdentity {
    NodeIdentity::from_keys(falcon_pk, falcon_sk, kyber_pk, kyber_sk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_secure_rpc_roundtrip() {
        // This would require a running NodeCore, so it's more of an integration test
        // For unit testing, we'd mock the NodeCore
    }
}
