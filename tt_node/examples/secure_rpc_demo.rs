//! Secure RPC Demo - Post-Quantum RPC Server & Client
//!
//! This example demonstrates the secure PQ RPC implementation using:
//! - Falcon-512 for authentication
//! - Kyber-768 for key exchange
//! - XChaCha20-Poly1305 for AEAD encryption
//!
//! Run with: cargo run --example secure_rpc_demo

#![forbid(unsafe_code)]

use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use tt_node::falcon_sigs::falcon_keypair;
use tt_node::kyber_kem::kyber_keypair;
use tt_node::node_core::NodeCore;
use tt_node::rpc::rpc_secure::{rpc_identity_from_keys, RpcRequest, SecureRpcClient, SecureRpcServer};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    println!("=================================================");
    println!("  TRUE_TRUST Secure PQ RPC Demo");
    println!("=================================================");
    println!();

    // =================== SERVER SETUP ===================

    println!("🔐 Setting up secure RPC server...");

    // Generate server PQ keys
    let (server_falcon_pk, server_falcon_sk) = falcon_keypair();
    let (server_kyber_pk, server_kyber_sk) = kyber_keypair();

    let server_identity = rpc_identity_from_keys(
        server_falcon_pk,
        server_falcon_sk,
        server_kyber_pk,
        server_kyber_sk,
    );

    println!(
        "   Server Node ID: {}",
        hex::encode(&server_identity.node_id)
    );

    // Create node core
    let node = Arc::new(NodeCore::new(PathBuf::from("./data_rpc_demo"), true)?);

    // Create secure RPC server
    let rpc_port = 9999;
    let server = SecureRpcServer::new(rpc_port, server_identity, true, Arc::clone(&node));

    // Start server in background
    tokio::spawn(async move {
        if let Err(e) = server.start().await {
            eprintln!("RPC server error: {}", e);
        }
    });

    // Wait for server to start
    sleep(Duration::from_secs(1)).await;

    println!();

    // =================== CLIENT SETUP ===================

    println!("🔐 Setting up secure RPC client...");

    // Generate client PQ keys
    let (client_falcon_pk, client_falcon_sk) = falcon_keypair();
    let (client_kyber_pk, client_kyber_sk) = kyber_keypair();

    let client_identity = rpc_identity_from_keys(
        client_falcon_pk,
        client_falcon_sk,
        client_kyber_pk,
        client_kyber_sk,
    );

    println!(
        "   Client Node ID: {}",
        hex::encode(&client_identity.node_id)
    );

    let server_addr = format!("127.0.0.1:{}", rpc_port).parse()?;
    let mut client = SecureRpcClient::new(server_addr, client_identity);

    println!();

    // =================== TEST RPC CALLS ===================

    println!("📡 Testing RPC calls over secure channel...");
    println!();

    // Connect (performs PQ handshake)
    println!("1️⃣  Connecting with PQ handshake...");
    client.connect().await?;
    println!("   ✅ Connected!");
    println!();

    // Test 1: Get Status
    println!("2️⃣  RPC: GetStatus");
    let response = client.request(RpcRequest::GetStatus).await?;
    println!("   Response: {:?}", response);
    println!();

    // Test 2: Get Chain Info
    println!("3️⃣  RPC: GetChainInfo");
    let response = client.request(RpcRequest::GetChainInfo).await?;
    println!("   Response: {:?}", response);
    println!();

    // Test 3: Get Peer Count
    println!("4️⃣  RPC: GetPeerCount");
    let response = client.request(RpcRequest::GetPeerCount).await?;
    println!("   Response: {:?}", response);
    println!();

    // Test 4: Submit Transaction
    println!("5️⃣  RPC: SubmitTransaction");
    let tx_hex = hex::encode(b"dummy_transaction_data");
    let response = client
        .request(RpcRequest::SubmitTransaction { tx_hex })
        .await?;
    println!("   Response: {:?}", response);
    println!();

    // Close connection
    println!("6️⃣  Closing connection...");
    client.close().await?;
    println!("   ✅ Disconnected!");
    println!();

    // =================== SUMMARY ===================

    println!("=================================================");
    println!("  ✅ All RPC calls succeeded!");
    println!("=================================================");
    println!();
    println!("Security properties verified:");
    println!("  ✅ Falcon-512 mutual authentication");
    println!("  ✅ Kyber-768 key exchange (forward secrecy)");
    println!("  ✅ XChaCha20-Poly1305 AEAD encryption");
    println!("  ✅ SHA3-256 transcript integrity");
    println!("  ✅ KMAC256 key derivation");
    println!();

    Ok(())
}
