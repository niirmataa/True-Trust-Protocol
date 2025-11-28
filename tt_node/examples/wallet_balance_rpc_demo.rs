//! Wallet Balance via Secure PQ RPC — Full Path Demo
//!
//! This example demonstrates the complete flow for wallet balance queries over
//! the secure post-quantum RPC channel:
//!
//! 1. Start a secure RPC server with Falcon+Kyber authentication
//! 2. Create test accounts and credit balances in the ledger
//! 3. Connect a secure client (PQ handshake with PoW)
//! 4. Query balances via RPC GetBalance
//! 5. Verify the returned balances are correct
//!
//! Run with: cargo run --example wallet_balance_rpc_demo -p tt_node

#![forbid(unsafe_code)]

use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use tt_node::falcon_sigs::falcon_keypair;
use tt_node::kyber_kem::kyber_keypair;
use tt_node::node_core::NodeCore;
use tt_node::p2p::secure::NodeIdentity;
use tt_node::rpc::rpc_secure::{RpcRequest, RpcResponse, SecureRpcClient, SecureRpcServer};

/// Create a NodeIdentity from fresh PQ keypairs
fn create_identity() -> NodeIdentity {
    let (falcon_pk, falcon_sk) = falcon_keypair();
    let (kyber_pk, kyber_sk) = kyber_keypair();
    NodeIdentity::from_keys(falcon_pk, falcon_sk, kyber_pk, kyber_sk)
}

/// Helper to display short hex IDs
fn short_hex(bytes: &[u8]) -> String {
    let h = hex::encode(bytes);
    if h.len() > 16 {
        format!("{}…", &h[..16])
    } else {
        h
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    println!("═══════════════════════════════════════════════════════════════");
    println!("  TRUE_TRUST — Wallet Balance via Secure PQ RPC Demo");
    println!("═══════════════════════════════════════════════════════════════");
    println!();

    // =========================================================================
    // 1. SERVER SETUP
    // =========================================================================

    println!("🔐 [1/5] Setting up secure RPC server...");

    let server_identity = create_identity();
    println!("   Server Node ID: {}", short_hex(&server_identity.node_id));

    // Create NodeCore (with in-memory ledger)
    let data_dir = PathBuf::from("./data_wallet_balance_demo");
    let node = Arc::new(NodeCore::new(data_dir, true)?);

    // =========================================================================
    // 2. CREATE TEST ACCOUNTS & CREDIT BALANCES
    // =========================================================================

    println!();
    println!("💰 [2/5] Creating test accounts and crediting balances...");

    // Account A: Alice
    let alice_id: [u8; 32] = {
        let mut id = [0u8; 32];
        id[0] = 0xAA;
        id[31] = 0x01;
        id
    };
    let alice_balance: u128 = 1_000_000_000; // 1 billion units

    // Account B: Bob
    let bob_id: [u8; 32] = {
        let mut id = [0u8; 32];
        id[0] = 0xBB;
        id[31] = 0x02;
        id
    };
    let bob_balance: u128 = 500_000_000; // 500 million units

    // Account C: Charlie (zero balance, never credited)
    let charlie_id: [u8; 32] = {
        let mut id = [0u8; 32];
        id[0] = 0xCC;
        id[31] = 0x03;
        id
    };

    // Credit balances via NodeCore ledger
    {
        let mut ledger = node.ledger.write().await;
        ledger.credit(&alice_id, alice_balance);
        ledger.credit(&bob_id, bob_balance);
    }

    println!("   Alice   ({}): {} units", short_hex(&alice_id), alice_balance);
    println!("   Bob     ({}): {} units", short_hex(&bob_id), bob_balance);
    println!("   Charlie ({}): 0 units (not credited)", short_hex(&charlie_id));

    // =========================================================================
    // 3. START RPC SERVER
    // =========================================================================

    println!();
    println!("🚀 [3/5] Starting secure RPC server on port 9998...");

    let rpc_port = 9998;
    let server = SecureRpcServer::new(rpc_port, server_identity, true, Arc::clone(&node));

    // Start server in background
    tokio::spawn(async move {
        if let Err(e) = server.start().await {
            eprintln!("   ❌ RPC server error: {}", e);
        }
    });

    // Wait for server to start
    sleep(Duration::from_millis(500)).await;
    println!("   ✅ Server listening on 127.0.0.1:{}", rpc_port);

    // =========================================================================
    // 4. CLIENT SETUP & PQ HANDSHAKE
    // =========================================================================

    println!();
    println!("🔗 [4/5] Connecting secure RPC client (PQ handshake + PoW)...");

    let client_identity = create_identity();
    println!("   Client Node ID: {}", short_hex(&client_identity.node_id));

    let server_addr = format!("127.0.0.1:{}", rpc_port).parse()?;
    let mut client = SecureRpcClient::new(server_addr, client_identity);

    // Connect performs: challenge → PoW → ClientHello → ServerHello → ClientFinished
    client.connect().await?;
    println!("   ✅ PQ handshake complete!");

    // =========================================================================
    // 5. QUERY BALANCES VIA RPC
    // =========================================================================

    println!();
    println!("📡 [5/5] Querying balances via secure RPC...");
    println!();

    // --- Query Alice ---
    println!("   ➤ GetBalance for Alice ({})", short_hex(&alice_id));
    let alice_hex = hex::encode(alice_id);
    let response = client
        .request(RpcRequest::GetBalance {
            address_hex: alice_hex.clone(),
        })
        .await?;

    match &response {
        RpcResponse::Balance {
            address_hex,
            confirmed,
            pending,
        } => {
            println!("     ✅ address: {}", short_hex(&hex::decode(address_hex)?));
            println!("     ✅ confirmed: {}", confirmed);
            println!("     ✅ pending: {}", pending);
            assert_eq!(*confirmed, alice_balance, "Alice balance mismatch!");
        }
        RpcResponse::Error { code, message, .. } => {
            panic!("Alice balance query failed: [{}] {}", code, message);
        }
        _ => panic!("Unexpected response type: {:?}", response),
    }
    println!();

    // --- Query Bob ---
    println!("   ➤ GetBalance for Bob ({})", short_hex(&bob_id));
    let bob_hex = hex::encode(bob_id);
    let response = client
        .request(RpcRequest::GetBalance {
            address_hex: bob_hex.clone(),
        })
        .await?;

    match &response {
        RpcResponse::Balance {
            address_hex,
            confirmed,
            pending,
        } => {
            println!("     ✅ address: {}", short_hex(&hex::decode(address_hex)?));
            println!("     ✅ confirmed: {}", confirmed);
            println!("     ✅ pending: {}", pending);
            assert_eq!(*confirmed, bob_balance, "Bob balance mismatch!");
        }
        RpcResponse::Error { code, message, .. } => {
            panic!("Bob balance query failed: [{}] {}", code, message);
        }
        _ => panic!("Unexpected response type: {:?}", response),
    }
    println!();

    // --- Query Charlie (zero balance) ---
    println!("   ➤ GetBalance for Charlie ({}) — expects 0", short_hex(&charlie_id));
    let charlie_hex = hex::encode(charlie_id);
    let response = client
        .request(RpcRequest::GetBalance {
            address_hex: charlie_hex.clone(),
        })
        .await?;

    match &response {
        RpcResponse::Balance {
            address_hex,
            confirmed,
            pending,
        } => {
            println!("     ✅ address: {}", short_hex(&hex::decode(address_hex)?));
            println!("     ✅ confirmed: {} (expected 0)", confirmed);
            println!("     ✅ pending: {}", pending);
            assert_eq!(*confirmed, 0, "Charlie should have zero balance!");
        }
        RpcResponse::Error { code, message, .. } => {
            panic!("Charlie balance query failed: [{}] {}", code, message);
        }
        _ => panic!("Unexpected response type: {:?}", response),
    }
    println!();

    // --- Query invalid address ---
    println!("   ➤ GetBalance for invalid address (too short) — expects error");
    let response = client
        .request(RpcRequest::GetBalance {
            address_hex: "deadbeef".to_string(), // Only 4 bytes, not 32
        })
        .await?;

    match &response {
        RpcResponse::Error { code, message, .. } => {
            println!("     ✅ Got expected error: [{}] {}", code, message);
            assert_eq!(*code, 400, "Expected error code 400");
        }
        _ => panic!("Expected error for invalid address, got: {:?}", response),
    }
    println!();

    // =========================================================================
    // CLEANUP
    // =========================================================================

    println!("🔒 Closing connection...");
    client.close().await?;
    println!("   ✅ Disconnected!");
    println!();

    // =========================================================================
    // SUMMARY
    // =========================================================================

    println!("═══════════════════════════════════════════════════════════════");
    println!("  ✅ Wallet Balance RPC Demo — ALL TESTS PASSED");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("Verified:");
    println!("  ✅ Secure RPC server startup");
    println!("  ✅ Ledger credit operations (Alice, Bob)");
    println!("  ✅ PQ handshake (Falcon + Kyber + PoW)");
    println!("  ✅ GetBalance for funded account (Alice: {})", alice_balance);
    println!("  ✅ GetBalance for funded account (Bob: {})", bob_balance);
    println!("  ✅ GetBalance for zero-balance account (Charlie: 0)");
    println!("  ✅ GetBalance error handling (invalid address)");
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration test: can be run with `cargo test --example wallet_balance_rpc_demo`
    #[tokio::test]
    async fn test_wallet_balance_rpc_roundtrip() -> Result<()> {
        // Create server
        let server_identity = create_identity();
        let data_dir = PathBuf::from("./data_wallet_balance_test");
        let node = Arc::new(NodeCore::new(data_dir, true)?);

        // Credit test account
        let test_id: [u8; 32] = {
            let mut id = [0u8; 32];
            id[0] = 0xDE;
            id[31] = 0xAD;
            id
        };
        let test_balance: u128 = 42_000_000;

        {
            let mut ledger = node.ledger.write().await;
            ledger.credit(&test_id, test_balance);
        }

        // Start server
        let rpc_port = 9997;
        let server = SecureRpcServer::new(rpc_port, server_identity, false, Arc::clone(&node));

        tokio::spawn(async move {
            let _ = server.start().await;
        });

        sleep(Duration::from_millis(300)).await;

        // Connect client
        let client_identity = create_identity();
        let server_addr = format!("127.0.0.1:{}", rpc_port).parse()?;
        let mut client = SecureRpcClient::new(server_addr, client_identity);
        client.connect().await?;

        // Query balance
        let response = client
            .request(RpcRequest::GetBalance {
                address_hex: hex::encode(test_id),
            })
            .await?;

        match response {
            RpcResponse::Balance { confirmed, .. } => {
                assert_eq!(confirmed, test_balance);
            }
            _ => panic!("Unexpected response"),
        }

        client.close().await?;
        Ok(())
    }
}
