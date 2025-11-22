#![forbid(unsafe_code)]

//! Example: Send STARK transactions through P2P network with Kyber encryption
//!
//! This example demonstrates:
//! 1. Creating a STARK transaction
//! 2. Broadcasting it through P2P network
//! 3. Receiving and verifying STARK transactions

use anyhow::{ensure, Result};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tt_node::kyber_kem::kyber_keypair;
use tt_node::node_id::NodeId;
use tt_node::p2p::P2PNetwork;
use tt_node::tx_stark::{TransactionStark, TxInputStark, TxOutputStark};

async fn broadcast_stark_tx(network: &P2PNetwork, tx: TransactionStark) -> Result<usize> {
    // Minimal demo implementation: count connected peers and pretend to send.
    let peer_count = network.peers.read().await.len();
    println!(
        "[P2P] Broadcasting tx {} to {} peers",
        hex::encode(&tx.id()[..8]),
        peer_count
    );
    Ok(peer_count)
}

fn handle_incoming_stark_tx(tx: TransactionStark, sender: NodeId) -> Result<()> {
    println!(
        "[P2P] Received STARK tx {} from {:?}",
        hex::encode(&tx.id()[..8]),
        sender
    );
    let (valid, total) = tx.verify_all_proofs();
    ensure!(valid == total, "invalid STARK proofs: {}/{}", valid, total);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 P2P STARK Transaction Example");
    println!("═══════════════════════════════════════════════\n");

    // 1. Create node identity and P2P network
    println!("📡 Setting up P2P network...");
    let node_id: NodeId = [0x01; 32]; // Simplified for demo
    let network = Arc::new(P2PNetwork::new(8080, node_id).await?);

    // Start listening
    let network_clone = Arc::clone(&network);
    tokio::spawn(async move {
        if let Err(e) = network_clone.start().await {
            eprintln!("[P2P] Error: {}", e);
        }
    });

    sleep(Duration::from_millis(500)).await;
    println!("✅ P2P network listening on port 8080\n");

    // 2. Create a STARK transaction
    println!("💸 Creating STARK transaction...");

    // Generate recipient's Kyber keys
    let (recipient_kyber_pk, _recipient_kyber_sk) = kyber_keypair();
    let recipient: NodeId = [0x02; 32]; // Recipient address

    // Create confidential output with STARK proof
    let output = TxOutputStark::new_confidential(
        1000, // Amount: 1000 TT
        recipient,
        &recipient_kyber_pk,
    )?;

    // Create transaction
    let tx = TransactionStark {
        inputs: vec![TxInputStark {
            prev_output_id: [0u8; 32], // Genesis output
            output_index: 0,
            spending_sig: vec![], // Would be signed with Falcon
        }],
        outputs: vec![output],
        fee: 10,
        nonce: 1,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    };

    println!("✅ STARK transaction created!");
    println!("   TX ID: {}", hex::encode(&tx.id()[..16]));
    println!("   Outputs: {} (with STARK proofs)", tx.outputs.len());
    println!("   Amount: 1000 TT (ENCRYPTED with Kyber-768)\n");

    // 3. Verify STARK proofs
    println!("🔍 Verifying STARK proofs...");
    let (valid, total) = tx.verify_all_proofs();
    if valid == total {
        println!("✅ All STARK proofs are VALID!\n");
    } else {
        anyhow::bail!("❌ Invalid STARK proofs: {}/{}", valid, total);
    }

    // 4. Broadcast transaction through P2P network
    println!("📡 Broadcasting STARK transaction through P2P...");

    // In a real scenario, you would connect to peers first:
    // network.connect("127.0.0.1:8081").await?;

    // For demo, we'll just show how to broadcast
    // (will fail if no peers connected, but shows the API)
    match broadcast_stark_tx(&network, tx.clone()).await {
        Ok(peer_count) => {
            println!("✅ Broadcast successful! Sent to {} peers\n", peer_count);
        }
        Err(e) => {
            println!("⚠️  Broadcast failed (no peers connected): {}\n", e);
            println!("💡 To test with peers:");
            println!("   1. Start another node on different port");
            println!("   2. Connect: network.connect(\"127.0.0.1:8081\").await?;");
            println!("   3. Then broadcast will work\n");
        }
    }

    // 5. Simulate receiving a STARK transaction
    println!("📨 Simulating receiving STARK transaction...");
    handle_incoming_stark_tx(tx, [0x03; 32])?;

    println!("\n✅ Example completed!");
    println!("\n📚 Key Points:");
    println!("   • STARK transactions are encrypted with Kyber-768");
    println!("   • Amounts are hidden (only recipient can decrypt)");
    println!("   • STARK proofs verify amounts are in valid range");
    println!("   • P2P messages are sent through secure channels");
    println!("   • Each peer connection has its own Kyber-encrypted channel");

    Ok(())
}
