#![forbid(unsafe_code)]

//! Example: Send STARK transactions through P2P network with Kyber encryption
//!
//! This example demonstrates:
//! 1. Creating a STARK transaction
//! 2. Broadcasting it through P2P network
//! 3. Receiving and verifying STARK transactions

use anyhow::{anyhow, ensure, Result};
use rand::RngCore;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

use tt_node::kyber_kem::kyber_keypair;
use tt_node::node_id::NodeId;
use tt_node::p2p::P2PNetwork;
use tt_node::tx_stark::{TransactionStark, TxInputStark, TxOutputStark};

/// "Broadcast" – demo: tylko liczy peerów i wypisuje ID transakcji.
async fn broadcast_stark_tx(network: &P2PNetwork, tx: &TransactionStark) -> Result<usize> {
    let peer_count = network.peers.read().await.len();
    println!(
        "[P2P] Broadcasting tx {} to {} peers",
        hex::encode(&tx.id()[..8]),
        peer_count
    );
    Ok(peer_count)
}

/// Obsługa przychodzącej transakcji: log + weryfikacja wszystkich dowodów STARK.
fn handle_incoming_stark_tx(tx: &TransactionStark, sender: NodeId) -> Result<()> {
    println!(
        "[P2P] Received STARK tx {} from {:?}",
        hex::encode(&tx.id()[..8]),
        sender
    );
    let (valid, total) = tx.verify_all_proofs();
    ensure!(
        valid == total,
        "invalid STARK proofs: {}/{}",
        valid,
        total
    );
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

    // Start listening (stub P2P – w Twoim kodzie na razie tylko bind + loop)
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
    let recipient: NodeId = [0x02; 32]; // Recipient address (NodeId == [u8;32])

    // Losowy blinding do ukrycia wartości (Poseidon / STARK)
    let mut blinding = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut blinding);

    // Create confidential output with STARK proof
    // UWAGA: używamy TxOutputStark::new (nie ma new_confidential w Twoim kodzie)
    let output = TxOutputStark::new(
        1000,               // Amount: 1000 TT
        &blinding,          // random blinding
        recipient,          // recipient as [u8;32]
        &recipient_kyber_pk // Kyber pk for encryption
    );

    // Create transaction
    let tx = TransactionStark {
        inputs: vec![TxInputStark {
            prev_output_id: [0u8; 32], // Genesis output (placeholder)
            output_index: 0,
            spending_sig: vec![], // TODO: Falcon signature over spend
        }],
        outputs: vec![output],
        fee: 10,
        nonce: 1,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow!("time error: {e}"))?
            .as_secs(),
    };

    println!("✅ STARK transaction created!");
    let txid = tx.id();
    println!("   TX ID: {}", hex::encode(&txid[..16]));
    println!("   Outputs: {} (with STARK proofs)", tx.outputs.len());
    println!("   Amount: 1000 TT (ENCRYPTED with Kyber-768)\n");

    // 3. Verify STARK proofs
    println!("🔍 Verifying STARK proofs...");
    let (valid, total) = tx.verify_all_proofs();
    if valid == total {
        println!("✅ All STARK proofs are VALID!\n");
    } else {
        return Err(anyhow!("❌ Invalid STARK proofs: {}/{}", valid, total));
    }

    // 4. Broadcast transaction through P2P network
    println!("📡 Broadcasting STARK transaction through P2P...");

    match broadcast_stark_tx(&network, &tx).await {
        Ok(peer_count) => {
            println!("✅ Broadcast simulated – would send to {} peers\n", peer_count);
        }
        Err(e) => {
            println!("⚠️  Broadcast failed: {}\n", e);
        }
    }

    // 5. Simulate receiving a STARK transaction
    println!("📨 Simulating receiving STARK transaction...");
    handle_incoming_stark_tx(&tx, [0x03; 32])?;

    println!("\n✅ Example completed!");
    println!("\n📚 Key Points:");
    println!("   • STARK transactions use Kyber-768 for encrypted amounts");
    println!("   • Only recipient (with Kyber SK) może odszyfrować wartość");
    println!("   • STARK proofs gwarantują poprawny zakres / sumę");
    println!("   • P2P jest tu szkieletem – węzeł ma ID + port, peers itd.");

    Ok(())
}
