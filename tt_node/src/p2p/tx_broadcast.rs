#![forbid(unsafe_code)]

//! Broadcast STARK transactions through P2P network with Kyber encryption
//!
//! This module provides functions to:
//! 1. Send STARK transactions through secure P2P channels
//! 2. Broadcast to all peers
//! 3. Handle incoming STARK transactions

use anyhow::{Context, Result};
use crate::p2p::{P2PNetwork, P2PMessage};
use crate::tx_stark::TransactionStark;
use crate::node_id::NodeId;
use hex;

/// Send STARK transaction to specific peer through secure channel
pub async fn send_stark_tx_to_peer(
    network: &P2PNetwork,
    peer_id: &NodeId,
    tx: TransactionStark,
) -> Result<()> {
    // Verify transaction proofs before sending
    let (valid, total) = tx.verify_all_proofs();
    if valid != total {
        anyhow::bail!("Transaction has invalid STARK proofs: {}/{} valid", valid, total);
    }
    
    // Create P2P message
    let msg = P2PMessage::NewTransactionStark { tx };
    
    // Send through secure channel (automatically encrypted with Kyber)
    network.send_to(peer_id, msg)
        .await
        .context("Failed to send STARK transaction to peer")?;
    
    println!("[P2P] ✅ Sent STARK transaction to peer {}", hex::encode(&peer_id[..8]));
    Ok(())
}

/// Broadcast STARK transaction to all connected peers
pub async fn broadcast_stark_tx(
    network: &P2PNetwork,
    tx: TransactionStark,
) -> Result<usize> {
    // Verify transaction proofs before broadcasting
    let (valid, total) = tx.verify_all_proofs();
    if valid != total {
        anyhow::bail!("Transaction has invalid STARK proofs: {}/{} valid", valid, total);
    }
    
    // Create P2P message
    let msg = P2PMessage::NewTransactionStark { tx };
    
    // Broadcast to all peers (each message is encrypted with peer's secure channel)
    network.broadcast(msg)
        .await
        .context("Failed to broadcast STARK transaction")?;
    
    let peer_count = network.peer_count().await;
    println!("[P2P] ✅ Broadcast STARK transaction to {} peers", peer_count);
    
    Ok(peer_count)
}

/// Handle incoming STARK transaction from peer
pub fn handle_incoming_stark_tx(
    tx: TransactionStark,
    sender_id: NodeId,
) -> Result<()> {
    println!("[P2P] 📨 Received STARK transaction from peer {}", hex::encode(&sender_id[..8]));
    
    // Verify STARK proofs
    let (valid, total) = tx.verify_all_proofs();
    if valid != total {
        eprintln!("[P2P] ⚠️  Invalid STARK proofs: {}/{} valid", valid, total);
        return Err(anyhow::anyhow!("Invalid STARK proofs in transaction"));
    }
    
    println!("[P2P] ✅ Transaction verified: TX ID = {}", hex::encode(&tx.id()[..16]));
    println!("[P2P]    Inputs: {}, Outputs: {}, Fee: {} TT", 
             tx.inputs.len(), tx.outputs.len(), tx.fee);
    
    // TODO: Add to mempool, validate balance, etc.
    // For now, just log that we received it
    
    Ok(())
}

/// Request STARK transactions from peer
pub async fn request_stark_txs(
    network: &P2PNetwork,
    peer_id: &NodeId,
) -> Result<()> {
    let msg = P2PMessage::GetTransactionsStark;
    network.send_to(peer_id, msg)
        .await
        .context("Failed to request STARK transactions")?;
    
    println!("[P2P] 📤 Requested STARK transactions from peer {}", hex::encode(&peer_id[..8]));
    Ok(())
}

/// Send STARK transactions list to peer (response to GetTransactionsStark)
pub async fn send_stark_txs_list(
    network: &P2PNetwork,
    peer_id: &NodeId,
    txs: Vec<TransactionStark>,
) -> Result<()> {
    let tx_count = txs.len();
    let msg = P2PMessage::TransactionsStark { txs };
    network.send_to(peer_id, msg)
        .await
        .context("Failed to send STARK transactions list")?;
    
    println!("[P2P] 📤 Sent {} STARK transactions to peer {}", 
             tx_count, hex::encode(&peer_id[..8]));
    Ok(())
}

