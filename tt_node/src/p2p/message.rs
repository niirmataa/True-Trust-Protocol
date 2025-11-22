#![forbid(unsafe_code)]

//! P2P Message Protocol

use crate::core::{Block, Hash32};
use crate::node_id::NodeId;
use crate::transaction::Transaction;
use serde::{Deserialize, Serialize};

/// P2P message types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2PMessage {
    /// Handshake with peer
    Handshake {
        node_id: NodeId,
        version: u32,
        chain_height: u64,
        best_block: Hash32,
    },

    /// Handshake acknowledgment
    HandshakeAck { node_id: NodeId, version: u32 },

    /// New block announcement
    NewBlock { block: Block },

    /// Request block by hash
    GetBlock { block_hash: Hash32 },

    /// Response with block
    Block { block: Block },

    /// New transaction
    NewTransaction { tx: Transaction },

    /// Request transactions in mempool
    GetTransactions,

    /// Response with transactions
    Transactions { txs: Vec<Transaction> },

    /// Ping to keep connection alive
    Ping { nonce: u64 },

    /// Pong response
    Pong { nonce: u64 },

    /// Request peer list
    GetPeers,

    /// Response with peer list
    Peers {
        peers: Vec<(NodeId, String)>, // (NodeId, address)
    },
}

impl P2PMessage {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("message serialize")
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    /// Get message type name
    pub fn type_name(&self) -> &'static str {
        match self {
            P2PMessage::Handshake { .. } => "Handshake",
            P2PMessage::HandshakeAck { .. } => "HandshakeAck",
            P2PMessage::NewBlock { .. } => "NewBlock",
            P2PMessage::GetBlock { .. } => "GetBlock",
            P2PMessage::Block { .. } => "Block",
            P2PMessage::NewTransaction { .. } => "NewTransaction",
            P2PMessage::GetTransactions => "GetTransactions",
            P2PMessage::Transactions { .. } => "Transactions",
            P2PMessage::Ping { .. } => "Ping",
            P2PMessage::Pong { .. } => "Pong",
            P2PMessage::GetPeers => "GetPeers",
            P2PMessage::Peers { .. } => "Peers",
        }
    }
}

/// Message framing: [length: u32][data: bytes]
pub fn frame_message(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut framed = Vec::with_capacity(4 + data.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(data);
    framed
}

/// Read framed message from buffer
pub fn read_framed_message(buffer: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buffer.len() < 4 {
        return None;
    }

    let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

    if buffer.len() < 4 + len {
        return None;
    }

    let data = buffer[4..4 + len].to_vec();
    Some((data, 4 + len))
}
