#![forbid(unsafe_code)]

//! Monitoring helpers for consensus and blockchain health.

use chrono::{DateTime, Utc};
use hex;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::chain_store::ChainStore;
use crate::consensus_pro::{ConsensusPro, ConsensusStats};
use crate::node_id::NodeId;
use crate::p2p::P2PNetwork;
use crate::transaction::TxPool;

/// Snapshot of chain health for RPC/monitoring.
#[derive(Debug, Clone, Serialize)]
pub struct ChainHealth {
    pub head: Option<String>,
    pub height: u64,
    pub total_blocks: usize,
    pub cumulative_weight: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Snapshot of P2P health for monitoring.
#[derive(Debug, Clone, Serialize)]
pub struct P2PHealth {
    pub peer_count: usize,
    pub peers: Vec<PeerEntry>,
    pub timestamp: DateTime<Utc>,
}

/// Connected peer entry.
#[derive(Debug, Clone, Serialize)]
pub struct PeerEntry {
    pub node_id: String,
    pub address: String,
    pub connected_seconds: u64,
}

/// Snapshot of transaction pool state.
#[derive(Debug, Clone, Serialize)]
pub struct TxPoolHealth {
    pub pending: usize,
    pub timestamp: DateTime<Utc>,
}

/// Aggregate monitoring helper.
pub struct MonitoringService {
    chain_store: Arc<RwLock<ChainStore>>,
    consensus: Arc<RwLock<ConsensusPro>>,
    tx_pool: Arc<RwLock<TxPool>>,
    p2p: Arc<P2PNetwork>,
}

impl MonitoringService {
    pub fn new(
        chain_store: Arc<RwLock<ChainStore>>,
        consensus: Arc<RwLock<ConsensusPro>>,
        tx_pool: Arc<RwLock<TxPool>>,
        p2p: Arc<P2PNetwork>,
    ) -> Self {
        Self {
            chain_store,
            consensus,
            tx_pool,
            p2p,
        }
    }

    /// Returns current chain health snapshot.
    pub async fn chain_health(&self) -> ChainHealth {
        let store = self.chain_store.read().await;
        let head = store.head();

        let (head_hash, height, cumw) = if let Some((hash, _)) = head {
            let height = store.height.get(hash).copied().unwrap_or(0);
            let cumulative = store.cumw.get(hash).copied();
            (Some(hex::encode(hash)), height, cumulative)
        } else {
            (None, 0, None)
        };

        ChainHealth {
            head: head_hash,
            height,
            total_blocks: store.blocks.len(),
            cumulative_weight: cumw.map(|w| w.to_string()),
            timestamp: Utc::now(),
        }
    }

    /// Returns consensus stats snapshot.
    pub async fn consensus_health(&self) -> ConsensusStats {
        let consensus = self.consensus.read().await;
        consensus.stats()
    }

    /// Returns P2P health snapshot.
    pub async fn p2p_health(&self) -> P2PHealth {
        let peers = self.p2p.peers.read().await;
        let timestamp = Utc::now();

        let entries = peers
            .values()
            .map(|p| PeerEntry {
                node_id: hex::encode(p.node_id),
                address: p.address.to_string(),
                connected_seconds: p.connected_at.elapsed().as_secs(),
            })
            .collect();

        P2PHealth {
            peer_count: peers.len(),
            peers: entries,
            timestamp,
        }
    }

    /// Returns transaction pool health snapshot.
    pub async fn txpool_health(&self) -> TxPoolHealth {
        let pool = self.tx_pool.read().await;
        TxPoolHealth {
            pending: pool.len(),
            timestamp: Utc::now(),
        }
    }
}

/// Lightweight summary for RPC.
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub node_id: String,
    pub validator: bool,
    pub chain: ChainHealth,
    pub consensus: ConsensusStats,
    pub p2p: P2PHealth,
    pub txpool: TxPoolHealth,
}

impl NodeStatus {
    pub fn new(
        node_id: NodeId,
        validator: bool,
        chain: ChainHealth,
        consensus: ConsensusStats,
        p2p: P2PHealth,
        txpool: TxPoolHealth,
    ) -> Self {
        Self {
            node_id: hex::encode(node_id),
            validator,
            chain,
            consensus,
            p2p,
            txpool,
        }
    }
}
