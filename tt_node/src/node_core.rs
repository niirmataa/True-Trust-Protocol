//! Core node functionality

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::chain_store::ChainStore;
use crate::consensus_pro::ConsensusPro;
use crate::core::Hash32;

/// Transaction pool (simple in-memory for now)
pub struct TxPool {
    transactions: Vec<Vec<u8>>,
}

impl TxPool {
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
        }
    }

    pub fn add(&mut self, tx_bytes: Vec<u8>) -> Result<()> {
        // Simple validation: non-empty
        if tx_bytes.is_empty() {
            anyhow::bail!("Empty transaction");
        }
        self.transactions.push(tx_bytes);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }
}

/// Core blockchain node implementation
pub struct NodeCore {
    /// Chain data store
    pub chain_store: Arc<RwLock<ChainStore>>,

    /// Consensus engine
    pub consensus: Arc<RwLock<ConsensusPro>>,

    /// Transaction pool
    pub tx_pool: Arc<RwLock<TxPool>>,

    /// Node configuration
    pub config: NodeConfig,

    /// Is this a validator node?
    pub is_validator: bool,

    /// Peer count (simple counter for now)
    peer_count: Arc<RwLock<usize>>,
}

/// Node configuration
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Data directory
    pub data_dir: PathBuf,
    
    /// Chain ID
    pub chain_id: String,
    
    /// Block time in milliseconds
    pub block_time_ms: u64,
}

impl NodeCore {
    /// Create a new node instance
    pub fn new(data_dir: PathBuf, is_validator: bool) -> Result<Self> {
        // Create data directory if it doesn't exist
        std::fs::create_dir_all(&data_dir)
            .context("Failed to create data directory")?;

        // Initialize chain store
        let chain_store = Arc::new(RwLock::new(ChainStore::new()));

        // Initialize consensus
        let consensus = Arc::new(RwLock::new(ConsensusPro::new_default()));

        // Initialize transaction pool
        let tx_pool = Arc::new(RwLock::new(TxPool::new()));

        // Default configuration
        let config = NodeConfig {
            data_dir,
            chain_id: "tt-mainnet".to_string(),
            block_time_ms: 6000, // 6 seconds
        };

        Ok(Self {
            chain_store,
            consensus,
            tx_pool,
            config,
            is_validator,
            peer_count: Arc::new(RwLock::new(0)),
        })
    }
    
    /// Initialize from genesis
    pub async fn init_genesis(&self, genesis_data: &[u8]) -> Result<()> {
        // TODO: Parse and apply genesis state
        Ok(())
    }
    
    /// Start the node
    pub async fn start(&self) -> Result<()> {
        if self.is_validator {
            println!("Starting as validator node...");
            // TODO: Start block production
        } else {
            println!("Starting as full node...");
            // TODO: Start syncing
        }
        
        Ok(())
    }
    
    /// Stop the node
    pub async fn stop(&self) -> Result<()> {
        println!("Stopping node...");
        // TODO: Graceful shutdown
        Ok(())
    }

    // =================== RPC Methods ===================

    /// Get current chain height
    pub async fn get_chain_height(&self) -> u64 {
        let store = self.chain_store.read().await;
        store.get_height()
    }

    /// Get best block hash
    pub async fn get_best_block_hash(&self) -> Hash32 {
        let store = self.chain_store.read().await;
        store.get_best_block_hash()
    }

    /// Get peer count
    pub async fn get_peer_count(&self) -> usize {
        *self.peer_count.read().await
    }

    /// Submit transaction to mempool
    pub async fn submit_transaction(&self, tx_bytes: &[u8]) -> Result<Hash32> {
        use sha3::{Digest, Sha3_256};

        // Compute TX ID
        let mut hasher = Sha3_256::new();
        hasher.update(b"TX_ID.v1");
        hasher.update(tx_bytes);
        let tx_id: Hash32 = hasher.finalize().into();

        // Add to pool
        let mut pool = self.tx_pool.write().await;
        pool.add(tx_bytes.to_vec())?;

        Ok(tx_id)
    }

    /// Update peer count (for P2P module)
    pub async fn set_peer_count(&self, count: usize) {
        *self.peer_count.write().await = count;
    }
}
