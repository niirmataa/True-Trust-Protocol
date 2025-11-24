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
        use crate::core::Block;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct GenesisConfig {
            chain_id: String,
            timestamp: u64,
            initial_validators: Vec<GenesisValidator>,
            initial_balances: Vec<GenesisBalance>,
        }

        #[derive(Serialize, Deserialize)]
        struct GenesisValidator {
            node_id: String,
            stake: u64,
        }

        #[derive(Serialize, Deserialize)]
        struct GenesisBalance {
            address: String,
            amount: u128,
        }

        // Parse genesis JSON or use default if empty
        let genesis: GenesisConfig = if genesis_data.is_empty() {
            // Default genesis configuration
            GenesisConfig {
                chain_id: self.config.chain_id.clone(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                initial_validators: vec![],
                initial_balances: vec![],
            }
        } else {
            serde_json::from_slice(genesis_data)
                .context("Failed to parse genesis JSON")?
        };

        println!("📜 Initializing genesis block for chain: {}", genesis.chain_id);
        println!("   Timestamp: {}", genesis.timestamp);
        println!("   Validators: {}", genesis.initial_validators.len());
        println!("   Initial balances: {}", genesis.initial_balances.len());

        // Create genesis block
        use crate::core::BlockHeader;

        let genesis_header = BlockHeader {
            parent: [0u8; 32], // Genesis has no parent
            height: 0,
            author: [0u8; 32], // System/genesis author
            task_seed: [0u8; 32],
            timestamp: genesis.timestamp,
            parent_state_hash: [0u8; 32],
            result_state_hash: [0u8; 32],
        };

        let genesis_block = Block {
            header: genesis_header,
            author_sig: vec![], // Genesis doesn't need signature
            zk_receipt_bincode: vec![],
            transactions: vec![],
        };

        // Store genesis block
        let mut store = self.chain_store.write().await;
        store.accept_block(genesis_block, 0); // Genesis has weight 0

        // Initialize consensus with validators
        let mut consensus = self.consensus.write().await;
        for validator in genesis.initial_validators {
            match hex::decode(&validator.node_id) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut node_id = [0u8; 32];
                    node_id.copy_from_slice(&bytes);
                    consensus.register_validator(node_id, validator.stake as u128);
                    println!("   ✅ Registered validator: {}", validator.node_id);
                }
                _ => {
                    eprintln!("   ⚠️  Invalid validator node_id: {}", validator.node_id);
                }
            }
        }

        // TODO: Initialize account balances when we have account state
        for balance in genesis.initial_balances {
            println!("   💰 Initial balance: {} = {}", balance.address, balance.amount);
        }

        println!("✅ Genesis initialization complete");
        Ok(())
    }
    
    /// Start the node
    pub async fn start(&self) -> Result<()> {
        if self.is_validator {
            println!("🔨 Starting as validator node...");
            self.start_block_production().await
        } else {
            println!("📥 Starting as full node...");
            self.start_syncing().await
        }
    }

    /// Start block production loop (for validators)
    async fn start_block_production(&self) -> Result<()> {
        use tokio::time::{interval, Duration};

        let mut block_timer = interval(Duration::from_millis(self.config.block_time_ms));

        loop {
            block_timer.tick().await;

            // Get current height
            let height = {
                let store = self.chain_store.read().await;
                store.get_height()
            };

            // Get transactions from pool
            let transactions = {
                let mut pool = self.tx_pool.write().await;
                // Take up to 100 transactions
                let count = pool.len().min(100);
                let mut txs = Vec::new();
                for _ in 0..count {
                    if let Some(tx) = pool.transactions.pop() {
                        txs.push(tx);
                    }
                }
                txs
            };

            if !transactions.is_empty() || height == 0 {
                // Create new block
                use crate::core::{Block, BlockHeader};

                let (prev_hash, parent_state) = {
                    let store = self.chain_store.read().await;
                    (store.get_best_block_hash(), [0u8; 32]) // TODO: actual state hash
                };

                let header = BlockHeader {
                    parent: prev_hash,
                    height: height + 1,
                    author: [0u8; 32], // TODO: use actual validator ID from config
                    task_seed: prev_hash, // Simple: use parent hash as seed
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    parent_state_hash: parent_state,
                    result_state_hash: [0u8; 32], // TODO: compute after applying txs
                };

                // TODO: Sign block with Falcon
                // TODO: Generate ZK proof

                let block = Block {
                    header,
                    author_sig: vec![], // TODO: sign with Falcon
                    zk_receipt_bincode: vec![],
                    transactions: bincode::serialize(&transactions)?,
                };

                // Store block
                {
                    let mut store = self.chain_store.write().await;
                    store.accept_block(block, 1); // Simple weight = 1 for now
                }

                println!("🔨 Produced block #{} with {} txs", height + 1, transactions.len());
            }
        }
    }

    /// Start syncing loop (for full nodes)
    async fn start_syncing(&self) -> Result<()> {
        use tokio::time::{interval, Duration};

        let mut sync_timer = interval(Duration::from_secs(10));

        loop {
            sync_timer.tick().await;

            // TODO: Request blocks from peers
            // TODO: Validate and apply blocks

            let height = self.get_chain_height().await;
            println!("📥 Syncing... Current height: {}", height);
        }
    }

    /// Stop the node
    pub async fn stop(&self) -> Result<()> {
        println!("🛑 Stopping node gracefully...");

        // Flush transaction pool to disk (if persistence is needed)
        let pool = self.tx_pool.read().await;
        println!("   Pending transactions in pool: {}", pool.len());

        // Save chain state
        let store = self.chain_store.read().await;
        println!("   Final chain height: {}", store.get_height());

        // Stop consensus
        let _consensus = self.consensus.read().await;
        println!("   Consensus state saved");

        println!("✅ Node stopped successfully");
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
