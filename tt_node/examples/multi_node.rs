#![forbid(unsafe_code)]

//! Multi-Node Network Test
//!
//! This runs 4 nodes that connect to each other,
//! share transactions, and sync blocks via P2P.

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use tt_node::consensus_pro::ConsensusPro;
use tt_node::core::Hash32;
use tt_node::falcon_sigs::{falcon_keypair, FalconPublicKey, FalconSecretKey};
use tt_node::node_id::node_id_from_falcon_pk;
use tt_node::p2p::{P2PMessage, P2PNetwork};
use tt_node::transaction::{Transaction, TxPool};

/// Node configuration
struct NodeConfig {
    name: String,
    port: u16,
    pk: FalconPublicKey,
    sk: FalconSecretKey,
}

/// Simple node instance
struct SimpleNode {
    config: NodeConfig,
    p2p: Arc<P2PNetwork>,
    tx_pool: Arc<tokio::sync::RwLock<TxPool>>,
    consensus: Arc<tokio::sync::RwLock<ConsensusPro>>,
    balance: Arc<tokio::sync::RwLock<u128>>,
    next_nonce: Arc<tokio::sync::RwLock<u64>>,
}

impl SimpleNode {
    async fn new(config: NodeConfig) -> Result<Self> {
        let node_id = node_id_from_falcon_pk(&config.pk);
        let p2p = Arc::new(P2PNetwork::new(config.port, node_id).await?);

        Ok(Self {
            config,
            p2p,
            tx_pool: Arc::new(tokio::sync::RwLock::new(TxPool::new())),
            consensus: Arc::new(tokio::sync::RwLock::new(ConsensusPro::new_default())),
            balance: Arc::new(tokio::sync::RwLock::new(10000)), // Initial balance
            next_nonce: Arc::new(tokio::sync::RwLock::new(0)),
        })
    }

    fn node_id(&self) -> Hash32 {
        node_id_from_falcon_pk(&self.config.pk)
    }

    async fn start(self: Arc<Self>) -> Result<()> {
        // Start P2P network
        let p2p = self.p2p.clone();
        p2p.start().await?;

        println!(
            "[{}] Node started on port {}",
            self.config.name, self.config.port
        );
        println!(
            "[{}] Node ID: {}",
            self.config.name,
            hex::encode(&self.node_id()[..8])
        );

        // Message handler
        let node = self.clone();
        tokio::spawn(async move {
            // Take the receiver
            let mut rx_opt = node.p2p.message_rx.write().await.take();

            if let Some(mut rx) = rx_opt {
                while let Some((peer_id, msg)) = rx.recv().await {
                    if let Err(e) = node.handle_message(peer_id, msg).await {
                        eprintln!("[{}] Message handling error: {}", node.config.name, e);
                    }
                }
            }
        });

        // Periodic status
        let node = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(10)).await;
                let peer_count = node.p2p.peer_count().await;
                let tx_count = node.tx_pool.read().await.len();
                let balance = *node.balance.read().await;
                println!(
                    "[{}] Status: {} peers, {} txs in mempool, balance: {}",
                    node.config.name, peer_count, tx_count, balance
                );
            }
        });

        Ok(())
    }

    async fn handle_message(&self, peer_id: Hash32, msg: P2PMessage) -> Result<()> {
        match msg {
            P2PMessage::NewTransaction { tx } => {
                println!(
                    "[{}] Received transaction: {} → {} ({})",
                    self.config.name,
                    hex::encode(&tx.from[..4]),
                    hex::encode(&tx.to[..4]),
                    tx.amount
                );

                // Add to pool
                self.tx_pool.write().await.add(tx)?;
            }

            P2PMessage::NewBlock { block } => {
                println!(
                    "[{}] Received new block at height {}",
                    self.config.name, block.header.height
                );
                // TODO: Validate and add to chain
            }

            P2PMessage::Ping { nonce } => {
                // Respond with pong
                let pong = P2PMessage::Pong { nonce };
                self.p2p.send_to(&peer_id, pong).await?;
            }

            P2PMessage::GetTransactions => {
                // Send our transactions
                let txs = self.tx_pool.read().await.get_all();
                let response = P2PMessage::Transactions { txs };
                self.p2p.send_to(&peer_id, response).await?;
            }

            _ => {}
        }

        Ok(())
    }

    async fn send_transaction(&self, to: Hash32, amount: u64) -> Result<()> {
        let from = self.node_id();
        let balance = *self.balance.read().await;

        if balance < amount as u128 {
            anyhow::bail!("Insufficient balance");
        }

        let nonce = {
            let mut guard = self.next_nonce.write().await;
            let current = *guard;
            *guard += 1;
            current
        };
        let fee = 10;

        let mut tx = Transaction::new(from, to, amount, fee, nonce);
        tx.sign(&self.config.sk)?;

        println!(
            "[{}] Sending transaction: {} TT to {}",
            self.config.name,
            amount,
            hex::encode(&to[..8])
        );

        // Add to our pool
        self.tx_pool.write().await.add(tx.clone())?;

        // Update balance
        *self.balance.write().await -= amount as u128;

        // Broadcast to network
        let msg = P2PMessage::NewTransaction { tx };
        self.p2p.broadcast(msg).await?;

        Ok(())
    }

    async fn connect_to(&self, address: &str) -> Result<()> {
        self.p2p.connect(address).await
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  TRUE_TRUST Multi-Node Network Test (4 nodes)           ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // Create 4 nodes
    println!("🚀 Creating 4 nodes...");

    let (pk1, sk1) = falcon_keypair();
    let (pk2, sk2) = falcon_keypair();
    let (pk3, sk3) = falcon_keypair();
    let (pk4, sk4) = falcon_keypair();

    let node1 = Arc::new(
        SimpleNode::new(NodeConfig {
            name: "Alice".to_string(),
            port: 9001,
            pk: pk1.clone(),
            sk: sk1,
        })
        .await?,
    );

    let node2 = Arc::new(
        SimpleNode::new(NodeConfig {
            name: "Bob".to_string(),
            port: 9002,
            pk: pk2.clone(),
            sk: sk2,
        })
        .await?,
    );

    let node3 = Arc::new(
        SimpleNode::new(NodeConfig {
            name: "Carol".to_string(),
            port: 9003,
            pk: pk3.clone(),
            sk: sk3,
        })
        .await?,
    );

    let node4 = Arc::new(
        SimpleNode::new(NodeConfig {
            name: "Dave".to_string(),
            port: 9004,
            pk: pk4.clone(),
            sk: sk4,
        })
        .await?,
    );

    println!();

    // Start nodes
    println!("🌐 Starting nodes...");
    node1.clone().start().await?;
    node2.clone().start().await?;
    node3.clone().start().await?;
    node4.clone().start().await?;

    sleep(Duration::from_secs(1)).await;
    println!();

    // Connect nodes
    println!("🔗 Connecting nodes...");
    node1.connect_to("127.0.0.1:9002").await?;
    node1.connect_to("127.0.0.1:9003").await?;
    node1.connect_to("127.0.0.1:9004").await?;

    node2.connect_to("127.0.0.1:9003").await?;
    node2.connect_to("127.0.0.1:9004").await?;

    node3.connect_to("127.0.0.1:9004").await?;

    sleep(Duration::from_secs(2)).await;

    let n1_peers = node1.p2p.peer_count().await;
    let n2_peers = node2.p2p.peer_count().await;
    let n3_peers = node3.p2p.peer_count().await;
    let n4_peers = node4.p2p.peer_count().await;

    println!("  Alice: {} peers", n1_peers);
    println!("  Bob: {} peers", n2_peers);
    println!("  Carol: {} peers", n3_peers);
    println!("  Dave:  {} peers", n4_peers);
    println!();

    // Send some transactions
    println!("💸 Sending transactions...");
    sleep(Duration::from_secs(1)).await;

    let bob_id = node_id_from_falcon_pk(&pk2);
    let carol_id = node_id_from_falcon_pk(&pk3);
    let alice_id = node_id_from_falcon_pk(&pk1);
    let dave_id = node_id_from_falcon_pk(&pk4);

    // Alice → Bob: 1000 TT
    node1.send_transaction(bob_id, 1000).await?;
    sleep(Duration::from_secs(1)).await;

    // Bob → Carol: 500 TT
    node2.send_transaction(carol_id, 500).await?;
    sleep(Duration::from_secs(1)).await;

    // Carol → Alice: 250 TT
    node3.send_transaction(alice_id, 250).await?;
    sleep(Duration::from_secs(1)).await;

    // Alice → Dave: 600 TT
    node1.send_transaction(dave_id, 600).await?;
    sleep(Duration::from_secs(1)).await;

    // Dave → Alice: 750 TT
    node4.send_transaction(alice_id, 750).await?;
    sleep(Duration::from_secs(1)).await;

    println!();
    println!("✅ Transactions broadcasted!");
    println!();

    // Wait for propagation
    println!("⏳ Waiting for transaction propagation...");
    sleep(Duration::from_secs(3)).await;
    println!();

    // Check mempool sizes
    println!("📊 Final Status:");
    println!("═════════════════");

    let tx1 = node1.tx_pool.read().await.len();
    let tx2 = node2.tx_pool.read().await.len();
    let tx3 = node3.tx_pool.read().await.len();
    let tx4 = node4.tx_pool.read().await.len();

    let bal1 = *node1.balance.read().await;
    let bal2 = *node2.balance.read().await;
    let bal3 = *node3.balance.read().await;
    let bal4 = *node4.balance.read().await;

    println!("Alice: {} txs in pool, balance: {}", tx1, bal1);
    println!("Bob:   {} txs in pool, balance: {}", tx2, bal2);
    println!("Carol: {} txs in pool, balance: {}", tx3, bal3);
    println!("Dave:  {} txs in pool, balance: {}", tx4, bal4);
    println!();

    // Test ping
    println!("🏓 Testing ping/pong...");
    let ping = P2PMessage::Ping { nonce: 12345 };
    node1.p2p.broadcast(ping).await?;
    sleep(Duration::from_secs(1)).await;
    println!();

    println!("🎉 Multi-node test completed!");
    println!();
    println!("Network running. Demo will auto-stop in 30 seconds (set TT_DEMO_SECS to override).");

    let run_seconds: u64 = std::env::var("TT_DEMO_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    sleep(Duration::from_secs(run_seconds)).await;

    println!(
        "🛑 Demo finished after {} seconds. Shutting down.",
        run_seconds
    );

    Ok(())
}
