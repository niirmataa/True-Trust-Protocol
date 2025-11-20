#![forbid(unsafe_code)]

//! Interactive Node Binary
//!
//! Run multiple nodes manually and send transactions between them.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "tt_node")]
#[command(about = "TRUE_TRUST Interactive Node", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create new wallet
    NewWallet {
        /// Output file
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Show wallet address
    ShowAddress {
        /// Wallet file
        #[arg(short, long)]
        wallet: PathBuf,
    },

    /// Start node
    Start {
        /// Node name
        #[arg(short, long)]
        name: String,

        /// Port to listen on
        #[arg(short, long)]
        port: u16,

        /// Wallet file
        #[arg(short, long)]
        wallet: PathBuf,

        /// Peers to connect (comma separated: ip:port)
        #[arg(long)]
        peers: Option<String>,
    },

    /// Send transaction (node must be running)
    Send {
        /// Node RPC port
        #[arg(short, long, default_value = "8080")]
        rpc: u16,

        /// Recipient address
        #[arg(short, long)]
        to: String,

        /// Amount
        #[arg(short, long)]
        amount: u64,
    },

    /// Check balance
    Balance {
        /// Node RPC port
        #[arg(short, long, default_value = "8080")]
        rpc: u16,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::NewWallet { output } => create_wallet(output),
        Commands::ShowAddress { wallet } => show_address(wallet),
        Commands::Start {
            name,
            port,
            wallet,
            peers,
        } => start_node(name, port, wallet, peers),
        Commands::Send { rpc, to, amount } => send_transaction(rpc, to, amount),
        Commands::Balance { rpc } => check_balance(rpc),
    }
}

fn create_wallet(output: PathBuf) -> Result<()> {
    use std::fs;
    use tt_node::falcon_sigs::falcon_keypair;
    use tt_node::kyber_kem::kyber_keypair;
    use tt_node::node_id::node_id_from_falcon_pk;

    println!("🔐 Generating new wallet...");

    let (falcon_pk, falcon_sk) = falcon_keypair();
    let (kyber_pk, kyber_sk) = kyber_keypair();
    let address = node_id_from_falcon_pk(&falcon_pk);

    // Simple wallet format (for demo)
    use pqcrypto_traits::kem::{PublicKey as PQKemPublicKey, SecretKey as PQKemSecretKey};
    use pqcrypto_traits::sign::PublicKey as PQPublicKey;
    use pqcrypto_traits::sign::SecretKey as PQSecretKey;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct SimpleWallet {
        falcon_pk: Vec<u8>,
        falcon_sk: Vec<u8>,
        kyber_pk: Vec<u8>,
        kyber_sk: Vec<u8>,
        address: [u8; 32],
    }

    let wallet = SimpleWallet {
        falcon_pk: PQPublicKey::as_bytes(&falcon_pk).to_vec(),
        falcon_sk: PQSecretKey::as_bytes(&falcon_sk).to_vec(),
        kyber_pk: PQKemPublicKey::as_bytes(&kyber_pk).to_vec(),
        kyber_sk: PQKemSecretKey::as_bytes(&kyber_sk).to_vec(),
        address,
    };

    let json = serde_json::to_string_pretty(&wallet)?;
    fs::write(&output, json)?;

    println!("✅ Wallet created: {}", output.display());
    println!("📍 Address: {}", hex::encode(&address));
    println!();
    println!("⚠️  KEEP THIS FILE SAFE! It contains your private keys.");

    Ok(())
}

fn show_address(wallet: PathBuf) -> Result<()> {
    use serde::{Deserialize, Serialize};
    use std::fs;

    #[derive(Serialize, Deserialize)]
    struct SimpleWallet {
        falcon_pk: Vec<u8>,
        falcon_sk: Vec<u8>,
        kyber_pk: Vec<u8>,
        kyber_sk: Vec<u8>,
        address: [u8; 32],
    }

    let json = fs::read_to_string(&wallet)?;
    let wallet: SimpleWallet = serde_json::from_str(&json)?;

    println!("📍 Wallet Address:");
    println!("   {}", hex::encode(&wallet.address));
    println!();
    println!("🔑 Public Keys:");
    println!("   Falcon: {} bytes", wallet.falcon_pk.len());
    println!("   Kyber:  {} bytes", wallet.kyber_pk.len());

    Ok(())
}

fn start_node(name: String, port: u16, wallet_path: PathBuf, peers: Option<String>) -> Result<()> {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::fs;
    use std::sync::Arc;
    use tokio::runtime::Runtime;
    use tokio::sync::RwLock;

    #[derive(Serialize, Deserialize)]
    struct SimpleWallet {
        falcon_pk: Vec<u8>,
        falcon_sk: Vec<u8>,
        kyber_pk: Vec<u8>,
        kyber_sk: Vec<u8>,
        address: [u8; 32],
    }

    // Load wallet
    let json = fs::read_to_string(&wallet_path)?;
    let wallet: SimpleWallet = serde_json::from_str(&json)?;

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  TRUE_TRUST Node - {}                      ", name);
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("📍 Address: {}", hex::encode(&wallet.address));
    println!("🌐 Port: {}", port);
    println!("💰 Balance: 10000 TT (initial)");
    println!();

    // Simple in-memory state
    let balance = Arc::new(RwLock::new(10000u128));
    let transactions: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));

    // Start runtime
    let rt = Runtime::new()?;

    rt.block_on(async {
        println!("✅ Node started successfully!");
        println!();
        println!("Commands:");
        println!("  Send transaction:  Use 'tt_node send' in another terminal");
        println!("  Check balance:     Use 'tt_node balance' in another terminal");
        println!("  Stop node:         Press Ctrl+C");
        println!();

        if let Some(peer_list) = peers {
            println!("🔗 Connecting to peers...");
            for peer in peer_list.split(',') {
                println!("   → {}", peer.trim());
            }
            println!();
        }

        // Simple status loop
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            let bal = *balance.read().await;
            let tx_count = transactions.read().await.len();
            println!("[Status] Balance: {} TT | Transactions: {}", bal, tx_count);
        }
    })
}

fn send_transaction(_rpc: u16, to: String, amount: u64) -> Result<()> {
    println!("💸 Sending Transaction");
    println!("   To: {}", to);
    println!("   Amount: {} TT", amount);
    println!();
    println!("⚠️  This is a simplified demo.");
    println!("   In real implementation, this would connect to node's RPC.");
    println!();
    println!("✅ Transaction would be broadcasted!");

    Ok(())
}

fn check_balance(_rpc: u16) -> Result<()> {
    println!("💰 Balance: 10000 TT");
    println!();
    println!("⚠️  This is a simplified demo.");
    println!("   In real implementation, this would connect to node's RPC.");

    Ok(())
}
