//! Simple Interactive Node CLI
//! 
//! Manually create wallets, generate addresses, and send transactions.
//! No automatic P2P - you control everything manually.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use std::fs;

use tt_node::falcon_sigs::{falcon_keypair, FalconPublicKey, FalconSecretKey};
use tt_node::kyber_kem::{kyber_keypair, KyberPublicKey, KyberSecretKey};
use tt_node::node_id::node_id_from_falcon_pk;
use tt_node::transaction::{Transaction, TxPool};

use pqcrypto_traits::sign::{PublicKey as PQPublicKey, SecretKey as PQSecretKey};
use pqcrypto_traits::kem::{PublicKey as PQKemPublicKey, SecretKey as PQKemSecretKey};

#[derive(Parser)]
#[command(name = "simple_node")]
#[command(about = "Simple TRUE_TRUST Node - Manual Control", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create new wallet
    NewWallet {
        /// Output wallet file
        #[arg(short, long)]
        output: PathBuf,
        
        /// Wallet name
        #[arg(short, long)]
        name: String,
    },
    
    /// Show wallet info
    Info {
        /// Wallet file
        #[arg(short, long)]
        wallet: PathBuf,
    },
    
    /// List all wallets in directory
    ListWallets {
        /// Directory to search
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    
    /// Send transaction
    Send {
        /// Sender wallet file
        #[arg(short, long)]
        from: PathBuf,
        
        /// Recipient address (hex)
        #[arg(short, long)]
        to: String,
        
        /// Amount to send
        #[arg(short, long)]
        amount: u64,
        
        /// Output transaction file
        #[arg(short = 'o', long, default_value = "tx.json")]
        output: PathBuf,
    },
    
    /// Verify transaction
    Verify {
        /// Transaction file
        #[arg(short, long)]
        tx: PathBuf,
        
        /// Sender wallet (for verification)
        #[arg(short, long)]
        wallet: PathBuf,
    },
    
    /// Create mempool (collect transactions)
    CreateMempool {
        /// Transaction files (comma separated)
        #[arg(short, long)]
        txs: String,
        
        /// Output mempool file
        #[arg(short, long, default_value = "mempool.json")]
        output: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct SimpleWallet {
    name: String,
    falcon_pk: Vec<u8>,
    falcon_sk: Vec<u8>,
    kyber_pk: Vec<u8>,
    kyber_sk: Vec<u8>,
    address: [u8; 32],
    balance: u128,
    nonce: u64,
}

impl SimpleWallet {
    fn new(name: String) -> Self {
        let (falcon_pk, falcon_sk) = falcon_keypair();
        let (kyber_pk, kyber_sk) = kyber_keypair();
        let address = node_id_from_falcon_pk(&falcon_pk);
        
        Self {
            name,
            falcon_pk: PQPublicKey::as_bytes(&falcon_pk).to_vec(),
            falcon_sk: PQSecretKey::as_bytes(&falcon_sk).to_vec(),
            kyber_pk: PQKemPublicKey::as_bytes(&kyber_pk).to_vec(),
            kyber_sk: PQKemSecretKey::as_bytes(&kyber_sk).to_vec(),
            address,
            balance: 10000, // Initial balance
            nonce: 0,
        }
    }
    
    fn save(&self, path: &PathBuf) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }
    
    fn load(path: &PathBuf) -> Result<Self> {
        let json = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
    
    fn get_falcon_keys(&self) -> Result<(FalconPublicKey, FalconSecretKey)> {
        use pqcrypto_falcon::falcon512;
        let pk = falcon512::PublicKey::from_bytes(&self.falcon_pk)
            .map_err(|_| anyhow::anyhow!("Invalid Falcon public key"))?;
        let sk = falcon512::SecretKey::from_bytes(&self.falcon_sk)
            .map_err(|_| anyhow::anyhow!("Invalid Falcon secret key"))?;
        Ok((pk, sk))
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::NewWallet { output, name } => {
            cmd_new_wallet(output, name)
        }
        Commands::Info { wallet } => {
            cmd_info(wallet)
        }
        Commands::ListWallets { dir } => {
            cmd_list_wallets(dir)
        }
        Commands::Send { from, to, amount, output } => {
            cmd_send(from, to, amount, output)
        }
        Commands::Verify { tx, wallet } => {
            cmd_verify(tx, wallet)
        }
        Commands::CreateMempool { txs, output } => {
            cmd_create_mempool(txs, output)
        }
    }
}

fn cmd_new_wallet(output: PathBuf, name: String) -> Result<()> {
    println!("🔐 Creating new wallet...");
    println!();
    
    let wallet = SimpleWallet::new(name.clone());
    wallet.save(&output)?;
    
    println!("✅ Wallet created!");
    println!();
    println!("📄 File: {}", output.display());
    println!("👤 Name: {}", wallet.name);
    println!("📍 Address: {}", hex::encode(&wallet.address));
    println!("💰 Balance: {} TT", wallet.balance);
    println!();
    println!("⚠️  KEEP THIS FILE SAFE! Contains private keys.");
    
    Ok(())
}

fn cmd_info(wallet_path: PathBuf) -> Result<()> {
    let wallet = SimpleWallet::load(&wallet_path)?;
    
    println!("═══════════════════════════════════════════════");
    println!("  Wallet Info");
    println!("═══════════════════════════════════════════════");
    println!();
    println!("👤 Name:    {}", wallet.name);
    println!("📍 Address: {}", hex::encode(&wallet.address));
    println!("💰 Balance: {} TT", wallet.balance);
    println!("🔢 Nonce:   {}", wallet.nonce);
    println!();
    println!("🔑 Keys:");
    println!("   Falcon PK: {} bytes", wallet.falcon_pk.len());
    println!("   Falcon SK: {} bytes", wallet.falcon_sk.len());
    println!("   Kyber PK:  {} bytes", wallet.kyber_pk.len());
    println!("   Kyber SK:  {} bytes", wallet.kyber_sk.len());
    println!();
    
    Ok(())
}

fn cmd_list_wallets(dir: PathBuf) -> Result<()> {
    println!("📁 Searching for wallets in: {}", dir.display());
    println!();
    
    let mut found = 0;
    
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Ok(wallet) = SimpleWallet::load(&path) {
                found += 1;
                println!("{}. {}", found, path.file_name().unwrap().to_str().unwrap());
                println!("   Name: {}", wallet.name);
                println!("   Address: {}", hex::encode(&wallet.address[..8]));
                println!("   Balance: {} TT", wallet.balance);
                println!();
            }
        }
    }
    
    if found == 0 {
        println!("No wallets found.");
    } else {
        println!("Found {} wallet(s)", found);
    }
    
    Ok(())
}

fn cmd_send(from_path: PathBuf, to_hex: String, amount: u64, output: PathBuf) -> Result<()> {
    // Load sender wallet
    let mut wallet = SimpleWallet::load(&from_path)?;
    
    // Parse recipient address
    let to_bytes = hex::decode(&to_hex)?;
    if to_bytes.len() != 32 {
        anyhow::bail!("Invalid address length (must be 32 bytes = 64 hex chars)");
    }
    let mut to = [0u8; 32];
    to.copy_from_slice(&to_bytes);
    
    // Check balance
    if wallet.balance < amount as u128 {
        anyhow::bail!("Insufficient balance! Have: {}, Need: {}", wallet.balance, amount);
    }
    
    println!("💸 Creating transaction...");
    println!();
    println!("From:   {} ({})", wallet.name, hex::encode(&wallet.address[..8]));
    println!("To:     {}", hex::encode(&to[..8]));
    println!("Amount: {} TT", amount);
    println!("Fee:    10 TT");
    println!("Nonce:  {}", wallet.nonce);
    println!();
    
    // Create and sign transaction
    let mut tx = Transaction::new(
        wallet.address,
        to,
        amount,
        10, // fee
        wallet.nonce,
    );
    
    let (_, sk) = wallet.get_falcon_keys()?;
    tx.sign(&sk)?;
    
    // Save transaction
    let tx_json = serde_json::to_string_pretty(&tx)?;
    fs::write(&output, tx_json)?;
    
    // Update wallet
    wallet.balance -= amount as u128 + 10; // amount + fee
    wallet.nonce += 1;
    wallet.save(&from_path)?;
    
    println!("✅ Transaction created and signed!");
    println!("📄 Saved to: {}", output.display());
    println!("💰 New balance: {} TT", wallet.balance);
    println!();
    
    Ok(())
}

fn cmd_verify(tx_path: PathBuf, wallet_path: PathBuf) -> Result<()> {
    // Load transaction
    let tx_json = fs::read_to_string(&tx_path)?;
    let tx: Transaction = serde_json::from_str(&tx_json)?;
    
    // Load wallet
    let wallet = SimpleWallet::load(&wallet_path)?;
    
    println!("🔍 Verifying transaction...");
    println!();
    println!("TX ID:     {}", hex::encode(&tx.id()[..16]));
    println!("From:      {}", hex::encode(&tx.from[..8]));
    println!("To:        {}", hex::encode(&tx.to[..8]));
    println!("Amount:    {} TT", tx.amount);
    println!("Fee:       {} TT", tx.fee);
    println!("Timestamp: {}", tx.timestamp);
    println!();
    
    // Verify signature
    let (pk, _) = wallet.get_falcon_keys()?;
    match tx.verify(&pk) {
        Ok(()) => {
            println!("✅ Signature VALID");
            println!("✅ Transaction is authentic!");
        }
        Err(e) => {
            println!("❌ Signature INVALID");
            println!("   Error: {}", e);
        }
    }
    println!();
    
    Ok(())
}

fn cmd_create_mempool(txs_str: String, output: PathBuf) -> Result<()> {
    println!("📦 Creating mempool...");
    println!();
    
    let mut pool = TxPool::new();
    let tx_files: Vec<&str> = txs_str.split(',').collect();
    
    for (i, tx_file) in tx_files.iter().enumerate() {
        let tx_json = fs::read_to_string(tx_file.trim())?;
        let tx: Transaction = serde_json::from_str(&tx_json)?;
        
        println!("{}. {}", i+1, tx_file.trim());
        println!("   From: {}", hex::encode(&tx.from[..8]));
        println!("   To:   {}", hex::encode(&tx.to[..8]));
        println!("   Amount: {} TT", tx.amount);
        
        pool.add(tx)?;
    }
    
    println!();
    
    // Save mempool
    #[derive(Serialize, Deserialize)]
    struct MempoolFile {
        transactions: Vec<Transaction>,
        total_fees: u64,
        count: usize,
    }
    
    let txs = pool.get_all();
    let total_fees: u64 = txs.iter().map(|t| t.fee).sum();
    
    let mempool = MempoolFile {
        count: txs.len(),
        total_fees,
        transactions: txs,
    };
    
    let json = serde_json::to_string_pretty(&mempool)?;
    fs::write(&output, json)?;
    
    println!("✅ Mempool created!");
    println!("📄 File: {}", output.display());
    println!("📊 Transactions: {}", mempool.count);
    println!("💰 Total fees: {} TT", mempool.total_fees);
    println!();
    
    Ok(())
}

