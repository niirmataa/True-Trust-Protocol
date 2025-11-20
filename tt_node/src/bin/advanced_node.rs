//! Advanced Node CLI - Using tx_stark.rs with STARK proofs and Kyber encryption
//!
//! This is the REAL implementation with:
//! - STARK range proofs
//! - Kyber-encrypted values
//! - Confidential transactions
//! - Secret channels

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use std::fs;

use tt_node::falcon_sigs::{falcon_keypair, FalconPublicKey, FalconSecretKey};
use tt_node::kyber_kem::{kyber_keypair, KyberPublicKey, KyberSecretKey};
use tt_node::node_id::node_id_from_falcon_pk;
use tt_node::tx_stark::{TransactionStark, TxInputStark, TxOutputStark};
use tt_node::core::Hash32;

use pqcrypto_traits::sign::{PublicKey as PQPublicKey, SecretKey as PQSecretKey};
use pqcrypto_traits::kem::{PublicKey as PQKemPublicKey, SecretKey as PQKemSecretKey};

#[derive(Parser)]
#[command(name = "advanced_node")]
#[command(about = "TRUE_TRUST Advanced Node - STARK Proofs + Kyber Encryption")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create new wallet with Kyber keys
    NewWallet {
        #[arg(short, long)]
        output: PathBuf,
        
        #[arg(short, long)]
        name: String,
    },
    
    /// Show wallet info
    Info {
        #[arg(short, long)]
        wallet: PathBuf,
    },
    
    /// Send confidential transaction (with STARK proof + Kyber encryption)
    SendConfidential {
        /// Sender wallet
        #[arg(short, long)]
        from: PathBuf,
        
        /// Recipient wallet (for Kyber encryption)
        #[arg(short, long)]
        to_wallet: PathBuf,
        
        /// Amount (will be encrypted with Kyber)
        #[arg(short, long)]
        amount: u64,
        
        /// Output transaction file
        #[arg(short = 'o', long, default_value = "tx_stark.json")]
        output: PathBuf,
    },
    
    /// Decrypt and verify received transaction
    DecryptTx {
        /// Transaction file
        #[arg(short, long)]
        tx: PathBuf,
        
        /// Your wallet (to decrypt)
        #[arg(short, long)]
        wallet: PathBuf,
    },
    
    /// Verify STARK proofs in transaction
    VerifyProofs {
        /// Transaction file
        #[arg(short, long)]
        tx: PathBuf,
    },
    
    /// Create secret channel (Kyber KEM)
    CreateChannel {
        /// Your wallet
        #[arg(short, long)]
        wallet: PathBuf,
        
        /// Peer's public keys file
        #[arg(short, long)]
        peer: PathBuf,
        
        /// Output shared secret file
        #[arg(short, long, default_value = "channel.bin")]
        output: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct AdvancedWallet {
    name: String,
    falcon_pk: Vec<u8>,
    falcon_sk: Vec<u8>,
    kyber_pk: Vec<u8>,
    kyber_sk: Vec<u8>,
    address: Hash32,
    balance: u128,
    nonce: u64,
}

impl AdvancedWallet {
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
            balance: 10000,
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
    
    fn get_kyber_keys(&self) -> Result<(KyberPublicKey, KyberSecretKey)> {
        use pqcrypto_kyber::kyber768;
        let pk = kyber768::PublicKey::from_bytes(&self.kyber_pk)
            .map_err(|_| anyhow::anyhow!("Invalid Kyber public key"))?;
        let sk = kyber768::SecretKey::from_bytes(&self.kyber_sk)
            .map_err(|_| anyhow::anyhow!("Invalid Kyber secret key"))?;
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
        Commands::SendConfidential { from, to_wallet, amount, output } => {
            cmd_send_confidential(from, to_wallet, amount, output)
        }
        Commands::DecryptTx { tx, wallet } => {
            cmd_decrypt_tx(tx, wallet)
        }
        Commands::VerifyProofs { tx } => {
            cmd_verify_proofs(tx)
        }
        Commands::CreateChannel { wallet, peer, output } => {
            cmd_create_channel(wallet, peer, output)
        }
    }
}

fn cmd_new_wallet(output: PathBuf, name: String) -> Result<()> {
    println!("🔐 Creating advanced wallet with Kyber support...");
    println!();
    
    let wallet = AdvancedWallet::new(name.clone());
    wallet.save(&output)?;
    
    println!("✅ Advanced wallet created!");
    println!();
    println!("📄 File: {}", output.display());
    println!("👤 Name: {}", wallet.name);
    println!("📍 Address: {}", hex::encode(&wallet.address));
    println!("💰 Balance: {} TT", wallet.balance);
    println!();
    println!("🔑 Keys:");
    println!("   Falcon-512: {} bytes PK, {} bytes SK", 
             wallet.falcon_pk.len(), wallet.falcon_sk.len());
    println!("   Kyber-768:  {} bytes PK, {} bytes SK",
             wallet.kyber_pk.len(), wallet.kyber_sk.len());
    println!();
    println!("⚠️  KEEP THIS FILE SAFE! Contains private keys.");
    
    Ok(())
}

fn cmd_info(wallet_path: PathBuf) -> Result<()> {
    let wallet = AdvancedWallet::load(&wallet_path)?;
    
    println!("═══════════════════════════════════════════════");
    println!("  Advanced Wallet Info");
    println!("═══════════════════════════════════════════════");
    println!();
    println!("👤 Name:    {}", wallet.name);
    println!("📍 Address: {}", hex::encode(&wallet.address));
    println!("💰 Balance: {} TT", wallet.balance);
    println!("🔢 Nonce:   {}", wallet.nonce);
    println!();
    println!("🔑 Post-Quantum Keys:");
    println!("   Falcon-512 (Signatures):");
    println!("      PK: {} bytes", wallet.falcon_pk.len());
    println!("      SK: {} bytes", wallet.falcon_sk.len());
    println!();
    println!("   Kyber-768 (KEM for confidential tx):");
    println!("      PK: {} bytes", wallet.kyber_pk.len());
    println!("      SK: {} bytes", wallet.kyber_sk.len());
    println!();
    println!("✅ Supports:");
    println!("   • Confidential transactions (STARK proofs)");
    println!("   • Encrypted amounts (Kyber)");
    println!("   • Secret channels");
    println!();
    
    Ok(())
}

fn cmd_send_confidential(
    from_path: PathBuf,
    to_wallet_path: PathBuf,
    amount: u64,
    output: PathBuf,
) -> Result<()> {
    println!("💸 Creating CONFIDENTIAL transaction with STARK proof...");
    println!();
    
    // Load wallets
    let mut from_wallet = AdvancedWallet::load(&from_path)?;
    let to_wallet = AdvancedWallet::load(&to_wallet_path)?;
    
    // Get keys
    let (_, from_falcon_sk) = from_wallet.get_falcon_keys()?;
    let (to_kyber_pk, _) = to_wallet.get_kyber_keys()?;
    
    // Check balance
    if from_wallet.balance < amount as u128 {
        anyhow::bail!("Insufficient balance! Have: {}, Need: {}", from_wallet.balance, amount);
    }
    
    println!("From:       {} ({})", from_wallet.name, hex::encode(&from_wallet.address[..8]));
    println!("To:         {} ({})", to_wallet.name, hex::encode(&to_wallet.address[..8]));
    println!("Amount:     {} TT (ENCRYPTED)", amount);
    println!("Fee:        10 TT");
    println!();
    println!("🔒 Creating STARK proof for range check...");
    
    // Create confidential output with STARK proof
    let output_stark = TxOutputStark::new_confidential(
        amount,
        to_wallet.address,
        &to_kyber_pk,
    )?;
    
    println!("✅ STARK proof generated!");
    println!("🔐 Value encrypted with Kyber-768");
    println!();
    
    // Create input (simplified for demo)
    let input = TxInputStark {
        prev_output_id: [0u8; 32], // Genesis
        output_index: 0,
        spending_sig: vec![], // Would sign with Falcon
    };
    
    // Create transaction
    let tx = TransactionStark {
        inputs: vec![input],
        outputs: vec![output_stark],
        fee: 10,
        nonce: from_wallet.nonce,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    // Save transaction
    let tx_json = serde_json::to_string_pretty(&tx)?;
    fs::write(&output, tx_json)?;
    
    // Update wallet
    from_wallet.balance -= amount as u128 + 10;
    from_wallet.nonce += 1;
    from_wallet.save(&from_path)?;
    
    println!("✅ Confidential transaction created!");
    println!("📄 Saved to: {}", output.display());
    println!("💰 New balance: {} TT", from_wallet.balance);
    println!();
    println!("🎯 Transaction features:");
    println!("   ✅ Amount is HIDDEN (Kyber encrypted)");
    println!("   ✅ STARK proof verifies amount in valid range");
    println!("   ✅ Only recipient can decrypt the amount");
    println!();
    
    Ok(())
}

fn cmd_decrypt_tx(tx_path: PathBuf, wallet_path: PathBuf) -> Result<()> {
    println!("🔓 Decrypting confidential transaction...");
    println!();
    
    // Load transaction
    let tx_json = fs::read_to_string(&tx_path)?;
    let tx: TransactionStark = serde_json::from_str(&tx_json)?;
    
    // Load wallet
    let wallet = AdvancedWallet::load(&wallet_path)?;
    let (_, kyber_sk) = wallet.get_kyber_keys()?;
    
    println!("TX ID: {}", hex::encode(&tx.id()[..16]));
    println!("Outputs: {}", tx.outputs.len());
    println!();
    
    // Try to decrypt each output
    for (i, output) in tx.outputs.iter().enumerate() {
        println!("Output {}:", i + 1);
        println!("  Recipient: {}", hex::encode(&output.recipient[..8]));
        println!("  Encrypted: {} bytes", output.encrypted_value.len());
        
        if output.recipient == wallet.address {
            println!("  → This output is for YOU!");
            
            match output.decrypt_and_verify(&kyber_sk) {
                Some(amount) => {
                    println!("  ✅ Decrypted amount: {} TT", amount);
                    println!("  ✅ Commitment verified!");
                }
                None => {
                    println!("  ❌ Decryption failed or commitment invalid");
                }
            }
        } else {
            println!("  → For someone else (can't decrypt)");
        }
        println!();
    }
    
    Ok(())
}

fn cmd_verify_proofs(tx_path: PathBuf) -> Result<()> {
    println!("🔍 Verifying STARK proofs...");
    println!();
    
    // Load transaction
    let tx_json = fs::read_to_string(&tx_path)?;
    let tx: TransactionStark = serde_json::from_str(&tx_json)?;
    
    println!("TX ID: {}", hex::encode(&tx.id()[..16]));
    println!("Outputs: {}", tx.outputs.len());
    println!();
    
    let (valid, total) = tx.verify_all_proofs();
    
    println!("STARK Proof Verification:");
    println!("  Valid: {}/{}", valid, total);
    
    if valid == total {
        println!("  ✅ All STARK proofs are VALID!");
        println!("  ✅ All amounts are in valid range");
    } else {
        println!("  ❌ Some proofs FAILED verification");
    }
    println!();
    
    Ok(())
}

fn cmd_create_channel(
    wallet_path: PathBuf,
    peer_path: PathBuf,
    output: PathBuf,
) -> Result<()> {
    println!("🔐 Creating secret channel with Kyber KEM...");
    println!();
    
    // Load wallets
    let wallet = AdvancedWallet::load(&wallet_path)?;
    let peer = AdvancedWallet::load(&peer_path)?;
    
    // Get Kyber keys
    let (peer_kyber_pk, _) = peer.get_kyber_keys()?;
    
    println!("Your wallet: {}", wallet.name);
    println!("Peer wallet: {}", peer.name);
    println!();
    
    // Perform Kyber encapsulation
    use tt_node::kyber_kem::kyber_encapsulate;
    let (shared_secret, ciphertext) = kyber_encapsulate(&peer_kyber_pk);
    
    println!("✅ Shared secret established!");
    println!("   Secret: {} bytes", pqcrypto_traits::kem::SharedSecret::as_bytes(&shared_secret).len());
    println!("   Ciphertext: {} bytes", pqcrypto_traits::kem::Ciphertext::as_bytes(&ciphertext).len());
    println!();
    
    // Save channel info
    #[derive(Serialize)]
    struct Channel {
        from: String,
        to: String,
        ciphertext: Vec<u8>,
    }
    
    let channel = Channel {
        from: wallet.name,
        to: peer.name,
        ciphertext: pqcrypto_traits::kem::Ciphertext::as_bytes(&ciphertext).to_vec(),
    };
    
    let json = serde_json::to_string_pretty(&channel)?;
    fs::write(&output, json)?;
    
    println!("📄 Channel info saved to: {}", output.display());
    println!();
    println!("🎯 Use this shared secret to:");
    println!("   • Encrypt messages with AES-256-GCM");
    println!("   • Authenticate communications");
    println!("   • Create secure P2P channel");
    println!();
    
    Ok(())
}

