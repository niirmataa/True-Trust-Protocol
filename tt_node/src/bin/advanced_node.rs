//! Advanced Node CLI - Using tx_stark.rs with STARK proofs and Kyber encryption
//!
//! This version relies **exclusively** on encrypted wallets created by `tt_wallet`.
//! Keys are never stored in plaintext JSON. Balances and nonces are kept in a
//! lightweight state file (`<wallet>.state.json`).

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use pqcrypto_traits::kem::{Ciphertext as KemCiphertext, PublicKey as PQKemPublicKey};
use pqcrypto_traits::sign::PublicKey as PQSignPublicKey;

use tt_node::kyber_kem::kyber_encapsulate;
use tt_node::node_id::NodeId;
use tt_node::tx_stark::{TransactionStark, TxInputStark, TxOutputStark};
use tt_node::wallet::api::{
    get_all_keys_from_wallet, get_kyber_keys_from_wallet, get_wallet_address, get_wallet_info,
    WalletInfo,
};

#[derive(Parser)]
#[command(name = "advanced_node")]
#[command(about = "TRUE_TRUST Advanced Node - STARK Proofs + Kyber Encryption (tt_wallet)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize state for an existing tt_wallet file
    NewWallet {
        /// Encrypted wallet created by `tt_wallet wallet-init`
        #[arg(short, long, value_name = "WALLET.dat")]
        output: PathBuf,

        /// Human-friendly label for state tracking (not stored in wallet keys)
        #[arg(short, long)]
        name: String,
    },

    /// Show wallet info (requires wallet password)
    Info {
        #[arg(short, long, value_name = "WALLET.dat")]
        wallet: PathBuf,
    },

    /// Send confidential transaction (with STARK proof + Kyber encryption)
    SendConfidential {
        /// Sender wallet (tt_wallet format)
        #[arg(short, long, value_name = "FROM.dat")]
        from: PathBuf,

        /// Recipient wallet (tt_wallet format)
        #[arg(short, long, value_name = "TO.dat")]
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
        #[arg(short, long, value_name = "WALLET.dat")]
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
        /// Your wallet (tt_wallet format)
        #[arg(short, long, value_name = "WALLET.dat")]
        wallet: PathBuf,

        /// Peer's public keys file (tt_wallet format)
        #[arg(short, long, value_name = "PEER.dat")]
        peer: PathBuf,

        /// Output shared secret file
        #[arg(short, long, default_value = "channel.bin")]
        output: PathBuf,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletState {
    name: String,
    balance: u128,
    nonce: u64,
}

impl WalletState {
    fn default_named(name: String) -> Self {
        Self {
            name,
            balance: 10_000,
            nonce: 0,
        }
    }

    fn state_path(wallet_path: &PathBuf) -> PathBuf {
        let mut state_name = wallet_path
            .file_name()
            .map(|os| os.to_string_lossy().to_string())
            .unwrap_or_else(|| "wallet".to_string());
        state_name.push_str(".state.json");
        wallet_path.with_file_name(state_name)
    }

    fn load(wallet_path: &PathBuf, default_name: &str) -> Result<Self> {
        let state_path = Self::state_path(wallet_path);
        if state_path.exists() {
            let json = fs::read_to_string(&state_path)
                .with_context(|| format!("Failed to read state file: {}", state_path.display()))?;
            Ok(serde_json::from_str(&json)
                .with_context(|| format!("Failed to parse state file: {}", state_path.display()))?)
        } else {
            Ok(Self::default_named(default_name.to_string()))
        }
    }

    fn save(&self, wallet_path: &PathBuf) -> Result<()> {
        let state_path = Self::state_path(wallet_path);
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&state_path, json)
            .with_context(|| format!("Failed to write state file: {}", state_path.display()))?;
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::NewWallet { output, name } => cmd_new_wallet(output, name),
        Commands::Info { wallet } => cmd_info(wallet),
        Commands::SendConfidential {
            from,
            to_wallet,
            amount,
            output,
        } => cmd_send_confidential(from, to_wallet, amount, output),
        Commands::DecryptTx { tx, wallet } => cmd_decrypt_tx(tx, wallet),
        Commands::VerifyProofs { tx } => cmd_verify_proofs(tx),
        Commands::CreateChannel {
            wallet,
            peer,
            output,
        } => cmd_create_channel(wallet, peer, output),
    }
}

fn wallet_label(wallet_path: &PathBuf) -> String {
    wallet_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "wallet".to_string())
}

fn ensure_wallet_exists(wallet_path: &PathBuf) -> Result<()> {
    if !wallet_path.exists() {
        bail!(
            "Wallet file not found: {}. Create one with `tt_wallet wallet-init --file <name>.dat>`",
            wallet_path.display()
        );
    }
    Ok(())
}

fn print_wallet_overview(info: &WalletInfo, state: &WalletState) {
    println!("👤 Name:    {}", state.name);
    println!("📍 Address: {}", hex::encode(&info.address));
    println!("💰 Balance: {} TT (state file)", state.balance);
    println!("🔢 Nonce:   {}", state.nonce);
    println!("Wallet ID: {}", hex::encode(info.wallet_id));
    println!();
    println!("🔑 Post-Quantum Keys (tt_wallet)");
    println!(
        "   Falcon-512 PK: {} bytes",
        info.falcon_pk.as_bytes().len()
    );
    println!("   Kyber-768  PK: {} bytes", info.kyber_pk.as_bytes().len());
}

fn cmd_new_wallet(wallet_path: PathBuf, name: String) -> Result<()> {
    ensure_wallet_exists(&wallet_path)?;

    println!("🔐 Detected tt_wallet file. Initializing state...");

    let info = get_wallet_info(&wallet_path, None)?;
    let state = WalletState::default_named(name.clone());
    state.save(&wallet_path)?;

    println!("✅ State initialized for tt_wallet file");
    println!("📄 Wallet: {}", wallet_path.display());
    println!(
        "🗂  State:  {}",
        WalletState::state_path(&wallet_path).display()
    );
    println!();
    print_wallet_overview(&info, &state);

    Ok(())
}

fn cmd_info(wallet_path: PathBuf) -> Result<()> {
    ensure_wallet_exists(&wallet_path)?;

    let info = get_wallet_info(&wallet_path, None)?;
    let state = WalletState::load(&wallet_path, &wallet_label(&wallet_path))?;

    println!("═══════════════════════════════════════════════");
    println!("  Advanced Wallet Info (tt_wallet)");
    println!("═══════════════════════════════════════════════");
    println!();
    print_wallet_overview(&info, &state);

    Ok(())
}

fn cmd_send_confidential(
    from_path: PathBuf,
    to_wallet_path: PathBuf,
    amount: u64,
    output: PathBuf,
) -> Result<()> {
    ensure_wallet_exists(&from_path)?;
    ensure_wallet_exists(&to_wallet_path)?;

    println!("💸 Creating CONFIDENTIAL transaction with STARK proof (tt_wallet)...");
    println!();

    // Load keys from encrypted tt_wallet files (will prompt for passwords)
    let (from_falcon_pk, _, from_kyber_pk, _, from_address) =
        get_all_keys_from_wallet(&from_path, None)?;
    let (to_kyber_pk, _) = get_kyber_keys_from_wallet(&to_wallet_path, None)?;
    let to_address: NodeId = get_wallet_address(&to_wallet_path, None)?;

    let mut from_state = WalletState::load(&from_path, &wallet_label(&from_path))?;

    // Check balance
    let total = amount as u128 + 10;
    if from_state.balance < total {
        bail!(
            "Insufficient balance! Have: {} TT, Need: {} TT",
            from_state.balance,
            total
        );
    }

    println!(
        "From:       {} ({})",
        from_state.name,
        hex::encode(&from_address[..8])
    );
    println!(
        "To:         {} ({})",
        wallet_label(&to_wallet_path),
        hex::encode(&to_address[..8])
    );
    println!("Amount:     {} TT (ENCRYPTED)", amount);
    println!("Fee:        10 TT");
    println!();
    println!(
        "🔑 Sender keys: Falcon PK {} bytes, Kyber PK {} bytes",
        from_falcon_pk.as_bytes().len(),
        from_kyber_pk.as_bytes().len()
    );
    println!("🔒 Creating STARK proof for range check...");

    // Create confidential output with STARK proof
    let output_stark = TxOutputStark::new_confidential(amount, to_address, &to_kyber_pk)?;

    println!("✅ STARK proof generated!");
    println!("🔐 Value encrypted with Kyber-768 (tt_wallet)");
    println!();

    // Create input (simplified for demo)
    let input = TxInputStark {
        prev_output_id: [0u8; 32], // Genesis
        output_index: 0,
        spending_sig: vec![], // Signatures handled by tt_wallet in full node
    };

    // Create transaction
    let tx = TransactionStark {
        inputs: vec![input],
        outputs: vec![output_stark],
        fee: 10,
        nonce: from_state.nonce,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Save transaction
    let tx_json = serde_json::to_string_pretty(&tx)?;
    fs::write(&output, tx_json)?;

    // Update wallet state (state file only)
    from_state.balance -= total;
    from_state.nonce += 1;
    from_state.save(&from_path)?;

    println!("✅ Confidential transaction created!");
    println!("📄 Saved to: {}", output.display());
    println!("💰 New balance (state): {} TT", from_state.balance);
    println!();
    println!("🎯 Transaction features:");
    println!("   ✅ Amount is HIDDEN (Kyber encrypted)");
    println!("   ✅ STARK proof verifies amount in valid range");
    println!("   ✅ Keys loaded from encrypted tt_wallet file");
    println!();

    Ok(())
}

fn cmd_decrypt_tx(tx_path: PathBuf, wallet_path: PathBuf) -> Result<()> {
    ensure_wallet_exists(&wallet_path)?;

    println!("🔓 Decrypting confidential transaction (tt_wallet)...");
    println!();

    // Load transaction
    let tx_json = fs::read_to_string(&tx_path)?;
    let tx: TransactionStark = serde_json::from_str(&tx_json)?;

    // Load wallet
    let wallet_address = get_wallet_address(&wallet_path, None)?;
    let (_, kyber_sk) = get_kyber_keys_from_wallet(&wallet_path, None)?;

    println!("TX ID: {}", hex::encode(&tx.id()[..16]));
    println!("Outputs: {}", tx.outputs.len());
    println!();

    // Try to decrypt each output
    for (i, output) in tx.outputs.iter().enumerate() {
        println!("Output {}:", i + 1);
        println!("  Recipient: {}", hex::encode(&output.recipient[..8]));
        println!("  Encrypted: {} bytes", output.encrypted_value.len());

        if output.recipient == wallet_address {
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

fn cmd_create_channel(wallet_path: PathBuf, peer_path: PathBuf, output: PathBuf) -> Result<()> {
    ensure_wallet_exists(&wallet_path)?;
    ensure_wallet_exists(&peer_path)?;

    println!("🔐 Creating secret channel with Kyber KEM (tt_wallet)...");
    println!();

    let wallet_state = WalletState::load(&wallet_path, &wallet_label(&wallet_path))?;
    let peer_state = WalletState::load(&peer_path, &wallet_label(&peer_path))?;

    // Get Kyber keys
    let (peer_kyber_pk, _) = get_kyber_keys_from_wallet(&peer_path, None)?;

    println!("Your wallet: {}", wallet_state.name);
    println!("Peer wallet: {}", peer_state.name);
    println!();

    // Perform Kyber encapsulation
    let (shared_secret, ciphertext) = kyber_encapsulate(&peer_kyber_pk);

    println!("✅ Shared secret established!");
    println!(
        "   Secret: {} bytes",
        pqcrypto_traits::kem::SharedSecret::as_bytes(&shared_secret).len()
    );
    println!("   Ciphertext: {} bytes", ciphertext.as_bytes().len());
    println!();

    // Save channel info
    #[derive(Serialize)]
    struct Channel {
        from: String,
        to: String,
        ciphertext: Vec<u8>,
    }

    let channel = Channel {
        from: wallet_state.name,
        to: peer_state.name,
        ciphertext: ciphertext.as_bytes().to_vec(),
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
