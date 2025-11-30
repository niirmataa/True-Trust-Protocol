//! TT Protocol Local Testnet (Light Mode)
//!
//! Testnet BEZ RandomX PoW i consensus - do testowania:
//! - PQ RPC (Falcon + Kyber handshake)
//! - Wallet operations
//! - P2P communication
//! - Stealth transactions
//! - Device PoW enrollment (lekki SHA3)
//!
//! NIE testujemy (wymaga wielu maszyn):
//! - RandomX mining
//! - Consensus/finalizacja bloków
//!
//! Usage:
//!   cargo run --release --bin testnet
//!   cargo run --release --bin testnet -- --nodes 3
//!   cargo run --release --bin testnet -- --demo

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use tt_node::node_core::NodeCore;
use tt_node::p2p::secure::NodeIdentity;
use tt_node::rpc::rpc_secure::{SecureRpcServer, SecureRpcClient, RpcRequest, RpcResponse};
use tt_node::falcon_sigs::falcon_keypair;

/// TT Protocol Local Testnet (Light - no RandomX)
#[derive(Parser, Debug)]
#[command(name = "tt-testnet")]
#[command(about = "Local TT testnet for RPC/Wallet/P2P testing (no RandomX consensus)")]
struct Args {
    /// Number of nodes to run
    #[arg(short, long, default_value = "3")]
    nodes: u32,
    
    /// Base RPC port (nodes will use consecutive ports)
    #[arg(short, long, default_value = "9000")]
    base_port: u16,
    
    /// Run demo scenarios after startup
    #[arg(short, long)]
    demo: bool,
    
    /// Interactive mode - REPL for manual testing
    #[arg(short, long)]
    interactive: bool,
}

/// Testnet node info
#[derive(Debug, Clone)]
pub struct TestnetNode {
    pub id: u32,
    pub rpc_port: u16,
    pub node_id: [u8; 32],
    pub address: [u8; 32],
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    print_banner();
    
    println!("Configuration:");
    println!("  • Nodes: {}", args.nodes);
    println!("  • RPC ports: {}-{}", args.base_port, args.base_port + args.nodes as u16 - 1);
    println!("  • Mode: Light (no RandomX, no consensus)");
    println!();
    
    // Start nodes
    let nodes = start_testnet_nodes(args.nodes, args.base_port).await?;
    
    print_nodes_table(&nodes);
    
    if args.demo {
        run_demo_scenarios(&nodes).await?;
    }
    
    if args.interactive {
        run_interactive_mode(&nodes).await?;
    } else {
        // Keep running
        println!("\n📡 Testnet running. Press Ctrl+C to stop.\n");
        println!("To interact:");
        println!("  cargo run --release --bin testnet -- --interactive");
        println!("  cargo run --release --bin testnet -- --demo\n");
        
        loop {
            sleep(Duration::from_secs(30)).await;
        }
    }
    
    Ok(())
}

fn print_banner() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║        🔐 TT PROTOCOL LOCAL TESTNET (LIGHT) 🔐              ║");
    println!("║                                                              ║");
    println!("║  Testing: RPC • Wallet • P2P • Stealth TX • Device PoW      ║");
    println!("║  Disabled: RandomX Mining • Consensus • Block Finalization  ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}

fn print_nodes_table(nodes: &[TestnetNode]) {
    println!("\n┌────────┬───────────┬──────────────────────────────────────┐");
    println!("│ Node   │ RPC Port  │ Address                              │");
    println!("├────────┼───────────┼──────────────────────────────────────┤");
    for node in nodes {
        println!("│ {:>6} │ {:>9} │ {}... │", 
            node.id,
            node.rpc_port,
            hex::encode(&node.address[..16])
        );
    }
    println!("└────────┴───────────┴──────────────────────────────────────┘");
}

/// Starts testnet nodes (light mode - no mining)
async fn start_testnet_nodes(count: u32, base_rpc: u16) -> Result<Vec<TestnetNode>> {
    let mut nodes = Vec::new();
    
    for i in 0..count {
        let rpc_port = base_rpc + i as u16;
        
        print!("🚀 Starting node {}...", i);
        
        // Create identity
        let identity = create_node_identity()?;
        let node_id = identity.node_id;
        
        // Create NodeCore with temp data dir
        let data_dir = PathBuf::from(format!("/tmp/tt_testnet_node_{}", i));
        std::fs::create_dir_all(&data_dir).ok();
        let node_core = Arc::new(NodeCore::new(data_dir, false)?);  // Not validator in light mode
        
        // Derive address and credit genesis funds
        let address = derive_address(&node_id);
        {
            let mut ledger = node_core.ledger.write().await;
            ledger.credit(&address, 1_000_000_000_000); // 1T tokens
        }
        
        // Start RPC server
        let server = SecureRpcServer::new(
            rpc_port,
            identity,
            false, // Not validator (no consensus in light mode)
            node_core,
        );
        
        tokio::spawn(async move {
            if let Err(e) = server.start().await {
                eprintln!("\nNode {} error: {}", i, e);
            }
        });
        
        nodes.push(TestnetNode {
            id: i,
            rpc_port,
            node_id,
            address,
        });
        
        println!(" ✓");
        sleep(Duration::from_millis(50)).await;
    }
    
    // Wait for servers to bind
    sleep(Duration::from_millis(300)).await;
    
    Ok(nodes)
}

fn create_node_identity() -> Result<NodeIdentity> {
    // Use the built-in generator which handles all the complexity
    Ok(NodeIdentity::generate())
}

fn derive_address(node_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"TT_ADDR_V1");
    hasher.update(node_id);
    let hash = hasher.finalize();
    let mut addr = [0u8; 32];
    addr.copy_from_slice(hash.as_bytes());
    addr
}

/// Interactive REPL mode
async fn run_interactive_mode(nodes: &[TestnetNode]) -> Result<()> {
    use std::io::{self, Write};
    
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                    INTERACTIVE MODE                          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Commands:");
    println!("  status <node>     - Get node status");
    println!("  balance <node>    - Get node balance");
    println!("  transfer <from> <to> <amount> - Transfer tokens");
    println!("  credit <node> <amount> - Credit tokens (faucet)");
    println!("  connect <node>    - Test PQ connection");
    println!("  privacy <node>    - Test ProPrivacy mode");
    println!("  stealth           - Demo stealth transaction");
    println!("  enrollment        - Demo device enrollment");
    println!("  help              - Show commands");
    println!("  quit              - Exit");
    println!();
    
    let mut client: Option<SecureRpcClient> = None;
    let mut connected_node: Option<u32> = None;
    
    loop {
        print!("tt> ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        
        if parts.is_empty() {
            continue;
        }
        
        match parts[0] {
            "quit" | "exit" | "q" => {
                println!("Goodbye!");
                break;
            }
            "help" | "h" | "?" => {
                println!("Commands: status, balance, transfer, credit, connect, privacy, stealth, enrollment, quit");
            }
            "connect" => {
                if parts.len() < 2 {
                    println!("Usage: connect <node_id>");
                    continue;
                }
                let node_id: u32 = parts[1].parse().unwrap_or(0);
                if let Some(node) = nodes.get(node_id as usize) {
                    match connect_to_node(node).await {
                        Ok(c) => {
                            println!("✅ Connected to node {} (PQ handshake OK)", node_id);
                            client = Some(c);
                            connected_node = Some(node_id);
                        }
                        Err(e) => println!("❌ Connection failed: {}", e),
                    }
                } else {
                    println!("❌ Invalid node ID");
                }
            }
            "status" => {
                let node_id = parts.get(1).and_then(|s| s.parse().ok()).or(connected_node).unwrap_or(0);
                if let Some(node) = nodes.get(node_id as usize) {
                    if let Err(e) = cmd_status(node).await {
                        println!("❌ Error: {}", e);
                    }
                }
            }
            "balance" => {
                let node_id = parts.get(1).and_then(|s| s.parse().ok()).or(connected_node).unwrap_or(0);
                if let Some(node) = nodes.get(node_id as usize) {
                    if let Err(e) = cmd_balance(nodes, node_id).await {
                        println!("❌ Error: {}", e);
                    }
                }
            }
            "credit" => {
                if parts.len() < 3 {
                    println!("Usage: credit <node_id> <amount>");
                    continue;
                }
                let node_id: u32 = parts[1].parse().unwrap_or(0);
                let amount: u128 = parts[2].parse().unwrap_or(0);
                if let Some(node) = nodes.get(node_id as usize) {
                    if let Err(e) = cmd_credit(nodes, node_id, amount).await {
                        println!("❌ Error: {}", e);
                    }
                }
            }
            "transfer" => {
                if parts.len() < 4 {
                    println!("Usage: transfer <from_node> <to_node> <amount>");
                    continue;
                }
                let from: u32 = parts[1].parse().unwrap_or(0);
                let to: u32 = parts[2].parse().unwrap_or(1);
                let amount: u128 = parts[3].parse().unwrap_or(0);
                if let Err(e) = cmd_transfer(nodes, from, to, amount).await {
                    println!("❌ Error: {}", e);
                }
            }
            "privacy" => {
                let node_id = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = nodes.get(node_id as usize) {
                    if let Err(e) = cmd_pro_privacy(node).await {
                        println!("❌ Error: {}", e);
                    }
                }
            }
            "stealth" => {
                if let Err(e) = cmd_stealth_demo(nodes).await {
                    println!("❌ Error: {}", e);
                }
            }
            "enrollment" => {
                if let Err(e) = cmd_enrollment_demo(nodes).await {
                    println!("❌ Error: {}", e);
                }
            }
            _ => {
                println!("Unknown command. Type 'help' for list.");
            }
        }
    }
    
    Ok(())
}

async fn connect_to_node(node: &TestnetNode) -> Result<SecureRpcClient> {
    let addr: SocketAddr = format!("127.0.0.1:{}", node.rpc_port).parse()?;
    let identity = create_node_identity()?;
    let mut client = SecureRpcClient::new(addr, identity);
    client.connect().await?;
    Ok(client)
}

async fn cmd_status(node: &TestnetNode) -> Result<()> {
    let mut client = connect_to_node(node).await?;
    
    let response = client.request(RpcRequest::GetStatus).await?;
    match response {
        RpcResponse::Status { node_id, is_validator, height, uptime, .. } => {
            println!("📊 Node {} Status:", node.id);
            println!("   ID: {}...", &node_id[..16]);
            println!("   Validator: {}", is_validator);
            println!("   Height: {}", height);
            println!("   Uptime: {}s", uptime);
        }
        RpcResponse::Error { message, .. } => println!("❌ {}", message),
        _ => {}
    }
    Ok(())
}

async fn cmd_balance(nodes: &[TestnetNode], node_id: u32) -> Result<()> {
    let node = &nodes[0]; // Connect to first node
    let mut client = connect_to_node(node).await?;
    
    let target = &nodes[node_id as usize];
    let response = client.request(RpcRequest::GetBalance {
        address_hex: hex::encode(target.address),
    }).await?;
    
    match response {
        RpcResponse::Balance { confirmed, pending, .. } => {
            println!("💰 Node {} Balance:", node_id);
            println!("   Confirmed: {} TT", confirmed);
            println!("   Pending: {} TT", pending);
        }
        RpcResponse::Error { message, .. } => println!("❌ {}", message),
        _ => {}
    }
    Ok(())
}

async fn cmd_credit(nodes: &[TestnetNode], node_id: u32, amount: u128) -> Result<()> {
    let node = &nodes[0];
    let mut client = connect_to_node(node).await?;
    
    let target = &nodes[node_id as usize];
    let response = client.request(RpcRequest::Credit {
        address_hex: hex::encode(target.address),
        amount,
    }).await?;
    
    match response {
        RpcResponse::Credited { new_balance, .. } => {
            println!("✅ Credited {} TT to node {}", amount, node_id);
            println!("   New balance: {} TT", new_balance);
        }
        RpcResponse::Error { message, .. } => println!("❌ {}", message),
        _ => {}
    }
    Ok(())
}

async fn cmd_transfer(nodes: &[TestnetNode], from: u32, to: u32, amount: u128) -> Result<()> {
    println!("🔄 Transfer {} TT: node {} → node {}", amount, from, to);
    
    let node = &nodes[0];
    let mut client = connect_to_node(node).await?;
    
    // Create sender keys
    let (sender_pk, sender_sk) = falcon_keypair();
    let mut hasher = blake3::Hasher::new();
    hasher.update(tt_node::falcon_sigs::falcon_pk_to_bytes(&sender_pk));
    let hash = hasher.finalize();
    let mut sender_addr = [0u8; 32];
    sender_addr.copy_from_slice(hash.as_bytes());
    
    // Credit sender first
    let _ = client.request(RpcRequest::Credit {
        address_hex: hex::encode(sender_addr),
        amount: amount + 100, // + fee
    }).await?;
    
    let recipient = nodes[to as usize].address;
    let fee: u128 = 10;
    let nonce: u64 = 1;
    
    // Sign
    let mut msg = Vec::new();
    msg.extend_from_slice(&sender_addr);
    msg.extend_from_slice(&recipient);
    msg.extend_from_slice(&amount.to_le_bytes());
    msg.extend_from_slice(&fee.to_le_bytes());
    msg.extend_from_slice(&nonce.to_le_bytes());
    
    let sig = tt_node::falcon_sigs::falcon_sign(&msg, &sender_sk)?;
    
    let response = client.request(RpcRequest::SubmitSimplePqTx {
        from_hex: hex::encode(sender_addr),
        to_hex: hex::encode(recipient),
        amount,
        fee,
        nonce,
        falcon_pk_hex: hex::encode(tt_node::falcon_sigs::falcon_pk_to_bytes(&sender_pk)),
        falcon_sig_hex: hex::encode(&sig.signed_message_bytes),
    }).await?;
    
    match response {
        RpcResponse::SimplePqTxSubmitted { tx_id, accepted, new_sender_balance, new_recipient_balance } => {
            if accepted {
                println!("✅ Transfer complete!");
                println!("   TX: {}...", &tx_id[..16]);
                println!("   Sender balance: {}", new_sender_balance);
                println!("   Recipient balance: {}", new_recipient_balance);
            } else {
                println!("❌ Transfer rejected");
            }
        }
        RpcResponse::Error { message, .. } => println!("❌ {}", message),
        _ => {}
    }
    Ok(())
}

async fn cmd_pro_privacy(node: &TestnetNode) -> Result<()> {
    println!("🔒 Testing ProPrivacy mode (ephemeral identity)...");
    
    let addr: SocketAddr = format!("127.0.0.1:{}", node.rpc_port).parse()?;
    let mut client = SecureRpcClient::new_pro_privacy(addr)?;
    client.connect().await?;
    
    println!("✅ Connected with \x1b[1;31mProPrivacy\x1b[0m mode");
    println!("   • New PQ identity generated");
    println!("   • Session unlinkable to previous connections");
    
    let response = client.request(RpcRequest::GetStatus).await?;
    match response {
        RpcResponse::Status { height, .. } => {
            println!("   • Successfully queried (height: {})", height);
        }
        _ => {}
    }
    
    println!("\n💡 For full anonymity, combine with Tor (--features tor_proxy)");
    Ok(())
}

async fn cmd_stealth_demo(nodes: &[TestnetNode]) -> Result<()> {
    println!("🔐 Stealth Transaction Demo");
    println!("────────────────────────────");
    
    let node = &nodes[0];
    let mut client = connect_to_node(node).await?;
    
    // Create stealth hint
    use rand::RngCore;
    let mut hint = vec![0u8; 64];
    rand::thread_rng().fill_bytes(&mut hint);
    
    println!("1. Creating stealth hint...");
    let response = client.request(RpcRequest::SubmitStealthHint {
        hint_hex: hex::encode(&hint),
    }).await?;
    
    match response {
        RpcResponse::StealthHintSubmitted { hint_id, .. } => {
            println!("   ✅ Hint submitted: {}...", &hint_id[..16]);
        }
        RpcResponse::Error { message, .. } => {
            println!("   ❌ {}", message);
            return Ok(());
        }
        _ => {}
    }
    
    println!("2. Retrieving stealth hints...");
    let response = client.request(RpcRequest::GetStealthHints {
        limit: Some(10),
        offset: None,
    }).await?;
    
    match response {
        RpcResponse::StealthHints { hints, total_count } => {
            println!("   ✅ Found {} hints in pool", total_count);
            println!("   Latest: {}...", &hints.last().unwrap_or(&String::new())[..32.min(hints.last().map(|s| s.len()).unwrap_or(0))]);
        }
        _ => {}
    }
    
    println!("\n💡 Full stealth TX requires wallet integration");
    Ok(())
}

async fn cmd_enrollment_demo(nodes: &[TestnetNode]) -> Result<()> {
    use tt_node::rpc::verified_device_pow::{solve_pow, EnrollmentChallenge};
    
    println!("📱 Device PoW Enrollment Demo");
    println!("──────────────────────────────");
    
    println!("1. Creating enrollment challenge...");
    let challenge = EnrollmentChallenge::new();
    println!("   Challenge: {}...", hex::encode(&challenge.challenge_data[..8]));
    println!("   Difficulty: {} bits", challenge.difficulty_bits);
    
    println!("2. Solving PoW (SHA3-256, NOT RandomX)...");
    let start = std::time::Instant::now();
    let solution = solve_pow(&challenge.challenge_data, challenge.difficulty_bits);
    let elapsed = start.elapsed();
    
    println!("   ✅ Solved in {:?}", elapsed);
    println!("   Nonce: {}", solution.nonce);
    
    println!("3. Enrollment complete!");
    println!("   • Device would receive signed credential");
    println!("   • Credential proves device power class");
    println!("   • Used for adaptive rate limiting");
    
    println!("\n💡 This is DIFFERENT from RandomX mining:");
    println!("   • Device PoW: SHA3, ~100ms, for rate limiting");
    println!("   • RandomX: Memory-hard, minutes, for consensus");
    
    Ok(())
}

/// Run demo scenarios automatically
async fn run_demo_scenarios(nodes: &[TestnetNode]) -> Result<()> {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                      DEMO SCENARIOS                          ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");
    
    // Demo 1: PQ Connection
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 DEMO 1: Post-Quantum RPC Connection");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    if let Err(e) = cmd_status(&nodes[0]).await {
        println!("❌ Demo 1 failed: {}", e);
    }
    sleep(Duration::from_millis(300)).await;
    
    // Demo 2: Balances
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 DEMO 2: Check Genesis Balances");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    for i in 0..nodes.len().min(3) {
        if let Err(e) = cmd_balance(nodes, i as u32).await {
            println!("❌ Balance check failed: {}", e);
        }
    }
    sleep(Duration::from_millis(300)).await;
    
    // Demo 3: ProPrivacy
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 DEMO 3: ProPrivacy Mode");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    if let Err(e) = cmd_pro_privacy(&nodes[0]).await {
        println!("❌ Demo 3 failed: {}", e);
    }
    sleep(Duration::from_millis(300)).await;
    
    // Demo 4: Transfer
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 DEMO 4: PQ-Signed Transfer");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    if nodes.len() >= 2 {
        if let Err(e) = cmd_transfer(nodes, 0, 1, 1000).await {
            println!("❌ Demo 4 failed: {}", e);
        }
    }
    sleep(Duration::from_millis(300)).await;
    
    // Demo 5: Device Enrollment
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 DEMO 5: Device PoW Enrollment");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    if let Err(e) = cmd_enrollment_demo(nodes).await {
        println!("❌ Demo 5 failed: {}", e);
    }
    
    println!("\n✅ All demos complete!\n");
    Ok(())
}
