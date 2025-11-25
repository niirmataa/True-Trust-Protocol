#![forbid(unsafe_code)]

use std::{env, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use tt_node::{
    node_core::NodeCore,
    p2p::P2PNetwork,
    rpc::rpc_secure::{create_secure_rpc_identity, SecureRpcServer},
};

#[tokio::main]
async fn main() -> Result<()> {
    // ── Proste parsowanie argumentów ──────────────────────────────────────
    let args: Vec<String> = env::args().collect();

    let mut data_dir = PathBuf::from("./data_secure_node");
    let mut p2p_port: u16 = 18100;
    let mut rpc_port: u16 = 18200;
    let mut bootstrap: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" if i + 1 < args.len() => {
                data_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--p2p-port" if i + 1 < args.len() => {
                p2p_port = args[i + 1].parse().expect("invalid --p2p-port");
                i += 2;
            }
            "--rpc-port" if i + 1 < args.len() => {
                rpc_port = args[i + 1].parse().expect("invalid --rpc-port");
                i += 2;
            }
            "--bootstrap" if i + 1 < args.len() => {
                bootstrap = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                eprintln!("Ignoring unknown/incomplete arg: {}", args[i]);
                i += 1;
            }
        }
    }

    let is_validator = true;

    // ── NodeCore ──────────────────────────────────────────────────────────
    let node = Arc::new(NodeCore::new(data_dir, is_validator)?);

    // ── Wspólna PQC tożsamość dla P2P i RPC ───────────────────────────────
    let identity = create_secure_rpc_identity()?;
    let node_id = identity.node_id;

    println!("🚀 TrueTrust Secure Node");
    println!("   Node ID   : {}", hex::encode(node_id));
    println!("   P2P port  : {p2p_port}");
    println!("   RPC port  : {rpc_port}\n");

    // ── Secure P2P ───────────────────────────────────────────────────────
    let p2p = Arc::new(P2PNetwork::new(p2p_port, identity.clone()).await?);

    let p2p_task = {
        let p2p = Arc::clone(&p2p);
        tokio::spawn(async move {
            if let Err(e) = p2p.start().await {
                eprintln!("[P2P] fatal error: {}", e);
            }
        })
    };

    // Aktualizuj peer_count w NodeCore, żeby RPC GetPeerCount miało sens
    {
        let node = Arc::clone(&node);
        let p2p = Arc::clone(&p2p);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                let peers_len = p2p.peers.read().await.len();
                node.set_peer_count(peers_len).await;
            }
        });
    }

    // ── Secure RPC (Kyber+Falcon+PoW+XChaCha) ────────────────────────────
    let rpc_server = SecureRpcServer::new(rpc_port, identity, is_validator, Arc::clone(&node));
    let rpc_task = tokio::spawn(async move {
        if let Err(e) = rpc_server.start().await {
            eprintln!("[RPC] fatal error: {}", e);
        }
    });

    // ── Opcjonalne bootstrapowanie do innego noda ────────────────────────
    if let Some(addr) = bootstrap {
        let p2p = Arc::clone(&p2p);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            println!("[P2P] Bootstrapping to {addr} ...");
            if let Err(e) = p2p.connect(&addr).await {
                eprintln!("[P2P] bootstrap failed: {}", e);
            }
        });
    }

    println!("✅ Secure node running. Press Ctrl+C to exit.\n");

    tokio::signal::ctrl_c().await?;
    println!("🛑 Shutting down ...");

    p2p_task.abort();
    rpc_task.abort();

    Ok(())
}
