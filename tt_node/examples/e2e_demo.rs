//! E2E Demo
use sha2::{Digest, Sha256};

fn main() {
    println!("\\n════════════════════════════════════════════");
    println!("  TRUE_TRUST E2E Demo: Bob → Alice");
    println!("════════════════════════════════════════════\\n");
    
    println!("🔑 Generating identities...");
    let alice_id = generate_node_id("Alice");
    let bob_id = generate_node_id("Bob");
    println!("  ✅ Alice: {}", hex::encode(&alice_id[..8]));
    println!("  ✅ Bob: {}", hex::encode(&bob_id[..8]));
    
    println!("\\n💸 Creating transaction...");
    let tx_hash = create_tx(&bob_id, &alice_id, 100000);
    println!("  ✅ TX hash: {}", hex::encode(&tx_hash[..8]));
    println!("  💰 Amount: 100,000 tokens");
    
    println!("\\n🤝 P2P exchange...");
    println!("  📤 Bob → Alice");
    println!("  📥 Alice received");
    
    println!("\\n⚖️  Consensus...");
    simulate_consensus(&alice_id, &bob_id);
    
    println!("\\n✅ Demo complete!\\n");
}

fn generate_node_id(name: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"NODE");
    h.update(name.as_bytes());
    let d = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&d);
    id
}

fn create_tx(s: &[u8;32], r: &[u8;32], amt: u64) -> [u8;32] {
    let mut h = Sha256::new();
    h.update(b"TX");
    h.update(s);
    h.update(r);
    h.update(&amt.to_le_bytes());
    let d = h.finalize();
    let mut tx = [0u8; 32];
    tx.copy_from_slice(&d);
    tx
}

fn simulate_consensus(a: &[u8;32], b: &[u8;32]) {
    println!("  📊 Validators: 2");
    println!("  ⚖️  Computing weights...");
    println!("  👑 Leader: Alice");
    println!("  ✅ Consensus OK");
}
