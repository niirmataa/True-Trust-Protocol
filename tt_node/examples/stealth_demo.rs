//! Simple demo: build and decrypt a PQ stealth hint (local roundtrip)
//!
//! Run with: cargo run --example stealth_demo -p tt_node

use anyhow::Result;
use tt_node::falcon_sigs::falcon_keypair;
use tt_node::kyber_kem::kyber_keypair;
use tt_node::stealth_pq::{
    StealthAddressPQ, StealthSecretsPQ, StealthHintBuilder, StealthHint, decrypt_stealth_hint,
    ScanResult,
};

fn main() -> Result<()> {
    // Create recipient keypair
    let (spend_pk, spend_sk) = falcon_keypair();
    let (scan_pk, scan_sk) = kyber_keypair();

    let addr = StealthAddressPQ::from_pks(spend_pk.clone(), scan_pk.clone());
    let secrets = StealthSecretsPQ::from_sks(spend_sk, scan_sk, &spend_pk, &scan_pk);

    println!("Recipient addr_id: {}", hex::encode(addr.id()));

    // Sender builds a hint
    let hint = StealthHintBuilder::new(1_234)
        .memo(b"demo payment".to_vec())?
        .build(&addr)?;

    let bytes = hint.to_bytes();
    println!("Built hint ({} bytes)", bytes.len());

    // Deserialize and decrypt as recipient
    let hint2 = StealthHint::from_bytes(&bytes)?;
    match decrypt_stealth_hint(&secrets, &hint2) {
        ScanResult::Match(payload) => {
            println!("Decrypted payload:");
            println!("  value: {}", payload.value);
            println!("  memo: {}", String::from_utf8_lossy(&payload.memo));
            println!("  hint_id: {}", hex::encode(&payload.hint_id));
        }
        other => {
            println!("Decrypt result: {:?}", other);
        }
    }

    Ok(())
}
