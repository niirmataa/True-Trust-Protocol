// src/main.rs
#![forbid(unsafe_code)]

mod core;
mod chain_store;
mod state_priv;
mod randomx_full;

mod falcon_sigs;
mod kyber_kem;
mod crypto_kmac_consensus;
mod hybrid_commit;
mod node_id;
mod rtt_pro;
mod golden_trio;
mod consensus_weights;
mod consensus_pro;
mod snapshot_pro;
mod snapshot_witness;
mod stark_security;
mod stark_full;
mod tx_stark;
mod range_proof_winterfell; // i tak jest pod cfg(feature)
mod crypto;           // <-- tu siedzi kmac.rs i kmac_drbg.rs
mod pqc_verification;

mod p2p; // p2p/mod.rs

fn main() {
    // Na razie tylko placeholder.
    println!("tt_node: PQC node skeleton ready.");
}
