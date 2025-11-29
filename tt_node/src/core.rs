// core.rs
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub type Hash32 = [u8; 32];

/// PQC node identifier (powinien być taki sam jak w node_id.rs)
pub type NodeId = [u8; 32];

pub fn shake256_bytes(data: &[u8]) -> Hash32 {
    use tiny_keccak::{Shake, Hasher};
    let mut sh = Shake::v256();
    sh.update(data);
    let mut out = [0u8; 32];
    sh.finalize(&mut out);
    out
}

pub fn bytes32(data: &[u8]) -> Hash32 {
    shake256_bytes(data)
}

pub fn now_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Nagłówek bloku – **czysty konsensus**, zero f64, zero „hintów”.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlockHeader {
    /// Rodzic (hash headera rodzica).
    pub parent: Hash32,

    /// Wysokość (0 dla genesis).
    pub height: u64,

    /// Autor bloku – PQC NodeId (SHAKE256 z Falcon PK).
    pub author: NodeId,

    /// Seed / challenge dla RandomX (np. hash poprzedniego bloku + slot).
    pub task_seed: Hash32,

    /// Timestamp (sekundy od UNIX_EPOCH).
    pub timestamp: u64,

    /// Hash stanu przed wykonaniem (np. Merkle / Poseidon).
    pub parent_state_hash: Hash32,

    /// Hash stanu po wykonaniu bloku.
    pub result_state_hash: Hash32,
}

impl BlockHeader {
    /// Deterministyczny identyfikator – hash nagłówka.
    pub fn id(&self) -> Hash32 {
        let bin = bincode::serialize(self).expect("hdr->bin");
        shake256_bytes(&bin)
    }
}

/// TODO: docelowo transakcje będą prawdziwym typem, nie Vec<u8>.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Block {
    pub header: BlockHeader,

    /// PQC podpis autora (Falcon) po `header.id()`.
    /// Format: `falcon_sigs::BlockSignature` (SignedMessage) zakodowany binarnie.
    pub author_sig: Vec<u8>,

    /// ZK proof (np. RISC Zero / STARK) – bincode / raw bytes.
    pub zk_receipt_bincode: Vec<u8>,

    /// Zserializowane transakcje (na razie placeholder).
    pub transactions: Vec<u8>,
}

/// Block V2 - with native STARK transactions and stealth hints (Monero-style)
/// Stealth hints are embedded in transaction outputs and persisted in blockchain
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlockV2 {
    pub header: BlockHeader,

    /// PQC signature (Falcon) over header.id()
    pub author_sig: Vec<u8>,

    /// Optional ZK proof
    pub zk_receipt_bincode: Vec<u8>,

    /// Native STARK transactions with embedded stealth hints
    /// Each TxOutputStark can contain TxStealthData for Monero-style hint persistence
    pub stark_transactions: Vec<crate::tx_stark::TransactionStark>,

    /// Legacy transactions (for backwards compatibility)
    pub legacy_transactions: Vec<u8>,
}

impl BlockV2 {
    /// Get all stealth hints from this block's transactions
    /// Used for wallet scanning (Monero-style)
    pub fn collect_stealth_hints(&self) -> Vec<crate::tx_stark::TxStealthData> {
        let mut hints = Vec::new();
        for tx in &self.stark_transactions {
            for output in &tx.outputs {
                if let Some(ref hint) = output.stealth_hint {
                    hints.push(hint.clone());
                }
            }
        }
        hints
    }

    /// Get block ID
    pub fn id(&self) -> Hash32 {
        self.header.id()
    }

    /// Convert to bytes for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("BlockV2 serialize")
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}
