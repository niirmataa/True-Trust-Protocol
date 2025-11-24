#![forbid(unsafe_code)]

//! PQ-only "hybrid commit" dla NodeId / fingerprintu:
//!   NodeId = SHA3-256("TT-NODEID-PQ.v1" || falcon_pk || mlkem_pk)

use sha3::{Digest, Sha3_256};

use crate::node_id::NodeId;

/// PQC fingerprint (Falcon + Kyber) → NodeId (32B)
pub fn pqc_fingerprint(falcon_pk_bytes: &[u8], mlkem_pk_bytes: &[u8]) -> NodeId {
    let mut h = Sha3_256::new();
    h.update(b"TT-NODEID-PQ.v1");
    h.update(falcon_pk_bytes);
    h.update(mlkem_pk_bytes);
    let digest = h.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
