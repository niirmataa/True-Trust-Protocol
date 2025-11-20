#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use crate::node_id::NodeId;

/// Computes hybrid PQ fingerprint from Falcon and ML-KEM public keys
pub fn pqc_fingerprint(falcon_pk: &[u8], mlkem_pk: &[u8]) -> NodeId {
    let mut hasher = Sha256::new();
    hasher.update(b"PQC-FINGERPRINT.v1");
    hasher.update(falcon_pk);
    hasher.update(mlkem_pk);
    let result = hasher.finalize();
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&result);
    fingerprint
}
