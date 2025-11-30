#![forbid(unsafe_code)]

//! Simple PQ transfer transaction signed with Falcon-512.
//!
//! To jest prosty, “account-based” transfer między dwoma 32-bajtowymi
//! identyfikatorami (NodeId / ttq raw addr), podpisany Falconem.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::core::Hash32;
use crate::node_id::NodeId;
use crate::falcon_sigs::{
    FalconPublicKey,
    FalconSecretKey,
    SignedNullifier,
    falcon_sign,
    falcon_verify,
    falcon_pk_from_bytes,
    falcon_pk_to_bytes,
};

/// Domain separator dla SimplePqTxSigned - zapobiega cross-type replay attacks
const SIMPLE_PQ_TX_DOMAIN: &[u8] = b"TT.v1.SIMPLE_PQ_TX_SIGNED";

/// Prosta transakcja PQ z wbudowanym podpisem Falcon-512:
/// - from / to: 32B identyfikatory (NodeId / ttq raw addr),
/// - amount: kwota w najmniejszej jednostce (u64),
/// - nonce: anty-replay per nadawca,
/// - falcon_pk: bytes klucza nadawcy,
/// - sig: podpis Falcon-512 (attached SignedNullifier).
///
/// UWAGA: To jest inna struktura niż `node_core::SimplePqTx` która ma u128 amount i fee.
/// Ta wersja jest używana przez testy i moduły które potrzebują self-contained tx.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimplePqTxSigned {
    pub from: NodeId,
    pub to: NodeId,
    pub amount: u64,
    pub nonce: u64,
    pub falcon_pk: Vec<u8>,
    pub sig: SignedNullifier,
}

impl SimplePqTxSigned {
    /// Zbuduj i od razu podpisz transakcję Falconem.
    pub fn new_signed(
        from: NodeId,
        to: NodeId,
        amount: u64,
        nonce: u64,
        falcon_pk: &FalconPublicKey,
        falcon_sk: &FalconSecretKey,
    ) -> Result<Self> {
        let pk_bytes = falcon_pk_to_bytes(falcon_pk);
        let mut msg = Vec::with_capacity(32 + 32 + 8 + 8 + pk_bytes.len());
        msg.extend_from_slice(&from);
        msg.extend_from_slice(&to);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg.extend_from_slice(&nonce.to_le_bytes());
        msg.extend_from_slice(pk_bytes);

        let sig = falcon_sign(&msg, falcon_sk)?;

        Ok(Self {
            from,
            to,
            amount,
            nonce,
            falcon_pk: pk_bytes.to_vec(),
            sig,
        })
    }

    /// Wiadomość podpisywana Falconem (bez pola `sig`).
    pub fn sign_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(32 + 32 + 8 + 8 + self.falcon_pk.len());
        msg.extend_from_slice(&self.from);
        msg.extend_from_slice(&self.to);
        msg.extend_from_slice(&self.amount.to_le_bytes());
        msg.extend_from_slice(&self.nonce.to_le_bytes());
        msg.extend_from_slice(&self.falcon_pk);
        msg
    }

    /// TxID = SHAKE256(domain || message || sig).
    /// 
    /// Domain separator zapobiega cross-type replay attacks między
    /// różnymi typami transakcji (SimplePqTx, PrivateCompactTx, PrivateStarkTx).
    pub fn tx_id(&self) -> Hash32 {
        use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};
        
        let mut h = Shake256::default();
        h.update(SIMPLE_PQ_TX_DOMAIN);
        h.update(&self.sign_message());
        h.update(&self.sig.signed_message_bytes);
        
        let mut out = [0u8; 32];
        h.finalize_xof().read(&mut out);
        out
    }

    /// Weryfikacja podpisu Falconem.
    pub fn verify(&self) -> Result<()> {
        let pk = falcon_pk_from_bytes(&self.falcon_pk)?;
        let msg = self.sign_message();
        falcon_verify(&msg, &self.sig, &pk)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPREHENSIVE TEST SUITE
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon_sigs::{falcon_keypair, falcon_pk_from_bytes};
    
    fn setup_test_keys() -> (FalconPublicKey, FalconSecretKey) {
        falcon_keypair()
    }
    
    fn random_node_id() -> NodeId {
        let mut id = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut id);
        id
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // BASIC FUNCTIONALITY
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_new_signed_creates_valid_tx() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        assert_eq!(tx.from, from);
        assert_eq!(tx.to, to);
        assert_eq!(tx.amount, 100);
        assert_eq!(tx.nonce, 1);
        assert!(!tx.falcon_pk.is_empty());
        assert!(!tx.sig.signed_message_bytes.is_empty());
    }
    
    #[test]
    fn test_verify_valid_signature() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        assert!(tx.verify().is_ok(), "Valid tx MUST verify");
    }
    
    #[test]
    fn test_tx_id_determinism() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        let id1 = tx.tx_id();
        let id2 = tx.tx_id();
        
        assert_eq!(id1, id2, "TxID MUST be deterministic");
    }
    
    #[test]
    fn test_sign_message_determinism() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        let msg1 = tx.sign_message();
        let msg2 = tx.sign_message();
        
        assert_eq!(msg1, msg2, "sign_message MUST be deterministic");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // SIGNATURE TAMPERING ATTACKS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_tampered_signature_rejects() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let mut tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        // Tamper with signature
        if !tx.sig.signed_message_bytes.is_empty() {
            tx.sig.signed_message_bytes[0] ^= 0xFF;
        }
        
        assert!(tx.verify().is_err(), 
            "SECURITY: Tampered signature MUST be rejected");
    }
    
    #[test]
    fn test_truncated_signature_rejects() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let mut tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        // Truncate signature
        tx.sig.signed_message_bytes.truncate(tx.sig.signed_message_bytes.len() / 2);
        
        assert!(tx.verify().is_err(), 
            "SECURITY: Truncated signature MUST be rejected");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // PUBLIC KEY ATTACKS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_wrong_public_key_rejects() {
        let (pk1, sk1) = setup_test_keys();
        let (pk2, _sk2) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let mut tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk1, &sk1)
            .expect("new_signed failed");
        
        // Replace with different public key
        tx.falcon_pk = falcon_pk_to_bytes(&pk2).to_vec();
        
        assert!(tx.verify().is_err(), 
            "SECURITY: Wrong public key MUST be rejected");
    }
    
    #[test]
    fn test_tampered_public_key_rejects() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let mut tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        // Tamper with public key
        if !tx.falcon_pk.is_empty() {
            tx.falcon_pk[0] ^= 0xFF;
        }
        
        assert!(tx.verify().is_err(), 
            "SECURITY: Tampered public key MUST be rejected");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // TRANSACTION DATA TAMPERING
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_tampered_from_rejects() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let mut tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        // Change sender
        tx.from[0] ^= 0xFF;
        
        assert!(tx.verify().is_err(), 
            "SECURITY: Tampered 'from' MUST be rejected");
    }
    
    #[test]
    fn test_tampered_to_rejects() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let mut tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        // Change recipient
        tx.to[0] ^= 0xFF;
        
        assert!(tx.verify().is_err(), 
            "SECURITY: Tampered 'to' MUST be rejected");
    }
    
    #[test]
    fn test_tampered_amount_rejects() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let mut tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        // Change amount
        tx.amount = 999999;
        
        assert!(tx.verify().is_err(), 
            "SECURITY: Tampered amount MUST be rejected");
    }
    
    #[test]
    fn test_tampered_nonce_rejects() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let mut tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        // Change nonce
        tx.nonce = 999;
        
        assert!(tx.verify().is_err(), 
            "SECURITY: Tampered nonce MUST be rejected");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // REPLAY ATTACK PREVENTION
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_different_nonce_different_signature() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let tx1 = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        let tx2 = SimplePqTxSigned::new_signed(from, to, 100, 2, &pk, &sk)
            .expect("new_signed failed");
        
        assert_ne!(tx1.sign_message(), tx2.sign_message(), 
            "Different nonces MUST produce different messages");
        assert_ne!(tx1.tx_id(), tx2.tx_id(), 
            "Different nonces MUST produce different tx_ids");
    }
    
    #[test]
    fn test_tx_id_uniqueness() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        // Same params but different nonces
        let tx1 = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        let tx2 = SimplePqTxSigned::new_signed(from, to, 100, 2, &pk, &sk)
            .expect("new_signed failed");
        let tx3 = SimplePqTxSigned::new_signed(from, to, 100, 3, &pk, &sk)
            .expect("new_signed failed");
        
        // All tx_ids must be unique
        assert_ne!(tx1.tx_id(), tx2.tx_id());
        assert_ne!(tx2.tx_id(), tx3.tx_id());
        assert_ne!(tx1.tx_id(), tx3.tx_id());
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // EDGE CASES
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_zero_amount() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let tx = SimplePqTxSigned::new_signed(from, to, 0, 1, &pk, &sk)
            .expect("new_signed failed");
        
        assert!(tx.verify().is_ok(), "Zero amount tx should verify");
        assert_eq!(tx.amount, 0);
    }
    
    #[test]
    fn test_max_amount() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let tx = SimplePqTxSigned::new_signed(from, to, u64::MAX, 1, &pk, &sk)
            .expect("new_signed failed");
        
        assert!(tx.verify().is_ok(), "Max amount tx should verify");
        assert_eq!(tx.amount, u64::MAX);
    }
    
    #[test]
    fn test_self_transfer() {
        let (pk, sk) = setup_test_keys();
        let addr = random_node_id();
        
        let tx = SimplePqTxSigned::new_signed(addr, addr, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        assert!(tx.verify().is_ok(), "Self-transfer should verify");
        assert_eq!(tx.from, tx.to);
    }
    
    #[test]
    fn test_zero_nonce() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let tx = SimplePqTxSigned::new_signed(from, to, 100, 0, &pk, &sk)
            .expect("new_signed failed");
        
        assert!(tx.verify().is_ok(), "Zero nonce tx should verify");
        assert_eq!(tx.nonce, 0);
    }
    
    #[test]
    fn test_max_nonce() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let tx = SimplePqTxSigned::new_signed(from, to, 100, u64::MAX, &pk, &sk)
            .expect("new_signed failed");
        
        assert!(tx.verify().is_ok(), "Max nonce tx should verify");
        assert_eq!(tx.nonce, u64::MAX);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // SERIALIZATION
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_serialization_roundtrip() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        // Serialize
        let json = serde_json::to_string(&tx).expect("serialize failed");
        
        // Deserialize
        let tx2: SimplePqTxSigned = serde_json::from_str(&json).expect("deserialize failed");
        
        // Verify deserialized tx is valid
        assert!(tx2.verify().is_ok(), "Deserialized tx MUST verify");
        assert_eq!(tx.tx_id(), tx2.tx_id(), "TxID must survive serialization");
    }
    
    #[test]
    fn test_bincode_serialization() {
        let (pk, sk) = setup_test_keys();
        let from = random_node_id();
        let to = random_node_id();
        
        let tx = SimplePqTxSigned::new_signed(from, to, 100, 1, &pk, &sk)
            .expect("new_signed failed");
        
        // Serialize with bincode
        let bytes = bincode::serialize(&tx).expect("bincode serialize failed");
        
        // Deserialize
        let tx2: SimplePqTxSigned = bincode::deserialize(&bytes).expect("bincode deserialize failed");
        
        assert!(tx2.verify().is_ok(), "Bincode deserialized tx MUST verify");
        assert_eq!(tx.tx_id(), tx2.tx_id());
    }
}
