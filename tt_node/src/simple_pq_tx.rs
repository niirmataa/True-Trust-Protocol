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
