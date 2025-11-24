use serde::{Serialize, Deserialize};
use crate::falcon_sigs;
use crate::falcon_sigs::{FalconPublicKey, falcon_pk_to_bytes, falcon_pk_from_bytes};
use crate::falcon_sigs::{SignedNullifier, falcon_sign_nullifier, falcon_verify_nullifier,
                         serialize_signature, deserialize_signature};

pub type Hash32 = [u8; 32]; // jeśli już masz, to reuse

/// Podpisana transakcja STARK Falconem.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedStarkTx {
    /// Surowa transakcja (z dowodami STARK, ciphertextami itd.).
    pub tx: TransactionStark,
    /// Publiczny klucz Falcon nadawcy (bytes).
    pub falcon_pk: Vec<u8>,
    /// Podpis Falcon nad `tx.id()` (zserializowany SignedNullifier).
    pub signature: Vec<u8>,
}

impl SignedStarkTx {
    /// Zbuduj i podpisz transakcję STARK.
    pub fn sign(tx: TransactionStark, sk: &falcon_sigs::FalconSecretKey)
        -> anyhow::Result<Self>
    {
        let tx_id: Hash32 = tx.id();
        let sig: SignedNullifier = falcon_sign_nullifier(&tx_id, sk)?;
        let sig_bytes = serialize_signature(&sig)?;
        let pk_bytes = falcon_pk_to_bytes(&falcon_sigs::falcon_derive_pk(sk)); // jeśli masz, dostosuj

        Ok(SignedStarkTx {
            tx,
            falcon_pk: pk_bytes.to_vec(),
            signature: sig_bytes,
        })
    }

    /// Weryfikacja podpisu i dowodów STARK.
    pub fn verify_all(&self) -> anyhow::Result<()> {
        // 1. Falcon
        let pk = falcon_pk_from_bytes(&self.falcon_pk)?;
        let sig = deserialize_signature(&self.signature)?;
        let tx_id = self.tx.id();
        falcon_verify_nullifier(&tx_id, &sig, &pk)?;

        // 2. STARK
        let (valid, total) = self.tx.verify_all_proofs();
        if valid != total {
            anyhow::bail!("STARK proofs invalid: {}/{}", valid, total);
        }
        Ok(())
    }
}
