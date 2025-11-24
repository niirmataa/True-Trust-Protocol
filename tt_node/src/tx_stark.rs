#![forbid(unsafe_code)]

//! Post-Quantum Transactions with STARK Range Proofs (Winterfell)
//!
//! - ZK range proof: 0 <= value < 2^k, z linkiem do Poseidon commitment
//! - Commitment: Poseidon(value, blinding, recipient) w BaseElement (u64 przez as_int())
//! - Szyfrowanie wartości: Kyber768 + XChaCha20-Poly1305
//!
//! Powiązania:
//! - STARK public input zawiera `poseidon_commitment` i `recipient`
//! - Encrypted payload zawiera (value, blinding)
//! - Przy decrypt: liczymy Poseidon(value, blinding, recipient) i porównujemy z commitment
//!   oraz weryfikujemy STARK proof na tych samych public inputs.

use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use rand::RngCore;

use winterfell::Proof as StarkProof;
use winterfell::math::StarkField;
use crate::falcon_sigs::BlockSignature;

use crate::core::Hash32;
use crate::crypto::poseidon_hash_cpu::poseidon_hash_cpu;
use crate::crypto::zk_range_poseidon::{
    Witness as RangeWitness,
    PublicInputs as RangePublicInputs,
    prove_range_with_poseidon,
    verify_range_with_poseidon,
};
 use crate::crypto::zk_range_poseidon::default_proof_options;
 
/// Kyber768 ciphertext size (1088 bytes)
const KYBER768_CT_BYTES: usize = 1088;

/// Liczba bitów zakresu dla wartości (u64)
const VALUE_NUM_BITS: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutputStark {
    /// Poseidon(value, blinding, recipient) jako u64 (BaseElement::as_int() castowane)
    pub poseidon_commitment: u64,

    /// STARK proof zakodowany jako bajty (Winterfell::Proof::to_bytes)
    pub stark_proof: Vec<u8>,

    /// Odbiorca (to samo pole, które wchodzi do Poseidona i do STARK public inputs)
    pub recipient: Hash32,

    /// Zaszyfrowana wartość: nonce(24B) || XChaCha20-Poly1305(ct) || KyberCiphertext
    pub encrypted_value: Vec<u8>,
}

impl TxOutputStark {
    pub fn new(
        value: u64,
        blinding: &[u8; 32],
        recipient: Hash32,
        recipient_kyber_pk: &crate::kyber_kem::KyberPublicKey,
    ) -> Self {
        // 1) Commitment po stronie CPU (musi być identyczny jak w STARKu)
        let poseidon_elem = poseidon_hash_cpu(value, blinding, &recipient);
        let poseidon_commitment = poseidon_elem.as_int() as u64;

        // 2) ZK range proof z linkiem do Poseidon commitment
        let witness = RangeWitness::new(value, *blinding, recipient);
        let opts = default_proof_options();
        let (proof, mut pub_inputs) = prove_range_with_poseidon(witness, VALUE_NUM_BITS, opts);

        // pub_inputs.value_commitment powstał z trace’u, powinien się równać temu z CPU
        debug_assert_eq!(
            pub_inputs.value_commitment,
            poseidon_commitment,
            "Poseidon commitment from STARK trace != CPU hash"
        );

        // nadpisujemy recipient w public inputs: musi być identyczny z polem w UTXO
        pub_inputs.recipient = recipient;

        // Serializacja proofa i *jawne* przeniesienie commitmentu (jako u64)
        let stark_proof = proof.to_bytes();

        // 3) Kyber768: encapsulation + wyprowadzenie klucza AEAD
        let (ss, ct) = crate::kyber_kem::kyber_encapsulate(recipient_kyber_pk);
        let ss_bytes = crate::kyber_kem::kyber_ss_to_bytes(&ss);
        let aes_key = crate::kyber_kem::derive_aes_key_from_shared_secret_bytes(
            &ss_bytes,
            b"TX_VALUE_ENC",
        );

        // 4) Szyfrowanie (value || blinding) XChaCha20-Poly1305
        use chacha20poly1305::{
            XChaCha20Poly1305, Key, XNonce,
            aead::{Aead, KeyInit},
        };

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&aes_key));
        let mut nonce_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);

        let mut plaintext = Vec::with_capacity(8 + 32);
        plaintext.extend_from_slice(&value.to_le_bytes());
        plaintext.extend_from_slice(blinding);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .expect("encryption failed");

        // 5) Pakujemy wszystko: nonce || AEAD-ciphertext || Kyber-CT
        let ct_bytes = crate::kyber_kem::kyber_ct_to_bytes(&ct);
        let mut encrypted_value = Vec::with_capacity(24 + ciphertext.len() + ct_bytes.len());
        encrypted_value.extend_from_slice(&nonce_bytes);
        encrypted_value.extend_from_slice(&ciphertext);
        encrypted_value.extend_from_slice(&ct_bytes);

        Self {
            poseidon_commitment,
            stark_proof,
            recipient,
            encrypted_value,
        }
    }

    /// Weryfikacja tylko STARK-a (bez decryptowania)
    pub fn verify(&self) -> bool {
        // Deserializacja proofa z bajtów
        let proof = match StarkProof::from_bytes(&self.stark_proof) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Odtwarzamy public inputs z danych w UTXO
        let pub_inputs = RangePublicInputs {
            value_commitment: self.poseidon_commitment,
            recipient: self.recipient,
            num_bits: VALUE_NUM_BITS as u32,
        };

        verify_range_with_poseidon(proof, pub_inputs)
    }

    /// Tylko odszyfrowanie (bez sprawdzania STARK ani commitmentu)
    pub fn decrypt_value(
        &self,
        kyber_sk: &crate::kyber_kem::KyberSecretKey,
    ) -> Option<(u64, [u8; 32])> {
        use pqcrypto_traits::kem::Ciphertext as KemCt;
        use chacha20poly1305::{
            XChaCha20Poly1305, Key, XNonce,
            aead::{Aead, KeyInit},
        };

        if self.encrypted_value.len() < 24 + 16 + KYBER768_CT_BYTES {
            return None;
        }

        let nonce_bytes = &self.encrypted_value[0..24];
        let ct_end = self.encrypted_value.len() - KYBER768_CT_BYTES;
        let ciphertext = &self.encrypted_value[24..ct_end];
        let kyber_ct_bytes = &self.encrypted_value[ct_end..];

        let kyber_ct = crate::kyber_kem::kyber_ct_from_bytes(kyber_ct_bytes).ok()?;
        let ss = crate::kyber_kem::kyber_decapsulate(&kyber_ct, kyber_sk).ok()?;
        let aes_key = crate::kyber_kem::derive_aes_key_from_shared_secret(&ss, b"TX_VALUE_ENC");

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&aes_key));
        let nonce = XNonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;

        if plaintext.len() != 40 {
            return None;
        }

        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&plaintext[0..8]);
        let value = u64::from_le_bytes(value_bytes);

        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&plaintext[8..40]);

        Some((value, blinding))
    }

    /// Decrypt + pełna weryfikacja: STARK + Poseidon commitment link
    pub fn decrypt_and_verify(
        &self,
        kyber_sk: &crate::kyber_kem::KyberSecretKey,
    ) -> Option<u64> {
        let (value, blinding) = self.decrypt_value(kyber_sk)?;

        // Sprawdzenie commitmentu: Poseidon(value, blinding, recipient)
        let poseidon_elem = poseidon_hash_cpu(value, &blinding, &self.recipient);
        let expected_commitment = poseidon_elem.as_int() as u64;

        if expected_commitment != self.poseidon_commitment {
            return None;
        }

        // Sprawdzenie STARK proofa
        if !self.verify() {
            return None;
        }

        Some(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInputStark {
    pub prev_output_id: Hash32,
    pub output_index: u32,
    pub spending_sig: Vec<u8>, // Falcon512
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionStark {
    pub inputs: Vec<TxInputStark>,
    pub outputs: Vec<TxOutputStark>,
    pub fee: u64,
    pub nonce: u64,
    pub timestamp: u64,
}

impl TransactionStark {
    pub fn id(&self) -> Hash32 {
        let bytes = bincode::serialize(self).expect("tx serialize");
        let mut h = Sha3_256::new();
        h.update(b"TX_ID.v2");
        h.update(&bytes);
        h.finalize().into()
    }

    pub fn verify_all_proofs(&self) -> (u32, u32) {
        let mut valid = 0u32;
        for o in &self.outputs {
            if o.verify() {
                valid += 1;
            }
        }
        (valid, self.outputs.len() as u32)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("tx serialize")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes)
            .map_err(|e| format!("TX deserialization failed: {}", e))
    }
}

/// Signed Stark transaction:
/// - `tx_bytes`        – zserializowany `TransactionStark` (bincode),
/// - `signer_pk_bytes` – Falcon-512 public key w postaci bytes,
/// - `signature`       – Falcon signature na tx_id (hash32).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedStarkTx {
    /// Raw bincode-encoded TransactionStark
    pub tx_bytes: Vec<u8>,
    /// Falcon-512 public key of the signer (serialized bytes)
    pub signer_pk_bytes: Vec<u8>,
    /// Falcon signature over tx_id (BlockSignature = SignedNullifier)
    pub signature: BlockSignature,
}

impl SignedStarkTx {
    /// Parse inner TransactionStark from bytes
    pub fn parse_tx(&self) -> std::result::Result<TransactionStark, String> {
        TransactionStark::from_bytes(&self.tx_bytes)
    }

    /// Convenience: compute tx_id (hash32) from inner tx
    pub fn tx_id(&self) -> std::result::Result<crate::core::Hash32, String> {
        self.parse_tx().map(|tx| tx.id())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_tx_output_stark_new_and_verify() {
        let (kyber_pk, kyber_sk) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let output = TxOutputStark::new(
            100_000,
            &blinding,
            [1u8; 32],
            &kyber_pk,
        );

        assert!(!output.stark_proof.is_empty());
        assert_ne!(output.poseidon_commitment, 0);

        // STARK proof powinien przejść
        assert!(output.verify());

        // decrypt + verify powinno zwrócić tę samą wartość
        let val = output.decrypt_and_verify(&kyber_sk).expect("decrypt_and_verify failed");
        assert_eq!(val, 100_000);
    }

    #[test]
    fn test_transaction_stark_verify_all() {
        let (kyber_pk, _) = crate::kyber_kem::kyber_keypair();
        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b1);
        rand::thread_rng().fill_bytes(&mut b2);

        let o1 = TxOutputStark::new(123, &b1, [1u8; 32], &kyber_pk);
        let o2 = TxOutputStark::new(456, &b2, [2u8; 32], &kyber_pk);

        let tx = TransactionStark {
            inputs: vec![],
            outputs: vec![o1, o2],
            fee: 10,
            nonce: 1,
            timestamp: 1_234_567_890,
        };

        let (valid, total) = tx.verify_all_proofs();
        assert_eq!(valid, total);
        assert_eq!(total, 2);
    }
}
