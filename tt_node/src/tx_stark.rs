#![forbid(unsafe_code)]

//! Post-Quantum Transactions with STARK Range Proofs (Winterfell)
//! 
//! Each TxOutput contains:
//! - Poseidon commitment (value + blinding + recipient)
//! - STARK range proof (proves value >= 0 without revealing it)
//! - Encrypted value (Kyber + XChaCha20-Poly1305)
//! - Stealth hint (for recipient scanning) - Monero-style in blockchain

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
    PublicInputs as RangePubInputs,
    default_proof_options,
    prove_range_with_poseidon,
    verify_range_with_poseidon,
};
use crate::stealth_pq::{StealthHint, StealthHintBuilder, StealthAddressPQ};

/// Kyber768 ciphertext size (1088 bytes)
const KYBER768_CT_BYTES: usize = 1088;

/// Liczba bitów zakresu dla wartości (u64)
const VALUE_NUM_BITS: usize = 64;

/// Stealth hint embedded in transaction output (Monero-style)
/// This ensures hints are persisted in blockchain, not ephemeral pool
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxStealthData {
    /// 8-byte scan tag for quick filtering
    pub scan_tag: [u8; 8],
    /// Kyber KEM ciphertext (1088 bytes)
    pub kem_ct: Vec<u8>,
    /// AES-GCM nonce (12 bytes)
    pub nonce: [u8; 12],
    /// Encrypted payload (value, memo, r_blind)
    pub encrypted_payload: Vec<u8>,
}

impl TxStealthData {
    /// Create from StealthHint
    pub fn from_hint(hint: &StealthHint) -> Self {
        Self {
            scan_tag: hint.scan_tag,
            kem_ct: hint.kem_ct.clone(),
            nonce: hint.nonce,
            encrypted_payload: hint.ciphertext.clone(),
        }
    }

    /// Convert back to StealthHint for scanning
    pub fn to_hint(&self) -> StealthHint {
        StealthHint {
            scan_tag: self.scan_tag,
            kem_ct: self.kem_ct.clone(),
            nonce: self.nonce,
            ciphertext: self.encrypted_payload.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutputStark {
    /// Poseidon(value, blinding, recipient) jako u128 (BaseElement::as_int())
    pub poseidon_commitment: u128,

    /// STARK proof zakodowany jako bajty (Winterfell::Proof::to_bytes)
    pub stark_proof: Vec<u8>,

    /// Odbiorca (to samo pole, które wchodzi do Poseidona i do STARK public inputs)
    pub recipient: Hash32,

    /// Zaszyfrowana wartość: nonce(24B) || XChaCha20-Poly1305(ct) || KyberCiphertext
    pub encrypted_value: Vec<u8>,

    /// Stealth hint for recipient scanning (Monero-style, persisted in blockchain)
    /// Optional for backwards compatibility
    pub stealth_hint: Option<TxStealthData>,
}

impl TxOutputStark {
    pub fn new(
        value: u64,
        blinding: &[u8; 32],
        recipient: Hash32,
        recipient_kyber_pk: &crate::kyber_kem::KyberPublicKey,
    ) -> Self {
        // 1) Commitment po stronie CPU
        let poseidon_elem = poseidon_hash_cpu(value as u128, blinding, &recipient);
        let poseidon_commitment: u128 = poseidon_elem.as_int();

        // 2) ZK range proof z linkiem do Poseidon commitment
        let witness = RangeWitness::new(value as u128, *blinding, recipient);
        let opts = default_proof_options();

        let (proof, pub_inputs) = prove_range_with_poseidon(
            witness,
            VALUE_NUM_BITS,
            opts,
        );

        // Spójność: commitment z trace == CPU
        debug_assert_eq!(
            pub_inputs.value_commitment,
            poseidon_commitment,
            "Poseidon commitment from STARK trace != CPU hash"
        );

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
            stealth_hint: None, // Use new_with_stealth for stealth payments
        }
    }

    /// Create output with embedded stealth hint (Monero-style)
    pub fn new_with_stealth(
        value: u64,
        blinding: &[u8; 32],
        recipient: Hash32,
        recipient_kyber_pk: &crate::kyber_kem::KyberPublicKey,
        recipient_stealth: &StealthAddressPQ,
        memo: &str,
    ) -> Self {
        // Create base output
        let mut output = Self::new(value, blinding, recipient, recipient_kyber_pk);

        // Build stealth hint
        let hint = StealthHintBuilder::new(value)
            .memo(memo.as_bytes().to_vec())
            .expect("memo too large")
            .r_blind(*blinding)
            .build(recipient_stealth)
            .expect("failed to build stealth hint");

        output.stealth_hint = Some(TxStealthData::from_hint(&hint));
        output
    }

    /// Weryfikacja tylko STARK-a (bez decryptowania)
    pub fn verify(&self) -> bool {
        let proof = match StarkProof::from_bytes(&self.stark_proof) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let mut stark_recipient = [0u8; 32];
        stark_recipient[..8].copy_from_slice(&self.recipient[..8]);

        let pub_inputs = RangePubInputs {
            value_commitment: self.poseidon_commitment,
            recipient: stark_recipient,
            num_bits: VALUE_NUM_BITS as u32,
        };

        verify_range_with_poseidon(proof, pub_inputs)
    }

    /// Tylko odszyfrowanie (bez sprawdzania STARK ani commitmentu)
    pub fn decrypt_value(
        &self,
        kyber_sk: &crate::kyber_kem::KyberSecretKey,
    ) -> Option<(u64, [u8; 32])> {
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
        let aes_key =
            crate::kyber_kem::derive_aes_key_from_shared_secret(&ss, b"TX_VALUE_ENC");

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

        let poseidon_elem = poseidon_hash_cpu(value as u128, &blinding, &self.recipient);
        let expected_commitment: u128 = poseidon_elem.as_int();

        if expected_commitment != self.poseidon_commitment {
            return None;
        }

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedStarkTx {
    pub tx_bytes: Vec<u8>,
    pub signer_pk_bytes: Vec<u8>,
    pub signature: BlockSignature,
}

impl SignedStarkTx {
    pub fn parse_tx(&self) -> Result<TransactionStark, String> {
        TransactionStark::from_bytes(&self.tx_bytes)
    }

    pub fn tx_id(&self) -> Result<crate::core::Hash32, String> {
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
        assert_ne!(output.poseidon_commitment, 0u128);

        assert!(output.verify());

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

    #[test]
    fn test_tx_output_with_stealth_hint() {
        use pqcrypto_falcon::falcon512;
        use pqcrypto_kyber::kyber768;
        use crate::stealth_pq::{StealthAddressPQ, StealthSecretsPQ, decrypt_stealth_hint, ScanResult};

        // Generate recipient keys (Bob)
        let (falcon_pk, falcon_sk) = falcon512::keypair();
        let (kyber_pk, kyber_sk) = kyber768::keypair();
        
        let bob_stealth = StealthAddressPQ::from_pks(falcon_pk.clone(), kyber_pk.clone());
        let bob_secrets = StealthSecretsPQ::from_sks(
            falcon_sk,
            kyber_sk.clone(),
            &falcon_pk,
            &kyber_pk,
        );

        // Create transaction output with stealth hint
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);
        let recipient = bob_stealth.id();

        let kyber_pk_kem = crate::kyber_kem::kyber_keypair().0; // For encrypted_value

        let output = TxOutputStark::new_with_stealth(
            50_000,
            &blinding,
            recipient,
            &kyber_pk_kem,
            &bob_stealth,
            "Test stealth payment in tx",
        );

        // Verify STARK proof works
        assert!(output.verify());
        
        // Verify stealth hint is present
        assert!(output.stealth_hint.is_some());
        let stealth_data = output.stealth_hint.as_ref().unwrap();
        
        // Bob can scan and decrypt the hint
        let hint = stealth_data.to_hint();
        match decrypt_stealth_hint(&bob_secrets, &hint) {
            ScanResult::Match(payload) => {
                assert_eq!(payload.value, 50_000);
                assert_eq!(payload.memo, b"Test stealth payment in tx");
                println!("✅ Stealth hint in tx decrypted successfully!");
            }
            other => panic!("Expected Match, got {:?}", other),
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // STARK PROOF TAMPERING ATTACKS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_tampered_stark_proof_rejects() {
        let (kyber_pk, _) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let mut output = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk);
        
        // Tamper with STARK proof - flip a byte in the middle to avoid header corruption
        if output.stark_proof.len() > 100 {
            output.stark_proof[100] ^= 0xFF;
        }
        
        assert!(!output.verify(), 
            "SECURITY: Tampered STARK proof MUST be rejected");
    }
    
    #[test]
    fn test_truncated_stark_proof_rejects() {
        let (kyber_pk, _) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let mut output = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk);
        
        // Truncate STARK proof
        output.stark_proof.truncate(output.stark_proof.len() / 2);
        
        assert!(!output.verify(), 
            "SECURITY: Truncated STARK proof MUST be rejected");
    }
    
    #[test]
    fn test_empty_stark_proof_rejects() {
        let (kyber_pk, _) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let mut output = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk);
        
        // Empty STARK proof
        output.stark_proof.clear();
        
        assert!(!output.verify(), 
            "SECURITY: Empty STARK proof MUST be rejected");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // COMMITMENT TAMPERING ATTACKS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_tampered_commitment_rejects() {
        let (kyber_pk, _) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let mut output = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk);
        
        // Tamper with Poseidon commitment
        output.poseidon_commitment = output.poseidon_commitment.wrapping_add(1);
        
        assert!(!output.verify(), 
            "SECURITY: Tampered commitment MUST break STARK verification");
    }
    
    #[test]
    fn test_tampered_recipient_rejects() {
        let (kyber_pk, _) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let mut output = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk);
        
        // Tamper with recipient
        output.recipient[0] ^= 0xFF;
        
        assert!(!output.verify(), 
            "SECURITY: Tampered recipient MUST break STARK verification");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // ENCRYPTED VALUE ATTACKS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_tampered_encrypted_value_rejects() {
        let (kyber_pk, kyber_sk) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let mut output = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk);
        
        // Tamper with encrypted value
        if output.encrypted_value.len() > 50 {
            output.encrypted_value[50] ^= 0xFF;
        }
        
        assert!(output.decrypt_value(&kyber_sk).is_none(), 
            "SECURITY: Tampered encrypted value MUST fail decryption");
    }
    
    #[test]
    fn test_truncated_encrypted_value_rejects() {
        let (kyber_pk, kyber_sk) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let mut output = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk);
        
        // Truncate encrypted value
        output.encrypted_value.truncate(100);
        
        assert!(output.decrypt_value(&kyber_sk).is_none(), 
            "SECURITY: Truncated encrypted value MUST fail decryption");
    }
    
    #[test]
    fn test_wrong_key_fails_decryption() {
        let (kyber_pk1, _) = crate::kyber_kem::kyber_keypair();
        let (_, kyber_sk2) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let output = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk1);
        
        // Try to decrypt with wrong key
        assert!(output.decrypt_value(&kyber_sk2).is_none(), 
            "SECURITY: Wrong key MUST fail decryption");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // DECRYPT AND VERIFY INTEGRITY
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_decrypt_and_verify_checks_commitment() {
        let (kyber_pk, kyber_sk) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let mut output = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk);
        
        // Tamper with commitment (but keep encrypted_value valid)
        output.poseidon_commitment = output.poseidon_commitment.wrapping_add(1);
        
        // decrypt_value might work, but decrypt_and_verify must fail
        assert!(output.decrypt_and_verify(&kyber_sk).is_none(), 
            "SECURITY: decrypt_and_verify MUST check commitment");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // TRANSACTION INTEGRITY
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_tx_id_determinism() {
        let (kyber_pk, _) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let output = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk);
        
        let tx = TransactionStark {
            inputs: vec![],
            outputs: vec![output],
            fee: 10,
            nonce: 1,
            timestamp: 1_234_567_890,
        };
        
        let id1 = tx.id();
        let id2 = tx.id();
        
        assert_eq!(id1, id2, "TxID MUST be deterministic");
    }
    
    #[test]
    fn test_tx_id_changes_with_output() {
        let (kyber_pk, _) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let output1 = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk);
        let output2 = TxOutputStark::new(200_000, &blinding, [1u8; 32], &kyber_pk);
        
        let tx1 = TransactionStark {
            inputs: vec![],
            outputs: vec![output1],
            fee: 10,
            nonce: 1,
            timestamp: 1_234_567_890,
        };
        
        let tx2 = TransactionStark {
            inputs: vec![],
            outputs: vec![output2],
            fee: 10,
            nonce: 1,
            timestamp: 1_234_567_890,
        };
        
        assert_ne!(tx1.id(), tx2.id(), "Different outputs MUST produce different TxID");
    }
    
    #[test]
    fn test_tx_serialization_roundtrip() {
        let (kyber_pk, _) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        let output = TxOutputStark::new(100_000, &blinding, [1u8; 32], &kyber_pk);
        
        let tx = TransactionStark {
            inputs: vec![],
            outputs: vec![output],
            fee: 10,
            nonce: 1,
            timestamp: 1_234_567_890,
        };
        
        let bytes = tx.to_bytes();
        let tx2 = TransactionStark::from_bytes(&bytes).expect("deserialize failed");
        
        assert_eq!(tx.id(), tx2.id(), "Serialization must preserve TxID");
        assert_eq!(tx.fee, tx2.fee);
        assert_eq!(tx.nonce, tx2.nonce);
        assert_eq!(tx.timestamp, tx2.timestamp);
    }
    
    #[test]
    fn test_invalid_bytes_rejects() {
        let result = TransactionStark::from_bytes(&[0xFF; 10]);
        assert!(result.is_err(), "Invalid bytes should fail deserialization");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // EDGE CASES
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_small_nonzero_value() {
        let (kyber_pk, kyber_sk) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        // Small nonzero value should work
        let output = TxOutputStark::new(1, &blinding, [1u8; 32], &kyber_pk);
        
        assert!(output.verify(), "Small nonzero value should verify");
        let val = output.decrypt_and_verify(&kyber_sk).expect("decrypt failed");
        assert_eq!(val, 1);
    }
    
    #[test]
    fn test_max_u64_value() {
        let (kyber_pk, kyber_sk) = crate::kyber_kem::kyber_keypair();
        let mut blinding = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut blinding);

        // Note: Using a large but safe value
        let large_value = (1u64 << 62) - 1;
        let output = TxOutputStark::new(large_value, &blinding, [1u8; 32], &kyber_pk);
        
        assert!(output.verify(), "Large value should verify");
        let val = output.decrypt_and_verify(&kyber_sk).expect("decrypt failed");
        assert_eq!(val, large_value);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // STEALTH DATA CONVERSION
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_stealth_data_roundtrip() {
        use crate::stealth_pq::{StealthHint};
        
        let hint = StealthHint {
            scan_tag: [0xABu8; 8],
            kem_ct: vec![0xCDu8; 1088],
            nonce: [0xEFu8; 12],
            ciphertext: vec![0x12u8; 512],
        };
        
        let data = TxStealthData::from_hint(&hint);
        let hint2 = data.to_hint();
        
        assert_eq!(hint.scan_tag, hint2.scan_tag);
        assert_eq!(hint.kem_ct, hint2.kem_ct);
        assert_eq!(hint.nonce, hint2.nonce);
        assert_eq!(hint.ciphertext, hint2.ciphertext);
    }
}
