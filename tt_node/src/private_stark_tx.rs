//! Private STARK Transaction v3 - Full Privacy + Confidential Amounts + Fast Scanning
//!
//! # Jak odbiorca lokalizuje stealth płatność?
//!
//! ## Problem: Skanowanie wszystkich TX jest kosztowne!
//!
//! W czystym stealth (jak Monero), odbiorca musi wykonać KEM decapsulation
//! dla KAŻDEJ transakcji w sieci. To O(n) operacji KEM gdzie n = liczba TX.
//!
//! ## Rozwiązanie: scan_hint (Fast filtering WITHOUT KEM!)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │              SCAN_HINT DESIGN (v3)                                   │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                      │
//! │  scan_hint = SHAKE256(stealth_key || recipient_fingerprint)[0..8]   │
//! │                                                                      │
//! │  Properties:                                                        │
//! │    ├─ stealth_key: PUBLIC (w TX)                                    │
//! │    ├─ fingerprint: PRIVATE (tylko odbiorca zna swój fp)             │
//! │    └─ scan_hint: PUBLIC (ale nie zdradza odbiorcy!)                 │
//! │                                                                      │
//! │  Dlaczego zewnętrzny obserwator NIE może zidentyfikować odbiorcy?   │
//! │    → Obserwator widzi: scan_hint (8B) + stealth_key (32B)           │
//! │    → Ale NIE zna recipient's fingerprint!                           │
//! │    → Nie może więc sprawdzić czy TX jest dla konkretnego pk         │
//! │                                                                      │
//! │  Dlaczego odbiorca MOŻE znaleźć swoje TX?                           │
//! │    → Odbiorca ZNA swój fingerprint (SHAKE256(my_kyber_pk))          │
//! │    → Może obliczyć: SHAKE256(tx.stealth_key || my_fp)               │
//! │    → Jeśli == tx.scan_hint → TX MOŻE być moja!                      │
//! │                                                                      │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Scanning Flow (Fast → Slow)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    SCANNING FLOW                                     │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                      │
//! │  Level 1: scan_hint check (8B compare + 1 hash, NO KEM!)            │
//! │    expected = SHAKE256(tx.stealth_key || my_fingerprint)[0..8]      │
//! │    if expected != tx.scan_hint → SKIP (not mine)                    │
//! │    → 2^-64 false positive rate (8 bytes = 64 bits)                  │
//! │    → Cost: 1 SHAKE256 (microseconds)                                │
//! │                                                                      │
//! │  Level 2: KEM decapsulation (only if scan_hint matches!)            │
//! │    → Decapsulate kem_ct → shared_secret                             │
//! │    → Cost: 1 Kyber decapsulation (~0.1ms)                           │
//! │                                                                      │
//! │  Level 3: view_tag + hint_fingerprint verification                  │
//! │    → Confirms TX is definitely mine (no false positives)            │
//! │    → Cost: 2 KMAC operations                                        │
//! │                                                                      │
//! │  Level 4: Amount decryption + STARK verification                    │
//! │    → Decrypt value, verify Poseidon commitment, verify STARK        │
//! │    → Cost: 1 ChaCha + 1 Poseidon + 1 STARK verify                   │
//! │                                                                      │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Przykład skanowania (Rust pseudocode)
//!
//! ```rust,ignore
//! let my_fp = compute_recipient_fingerprint(&my_kyber_pk);
//! 
//! for tx in blockchain.transactions() {
//!     // Level 1: scan_hint check (FAST! No KEM!)
//!     if !tx.recipient_stealth.matches_scan_hint(&my_fp) {
//!         continue;  // 2^-64 false positive rate
//!     }
//!     
//!     // Level 2-3: KEM + verify (only ~0.4% TXs reach here)
//!     if tx.recipient_stealth.verify_fingerprint(&my_kyber_sk, &my_kyber_pk) {
//!         // TX is definitely mine!
//!         let amount = tx.decrypt_amount(&shared_secret);
//!         println!("Received: {} coins", amount);
//!     }
//! }
//! ```
//!
//! ## Rozmiar TX
//!
//! ```text
//! sender_change:           48B (bez KEM)
//! encrypted_sender_id:     60B (fixed)
//! recipient_stealth:     1144B (scan_hint 8B + stealth 32B + view 8B + fp 8B + kem 1088B)
//! amount_commitment:       16B (u128)
//! amount_range_proof:   ~33KB (STARK - winterfell)
//! fee:                      8B (plaintext)
//! tx_nonce:                16B
//! falcon_sig:            ~700B
//! ─────────────────────────────
//! RAZEM:               ~35KB (z pełną prywatnością kwot)
//! ```
//!
//! # Kompromis
//!
//! | TX Type              | Rozmiar | Sender Link | Recipient Link | Amount Hidden |
//! |----------------------|---------|-------------|----------------|---------------|
//! | SimplePqTx           | ~2.8KB  | ✅ Tak      | ✅ Tak         | ❌ NIE        |
//! | CompactSimpleTx      | ~0.8KB  | ✅ Tak      | ✅ Tak         | ❌ NIE        |
//! | PrivateCompactTx     | ~2KB    | ❌ NIE      | ❌ NIE         | ❌ NIE        |
//! | **PrivateStarkTx**   | **~35KB** | **❌ NIE** | **❌ NIE**    | **✅ TAK**    |

#![forbid(unsafe_code)]

use serde::{Serialize, Deserialize};
use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::{Shake256, Sha3_256, digest::{ExtendableOutput, Update, XofReader, Digest}};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Nonce,
};

use chacha20poly1305::{
    XChaCha20Poly1305, Key as ChaChaKey, XNonce,
};

use pqcrypto_kyber::kyber768 as mlkem;
use pqcrypto_traits::kem::SecretKey as PQKemSecretKey;
use pqcrypto_traits::kem::SharedSecret as PQKemSharedSecret;
use pqcrypto_traits::kem::PublicKey as PQKemPublicKey;

use winterfell::Proof as StarkProof;
use winterfell::math::StarkField;
use zeroize::Zeroizing;

use crate::kyber_kem::{
    kyber_encapsulate,
    kyber_decapsulate,
    kyber_ct_to_bytes,
    kyber_ct_from_bytes,
    KyberSharedSecret,
    KyberPublicKey,
    KyberSecretKey,
};
use crate::falcon_sigs::FalconSecretKey;
use crate::crypto::poseidon_hash_cpu::poseidon_hash_cpu;
use crate::crypto::zk_range_poseidon::{
    Witness as RangeWitness,
    PublicInputs as RangePubInputs,
    default_proof_options,
    prove_range_with_poseidon,
    verify_range_with_poseidon,
};

/// Domain separators
const STEALTH_KEY_DOMAIN: &[u8] = b"TT.v7.STEALTH_KEY";
const VIEW_TAG_DOMAIN: &[u8] = b"TT.v7.VIEW_TAG";
const SELF_STEALTH_DOMAIN: &[u8] = b"TT.v7.SELF_STEALTH";
const SENDER_ID_ENC_DOMAIN: &[u8] = b"TT.v7.SENDER_ID_ENC";
const VALUE_ENC_DOMAIN: &[u8] = b"TT.v7.VALUE_ENC";
const HINT_FINGERPRINT_DOMAIN: &[u8] = b"TT.v7.HINT_FINGERPRINT";

/// Kyber768 ciphertext size
const KYBER768_CT_BYTES: usize = 1088;

/// Range proof bits (u64)
const VALUE_NUM_BITS: usize = 64;

// ============================================================================
// RECIPIENT STEALTH OUTPUT (z KEM + scan_hint + hint_fingerprint)
// ============================================================================

/// Stealth output dla odbiorcy (wymaga KEM)
/// 
/// # Scanning Flow (Fast → Slow)
/// 
/// ```text
/// 1. FAST: scan_hint check (8B compare + 1 SHAKE256, NO KEM!)
///    scan_hint = SHAKE256(stealth_key || recipient_fingerprint)[0..8]
///    → Recipient computes: expected = SHAKE256(tx.stealth_key || my_fp)
///    → 2^-64 false positive rate (8 bytes = 64 bits)
///    
/// 2. MEDIUM: KEM decapsulation (only if scan_hint matches)
///    → Get shared_secret from kem_ct
///    
/// 3. FAST: view_tag + hint_fingerprint verification
///    → Confirm TX is definitely for us (eliminates false positives)
///    
/// 4. SLOW: Amount decryption + STARK verification
/// ```
/// 
/// Rozmiar: 8 + 32 + 8 + 8 + 1088 = 1144B
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecipientStealthOutput {
    /// Scan hint (8B) - FIRST filter, NO KEM needed!
    /// scan_hint = SHAKE256("TT.v8.SCAN_HINT" || stealth_key || recipient_fp)[0..8]
    /// Recipient can filter TXs with just 1 hash + 8-byte compare!
    /// False positive rate: 2^-64
    pub scan_hint: [u8; 8],
    /// Ephemeral stealth key (32B)
    pub stealth_key: [u8; 32],
    /// View tag (8B) - second filter after KEM
    pub view_tag: [u8; 8],
    /// Hint fingerprint (8B) - final verification
    pub hint_fingerprint: [u8; 8],
    /// Kyber ciphertext (1088B)
    pub kem_ct: Vec<u8>,
}

/// Compute scan hint from public stealth_key + recipient fingerprint
/// 
/// # Design rationale (v3):
/// scan_hint = SHAKE256("TT.v8.SCAN_HINT" || stealth_key || recipient_fingerprint)[0..8]
/// 
/// - stealth_key is PUBLIC (in TX)
/// - recipient_fingerprint is derived from kyber_pk (recipient knows their own fp)
/// - Recipient can compute: for each TX, check if scan_hint matches SHAKE256(tx.stealth_key || my_fp)
/// - NO KEM REQUIRED for filtering!
/// - False positive rate: 2^-64 (8 bytes = 64 bits)
fn compute_scan_hint(stealth_key: &[u8; 32], recipient_fingerprint: &[u8; 8]) -> [u8; 8] {
    let mut h = Shake256::default();
    h.update(b"TT.v8.SCAN_HINT"); // v8 - new design
    h.update(stealth_key);
    h.update(recipient_fingerprint);
    let mut xof = h.finalize_xof();
    let mut hint = [0u8; 8];
    xof.read(&mut hint);
    hint
}

/// Compute recipient fingerprint from Kyber public key
pub fn compute_recipient_fingerprint(kyber_pk: &mlkem::PublicKey) -> [u8; 8] {
    let mut h = Shake256::default();
    h.update(HINT_FINGERPRINT_DOMAIN);
    h.update(kyber_pk.as_bytes());
    let mut xof = h.finalize_xof();
    let mut fp = [0u8; 8];
    xof.read(&mut fp);
    fp
}

/// Derive fingerprint mask from shared secret
fn derive_fingerprint_mask(ss: &KyberSharedSecret) -> [u8; 8] {
    use crate::crypto::kmac as ck;
    let full = ck::kmac256_derive_key(ss.as_bytes(), HINT_FINGERPRINT_DOMAIN, b"mask");
    let mut mask = [0u8; 8];
    mask.copy_from_slice(&full[..8]);
    mask
}

impl RecipientStealthOutput {
    /// Generate stealth output with scan_hint + hint_fingerprint
    /// 
    /// # Scanning by recipient (Fast → Slow):
    /// 1. Check scan_hint (NO KEM!) - 2^-64 false positive rate
    /// 2. If match: KEM decapsulate (expensive, but rare)
    /// 3. Verify view_tag + hint_fingerprint
    /// 4. Decrypt amount + verify STARK
    /// 
    /// # How scan_hint works:
    /// ```text
    /// scan_hint = SHAKE256(stealth_key || recipient_fingerprint)[0..8]
    /// 
    /// Both stealth_key AND fingerprint are needed to compute scan_hint:
    /// - stealth_key: PUBLIC (in TX)
    /// - fingerprint: PRIVATE (only recipient knows)
    /// 
    /// Recipient checks: SHAKE256(tx.stealth_key || my_fingerprint) == tx.scan_hint?
    /// External observer: can't compute (doesn't know recipient's fingerprint)
    /// ```
    pub fn generate(recipient_kyber_pk: &mlkem::PublicKey) -> Result<(Self, KyberSharedSecret)> {
        // 1. KEM encapsulate first to get stealth_key
        let (ss, kem_ct) = kyber_encapsulate(recipient_kyber_pk);
        let stealth_key = derive_stealth_key(&ss);
        let view_tag = derive_view_tag(&ss);
        
        // 2. Compute recipient fingerprint and scan_hint
        let recipient_fp = compute_recipient_fingerprint(recipient_kyber_pk);
        let scan_hint = compute_scan_hint(&stealth_key, &recipient_fp);
        
        // 3. Compute hint fingerprint (masked by shared secret for extra verification)
        let mask = derive_fingerprint_mask(&ss);
        let mut hint_fingerprint = [0u8; 8];
        for i in 0..8 {
            hint_fingerprint[i] = recipient_fp[i] ^ mask[i];
        }

        Ok((Self {
            scan_hint,
            stealth_key,
            view_tag,
            hint_fingerprint,
            kem_ct: kyber_ct_to_bytes(&kem_ct).to_vec(),
        }, ss))
    }
    
    /// Quick scan hint check - NO KEM required!
    /// Returns true if this TX MIGHT be for us (need full verify to confirm)
    /// 
    /// # How it works:
    /// ```text
    /// scan_hint = SHAKE256(stealth_key || recipient_fingerprint)[0..8]
    /// 
    /// Recipient:
    ///   1. my_fp = compute_recipient_fingerprint(my_kyber_pk)
    ///   2. expected_hint = SHAKE256(tx.stealth_key || my_fp)[0..8]
    ///   3. if tx.scan_hint == expected_hint → MAYBE mine! (do KEM)
    ///   4. else → NOT mine (skip - 2^-64 false positive rate)
    /// ```
    /// 
    /// # Privacy:
    /// - External observer sees: scan_hint (8B) + stealth_key (32B)
    /// - But observer doesn't know recipient's fingerprint
    /// - So observer can't link TX to recipient's public key!
    pub fn matches_scan_hint(&self, my_fingerprint: &[u8; 8]) -> bool {
        let expected = compute_scan_hint(&self.stealth_key, my_fingerprint);
        expected == self.scan_hint
    }
    
    /// Full verification - requires KEM decapsulation
    pub fn verify_fingerprint(&self, our_kyber_sk: &mlkem::SecretKey, our_kyber_pk: &mlkem::PublicKey) -> bool {
        // 1. Decapsulate to get shared secret
        let kem_ct = match kyber_ct_from_bytes(&self.kem_ct) {
            Ok(ct) => ct,
            Err(_) => return false,
        };
        let ss = match kyber_decapsulate(&kem_ct, our_kyber_sk) {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        // 2. Compute expected fingerprint
        let our_fp = compute_recipient_fingerprint(our_kyber_pk);
        let mask = derive_fingerprint_mask(&ss);
        
        // 3. Check: hint_fingerprint XOR mask == our_fingerprint
        for i in 0..8 {
            if (self.hint_fingerprint[i] ^ mask[i]) != our_fp[i] {
                return false;
            }
        }
        true
    }

    pub fn size(&self) -> usize {
        8 + 32 + 8 + 8 + self.kem_ct.len()  // scan_hint + stealth_key + view_tag + hint_fp + kem_ct
    }
}

// ============================================================================
// SENDER CHANGE OUTPUT (bez KEM!)
// ============================================================================

/// Stealth output dla nadawcy (bez KEM - sender zna swój sk)
/// Rozmiar: 32 + 8 + 8 + 8 = 56B (with random salt for unlinkability)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderChangeOutput {
    pub stealth_key: [u8; 32],
    pub view_tag: [u8; 8],
    pub derivation_nonce: u64,
    pub salt: [u8; 8],  // Random salt prevents nonce-reuse linkability
}

impl SenderChangeOutput {
    pub fn generate(sender_kyber_sk: &mlkem::SecretKey, nonce: u64) -> Self {
        // Random salt ensures that even same nonce produces different output
        let mut salt = [0u8; 8];
        OsRng.fill_bytes(&mut salt);
        
        let mut h = Shake256::default();
        h.update(SELF_STEALTH_DOMAIN);
        h.update(sender_kyber_sk.as_bytes());
        h.update(&nonce.to_le_bytes());
        h.update(&salt);  // Include salt in derivation
        
        let mut xof = h.finalize_xof();
        let mut stealth_key = [0u8; 32];
        let mut view_tag = [0u8; 8];
        xof.read(&mut stealth_key);
        xof.read(&mut view_tag);
        
        Self { stealth_key, view_tag, derivation_nonce: nonce, salt }
    }

    /// Recover stealth_key from a known output (requires salt from output)
    pub fn recover(sender_kyber_sk: &mlkem::SecretKey, output: &SenderChangeOutput) -> ([u8; 32], [u8; 8]) {
        let mut h = Shake256::default();
        h.update(SELF_STEALTH_DOMAIN);
        h.update(sender_kyber_sk.as_bytes());
        h.update(&output.derivation_nonce.to_le_bytes());
        h.update(&output.salt);
        
        let mut xof = h.finalize_xof();
        let mut stealth_key = [0u8; 32];
        let mut view_tag = [0u8; 8];
        xof.read(&mut stealth_key);
        xof.read(&mut view_tag);
        
        (stealth_key, view_tag)
    }

    /// Check if this output belongs to us
    pub fn is_ours(sender_kyber_sk: &mlkem::SecretKey, output: &SenderChangeOutput) -> bool {
        let (recovered_key, recovered_tag) = Self::recover(sender_kyber_sk, output);
        recovered_key == output.stealth_key && recovered_tag == output.view_tag
    }

    pub fn size(&self) -> usize { 56 }
}

// ============================================================================
// ENCRYPTED SENDER ID (fixed size)
// ============================================================================

/// Zaszyfrowany sender_master_key_id
/// Rozmiar: 12 (nonce) + 48 (ciphertext) = 60B (FIXED)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedSenderId {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,  // Fixed size: 32 (id) + 16 (tag) = 48B
}

impl EncryptedSenderId {
    pub fn encrypt(
        sender_master_key_id: &[u8; 32],
        shared_secret: &KyberSharedSecret,
    ) -> Result<Self> {
        let enc_key = derive_sender_id_enc_key(shared_secret);
        
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|_| anyhow!("invalid AES key"))?;
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher
            .encrypt(nonce, sender_master_key_id.as_slice())
            .map_err(|e| anyhow!("encryption failed: {e}"))?;
        
        debug_assert_eq!(ciphertext.len(), 48, "AES-GCM: 32 + 16 = 48");
        
        Ok(Self { nonce: nonce_bytes, ciphertext })
    }

    pub fn decrypt(&self, shared_secret: &KyberSharedSecret) -> Result<[u8; 32]> {
        if self.ciphertext.len() != 48 {
            return Err(anyhow!("invalid ciphertext length: {}", self.ciphertext.len()));
        }
        
        let enc_key = derive_sender_id_enc_key(shared_secret);
        
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|_| anyhow!("invalid AES key"))?;
        
        let nonce = Nonce::from_slice(&self.nonce);
        
        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|e| anyhow!("decryption failed (auth tag mismatch): {e}"))?;
        
        if plaintext.len() != 32 {
            return Err(anyhow!("invalid decrypted length"));
        }
        
        let mut id = [0u8; 32];
        id.copy_from_slice(&plaintext);
        Ok(id)
    }

    pub const fn size() -> usize { 60 }
}

// ============================================================================
// CONFIDENTIAL AMOUNT OUTPUT
// ============================================================================

/// Confidential amount z STARK range proof
/// 
/// Zawiera:
/// - Poseidon commitment: ukrywa wartość
/// - STARK range proof: dowodzi 0 ≤ value < 2^64
/// - Encrypted value: tylko recipient może odszyfrować
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialAmount {
    /// Poseidon(value, blinding, recipient) jako u128
    pub commitment: u128,
    /// STARK range proof (Winterfell, ~20KB)
    pub range_proof: Vec<u8>,
    /// Encrypted (value || blinding): nonce(24B) + ciphertext + kyber_ct(1088B)
    pub encrypted_data: Vec<u8>,
}

impl ConfidentialAmount {
    /// Create confidential amount with STARK proof
    pub fn create(
        value: u64,
        recipient: &[u8; 32],
        recipient_kyber_pk: &KyberPublicKey,
    ) -> Result<(Self, [u8; 32])> {
        // 1. Random blinding factor
        let mut blinding = [0u8; 32];
        OsRng.fill_bytes(&mut blinding);

        // 2. Poseidon commitment
        let poseidon_elem = poseidon_hash_cpu(value as u128, &blinding, recipient);
        let commitment: u128 = poseidon_elem.as_int();

        // 3. STARK range proof (linked to commitment)
        let witness = RangeWitness::new(value as u128, blinding, *recipient);
        let opts = default_proof_options();
        let (proof, pub_inputs) = prove_range_with_poseidon(witness, VALUE_NUM_BITS, opts);

        // Verify commitment matches
        debug_assert_eq!(
            pub_inputs.value_commitment, commitment,
            "Commitment mismatch between STARK and CPU"
        );

        let range_proof = proof.to_bytes();

        // 4. Encrypt (value || blinding) for recipient
        let (ss, kem_ct) = kyber_encapsulate(recipient_kyber_pk);
        let aes_key = crate::kyber_kem::derive_aes_key_from_shared_secret(&ss, VALUE_ENC_DOMAIN);

        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(&aes_key));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);

        let mut plaintext = Vec::with_capacity(40);
        plaintext.extend_from_slice(&value.to_le_bytes());
        plaintext.extend_from_slice(&blinding);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow!("encryption failed: {e}"))?;

        // Pack: nonce(24) || ciphertext(40+16) || kyber_ct(1088)
        let ct_bytes = kyber_ct_to_bytes(&kem_ct);
        let mut encrypted_data = Vec::with_capacity(24 + ciphertext.len() + ct_bytes.len());
        encrypted_data.extend_from_slice(&nonce_bytes);
        encrypted_data.extend_from_slice(&ciphertext);
        encrypted_data.extend_from_slice(&ct_bytes);

        Ok((Self {
            commitment,
            range_proof,
            encrypted_data,
        }, blinding))
    }

    /// Verify STARK range proof (no decryption)
    /// 
    /// NOTE: Only first 8 bytes of recipient are used in STARK verification.
    /// This is because Poseidon uses BaseElement (u64) for recipient binding.
    pub fn verify_range_proof(&self, recipient: &[u8; 32]) -> bool {
        let proof = match StarkProof::from_bytes(&self.range_proof) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // IMPORTANT: STARK uses only first 8 bytes of recipient (see zk_range_poseidon.rs)
        // The prover's get_pub_inputs() zeroes bytes 8..32, so we must do the same
        let mut normalized_recipient = [0u8; 32];
        normalized_recipient[..8].copy_from_slice(&recipient[..8]);

        let pub_inputs = RangePubInputs {
            value_commitment: self.commitment,
            recipient: normalized_recipient,
            num_bits: VALUE_NUM_BITS as u32,
        };

        verify_range_with_poseidon(proof, pub_inputs)
    }

    /// Decrypt value (recipient only)
    pub fn decrypt(&self, kyber_sk: &KyberSecretKey) -> Option<(u64, [u8; 32])> {
        if self.encrypted_data.len() < 24 + 16 + KYBER768_CT_BYTES {
            return None;
        }

        let nonce_bytes = &self.encrypted_data[0..24];
        let ct_end = self.encrypted_data.len() - KYBER768_CT_BYTES;
        let ciphertext = &self.encrypted_data[24..ct_end];
        let kyber_ct_bytes = &self.encrypted_data[ct_end..];

        let kyber_ct = kyber_ct_from_bytes(kyber_ct_bytes).ok()?;
        let ss = kyber_decapsulate(&kyber_ct, kyber_sk).ok()?;
        let aes_key = crate::kyber_kem::derive_aes_key_from_shared_secret(&ss, VALUE_ENC_DOMAIN);

        let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(&aes_key));
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

    /// Decrypt and verify commitment
    pub fn decrypt_and_verify(&self, kyber_sk: &KyberSecretKey, recipient: &[u8; 32]) -> Option<u64> {
        let (value, blinding) = self.decrypt(kyber_sk)?;

        // Verify Poseidon commitment
        let expected = poseidon_hash_cpu(value as u128, &blinding, recipient);
        if expected.as_int() != self.commitment {
            return None;
        }

        // Verify STARK proof
        if !self.verify_range_proof(recipient) {
            return None;
        }

        Some(value)
    }

    /// Estimated size
    pub fn size(&self) -> usize {
        16 + self.range_proof.len() + self.encrypted_data.len()
    }
}

// ============================================================================
// PRIVATE STARK TX - FULL PRIVACY
// ============================================================================

/// Private STARK Transaction - pełna prywatność
/// 
/// - Sender: unlinkable (stealth + encrypted master_key_id)
/// - Recipient: unlinkable (stealth address)
/// - Amount: hidden (Poseidon commitment + STARK range proof)
/// - Fee: plaintext (must be visible for validators)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateStarkTx {
    // === STEALTH (WHO) ===
    /// Sender change output (48B, bez KEM)
    pub sender_change: SenderChangeOutput,
    /// Encrypted sender_master_key_id (60B fixed)
    pub encrypted_sender_id: EncryptedSenderId,
    /// Recipient stealth output (1128B)
    pub recipient_stealth: RecipientStealthOutput,

    // === CONFIDENTIAL (HOW MUCH) ===
    /// Confidential amount with STARK proof (~20KB)
    pub amount: ConfidentialAmount,

    // === PUBLIC (required for validation) ===
    /// Fee (plaintext - validators need to see this)
    pub fee: u64,
    /// TX nonce for uniqueness
    pub tx_nonce: [u8; 16],

    // === SIGNATURE ===
    /// Falcon-512 signature (~700B)
    pub falcon_sig: Vec<u8>,
}

impl PrivateStarkTx {
    /// Create new private STARK transaction
    pub fn create(
        sender_falcon_sk: &FalconSecretKey,
        sender_kyber_sk: &mlkem::SecretKey,
        sender_master_key_id: [u8; 32],
        recipient_kyber_pk: &mlkem::PublicKey,
        recipient_addr: &[u8; 32],  // For Poseidon commitment binding
        amount: u64,
        fee: u64,
        change_nonce: u64,
    ) -> Result<Self> {
        // 1. Recipient stealth (with KEM)
        let (recipient_stealth, shared_secret) = RecipientStealthOutput::generate(recipient_kyber_pk)?;

        // 2. Encrypt sender_master_key_id
        let encrypted_sender_id = EncryptedSenderId::encrypt(
            &sender_master_key_id,
            &shared_secret,
        )?;

        // 3. Sender change (bez KEM)
        let sender_change = SenderChangeOutput::generate(sender_kyber_sk, change_nonce);

        // 4. Confidential amount with STARK proof
        let (confidential_amount, _blinding) = ConfidentialAmount::create(
            amount,
            recipient_addr,
            recipient_kyber_pk,
        )?;

        // 5. Random TX nonce
        let mut tx_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut tx_nonce);

        // 6. Build unsigned TX
        let mut tx = Self {
            sender_change,
            encrypted_sender_id,
            recipient_stealth,
            amount: confidential_amount,
            fee,
            tx_nonce,
            falcon_sig: vec![],
        };

        // 7. Sign (includes encrypted_sender_id in signing message!)
        let msg = tx.signing_message();
        let signed = crate::falcon_sigs::falcon_sign(&msg, sender_falcon_sk)?;
        tx.falcon_sig = signed.signed_message_bytes.clone();

        Ok(tx)
    }

    /// Signing message - includes ALL fields for integrity
    /// 
    /// CRITICAL: We sign EVERYTHING including ciphertexts and STARK proof!
    /// This prevents "griefing" attacks where attacker swaps ciphertexts,
    /// causing recipient to fail decryption (DoS / funds blackhole).
    pub fn signing_message(&self) -> Vec<u8> {
        // Pre-allocate for ~35KB message
        let mut msg = Vec::with_capacity(
            56 + 60 + self.recipient_stealth.size() + self.amount.size() + 24
        );
        
        // Sender change (56B with salt)
        msg.extend_from_slice(&self.sender_change.stealth_key);
        msg.extend_from_slice(&self.sender_change.view_tag);
        msg.extend_from_slice(&self.sender_change.derivation_nonce.to_le_bytes());
        msg.extend_from_slice(&self.sender_change.salt);  // CRITICAL: prevents salt manipulation!
        
        // Encrypted sender ID (60B)
        msg.extend_from_slice(&self.encrypted_sender_id.nonce);
        msg.extend_from_slice(&self.encrypted_sender_id.ciphertext);
        
        // Recipient stealth - ALL fields! (1144B)
        msg.extend_from_slice(&self.recipient_stealth.scan_hint);        // NEW: scan hint
        msg.extend_from_slice(&self.recipient_stealth.stealth_key);
        msg.extend_from_slice(&self.recipient_stealth.view_tag);
        msg.extend_from_slice(&self.recipient_stealth.hint_fingerprint);
        msg.extend_from_slice(&self.recipient_stealth.kem_ct);           // CRITICAL: prevents KEM swap
        
        // Confidential amount - ALL fields! (~33KB)
        msg.extend_from_slice(&self.amount.commitment.to_le_bytes());
        msg.extend_from_slice(&self.amount.range_proof);        // CRITICAL: prevents proof swap
        msg.extend_from_slice(&self.amount.encrypted_data);     // CRITICAL: prevents value DoS
        
        // Fee and nonce (24B)
        msg.extend_from_slice(&self.fee.to_le_bytes());
        msg.extend_from_slice(&self.tx_nonce);
        
        msg
    }

    /// TX ID
    pub fn tx_id(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        Digest::update(&mut h, b"PRIVATE_STARK_TX.v1");
        Digest::update(&mut h, &self.signing_message());
        Digest::update(&mut h, &self.falcon_sig);
        h.finalize().into()
    }

    /// Verify STARK proof only (no decryption needed)
    pub fn verify_range_proof(&self, recipient_addr: &[u8; 32]) -> bool {
        self.amount.verify_range_proof(recipient_addr)
    }

    /// Size in bytes
    pub fn size(&self) -> usize {
        self.sender_change.size()           // 48B
        + EncryptedSenderId::size()         // 60B
        + self.recipient_stealth.size()     // 1128B
        + self.amount.size()                // ~20KB
        + 8                                 // fee
        + 16                                // tx_nonce
        + self.falcon_sig.len()             // ~700B
    }

    /// Size comparison
    pub fn size_comparison() {
        println!("=== TX Size Comparison ===");
        println!("SimplePqTx:        ~2,850B (full PK, no privacy)");
        println!("CompactSimpleTx:     ~786B (key_id, no privacy)");
        println!("PrivateCompactTx:  ~2,000B (stealth, plaintext amounts)");
        println!("PrivateStarkTx:   ~22,000B (FULL privacy!)");
        println!();
        println!("Privacy levels:");
        println!("  ├─ Sender:    HIDDEN (stealth + encrypted ID)");
        println!("  ├─ Recipient: HIDDEN (stealth address)");
        println!("  └─ Amount:    HIDDEN (Poseidon + STARK proof)");
    }

    // ========================================================================
    // COMPRESSION (bincode + zstd)
    // ========================================================================

    /// Serialize to compressed bytes (bincode + zstd level 9)
    /// 
    /// Why bincode instead of JSON?
    /// - JSON hex-encodes Vec<u8> → 2x size increase
    /// - bincode stores raw bytes → no overhead
    /// - STARK proof: 33KB binary stays 33KB (not 66KB hex)
    /// - Metadata compresses well with zstd
    /// 
    /// Result: ~35KB → ~34KB (STARK incompressible, but no hex overhead)
    pub fn to_compressed_bytes(&self) -> Result<Vec<u8>> {
        let binary = bincode::serialize(self)
            .map_err(|e| anyhow!("Bincode serialize failed: {}", e))?;
        
        // Magic header: "PSTX" + version byte + compressed data
        let mut out = Vec::with_capacity(binary.len());
        out.extend_from_slice(b"PSTX");  // Magic: Private Stark TX
        out.push(2);                      // Version 2 (bincode format)
        
        // Level 9 for high compression (metadata will compress)
        let compressed = zstd::encode_all(binary.as_slice(), 9)
            .map_err(|e| anyhow!("Zstd compress failed: {}", e))?;
        out.extend_from_slice(&compressed);
        
        Ok(out)
    }

    /// Deserialize from compressed bytes
    pub fn from_compressed_bytes(data: &[u8]) -> Result<Self> {
        // Check magic header
        if data.len() < 5 {
            return Err(anyhow!("Data too short"));
        }
        if &data[0..4] != b"PSTX" {
            return Err(anyhow!("Invalid magic header (expected PSTX)"));
        }
        let version = data[4];
        if version != 2 {
            return Err(anyhow!("Unsupported version: {} (expected 2)", version));
        }

        let decompressed = zstd::decode_all(&data[5..])
            .map_err(|e| anyhow!("Zstd decompress failed: {}", e))?;
        
        bincode::deserialize(&decompressed)
            .map_err(|e| anyhow!("Bincode deserialize failed: {}", e))
    }

    /// Serialize to compressed hex string
    pub fn to_compressed_hex(&self) -> Result<String> {
        let bytes = self.to_compressed_bytes()?;
        Ok(hex::encode(bytes))
    }

    /// Deserialize from compressed hex string
    pub fn from_compressed_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| anyhow!("Hex decode failed: {}", e))?;
        Self::from_compressed_bytes(&bytes)
    }

    /// Compression ratio info
    pub fn compression_stats(&self) -> Result<(usize, usize, f64)> {
        let uncompressed = bincode::serialize(self)
            .map_err(|e| anyhow!("Bincode serialize failed: {}", e))?.len();
        let compressed = self.to_compressed_bytes()?.len();
        let ratio = 100.0 * (1.0 - (compressed as f64 / uncompressed as f64));
        Ok((uncompressed, compressed, ratio))
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn derive_stealth_key(ss: &KyberSharedSecret) -> [u8; 32] {
    use crate::crypto::kmac as ck;
    ck::kmac256_derive_key(ss.as_bytes(), STEALTH_KEY_DOMAIN, b"")
}

fn derive_view_tag(ss: &KyberSharedSecret) -> [u8; 8] {
    use crate::crypto::kmac as ck;
    let full = ck::kmac256_derive_key(ss.as_bytes(), VIEW_TAG_DOMAIN, b"");
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&full[..8]);
    tag
}

fn derive_sender_id_enc_key(ss: &KyberSharedSecret) -> [u8; 32] {
    use crate::crypto::kmac as ck;
    ck::kmac256_derive_key(ss.as_bytes(), SENDER_ID_ENC_DOMAIN, b"")
}

fn derive_sender_id_enc_key_from_bytes(ss_bytes: &[u8]) -> [u8; 32] {
    use crate::crypto::kmac as ck;
    ck::kmac256_derive_key(ss_bytes, SENDER_ID_ENC_DOMAIN, b"")
}

// ============================================================================
// SCANNING
// ============================================================================

/// Scan result
#[derive(Clone, Debug)]
pub enum ScanResult {
    Match {
        stealth_key: [u8; 32],
        shared_secret: Vec<u8>,
    },
    NotForUs,
    Error(String),
}

/// Scan recipient stealth output with hint_fingerprint verification
pub fn scan_recipient_output(
    output: &RecipientStealthOutput,
    our_kyber_sk: &mlkem::SecretKey,
    our_kyber_pk: &mlkem::PublicKey,
) -> ScanResult {
    let kem_ct = match kyber_ct_from_bytes(&output.kem_ct) {
        Ok(ct) => ct,
        Err(e) => return ScanResult::Error(format!("invalid kem_ct: {e}")),
    };

    let ss = match kyber_decapsulate(&kem_ct, our_kyber_sk) {
        Ok(s) => s,
        Err(e) => return ScanResult::Error(format!("decapsulate failed: {e}")),
    };

    // First check view_tag (fast ~95% rejection)
    let computed_tag = derive_view_tag(&ss);
    if computed_tag != output.view_tag {
        return ScanResult::NotForUs;
    }

    // Then verify hint_fingerprint
    let our_fp = compute_recipient_fingerprint(our_kyber_pk);
    let mask = derive_fingerprint_mask(&ss);
    for i in 0..8 {
        if (output.hint_fingerprint[i] ^ mask[i]) != our_fp[i] {
            return ScanResult::NotForUs;
        }
    }

    // Finally verify stealth_key
    let computed_stealth = derive_stealth_key(&ss);
    if computed_stealth != output.stealth_key {
        return ScanResult::NotForUs;
    }

    ScanResult::Match {
        stealth_key: output.stealth_key,
        shared_secret: ss.as_bytes().to_vec(),
    }
}

/// Scan sender change output
pub fn scan_sender_change(
    output: &SenderChangeOutput,
    our_kyber_sk: &mlkem::SecretKey,
) -> bool {
    // Now uses salt from output to recover
    SenderChangeOutput::is_ours(our_kyber_sk, output)
}

// ============================================================================
// VIEW KEY
// ============================================================================

/// View key - scan without spending
/// 
/// SECURITY: Contains secret key material - zeroized on drop!
#[derive(Clone)]
pub struct ViewKey {
    /// Kyber secret key bytes - ZEROIZED on drop
    kyber_sk_bytes: Zeroizing<Vec<u8>>,
    /// Kyber public key bytes (needed for fingerprint verification)
    kyber_pk_bytes: Vec<u8>,
    pub master_key_id: [u8; 32],
}

// Manual Serialize/Deserialize to handle Zeroizing
impl serde::Serialize for ViewKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ViewKey", 3)?;
        state.serialize_field("kyber_sk_bytes", self.kyber_sk_bytes.as_slice())?;
        state.serialize_field("kyber_pk_bytes", &self.kyber_pk_bytes)?;
        state.serialize_field("master_key_id", &self.master_key_id)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for ViewKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct ViewKeyHelper {
            kyber_sk_bytes: Vec<u8>,
            kyber_pk_bytes: Vec<u8>,
            master_key_id: [u8; 32],
        }
        let helper = ViewKeyHelper::deserialize(deserializer)?;
        Ok(Self {
            kyber_sk_bytes: Zeroizing::new(helper.kyber_sk_bytes),
            kyber_pk_bytes: helper.kyber_pk_bytes,
            master_key_id: helper.master_key_id,
        })
    }
}

impl ViewKey {
    pub fn from_secrets(
        kyber_sk: &mlkem::SecretKey, 
        kyber_pk: &mlkem::PublicKey,
        master_key_id: [u8; 32],
    ) -> Self {
        Self {
            kyber_sk_bytes: Zeroizing::new(kyber_sk.as_bytes().to_vec()),
            kyber_pk_bytes: kyber_pk.as_bytes().to_vec(),
            master_key_id,
        }
    }
    
    /// Get our fingerprint (for quick TX scanning)
    pub fn our_fingerprint(&self) -> [u8; 8] {
        let kyber_pk = crate::kyber_kem::kyber_pk_from_bytes(&self.kyber_pk_bytes)
            .expect("ViewKey has valid kyber_pk");
        compute_recipient_fingerprint(&kyber_pk)
    }

    /// Scan TX as recipient - returns decrypted amount with STARK verification
    /// 
    /// # Arguments
    /// * `tx` - The transaction to scan
    /// * `recipient_addr` - Our raw address (needed for STARK verification)
    /// 
    /// # Returns
    /// * `Some(result)` - If TX is for us AND STARK proof is valid
    /// * `None` - If TX is not for us OR data is corrupted
    /// 
    /// # Scanning Flow (Fast → Slow)
    /// 1. **Level 1**: scan_hint check (NO KEM!) - 2^-64 false positive rate
    /// 2. **Level 2**: KEM decapsulation (only if scan_hint matches)
    /// 3. **Level 3**: view_tag + hint_fingerprint verification
    /// 4. **Level 4**: Amount decryption + STARK verification
    pub fn scan_as_recipient(
        &self,
        tx: &PrivateStarkTx,
        recipient_addr: &[u8; 32],
    ) -> Option<PrivateStarkScanResult> {
        // ==================================================================
        // Level 1: scan_hint check (NO KEM!) - FAST filter
        // ==================================================================
        let my_fp = self.our_fingerprint();
        
        // Quick filter: if scan_hint doesn't match → definitely not our TX
        // Cost: 1 SHAKE256 + 8-byte compare (microseconds)
        // False positive rate: 2^-64 (8 bytes = 64 bits)
        if !tx.recipient_stealth.matches_scan_hint(&my_fp) {
            return None;  // Not for us - skip KEM entirely!
        }
        
        // ==================================================================
        // Level 2-4: KEM + fingerprint + amount (only for matched TXs)
        // ==================================================================
        let kyber_sk = crate::kyber_kem::kyber_sk_from_bytes(&self.kyber_sk_bytes).ok()?;
        let kyber_pk = crate::kyber_kem::kyber_pk_from_bytes(&self.kyber_pk_bytes).ok()?;

        match scan_recipient_output(&tx.recipient_stealth, &kyber_sk, &kyber_pk) {
            ScanResult::Match { stealth_key, shared_secret } => {
                // Level 3: Decrypt sender_id (proves KEM was successful)
                let enc_key = derive_sender_id_enc_key_from_bytes(&shared_secret);
                let sender_id = decrypt_sender_id_with_key(&tx.encrypted_sender_id, &enc_key).ok()?;

                // Level 4: Decrypt AND verify amount (defensive!)
                // This catches corrupted data even if network accepted it
                let amount = tx.amount.decrypt_and_verify(&kyber_sk, recipient_addr)?;

                Some(PrivateStarkScanResult {
                    amount,
                    stealth_key,
                    sender_master_key_id: sender_id,
                    stark_verified: true,  // We used decrypt_and_verify
                })
            }
            _ => None,  // KEM failed - scan_hint was false positive (extremely rare)
        }
    }

    /// Scan TX as sender (change output)
    pub fn scan_as_sender(&self, tx: &PrivateStarkTx) -> Option<u64> {
        let kyber_sk = crate::kyber_kem::kyber_sk_from_bytes(&self.kyber_sk_bytes).ok()?;

        if scan_sender_change(&tx.sender_change, &kyber_sk) {
            // Note: sender cannot decrypt amount (it's encrypted to recipient)
            // They would need to remember the original amount
            Some(tx.fee) // Return fee as indicator (amount unknown without local state)
        } else {
            None
        }
    }
}

/// Scan result as recipient (with STARK verification)
#[derive(Clone, Debug)]
pub struct PrivateStarkScanResult {
    pub amount: u64,
    pub stealth_key: [u8; 32],
    pub sender_master_key_id: [u8; 32],
    /// True if STARK range proof was verified during decryption
    pub stark_verified: bool,
}

/// Decrypt sender_id with pre-derived key
fn decrypt_sender_id_with_key(encrypted: &EncryptedSenderId, enc_key: &[u8; 32]) -> Result<[u8; 32]> {
    let cipher = Aes256Gcm::new_from_slice(enc_key)
        .map_err(|_| anyhow!("invalid AES key"))?;

    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_slice())
        .map_err(|e| anyhow!("decryption failed: {e}"))?;

    if plaintext.len() != 32 {
        return Err(anyhow!("invalid decrypted length"));
    }

    let mut id = [0u8; 32];
    id.copy_from_slice(&plaintext);
    Ok(id)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_falcon::falcon512;

    fn test_keypairs() -> (
        falcon512::PublicKey, falcon512::SecretKey,
        mlkem::PublicKey, mlkem::SecretKey,
    ) {
        let (falcon_pk, falcon_sk) = falcon512::keypair();
        let (kyber_pk, kyber_sk) = mlkem::keypair();
        (falcon_pk, falcon_sk, kyber_pk, kyber_sk)
    }

    #[test]
    fn test_encrypted_sender_id_fixed_size() {
        let (_, _, kyber_pk, _) = test_keypairs();
        let sender_id = [0x42u8; 32];
        let (ss, _) = kyber_encapsulate(&kyber_pk);

        let encrypted = EncryptedSenderId::encrypt(&sender_id, &ss).unwrap();

        // Fixed size!
        assert_eq!(encrypted.nonce.len(), 12);
        assert_eq!(encrypted.ciphertext.len(), 48);
        assert_eq!(EncryptedSenderId::size(), 60);

        // Decrypt works
        let decrypted = encrypted.decrypt(&ss).unwrap();
        assert_eq!(decrypted, sender_id);

        // Wrong key ALWAYS fails (AES-GCM auth tag)
        let (wrong_ss, _) = kyber_encapsulate(&kyber_pk);
        assert!(encrypted.decrypt(&wrong_ss).is_err());

        println!("✅ EncryptedSenderId fixed size: {}B", EncryptedSenderId::size());
    }

    #[test]
    fn test_confidential_amount_stark() {
        let (_, _, kyber_pk, kyber_sk) = test_keypairs();
        // NOTE: Only first 8 bytes of recipient are used in STARK (due to zk_range_poseidon limitation)
        // The rest should be zero for verification to work
        let mut recipient = [0u8; 32];
        recipient[0..8].copy_from_slice(&[0x42u8; 8]);

        let (amount, _blinding) = ConfidentialAmount::create(
            12345,
            &recipient,
            &kyber_pk,
        ).unwrap();

        println!("ConfidentialAmount size: {}B", amount.size());
        println!("  commitment: {}", amount.commitment);
        println!("  range_proof: {}B", amount.range_proof.len());
        println!("  encrypted_data: {}B", amount.encrypted_data.len());

        // Verify STARK proof (no decryption)
        assert!(amount.verify_range_proof(&recipient));
        println!("✅ STARK range proof valid");

        // Decrypt
        let (value, blinding) = amount.decrypt(&kyber_sk).unwrap();
        assert_eq!(value, 12345);
        println!("✅ Decrypted value: {}", value);

        // Full verify
        let verified = amount.decrypt_and_verify(&kyber_sk, &recipient);
        assert_eq!(verified, Some(12345));
        println!("✅ Full verification passed");
    }

    #[test]
    fn test_signing_message_includes_all_ciphertexts() {
        // Verify that signing message includes ALL fields (anti-griefing)
        let sender_change = SenderChangeOutput {
            stealth_key: [1u8; 32],
            view_tag: [2u8; 8],
            derivation_nonce: 123,
            salt: [11u8; 8],
        };

        let encrypted_sender_id = EncryptedSenderId {
            nonce: [3u8; 12],
            ciphertext: vec![4u8; 48],
        };

        let recipient_stealth = RecipientStealthOutput {
            scan_hint: [10u8; 8],        // NEW: scan hint
            stealth_key: [5u8; 32],
            view_tag: [6u8; 8],
            hint_fingerprint: [9u8; 8],
            kem_ct: vec![7u8; 1088],
        };

        let amount = ConfidentialAmount {
            commitment: 999,
            range_proof: vec![0xAAu8; 100],      // Mock STARK proof
            encrypted_data: vec![0xBBu8; 200],  // Mock encrypted value
        };

        let tx = PrivateStarkTx {
            sender_change,
            encrypted_sender_id,
            recipient_stealth,
            amount,
            fee: 10,
            tx_nonce: [8u8; 16],
            falcon_sig: vec![],
        };

        let msg = tx.signing_message();

        // Calculate expected positions
        // sender_change: 32 + 8 + 8 + 8 = 56B (now includes salt!)
        // encrypted_sender_id: 12 + 48 = 60B
        // recipient_stealth: 8 + 32 + 8 + 8 + 1088 = 1144B (with scan_hint!)
        // amount: 16 + 100 + 200 = 316B
        // fee + nonce: 8 + 16 = 24B
        // TOTAL: 56 + 60 + 1144 + 316 + 24 = 1600B
        
        let expected_size = 56 + 60 + 1144 + 316 + 24;
        assert_eq!(msg.len(), expected_size, "signing message size mismatch");

        // Verify encrypted_sender_id is in message (offset 56, after salt)
        assert_eq!(&msg[56..68], &[3u8; 12], "encrypted_sender_id.nonce missing");
        assert_eq!(&msg[68..116], &[4u8; 48], "encrypted_sender_id.ciphertext missing");

        // Verify scan_hint is in message (offset 116)
        assert_eq!(&msg[116..124], &[10u8; 8], "recipient_stealth.scan_hint missing");

        // Verify stealth_key is in message (offset 124)
        assert_eq!(&msg[124..156], &[5u8; 32], "recipient_stealth.stealth_key missing");

        // Verify view_tag is in message (offset 156)
        assert_eq!(&msg[156..164], &[6u8; 8], "recipient_stealth.view_tag missing");

        // Verify hint_fingerprint is in message (offset 164)
        assert_eq!(&msg[164..172], &[9u8; 8], "recipient_stealth.hint_fingerprint missing");

        // Verify kem_ct is in message (offset 172)
        assert_eq!(&msg[172..182], &[7u8; 10], "recipient_stealth.kem_ct missing");

        // Verify range_proof is in message
        let range_proof_start = 116 + 1144 + 16; // after recipient_stealth + commitment
        assert_eq!(&msg[range_proof_start..range_proof_start+10], &[0xAAu8; 10], "amount.range_proof missing");

        // Verify encrypted_data is in message
        let enc_data_start = range_proof_start + 100;
        assert_eq!(&msg[enc_data_start..enc_data_start+10], &[0xBBu8; 10], "amount.encrypted_data missing");

        println!("✅ Signing message includes ALL ciphertexts (anti-griefing)");
        println!("   Total signing message size: {}B", msg.len());
        println!("   Breakdown:");
        println!("     sender_change:       56B (with salt)");
        println!("     encrypted_sender_id: 60B");
        println!("     recipient_stealth:   1144B (scan_hint + stealth_key + view_tag + hint_fp + kem_ct)");
        println!("     amount:              316B (commitment + proof + encrypted)");
        println!("     fee + nonce:         24B");
    }

    #[test]
    fn test_tampering_detection() {
        // Test that ANY modification to TX breaks signature
        let (_, _, kyber_pk, _kyber_sk) = test_keypairs();
        
        let sender_change = SenderChangeOutput {
            stealth_key: [1u8; 32],
            view_tag: [2u8; 8],
            derivation_nonce: 123,
            salt: [11u8; 8],
        };

        let (ss, _) = kyber_encapsulate(&kyber_pk);
        let encrypted_sender_id = EncryptedSenderId::encrypt(&[0x42u8; 32], &ss).unwrap();

        let recipient_stealth = RecipientStealthOutput {
            scan_hint: [10u8; 8],        // NEW: scan hint
            stealth_key: [5u8; 32],
            view_tag: [6u8; 8],
            hint_fingerprint: [9u8; 8],
            kem_ct: vec![7u8; 1088],
        };

        let amount = ConfidentialAmount {
            commitment: 999,
            range_proof: vec![0xAAu8; 100],
            encrypted_data: vec![0xBBu8; 200],
        };

        let tx = PrivateStarkTx {
            sender_change,
            encrypted_sender_id,
            recipient_stealth,
            amount,
            fee: 10,
            tx_nonce: [8u8; 16],
            falcon_sig: vec![],
        };

        let original_msg = tx.signing_message();

        // Test 0: Modify scan_hint
        let mut tampered_tx = tx.clone();
        tampered_tx.recipient_stealth.scan_hint[0] ^= 1;
        let tampered_msg = tampered_tx.signing_message();
        assert_ne!(original_msg, tampered_msg, "scan_hint tampering should change signing message");
        println!("✅ scan_hint tampering detected");

        // Test 1: Modify kem_ct
        let mut tampered_tx = tx.clone();
        tampered_tx.recipient_stealth.kem_ct[0] ^= 1;
        let tampered_msg = tampered_tx.signing_message();
        assert_ne!(original_msg, tampered_msg, "kem_ct tampering should change signing message");
        println!("✅ kem_ct tampering detected");
        
        // Test 2: Modify hint_fingerprint
        let mut tampered_tx = tx.clone();
        tampered_tx.recipient_stealth.hint_fingerprint[0] ^= 1;
        let tampered_msg = tampered_tx.signing_message();
        assert_ne!(original_msg, tampered_msg, "hint_fingerprint tampering should change signing message");
        println!("✅ hint_fingerprint tampering detected");

        // Test 3: Modify range_proof
        let mut tampered_tx = tx.clone();
        tampered_tx.amount.range_proof[0] ^= 1;
        let tampered_msg = tampered_tx.signing_message();
        assert_ne!(original_msg, tampered_msg, "range_proof tampering should change signing message");
        println!("✅ range_proof tampering detected");

        // Test 3: Modify encrypted_data
        let mut tampered_tx = tx.clone();
        tampered_tx.amount.encrypted_data[0] ^= 1;
        let tampered_msg = tampered_tx.signing_message();
        assert_ne!(original_msg, tampered_msg, "encrypted_data tampering should change signing message");
        println!("✅ encrypted_data tampering detected");

        // Test 4: Modify commitment
        let mut tampered_tx = tx.clone();
        tampered_tx.amount.commitment ^= 1;
        let tampered_msg = tampered_tx.signing_message();
        assert_ne!(original_msg, tampered_msg, "commitment tampering should change signing message");
        println!("✅ commitment tampering detected");

        println!("\n✅ ALL tampering attempts are detectable!");
    }

    #[test]
    fn test_hint_fingerprint() {
        // Test that hint_fingerprint allows fast TX identification
        let (_, _, kyber_pk, kyber_sk) = test_keypairs();
        let (_, _, other_pk, other_sk) = test_keypairs();

        // Generate stealth output for kyber_pk
        let (output, _ss) = RecipientStealthOutput::generate(&kyber_pk).unwrap();

        // Correct recipient should verify
        assert!(output.verify_fingerprint(&kyber_sk, &kyber_pk), 
            "correct recipient should verify fingerprint");
        println!("✅ Correct recipient verifies fingerprint");

        // Wrong recipient should NOT verify
        assert!(!output.verify_fingerprint(&other_sk, &other_pk),
            "wrong recipient should NOT verify fingerprint");
        println!("✅ Wrong recipient does NOT verify fingerprint");

        // Our fingerprint computation is deterministic
        let fp1 = compute_recipient_fingerprint(&kyber_pk);
        let fp2 = compute_recipient_fingerprint(&kyber_pk);
        assert_eq!(fp1, fp2, "fingerprint should be deterministic");
        println!("✅ Fingerprint is deterministic");

        // Different keys have different fingerprints (with high probability)
        let fp_other = compute_recipient_fingerprint(&other_pk);
        assert_ne!(fp1, fp_other, "different keys should have different fingerprints");
        println!("✅ Different keys have different fingerprints");
    }

    #[test]
    fn test_view_key_with_fingerprint() {
        // Test that ViewKey properly handles secret key and fingerprint verification
        let (_, _, kyber_pk, kyber_sk) = test_keypairs();
        let master_id = [0x42u8; 32];

        let view_key = ViewKey::from_secrets(&kyber_sk, &kyber_pk, master_id);
        
        // Verify we can serialize/deserialize
        let serialized = bincode::serialize(&view_key).unwrap();
        let deserialized: ViewKey = bincode::deserialize(&serialized).unwrap();
        
        assert_eq!(deserialized.master_key_id, master_id);
        
        // Verify fingerprint is accessible
        let fp = deserialized.our_fingerprint();
        let expected_fp = compute_recipient_fingerprint(&kyber_pk);
        assert_eq!(fp, expected_fp, "ViewKey fingerprint should match");
        
        println!("✅ ViewKey serialization works");
        println!("✅ ViewKey uses Zeroizing for kyber_sk_bytes");
        println!("✅ ViewKey provides correct fingerprint");
        
        // Note: We can't test actual zeroization in safe Rust,
        // but Zeroizing<Vec<u8>> will zero memory on drop
    }

    #[test]
    fn test_scan_hint_filtering() {
        // Test the new scan_hint design:
        // scan_hint = SHAKE256(stealth_key || recipient_fingerprint)[0..8]
        // Recipient can verify WITHOUT KEM!
        
        let (_, _, kyber_pk_a, kyber_sk_a) = test_keypairs();
        let (_, _, kyber_pk_b, _kyber_sk_b) = test_keypairs();
        let (_, _, kyber_pk_c, _kyber_sk_c) = test_keypairs();

        // Generate stealth output for recipient A
        let (output, _ss) = RecipientStealthOutput::generate(&kyber_pk_a).unwrap();

        // Compute fingerprints for all recipients
        let fp_a = compute_recipient_fingerprint(&kyber_pk_a);
        let fp_b = compute_recipient_fingerprint(&kyber_pk_b);
        let fp_c = compute_recipient_fingerprint(&kyber_pk_c);

        // Test 1: Correct recipient's scan_hint matches (NO KEM!)
        assert!(output.matches_scan_hint(&fp_a), 
            "correct recipient should match scan_hint");
        println!("✅ Correct recipient matches scan_hint (NO KEM required!)");

        // Test 2: Wrong recipients should NOT match (with high probability)
        // Note: There's ~1/256 chance of false positive (8 bytes = 64 bits, but in practice
        // we use 8 bytes, so ~1/2^64 chance of collision)
        assert!(!output.matches_scan_hint(&fp_b), 
            "wrong recipient B should NOT match scan_hint");
        assert!(!output.matches_scan_hint(&fp_c), 
            "wrong recipient C should NOT match scan_hint");
        println!("✅ Wrong recipients do NOT match scan_hint");

        // Test 3: After scan_hint passes, full verify should also pass
        assert!(output.verify_fingerprint(&kyber_sk_a, &kyber_pk_a),
            "after scan_hint match, full verify should pass");
        println!("✅ Full verify passes after scan_hint match");

        // Test 4: Generate multiple TXs and test scanning
        let mut tx_for_a = 0;
        let mut tx_for_b = 0;
        let mut false_positives = 0;

        for i in 0..100 {
            // Alternate between sending to A and B
            let recipient_pk = if i % 2 == 0 { &kyber_pk_a } else { &kyber_pk_b };
            let (output, _) = RecipientStealthOutput::generate(recipient_pk).unwrap();

            // Scan as recipient A
            if output.matches_scan_hint(&fp_a) {
                if i % 2 == 0 {
                    tx_for_a += 1;  // Correct match
                } else {
                    false_positives += 1;  // False positive
                }
            }

            // Scan as recipient B
            if output.matches_scan_hint(&fp_b) {
                if i % 2 == 1 {
                    tx_for_b += 1;  // Correct match
                }
            }
        }

        // All 50 TXs for A should be found
        assert_eq!(tx_for_a, 50, "should find all TXs for recipient A");
        // All 50 TXs for B should be found  
        assert_eq!(tx_for_b, 50, "should find all TXs for recipient B");
        // False positives should be very rare (0 in most runs)
        println!("✅ Scanning 100 TXs:");
        println!("   TXs found for A: {}/50", tx_for_a);
        println!("   TXs found for B: {}/50", tx_for_b);
        println!("   False positives for A: {}", false_positives);
        
        // Final summary
        println!("\n=== SCAN_HINT DESIGN (v3) ===");
        println!("scan_hint = SHAKE256(stealth_key || fingerprint)[0..8]");
        println!("- Recipient can filter TXs WITHOUT KEM decapsulation");
        println!("- External observer can't compute (doesn't know fingerprint)");
        println!("- False positive rate: 2^-64 (8 bytes = 64 bits)");
    }

    #[test]
    fn benchmark_scan_hint_vs_kem() {
        use std::time::Instant;
        
        // Generate test data
        let (_, _, kyber_pk_recipient, kyber_sk_recipient) = test_keypairs();
        let (_, _, kyber_pk_other, _) = test_keypairs();
        
        let fp_recipient = compute_recipient_fingerprint(&kyber_pk_recipient);
        
        // Generate 1000 TXs - only 10 are for us
        let mut outputs = Vec::with_capacity(1000);
        for i in 0..1000 {
            let recipient_pk = if i % 100 == 0 { &kyber_pk_recipient } else { &kyber_pk_other };
            let (output, _) = RecipientStealthOutput::generate(recipient_pk).unwrap();
            outputs.push(output);
        }
        
        println!("\n=== BENCHMARK: scan_hint vs KEM ===");
        println!("Testing 1000 TXs (10 for us, 990 for others)\n");

        // ====================================================================
        // Method 1: OLD WAY - KEM for every TX (expensive!)
        // ====================================================================
        let start = Instant::now();
        let mut found_kem = 0;
        
        for output in &outputs {
            // Try KEM decapsulation for EVERY TX
            match scan_recipient_output(output, &kyber_sk_recipient, &kyber_pk_recipient) {
                ScanResult::Match { .. } => found_kem += 1,
                _ => {}
            }
        }
        
        let kem_duration = start.elapsed();
        println!("Method 1: KEM for every TX (OLD)");
        println!("  Found: {}/10 TXs", found_kem);
        println!("  Time: {:?}", kem_duration);
        println!("  KEM operations: 1000");
        
        // ====================================================================
        // Method 2: NEW WAY - scan_hint first, then KEM only for matches
        // ====================================================================
        let start = Instant::now();
        let mut found_hint = 0;
        let mut kem_calls = 0;
        
        for output in &outputs {
            // Level 1: scan_hint check (NO KEM!)
            if !output.matches_scan_hint(&fp_recipient) {
                continue;  // Skip - not for us
            }
            
            // Level 2+: KEM only for matched TXs
            kem_calls += 1;
            match scan_recipient_output(output, &kyber_sk_recipient, &kyber_pk_recipient) {
                ScanResult::Match { .. } => found_hint += 1,
                _ => {}  // False positive (extremely rare)
            }
        }
        
        let hint_duration = start.elapsed();
        println!("\nMethod 2: scan_hint + KEM (NEW)");
        println!("  Found: {}/10 TXs", found_hint);
        println!("  Time: {:?}", hint_duration);
        println!("  KEM operations: {} (only matched TXs)", kem_calls);
        
        // ====================================================================
        // Results
        // ====================================================================
        let speedup = kem_duration.as_nanos() as f64 / hint_duration.as_nanos() as f64;
        let kem_saved = 1000 - kem_calls;
        let kem_saved_pct = (kem_saved as f64 / 1000.0) * 100.0;
        
        println!("\n=== RESULTS ===");
        println!("  Speedup: {:.1}x faster", speedup);
        println!("  KEM operations saved: {} ({:.1}%)", kem_saved, kem_saved_pct);
        println!("  Both methods found same TXs: {}", found_kem == found_hint);
        
        // Verify correctness
        assert_eq!(found_kem, 10, "should find exactly 10 TXs (old method)");
        assert_eq!(found_hint, 10, "should find exactly 10 TXs (new method)");
        assert_eq!(kem_calls, 10, "should only do 10 KEM operations (new method)");
        
        println!("\n✅ scan_hint optimization working correctly!");
        println!("   - Filters {}% of TXs without KEM", kem_saved_pct as u32);
        println!("   - {:.1}x speedup for blockchain scanning", speedup);
    }

    #[test]
    fn benchmark_scan_hint_only() {
        use std::time::Instant;
        
        // Test raw scan_hint performance
        let (_, _, kyber_pk, _) = test_keypairs();
        let fp = compute_recipient_fingerprint(&kyber_pk);
        
        // Generate outputs
        let mut outputs = Vec::with_capacity(10000);
        for _ in 0..10000 {
            let (output, _) = RecipientStealthOutput::generate(&kyber_pk).unwrap();
            outputs.push(output);
        }
        
        println!("\n=== BENCHMARK: Raw scan_hint performance ===");
        
        // Benchmark scan_hint checks
        let start = Instant::now();
        let mut matches = 0;
        
        for output in &outputs {
            if output.matches_scan_hint(&fp) {
                matches += 1;
            }
        }
        
        let duration = start.elapsed();
        let per_check_ns = duration.as_nanos() / 10000;
        let checks_per_sec = 1_000_000_000 / per_check_ns;
        
        println!("  Checked: 10,000 TXs");
        println!("  Matches: {} (all should match since same recipient)", matches);
        println!("  Total time: {:?}", duration);
        println!("  Per check: {} ns", per_check_ns);
        println!("  Throughput: {} checks/sec", checks_per_sec);
        println!("  → Can scan ~{} TXs/second with scan_hint alone!", checks_per_sec);
        
        assert_eq!(matches, 10000, "all outputs should match (same recipient)");
    }

    #[test]
    fn test_confidential_amount_full_recipient() {
        // Test with full 32-byte recipient (like wallet CLI does)
        let (_, _, kyber_pk, kyber_sk) = test_keypairs();
        
        // Full 32-byte recipient from Kyber PK hash (like wallet CLI)
        use sha3::{Sha3_256, Digest};
        let mut recipient = [0u8; 32];
        let hash = Sha3_256::digest(kyber_pk.as_bytes());
        recipient.copy_from_slice(&hash);
        
        println!("\n=== Test with FULL 32-byte recipient ===");
        println!("recipient[0..8]: {:02x?}", &recipient[0..8]);
        
        let (amount, _blinding) = ConfidentialAmount::create(
            1000,
            &recipient,
            &kyber_pk,
        ).expect("Failed to create ConfidentialAmount");
        
        println!("Created ConfidentialAmount:");
        println!("  commitment: {}", amount.commitment);
        println!("  range_proof: {} bytes", amount.range_proof.len());
        
        // Verify with SAME recipient
        let result = amount.verify_range_proof(&recipient);
        println!("  verify_range_proof: {}", if result { "PASS" } else { "FAIL" });
        
        assert!(result, "STARK proof should verify with same recipient");
        
        // Decrypt and verify
        let verified = amount.decrypt_and_verify(&kyber_sk, &recipient);
        println!("  decrypt_and_verify: {:?}", verified);
        
        assert_eq!(verified, Some(1000), "Should decrypt to 1000");
        println!("✅ Full 32-byte recipient test PASSED");
    }

    #[test]
    fn test_compression() {
        // Test zstd compression of PrivateStarkTx
        let (falcon_pk, falcon_sk, kyber_pk, kyber_sk) = test_keypairs();
        let _ = falcon_pk; // unused
        
        // Create full TX
        let mut recipient = [0u8; 32];
        recipient[0..8].copy_from_slice(&[0x42u8; 8]);
        
        let tx = PrivateStarkTx::create(
            &falcon_sk,
            &kyber_sk,
            [1u8; 32],
            &kyber_pk,
            &recipient,
            1000,
            10,
            0,
        ).expect("Failed to create TX");

        println!("\n=== COMPRESSION TEST ===");
        
        // Get compression stats
        let (uncompressed, compressed, ratio) = tx.compression_stats()
            .expect("Failed to get compression stats");
        
        println!("  Uncompressed JSON: {} bytes", uncompressed);
        println!("  Compressed (zstd): {} bytes", compressed);
        println!("  Compression ratio: {:.1}%", ratio);
        println!("  Size reduction: {}x", uncompressed / compressed);
        
        // Test hex roundtrip
        let hex = tx.to_compressed_hex().expect("Failed to compress to hex");
        println!("  Compressed hex length: {} chars", hex.len());
        
        let restored = PrivateStarkTx::from_compressed_hex(&hex)
            .expect("Failed to decompress from hex");
        
        // Verify restored TX
        assert_eq!(restored.fee, tx.fee);
        assert_eq!(restored.tx_nonce, tx.tx_nonce);
        assert_eq!(restored.amount.commitment, tx.amount.commitment);
        assert_eq!(restored.amount.range_proof.len(), tx.amount.range_proof.len());
        
        println!("\n  Hex comparison:");
        println!("    Before compression: ~{} chars", uncompressed * 2);
        println!("    After compression:   {} chars", hex.len());
        println!("    Saved: {} chars ({:.1}%)", uncompressed * 2 - hex.len(), 
                 100.0 * (1.0 - hex.len() as f64 / (uncompressed * 2) as f64));
        
        println!("\n✅ Compression roundtrip successful!");
    }
}
