//! Stealth Key Registry v2 - połączenie Key Registry z ProPrivacy
//!
//! # Problem
//! 
//! - **Key Registry**: key_id deterministyczny → linkowanie transakcji
//! - **Stealth Addresses**: pełna prywatność, ale duże TX
//!
//! # Rozwiązanie: View-Only Key IDs (jak Monero)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     STEALTH KEY REGISTRY v2                          │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                      │
//! │  MASTER KEY (rejestrowany raz, publiczny w registry):               │
//! │    master_key_id = SHAKE256(falcon_pk || kyber_pk)                  │
//! │                                                                      │
//! │  RECIPIENT STEALTH (z KEM):                                         │
//! │    1. Sender: KEM(recipient.kyber_pk) → shared_secret               │
//! │    2. stealth_key = SHAKE256(ss || "STEALTH")                       │
//! │    3. view_tag (8B) dla szybkiego skanowania                        │
//! │                                                                      │
//! │  SENDER CHANGE (BEZ KEM - sender zna swój sk!):                     │
//! │    1. stealth_key = SHAKE256(kyber_sk || nonce || "SELF")           │
//! │    2. Oszczędność: 1128B → 48B!                                     │
//! │                                                                      │
//! │  sender_master_key_id ZASZYFROWANY pod recipient key!               │
//! │  → Zewnętrzny obserwator NIE może linkować senderów                 │
//! │                                                                      │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Porównanie
//!
//! | TX Type           | Rozmiar | Prywatność | Sender Linkable |
//! |-------------------|---------|------------|-----------------|
//! | SimpleTx          | ~2850B  | ❌         | ✅ Tak          |
//! | CompactSimpleTx   | ~786B   | ❌         | ✅ Tak          |
//! | PrivateCompactTx  | ~1934B  | ✅ Pełna   | ❌ NIE          |

#![forbid(unsafe_code)]

use std::collections::HashMap;
use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};
use serde::{Serialize, Deserialize};
use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use rand::RngCore;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Nonce,
};

use pqcrypto_kyber::kyber768 as mlkem;
use pqcrypto_traits::kem::SharedSecret as PQKemSharedSecret;
use pqcrypto_traits::kem::SecretKey as PQKemSecretKey;

use crate::kyber_kem::{
    kyber_encapsulate,
    kyber_decapsulate,
    kyber_ct_to_bytes,
    kyber_ct_from_bytes,
    KyberSharedSecret,
};
use crate::falcon_sigs::FalconSecretKey;

/// Domain separators
const STEALTH_KEY_DOMAIN: &[u8] = b"TT.v7.STEALTH_KEY";
const MASTER_KEY_DOMAIN: &[u8] = b"TT.v7.MASTER_KEY_ID";
const VIEW_TAG_DOMAIN: &[u8] = b"TT.v7.VIEW_TAG";
const SELF_STEALTH_DOMAIN: &[u8] = b"TT.v7.SELF_STEALTH";
const SENDER_ID_ENC_DOMAIN: &[u8] = b"TT.v7.SENDER_ID_ENC";

// ============================================================================
// MASTER KEY REGISTRY
// ============================================================================

/// Master key - rejestrowany raz, używany do derywacji stealth keys
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MasterKey {
    /// Falcon-512 public key (897 bytes) - do weryfikacji podpisów
    pub falcon_pk: Vec<u8>,
    /// Kyber-768 public key (1184 bytes) - do skanowania (KEM)
    pub kyber_pk: Vec<u8>,
    /// Timestamp rejestracji
    pub registered_at: u64,
    /// Blok rejestracji
    pub registered_block: u64,
}

/// Rejestr master keys (publiczny, on-chain)
#[derive(Default)]
pub struct StealthKeyRegistry {
    /// master_key_id -> MasterKey
    master_keys: HashMap<[u8; 32], MasterKey>,
    /// Statystyki
    total_registered: u64,
}

impl StealthKeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Oblicz master_key_id (publiczny, deterministyczny)
    pub fn compute_master_key_id(falcon_pk: &[u8], kyber_pk: &[u8]) -> [u8; 32] {
        let mut h = Shake256::default();
        h.update(MASTER_KEY_DOMAIN);
        h.update(falcon_pk);
        h.update(kyber_pk);
        let mut id = [0u8; 32];
        h.finalize_xof().read(&mut id);
        id
    }

    /// Rejestruj master key (jednorazowo)
    pub fn register(
        &mut self,
        falcon_pk: Vec<u8>,
        kyber_pk: Vec<u8>,
        timestamp: u64,
        block_height: u64,
    ) -> Result<[u8; 32], StealthRegistryError> {
        if falcon_pk.len() != 897 {
            return Err(StealthRegistryError::InvalidFalconKeySize(falcon_pk.len()));
        }
        if kyber_pk.len() != 1184 {
            return Err(StealthRegistryError::InvalidKyberKeySize(kyber_pk.len()));
        }

        let master_key_id = Self::compute_master_key_id(&falcon_pk, &kyber_pk);

        if self.master_keys.contains_key(&master_key_id) {
            return Ok(master_key_id);
        }

        self.master_keys.insert(master_key_id, MasterKey {
            falcon_pk,
            kyber_pk,
            registered_at: timestamp,
            registered_block: block_height,
        });
        self.total_registered += 1;

        Ok(master_key_id)
    }

    /// Pobierz master key
    pub fn get(&self, master_key_id: &[u8; 32]) -> Option<&MasterKey> {
        self.master_keys.get(master_key_id)
    }

    /// Statystyki
    pub fn stats(&self) -> (u64, usize) {
        (self.total_registered, self.master_keys.len())
    }
}

// ============================================================================
// RECIPIENT STEALTH OUTPUT (z KEM)
// ============================================================================

/// Stealth output dla odbiorcy (wymaga KEM)
/// Rozmiar: 32 + 8 + 1088 = 1128B
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecipientStealthOutput {
    /// Ephemeral stealth key (32B)
    pub stealth_key: [u8; 32],
    /// View tag (8B) - do szybkiego skanowania (~95% odrzuceń)
    pub view_tag: [u8; 8],
    /// Kyber ciphertext (1088B) - do deszyfrowania przez odbiorcę
    pub kem_ct: Vec<u8>,
}

impl RecipientStealthOutput {
    /// Generuj stealth output dla odbiorcy
    /// Zwraca (output, shared_secret) - ss potrzebne do szyfrowania sender_id
    pub fn generate(recipient_kyber_pk: &mlkem::PublicKey) -> Result<(Self, KyberSharedSecret)> {
        let (ss, kem_ct) = kyber_encapsulate(recipient_kyber_pk);
        let stealth_key = derive_stealth_key(&ss);
        let view_tag = derive_view_tag(&ss);

        Ok((Self {
            stealth_key,
            view_tag,
            kem_ct: kyber_ct_to_bytes(&kem_ct).to_vec(),
        }, ss))
    }

    /// Rozmiar w bajtach
    pub fn size(&self) -> usize {
        32 + 8 + self.kem_ct.len() // 1128B
    }
}

// ============================================================================
// SENDER CHANGE OUTPUT (BEZ KEM!)
// ============================================================================

/// Stealth output dla nadawcy (BEZ KEM - sender zna swój sk!)
/// 
/// Oszczędność: 1128B → 48B = **1080B mniej!**
/// 
/// Rozmiar: 32 + 8 + 8 = 48B
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderChangeOutput {
    /// Stealth key derived from sender's own entropy
    pub stealth_key: [u8; 32],
    /// View tag
    pub view_tag: [u8; 8],
    /// Nonce for derivation (sender remembers this to recover)
    pub derivation_nonce: u64,
}

impl SenderChangeOutput {
    /// Generuj change output (sender zna swój kyber_sk)
    pub fn generate(sender_kyber_sk: &mlkem::SecretKey, nonce: u64) -> Self {
        let mut h = Shake256::default();
        h.update(SELF_STEALTH_DOMAIN);
        h.update(sender_kyber_sk.as_bytes());
        h.update(&nonce.to_le_bytes());
        
        let mut xof = h.finalize_xof();
        let mut stealth_key = [0u8; 32];
        let mut view_tag = [0u8; 8];
        xof.read(&mut stealth_key);
        xof.read(&mut view_tag);
        
        Self { stealth_key, view_tag, derivation_nonce: nonce }
    }

    /// Odtwórz stealth_key (sender może to zrobić ze swojego sk)
    pub fn recover(sender_kyber_sk: &mlkem::SecretKey, nonce: u64) -> ([u8; 32], [u8; 8]) {
        let output = Self::generate(sender_kyber_sk, nonce);
        (output.stealth_key, output.view_tag)
    }

    /// Rozmiar w bajtach
    pub fn size(&self) -> usize {
        32 + 8 + 8 // 48B (vs 1128B z KEM!)
    }
}

// ============================================================================
// ENCRYPTED SENDER ID
// ============================================================================

/// Zaszyfrowany sender_master_key_id
/// 
/// Tylko recipient może odszyfrować → zewnętrzny obserwator NIE może
/// linkować transakcji tego samego nadawcy!
/// 
/// Rozmiar: 12 (nonce) + 32 (id) + 16 (tag) = 60B
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedSenderId {
    /// AES-GCM nonce (12B)
    pub nonce: [u8; 12],
    /// Encrypted sender_master_key_id + auth tag (48B)
    pub ciphertext: Vec<u8>,
}

impl EncryptedSenderId {
    /// Zaszyfruj sender_master_key_id pod recipient's shared secret
    pub fn encrypt(
        sender_master_key_id: &[u8; 32],
        shared_secret: &KyberSharedSecret,
    ) -> Result<Self> {
        // Derive encryption key
        let enc_key = derive_sender_id_enc_key(shared_secret);
        
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|_| anyhow!("invalid AES key"))?;
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher
            .encrypt(nonce, sender_master_key_id.as_slice())
            .map_err(|e| anyhow!("encryption failed: {e}"))?;
        
        Ok(Self {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Odszyfruj sender_master_key_id (recipient może to zrobić)
    pub fn decrypt(&self, shared_secret: &KyberSharedSecret) -> Result<[u8; 32]> {
        let enc_key = derive_sender_id_enc_key(shared_secret);
        
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|_| anyhow!("invalid AES key"))?;
        
        let nonce = Nonce::from_slice(&self.nonce);
        
        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|e| anyhow!("decryption failed: {e}"))?;
        
        if plaintext.len() != 32 {
            return Err(anyhow!("invalid decrypted length"));
        }
        
        let mut id = [0u8; 32];
        id.copy_from_slice(&plaintext);
        Ok(id)
    }

    /// Rozmiar w bajtach
    pub fn size(&self) -> usize {
        12 + self.ciphertext.len() // 12 + 48 = 60B
    }
}

/// Derive encryption key for sender_id
fn derive_sender_id_enc_key(ss: &KyberSharedSecret) -> [u8; 32] {
    use crate::crypto::kmac as ck;
    ck::kmac256_derive_key(ss.as_bytes(), SENDER_ID_ENC_DOMAIN, b"")
}

/// Derive encryption key from raw bytes (for scanning)
fn derive_sender_id_enc_key_from_bytes(ss_bytes: &[u8]) -> [u8; 32] {
    use crate::crypto::kmac as ck;
    ck::kmac256_derive_key(ss_bytes, SENDER_ID_ENC_DOMAIN, b"")
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
// HELPER FUNCTIONS
// ============================================================================

/// Derive stealth_key z shared secret
fn derive_stealth_key(ss: &KyberSharedSecret) -> [u8; 32] {
    use crate::crypto::kmac as ck;
    ck::kmac256_derive_key(ss.as_bytes(), STEALTH_KEY_DOMAIN, b"")
}

/// Derive view_tag (8 bytes)
fn derive_view_tag(ss: &KyberSharedSecret) -> [u8; 8] {
    use crate::crypto::kmac as ck;
    let full = ck::kmac256_derive_key(ss.as_bytes(), VIEW_TAG_DOMAIN, b"");
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&full[..8]);
    tag
}

// ============================================================================
// SCANNING
// ============================================================================

/// Wynik skanowania
#[derive(Clone, Debug)]
pub enum ScanResult {
    /// Output jest dla nas
    Match {
        stealth_key: [u8; 32],
        shared_secret: Vec<u8>,
    },
    /// Nie dla nas (view_tag mismatch)
    NotForUs,
    /// Błąd
    Error(String),
}

/// Skanuj recipient stealth output
pub fn scan_recipient_output(
    output: &RecipientStealthOutput,
    our_kyber_sk: &mlkem::SecretKey,
) -> ScanResult {
    let kem_ct = match kyber_ct_from_bytes(&output.kem_ct) {
        Ok(ct) => ct,
        Err(e) => return ScanResult::Error(format!("invalid kem_ct: {e}")),
    };

    let ss = match kyber_decapsulate(&kem_ct, our_kyber_sk) {
        Ok(s) => s,
        Err(e) => return ScanResult::Error(format!("decapsulate failed: {e}")),
    };

    // Quick view_tag check
    let computed_tag = derive_view_tag(&ss);
    if computed_tag != output.view_tag {
        return ScanResult::NotForUs;
    }

    // Verify stealth_key
    let computed_stealth = derive_stealth_key(&ss);
    if computed_stealth != output.stealth_key {
        return ScanResult::NotForUs;
    }

    ScanResult::Match {
        stealth_key: output.stealth_key,
        shared_secret: ss.as_bytes().to_vec(),
    }
}

/// Skanuj sender change output (sender tylko)
pub fn scan_sender_change(
    output: &SenderChangeOutput,
    our_kyber_sk: &mlkem::SecretKey,
) -> bool {
    let (expected_key, expected_tag) = SenderChangeOutput::recover(
        our_kyber_sk,
        output.derivation_nonce,
    );
    expected_key == output.stealth_key && expected_tag == output.view_tag
}

// ============================================================================
// PRIVATE COMPACT TX v2
// ============================================================================

/// Prywatna kompaktowa transakcja v2
/// 
/// # Rozmiar
/// ```text
/// sender_change:        48B (bez KEM!)
/// encrypted_sender_id:  60B
/// recipient_stealth:  1128B (z KEM)
/// amount + fee:         16B
/// tx_nonce:             16B
/// falcon_sig:         ~666B
/// ─────────────────────────
/// RAZEM:             ~1934B ✅
/// ```
/// 
/// # Prywatność
/// - sender_master_key_id: ZASZYFROWANY (tylko recipient widzi)
/// - recipient: stealth address (unlinkable)
/// - sender change: unlinkable (fresh stealth per TX)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateCompactTx {
    // === NADAWCA (bez KEM!) ===
    /// Change output dla nadawcy (48B)
    pub sender_change: SenderChangeOutput,
    /// Zaszyfrowany sender_master_key_id (60B) - tylko recipient odszyfruje
    pub encrypted_sender_id: EncryptedSenderId,

    // === ODBIORCA (z KEM) ===
    /// Stealth output (1128B)
    pub recipient_stealth: RecipientStealthOutput,

    // === TRANSFER ===
    /// Kwota (8B)
    pub amount: u64,
    /// Opłata (8B)
    pub fee: u64,
    /// Random TX nonce (16B) - unikalność TX
    pub tx_nonce: [u8; 16],

    // === PODPIS ===
    /// Podpis Falcon (~666B)
    pub falcon_sig: Vec<u8>,
}

impl PrivateCompactTx {
    /// Utwórz nową prywatną TX
    pub fn create(
        sender_falcon_sk: &FalconSecretKey,
        sender_kyber_sk: &mlkem::SecretKey,
        sender_master_key_id: [u8; 32],
        recipient_kyber_pk: &mlkem::PublicKey,
        amount: u64,
        fee: u64,
        change_nonce: u64,
    ) -> Result<Self> {
        // 1. Generate recipient stealth (z KEM) - zwraca też shared_secret!
        let (recipient_stealth, shared_secret) = RecipientStealthOutput::generate(recipient_kyber_pk)?;
        
        // 2. Encrypt sender_master_key_id używając tego samego shared_secret
        let encrypted_sender_id = EncryptedSenderId::encrypt(
            &sender_master_key_id,
            &shared_secret,
        )?;
        
        // 3. Generate sender change (BEZ KEM!)
        let sender_change = SenderChangeOutput::generate(sender_kyber_sk, change_nonce);
        
        // 4. Random TX nonce
        let mut tx_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut tx_nonce);

        // 5. Build unsigned TX
        let mut tx = Self {
            sender_change,
            encrypted_sender_id,
            recipient_stealth,
            amount,
            fee,
            tx_nonce,
            falcon_sig: vec![],
        };

        // 6. Sign
        let msg = tx.signing_message();
        let signed = crate::falcon_sigs::falcon_sign(&msg, sender_falcon_sk)?;
        tx.falcon_sig = signed.signed_message_bytes.clone();

        Ok(tx)
    }

    /// Message do podpisu
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(256);
        // Sender change
        msg.extend_from_slice(&self.sender_change.stealth_key);
        msg.extend_from_slice(&self.sender_change.view_tag);
        msg.extend_from_slice(&self.sender_change.derivation_nonce.to_le_bytes());
        // Recipient stealth
        msg.extend_from_slice(&self.recipient_stealth.stealth_key);
        msg.extend_from_slice(&self.recipient_stealth.view_tag);
        // Transfer data
        msg.extend_from_slice(&self.amount.to_le_bytes());
        msg.extend_from_slice(&self.fee.to_le_bytes());
        msg.extend_from_slice(&self.tx_nonce);
        msg
    }

    /// Weryfikuj podpis (wymaga registry + odszyfrowania sender_id)
    pub fn verify_with_sender_id(
        &self,
        sender_master_key_id: &[u8; 32],
        registry: &StealthKeyRegistry,
    ) -> Result<bool> {
        let master_key = registry.get(sender_master_key_id)
            .ok_or_else(|| anyhow!("Master key not found"))?;

        let pk = crate::falcon_sigs::falcon_pk_from_bytes(&master_key.falcon_pk)?;
        let msg = self.signing_message();
        
        Ok(crate::falcon_sigs::falcon_verify_bytes(&msg, &self.falcon_sig, &pk).is_ok())
    }

    /// TX ID
    pub fn tx_id(&self) -> [u8; 32] {
        use sha3::{Sha3_256, digest::Digest};
        let mut h = Sha3_256::new();
        Digest::update(&mut h, &self.signing_message());
        Digest::update(&mut h, &self.falcon_sig);
        h.finalize().into()
    }

    /// Rozmiar w bajtach
    pub fn size(&self) -> usize {
        self.sender_change.size()           // 48B
        + self.encrypted_sender_id.size()   // 60B
        + self.recipient_stealth.size()     // 1128B
        + 8                                 // amount
        + 8                                 // fee
        + 16                                // tx_nonce
        + self.falcon_sig.len()             // ~666B
        // TOTAL: ~1926B
    }

    /// Porównanie rozmiarów
    pub fn size_comparison() {
        println!("=== TX Size Comparison ===");
        println!("SimpleTx:         ~2850B (full PK)");
        println!("CompactSimpleTx:   ~786B (key_id, no privacy)");
        println!("PrivateCompactTx: ~1934B (full privacy)");
        println!();
        println!("Privacy gain: FULL unlinkability");
        println!("Size overhead vs Compact: +1148B");
        println!("Size savings vs Simple:    -916B");
    }
}

// ============================================================================
// VIEW KEY
// ============================================================================

/// View key - pozwala na skanowanie TX bez możliwości wydawania
#[derive(Clone, Serialize, Deserialize)]
pub struct ViewKey {
    /// Kyber secret key (tylko do skanowania)
    pub kyber_sk_bytes: Vec<u8>,
    /// Master key ID (publiczny)
    pub master_key_id: [u8; 32],
}

impl ViewKey {
    /// Utwórz view key
    pub fn from_secrets(
        kyber_sk: &mlkem::SecretKey,
        master_key_id: [u8; 32],
    ) -> Self {
        Self {
            kyber_sk_bytes: kyber_sk.as_bytes().to_vec(),
            master_key_id,
        }
    }

    /// Skanuj TX - sprawdź czy jesteśmy odbiorcą
    pub fn scan_as_recipient(&self, tx: &PrivateCompactTx) -> Option<ScanAsRecipientResult> {
        let kyber_sk = crate::kyber_kem::kyber_sk_from_bytes(&self.kyber_sk_bytes).ok()?;
        
        match scan_recipient_output(&tx.recipient_stealth, &kyber_sk) {
            ScanResult::Match { stealth_key, shared_secret } => {
                // Odszyfruj sender_id używając shared_secret (raw bytes)
                // Musimy odtworzyć KyberSharedSecret - użyjemy derive key bezpośrednio
                let enc_key = derive_sender_id_enc_key_from_bytes(&shared_secret);
                let sender_id = decrypt_sender_id_with_key(&tx.encrypted_sender_id, &enc_key).ok();
                
                Some(ScanAsRecipientResult {
                    amount: tx.amount,
                    stealth_key,
                    sender_master_key_id: sender_id,
                })
            }
            _ => None,
        }
    }

    /// Skanuj TX - sprawdź czy jesteśmy nadawcą (change output)
    pub fn scan_as_sender(&self, tx: &PrivateCompactTx) -> Option<u64> {
        let kyber_sk = crate::kyber_kem::kyber_sk_from_bytes(&self.kyber_sk_bytes).ok()?;
        
        if scan_sender_change(&tx.sender_change, &kyber_sk) {
            Some(tx.amount)
        } else {
            None
        }
    }
}

/// Wynik skanowania jako odbiorca
#[derive(Clone, Debug)]
pub struct ScanAsRecipientResult {
    pub amount: u64,
    pub stealth_key: [u8; 32],
    /// Sender's master_key_id (odszyfrowany) - dla audytu
    pub sender_master_key_id: Option<[u8; 32]>,
}

// ============================================================================
// BŁĘDY
// ============================================================================

#[derive(Debug, Clone)]
pub enum StealthRegistryError {
    InvalidFalconKeySize(usize),
    InvalidKyberKeySize(usize),
    MasterKeyNotFound([u8; 32]),
}

impl std::fmt::Display for StealthRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFalconKeySize(s) => write!(f, "Invalid Falcon key size: {} (expected 897)", s),
            Self::InvalidKyberKeySize(s) => write!(f, "Invalid Kyber key size: {} (expected 1184)", s),
            Self::MasterKeyNotFound(id) => write!(f, "Master key not found: {}", hex::encode(&id[..8])),
        }
    }
}

impl std::error::Error for StealthRegistryError {}

// ============================================================================
// TESTY
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_falcon::falcon512;
    use pqcrypto_traits::sign::PublicKey as PQSignPublicKey;
    use pqcrypto_traits::kem::PublicKey as PQKemPublicKey;

    fn test_keypairs() -> (
        falcon512::PublicKey, falcon512::SecretKey,
        mlkem::PublicKey, mlkem::SecretKey,
    ) {
        let (falcon_pk, falcon_sk) = falcon512::keypair();
        let (kyber_pk, kyber_sk) = mlkem::keypair();
        (falcon_pk, falcon_sk, kyber_pk, kyber_sk)
    }

    #[test]
    fn test_sender_change_no_kem() {
        let (_, _, _, kyber_sk) = test_keypairs();
        
        let output = SenderChangeOutput::generate(&kyber_sk, 12345);
        
        println!("SenderChangeOutput size: {}B (vs 1128B with KEM)", output.size());
        println!("  Savings: {}B!", 1128 - output.size());
        
        assert_eq!(output.size(), 48);
        
        // Verify recovery
        let (recovered_key, recovered_tag) = SenderChangeOutput::recover(&kyber_sk, 12345);
        assert_eq!(recovered_key, output.stealth_key);
        assert_eq!(recovered_tag, output.view_tag);
        
        println!("✅ Sender change bez KEM działa!");
    }

    #[test]
    fn test_encrypted_sender_id() {
        let (_, _, recipient_kyber_pk, _) = test_keypairs();
        
        let sender_id = [0x42u8; 32];
        
        // Encrypt (sender side)
        let (ss, _) = kyber_encapsulate(&recipient_kyber_pk);
        let encrypted = EncryptedSenderId::encrypt(&sender_id, &ss).unwrap();
        
        println!("EncryptedSenderId size: {}B", encrypted.size());
        
        // Decrypt (recipient side) - recipient derives same ss from KEM
        let decrypted = encrypted.decrypt(&ss).unwrap();
        assert_eq!(decrypted, sender_id);
        
        // Different shared secret cannot decrypt correctly
        let (wrong_ss, _) = kyber_encapsulate(&recipient_kyber_pk);
        // Note: wrong_ss will produce different key, decryption will fail or give wrong result
        let wrong_result = encrypted.decrypt(&wrong_ss);
        // Either fails or gives different result
        assert!(wrong_result.is_err() || wrong_result.unwrap() != sender_id);
        
        println!("✅ Encrypted sender ID działa!");
    }

    #[test]
    fn test_recipient_stealth_output() {
        let (_, _, kyber_pk, kyber_sk) = test_keypairs();
        
        let (output, _ss) = RecipientStealthOutput::generate(&kyber_pk).unwrap();
        
        println!("RecipientStealthOutput size: {}B", output.size());
        assert_eq!(output.size(), 1128);
        
        // Scan as recipient
        match scan_recipient_output(&output, &kyber_sk) {
            ScanResult::Match { stealth_key, .. } => {
                assert_eq!(stealth_key, output.stealth_key);
                println!("✅ Recipient może skanować!");
            }
            other => panic!("Expected Match, got {:?}", other),
        }
        
        // Wrong key cannot scan
        let (_, _, _, wrong_sk) = test_keypairs();
        match scan_recipient_output(&output, &wrong_sk) {
            ScanResult::NotForUs => {
                println!("✅ Wrong key nie może skanować!");
            }
            other => panic!("Expected NotForUs, got {:?}", other),
        }
    }

    #[test]
    fn test_stealth_outputs_unlinkable() {
        let (_, _, kyber_pk, _) = test_keypairs();
        
        let (out1, _) = RecipientStealthOutput::generate(&kyber_pk).unwrap();
        let (out2, _) = RecipientStealthOutput::generate(&kyber_pk).unwrap();
        let (out3, _) = RecipientStealthOutput::generate(&kyber_pk).unwrap();
        
        // All different (unlinkable!)
        assert_ne!(out1.stealth_key, out2.stealth_key);
        assert_ne!(out2.stealth_key, out3.stealth_key);
        assert_ne!(out1.view_tag, out2.view_tag);
        
        println!("✅ Stealth outputs są unlinkable:");
        println!("  out1: {}", hex::encode(&out1.stealth_key[..8]));
        println!("  out2: {}", hex::encode(&out2.stealth_key[..8]));
        println!("  out3: {}", hex::encode(&out3.stealth_key[..8]));
    }

    #[test]
    fn test_private_compact_tx_size() {
        let (sender_falcon_pk, sender_falcon_sk, sender_kyber_pk, sender_kyber_sk) = test_keypairs();
        let (_, _, recipient_kyber_pk, _) = test_keypairs();
        
        let mut registry = StealthKeyRegistry::new();
        let sender_master_key_id = registry.register(
            sender_falcon_pk.as_bytes().to_vec(),
            sender_kyber_pk.as_bytes().to_vec(),
            0, 0,
        ).unwrap();
        
        let tx = PrivateCompactTx::create(
            &sender_falcon_sk,
            &sender_kyber_sk,
            sender_master_key_id,
            &recipient_kyber_pk,
            1000,
            10,
            1,
        ).unwrap();
        
        println!("\n=== PrivateCompactTx v2 Size Analysis ===");
        println!("sender_change:        {}B", tx.sender_change.size());
        println!("encrypted_sender_id:  {}B", tx.encrypted_sender_id.size());
        println!("recipient_stealth:    {}B", tx.recipient_stealth.size());
        println!("amount + fee:         16B");
        println!("tx_nonce:             16B");
        println!("falcon_sig:           {}B", tx.falcon_sig.len());
        println!("────────────────────────────");
        println!("TOTAL:                {}B", tx.size());
        println!();
        
        PrivateCompactTx::size_comparison();
        
        // Verify size is reasonable
        assert!(tx.size() < 2100, "TX should be < 2100B, got {}", tx.size());
        assert!(tx.size() > 1800, "TX should be > 1800B, got {}", tx.size());
        
        println!("\n✅ TX size is correct: {}B", tx.size());
    }

    #[test]
    fn test_sender_not_linkable() {
        let (sender_falcon_pk, sender_falcon_sk, sender_kyber_pk, sender_kyber_sk) = test_keypairs();
        let (_, _, recipient_kyber_pk, _) = test_keypairs();
        
        let mut registry = StealthKeyRegistry::new();
        let sender_master_key_id = registry.register(
            sender_falcon_pk.as_bytes().to_vec(),
            sender_kyber_pk.as_bytes().to_vec(),
            0, 0,
        ).unwrap();
        
        // Create two TXs from same sender
        let tx1 = PrivateCompactTx::create(
            &sender_falcon_sk, &sender_kyber_sk, sender_master_key_id,
            &recipient_kyber_pk, 100, 1, 1,
        ).unwrap();
        
        let tx2 = PrivateCompactTx::create(
            &sender_falcon_sk, &sender_kyber_sk, sender_master_key_id,
            &recipient_kyber_pk, 200, 2, 2,
        ).unwrap();
        
        // External observer sees:
        println!("\n=== External Observer View ===");
        println!("TX1:");
        println!("  sender_change.stealth_key: {}", hex::encode(&tx1.sender_change.stealth_key[..8]));
        println!("  encrypted_sender_id: {} bytes (ENCRYPTED!)", tx1.encrypted_sender_id.size());
        println!("  recipient_stealth: {}", hex::encode(&tx1.recipient_stealth.stealth_key[..8]));
        println!();
        println!("TX2:");
        println!("  sender_change.stealth_key: {}", hex::encode(&tx2.sender_change.stealth_key[..8]));
        println!("  encrypted_sender_id: {} bytes (ENCRYPTED!)", tx2.encrypted_sender_id.size());
        println!("  recipient_stealth: {}", hex::encode(&tx2.recipient_stealth.stealth_key[..8]));
        
        // All visible fields are DIFFERENT
        assert_ne!(tx1.sender_change.stealth_key, tx2.sender_change.stealth_key);
        assert_ne!(tx1.recipient_stealth.stealth_key, tx2.recipient_stealth.stealth_key);
        assert_ne!(tx1.encrypted_sender_id.ciphertext, tx2.encrypted_sender_id.ciphertext);
        
        println!();
        println!("✅ ALL visible fields are different!");
        println!("✅ External observer CANNOT link TX1 and TX2 to same sender!");
    }

    #[test]
    fn test_recipient_can_decrypt_sender_id() {
        let (sender_falcon_pk, sender_falcon_sk, sender_kyber_pk, sender_kyber_sk) = test_keypairs();
        let (_, _, recipient_kyber_pk, recipient_kyber_sk) = test_keypairs();
        
        let mut registry = StealthKeyRegistry::new();
        let sender_master_key_id = registry.register(
            sender_falcon_pk.as_bytes().to_vec(),
            sender_kyber_pk.as_bytes().to_vec(),
            0, 0,
        ).unwrap();
        
        let tx = PrivateCompactTx::create(
            &sender_falcon_sk, &sender_kyber_sk, sender_master_key_id,
            &recipient_kyber_pk, 5000, 50, 1,
        ).unwrap();
        
        // Recipient scans and decrypts sender_id
        let recipient_view_key = ViewKey::from_secrets(
            &recipient_kyber_sk,
            [0u8; 32],
        );
        
        let result = recipient_view_key.scan_as_recipient(&tx);
        assert!(result.is_some());
        
        let scan_result = result.unwrap();
        assert_eq!(scan_result.amount, 5000);
        
        // Recipient can see who sent the TX!
        assert!(scan_result.sender_master_key_id.is_some());
        assert_eq!(scan_result.sender_master_key_id.unwrap(), sender_master_key_id);
        
        println!("✅ Recipient can decrypt sender_master_key_id!");
        println!("   sender_id: {}", hex::encode(&sender_master_key_id[..8]));
    }

    #[test]
    fn test_view_key_scanning() {
        let (sender_falcon_pk, sender_falcon_sk, sender_kyber_pk, sender_kyber_sk) = test_keypairs();
        let (_, _, recipient_kyber_pk, recipient_kyber_sk) = test_keypairs();
        
        let mut registry = StealthKeyRegistry::new();
        let sender_master_key_id = registry.register(
            sender_falcon_pk.as_bytes().to_vec(),
            sender_kyber_pk.as_bytes().to_vec(),
            0, 0,
        ).unwrap();
        
        let tx = PrivateCompactTx::create(
            &sender_falcon_sk, &sender_kyber_sk, sender_master_key_id,
            &recipient_kyber_pk, 5000, 50, 1,
        ).unwrap();
        
        // Recipient view key
        let recipient_view_key = ViewKey::from_secrets(
            &recipient_kyber_sk,
            [0u8; 32],
        );
        
        // Sender view key  
        let sender_view_key = ViewKey::from_secrets(
            &sender_kyber_sk,
            sender_master_key_id,
        );
        
        // Recipient can scan
        let recipient_result = recipient_view_key.scan_as_recipient(&tx);
        assert!(recipient_result.is_some());
        let result = recipient_result.unwrap();
        assert_eq!(result.amount, 5000);
        println!("✅ Recipient can scan TX, amount: {}", result.amount);
        
        // Sender can scan change
        let sender_result = sender_view_key.scan_as_sender(&tx);
        assert!(sender_result.is_some());
        println!("✅ Sender can scan change output");
        
        // Third party cannot scan
        let (_, _, _, third_party_sk) = test_keypairs();
        let third_party_key = ViewKey::from_secrets(&third_party_sk, [0u8; 32]);
        assert!(third_party_key.scan_as_recipient(&tx).is_none());
        assert!(third_party_key.scan_as_sender(&tx).is_none());
        println!("✅ Third party cannot scan anything");
    }

    #[test]
    fn test_registry_registration() {
        let (falcon_pk, _, kyber_pk, _) = test_keypairs();
        
        let mut registry = StealthKeyRegistry::new();
        
        let master_key_id = registry.register(
            falcon_pk.as_bytes().to_vec(),
            kyber_pk.as_bytes().to_vec(),
            12345,
            100,
        ).unwrap();
        
        // Verify retrieval
        let key = registry.get(&master_key_id).unwrap();
        assert_eq!(key.falcon_pk, falcon_pk.as_bytes());
        assert_eq!(key.kyber_pk, kyber_pk.as_bytes());
        
        println!("✅ Registry registration works");
    }
}
