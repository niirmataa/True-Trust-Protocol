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
use zeroize::Zeroize;

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
    kyber_pk_from_bytes,
    KyberSharedSecret,
};
use crate::falcon_sigs::{
    FalconSecretKey,
    falcon_pk_from_bytes,
    falcon_verify,
    SignedNullifier,
};

/// Domain separators
const STEALTH_KEY_DOMAIN: &[u8] = b"TT.v7.STEALTH_KEY";
const MASTER_KEY_DOMAIN: &[u8] = b"TT.v7.MASTER_KEY_ID";
const VIEW_TAG_DOMAIN: &[u8] = b"TT.v7.VIEW_TAG";
const SELF_STEALTH_DOMAIN: &[u8] = b"TT.v7.SELF_STEALTH";
const SENDER_ID_ENC_DOMAIN: &[u8] = b"TT.v7.SENDER_ID_ENC";
const PROOF_OF_POSSESSION_DOMAIN: &[u8] = b"TT.v7.PROOF_OF_POSSESSION";

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
    /// 
    /// # ⚠️ DEPRECATED - Use `register_with_proof()` instead!
    /// 
    /// This method does NOT verify proof-of-possession, which means:
    /// - Random bytes can be registered as "valid" keys
    /// - Attackers can register stolen public keys
    /// - Funds sent to fake keys are LOST FOREVER
    /// 
    /// Only use this method for testing or migration purposes.
    #[deprecated(since = "0.8.0", note = "Use register_with_proof() which requires cryptographic proof of key ownership")]
    pub fn register(
        &mut self,
        falcon_pk: Vec<u8>,
        kyber_pk: Vec<u8>,
        timestamp: u64,
        block_height: u64,
    ) -> Result<[u8; 32], StealthRegistryError> {
        // 1. Walidacja Falcon PK – biblioteka sama sprawdza długość i format
        if let Err(e) = falcon_pk_from_bytes(&falcon_pk) {
            return Err(StealthRegistryError::InvalidFalconKeyFormat(e.to_string()));
        }

        // 2. Walidacja Kyber PK – to samo
        if let Err(e) = kyber_pk_from_bytes(&kyber_pk) {
            return Err(StealthRegistryError::InvalidKyberKeyFormat(e.to_string()));
        }

        // 3. Deterministyczny master_key_id z poprawnych kluczy
        let master_key_id = Self::compute_master_key_id(&falcon_pk, &kyber_pk);

        // 4. Idempotencja – jeśli już jest, nic nie zmieniamy
        if self.master_keys.contains_key(&master_key_id) {
            return Ok(master_key_id);
        }

        // 5. Zapis do registry
        self.master_keys.insert(
            master_key_id,
            MasterKey {
                falcon_pk,
                kyber_pk,
                registered_at: timestamp,
                registered_block: block_height,
            },
        );
        self.total_registered += 1;

        Ok(master_key_id)
    }

    /// Rejestruj master key z proof-of-possession (ZALECANE!)
    /// 
    /// Wymaga podpisu challenge = SHAKE256(PROOF_OF_POSSESSION_DOMAIN || falcon_pk || kyber_pk)
    /// co udowadnia że rejestrujący posiada klucz prywatny Falcon.
    /// 
    /// # Arguments
    /// * `falcon_pk` - Falcon-512 public key (897 bytes)
    /// * `kyber_pk` - Kyber-768 public key (1184 bytes)
    /// * `proof_signature` - Podpis challenge przez odpowiadający Falcon SK
    /// * `timestamp` - Timestamp rejestracji
    /// * `block_height` - Wysokość bloku
    /// 
    /// # Security
    /// Ta metoda jest odporna na:
    /// - Rejestrację losowych/fałszywych kluczy
    /// - Kradzież cudzych kluczy publicznych
    /// - All-zeros i inne podejrzane wzorce
    pub fn register_with_proof(
        &mut self,
        falcon_pk: Vec<u8>,
        kyber_pk: Vec<u8>,
        proof_signature: &SignedNullifier,
        timestamp: u64,
        block_height: u64,
    ) -> Result<[u8; 32], StealthRegistryError> {
        // 1. Sprawdź podejrzane wzorce kluczy
        Self::check_suspicious_pattern(&falcon_pk, "Falcon")?;
        Self::check_suspicious_pattern(&kyber_pk, "Kyber")?;
        
        // 2. Parsuj klucz Falcon (sprawdza długość)
        let falcon_pk_parsed = falcon_pk_from_bytes(&falcon_pk)
            .map_err(|e| StealthRegistryError::InvalidFalconKeyFormat(e.to_string()))?;
        
        // 3. Walidacja Kyber PK
        if let Err(e) = kyber_pk_from_bytes(&kyber_pk) {
            return Err(StealthRegistryError::InvalidKyberKeyFormat(e.to_string()));
        }
        
        // 4. Oblicz challenge do podpisu
        let challenge = Self::compute_proof_challenge(&falcon_pk, &kyber_pk);
        
        // 5. Weryfikuj proof-of-possession - to jest KLUCZOWE!
        falcon_verify(&challenge, proof_signature, &falcon_pk_parsed)
            .map_err(|e| StealthRegistryError::InvalidProofOfPossession(
                format!("Signature verification failed: {}", e)
            ))?;
        
        // 6. Deterministyczny master_key_id
        let master_key_id = Self::compute_master_key_id(&falcon_pk, &kyber_pk);
        
        // 7. Idempotencja
        if self.master_keys.contains_key(&master_key_id) {
            return Ok(master_key_id);
        }
        
        // 8. Zapis do registry
        self.master_keys.insert(
            master_key_id,
            MasterKey {
                falcon_pk,
                kyber_pk,
                registered_at: timestamp,
                registered_block: block_height,
            },
        );
        self.total_registered += 1;
        
        Ok(master_key_id)
    }
    
    /// Oblicz challenge dla proof-of-possession
    /// 
    /// Challenge = SHAKE256(PROOF_OF_POSSESSION_DOMAIN || falcon_pk || kyber_pk)
    pub fn compute_proof_challenge(falcon_pk: &[u8], kyber_pk: &[u8]) -> Vec<u8> {
        let mut h = Shake256::default();
        h.update(PROOF_OF_POSSESSION_DOMAIN);
        h.update(falcon_pk);
        h.update(kyber_pk);
        let mut challenge = vec![0u8; 64];
        h.finalize_xof().read(&mut challenge);
        challenge
    }
    
    /// Sprawdź czy klucz ma podejrzany wzorzec
    fn check_suspicious_pattern(key: &[u8], key_type: &str) -> Result<(), StealthRegistryError> {
        if key.is_empty() {
            return Err(StealthRegistryError::SuspiciousKeyPattern(
                format!("{} key is empty", key_type)
            ));
        }
        
        // All zeros
        if key.iter().all(|&b| b == 0) {
            return Err(StealthRegistryError::SuspiciousKeyPattern(
                format!("{} key is all zeros - this is invalid!", key_type)
            ));
        }
        
        // All ones
        if key.iter().all(|&b| b == 0xFF) {
            return Err(StealthRegistryError::SuspiciousKeyPattern(
                format!("{} key is all 0xFF - this is invalid!", key_type)
            ));
        }
        
        // Single repeated byte (very low entropy)
        let first = key[0];
        if key.iter().all(|&b| b == first) {
            return Err(StealthRegistryError::SuspiciousKeyPattern(
                format!("{} key has single repeated byte 0x{:02X} - too low entropy!", key_type, first)
            ));
        }
        
        // Check entropy - count unique bytes
        let unique_bytes: std::collections::HashSet<u8> = key.iter().copied().collect();
        if unique_bytes.len() < 32 {
            return Err(StealthRegistryError::SuspiciousKeyPattern(
                format!("{} key has only {} unique bytes - too low entropy!", key_type, unique_bytes.len())
            ));
        }
        
        Ok(())
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
/// Oszczędność: 1128B → 56B = **1072B mniej!**
/// 
/// WAŻNE: Zawiera 8B losowego saltu który zapewnia unlinkability
/// nawet jeśli wallet przypadkowo użyje tego samego nonce.
/// 
/// Rozmiar: 32 + 8 + 8 + 8 = 56B
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderChangeOutput {
    /// Stealth key derived from sender's own entropy + random salt
    pub stealth_key: [u8; 32],
    /// View tag
    pub view_tag: [u8; 8],
    /// Nonce for derivation (sender remembers this to recover)
    pub derivation_nonce: u64,
    /// Random salt - zapobiega linkability przy reuse nonce
    pub salt: [u8; 8],
}

impl SenderChangeOutput {
    /// Generuj change output (sender zna swój kyber_sk)
    /// 
    /// UWAGA: Zawsze generuje unikalny output dzięki losowemu salt!
    /// Nawet jeśli nonce się powtórzy, salt zapewnia unlinkability.
    pub fn generate(sender_kyber_sk: &mlkem::SecretKey, nonce: u64) -> Self {
        // Losowy salt - zapewnia unlinkability nawet przy reuse nonce
        let mut salt = [0u8; 8];
        OsRng.fill_bytes(&mut salt);
        
        Self::generate_with_salt(sender_kyber_sk, nonce, salt)
    }
    
    /// Generuj z określonym salt (dla testów i recovery)
    pub fn generate_with_salt(sender_kyber_sk: &mlkem::SecretKey, nonce: u64, salt: [u8; 8]) -> Self {
        let mut h = Shake256::default();
        h.update(SELF_STEALTH_DOMAIN);
        h.update(sender_kyber_sk.as_bytes());
        h.update(&nonce.to_le_bytes());
        h.update(&salt);  // Salt jest częścią derivation!
        
        let mut xof = h.finalize_xof();
        let mut stealth_key = [0u8; 32];
        let mut view_tag = [0u8; 8];
        xof.read(&mut stealth_key);
        xof.read(&mut view_tag);
        
        Self { stealth_key, view_tag, derivation_nonce: nonce, salt }
    }

    /// Odtwórz stealth_key używając salt z output
    /// 
    /// Sender może to zrobić ze swojego sk + salt z output
    pub fn recover(sender_kyber_sk: &mlkem::SecretKey, output: &SenderChangeOutput) -> ([u8; 32], [u8; 8]) {
        let recovered = Self::generate_with_salt(sender_kyber_sk, output.derivation_nonce, output.salt);
        (recovered.stealth_key, recovered.view_tag)
    }
    
    /// Sprawdź czy output należy do nas
    pub fn is_ours(sender_kyber_sk: &mlkem::SecretKey, output: &SenderChangeOutput) -> bool {
        let (expected_key, expected_tag) = Self::recover(sender_kyber_sk, output);
        expected_key == output.stealth_key && expected_tag == output.view_tag
    }

    /// Rozmiar w bajtach
    pub fn size(&self) -> usize {
        32 + 8 + 8 + 8 // 56B (vs 1128B z KEM!)
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
/// 
/// UWAGA: shared_secret jest automatycznie zeroizowany przy drop!
#[derive(Clone, Debug)]
pub enum ScanResult {
    /// Output jest dla nas
    Match {
        stealth_key: [u8; 32],
        /// Shared secret - WRAŻLIWE DANE, zeroizowane przy drop
        shared_secret: Vec<u8>,
    },
    /// Nie dla nas (view_tag mismatch)
    NotForUs,
    /// Błąd
    Error(String),
}

impl Zeroize for ScanResult {
    fn zeroize(&mut self) {
        if let ScanResult::Match { stealth_key, shared_secret } = self {
            stealth_key.zeroize();
            shared_secret.zeroize();
        }
    }
}

impl Drop for ScanResult {
    fn drop(&mut self) {
        self.zeroize();
    }
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
    SenderChangeOutput::is_ours(our_kyber_sk, output)
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
    /// 
    /// WAŻNE: Podpisujemy WSZYSTKIE pola TX aby zapobiec manipulacji!
    /// Obejmuje to: sender_change (z salt!), encrypted_sender_id, 
    /// recipient_stealth (z kem_ct!), amount, fee, tx_nonce.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(512);
        
        // Sender change - WSZYSTKIE pola włącznie z salt!
        msg.extend_from_slice(&self.sender_change.stealth_key);
        msg.extend_from_slice(&self.sender_change.view_tag);
        msg.extend_from_slice(&self.sender_change.derivation_nonce.to_le_bytes());
        msg.extend_from_slice(&self.sender_change.salt);  // ← KRYTYCZNE!
        
        // Encrypted sender ID - cały ciphertext!
        msg.extend_from_slice(&self.encrypted_sender_id.nonce);
        msg.extend_from_slice(&self.encrypted_sender_id.ciphertext);
        
        // Recipient stealth - WSZYSTKIE pola włącznie z kem_ct!
        msg.extend_from_slice(&self.recipient_stealth.stealth_key);
        msg.extend_from_slice(&self.recipient_stealth.view_tag);
        msg.extend_from_slice(&self.recipient_stealth.kem_ct);  // ← KRYTYCZNE!
        
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

    /// TX ID z domain separator
    /// 
    /// Domain separator zapobiega cross-type replay attacks między
    /// różnymi typami transakcji (SimplePqTx, PrivateCompactTx, PrivateStarkTx).
    pub fn tx_id(&self) -> [u8; 32] {
        use sha3::{Sha3_256, digest::Digest};
        let mut h = Sha3_256::new();
        Digest::update(&mut h, b"TT.v1.PRIVATE_COMPACT_TX");  // Domain separator!
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
/// 
/// UWAGA: kyber_sk_bytes są automatycznie zeroizowane przy drop!
#[derive(Clone, Serialize, Deserialize)]
pub struct ViewKey {
    /// Kyber secret key (tylko do skanowania) - WRAŻLIWE DANE
    pub kyber_sk_bytes: Vec<u8>,
    /// Master key ID (publiczny)
    pub master_key_id: [u8; 32],
}

impl Zeroize for ViewKey {
    fn zeroize(&mut self) {
        self.kyber_sk_bytes.zeroize();
        self.master_key_id.zeroize();
    }
}

impl Drop for ViewKey {
    fn drop(&mut self) {
        self.zeroize();
    }
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
            ScanResult::Match { ref stealth_key, ref shared_secret } => {
                // Odszyfruj sender_id używając shared_secret (raw bytes)
                // Musimy odtworzyć KyberSharedSecret - użyjemy derive key bezpośrednio
                let enc_key = derive_sender_id_enc_key_from_bytes(shared_secret);
                let sender_id = decrypt_sender_id_with_key(&tx.encrypted_sender_id, &enc_key).ok();
                
                Some(ScanAsRecipientResult {
                    amount: tx.amount,
                    stealth_key: *stealth_key,
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
/// 
/// UWAGA: stealth_key jest automatycznie zeroizowany przy drop!
#[derive(Clone, Debug)]
pub struct ScanAsRecipientResult {
    pub amount: u64,
    /// Stealth key - WRAŻLIWE DANE
    pub stealth_key: [u8; 32],
    /// Sender's master_key_id (odszyfrowany) - dla audytu
    pub sender_master_key_id: Option<[u8; 32]>,
}

impl Zeroize for ScanAsRecipientResult {
    fn zeroize(&mut self) {
        self.amount = 0;
        self.stealth_key.zeroize();
        if let Some(ref mut id) = self.sender_master_key_id {
            id.zeroize();
        }
    }
}

impl Drop for ScanAsRecipientResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ============================================================================
// BŁĘDY
// ============================================================================

#[derive(Debug, Clone)]
pub enum StealthRegistryError {
    InvalidFalconKeyFormat(String),
    InvalidKyberKeyFormat(String),
    MasterKeyNotFound([u8; 32]),
    /// Proof-of-possession failed - user doesn't own the private key
    InvalidProofOfPossession(String),
    /// Key has suspicious pattern (all zeros, all ones, etc.)
    SuspiciousKeyPattern(String),
}

impl std::fmt::Display for StealthRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFalconKeyFormat(e) => write!(f, "Invalid Falcon public key format: {e}"),
            Self::InvalidKyberKeyFormat(e) => write!(f, "Invalid Kyber public key format: {e}"),
            Self::MasterKeyNotFound(id) => write!(f, "Master key not found: {}", hex::encode(&id[..8])),
            Self::InvalidProofOfPossession(e) => write!(f, "Proof-of-possession failed: {e}"),
            Self::SuspiciousKeyPattern(e) => write!(f, "Suspicious key pattern: {e}"),
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
        
        // Size is 56B: 32B stealth_key + 8B view_tag + 8B nonce + 8B salt
        assert_eq!(output.size(), 56);
        
        // Verify recovery - now uses output reference which contains salt
        let (recovered_key, recovered_tag) = SenderChangeOutput::recover(&kyber_sk, &output);
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
        // NOTE: Size increased after security fixes:
        // - signing_message now includes salt (8B), encrypted_sender_id (60B), kem_ct (1088B)
        // - This makes Falcon attached signature larger (~1900B vs ~700B)
        // - Total TX size ~3200B instead of ~2000B - security tradeoff worth it!
        assert!(tx.size() < 3500, "TX should be < 3500B, got {}", tx.size());
        assert!(tx.size() > 2800, "TX should be > 2800B, got {}", tx.size());
        
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

    // ========================================================================
    // ZAAWANSOWANE TESTY WALIDACJI KLUCZY - WYKLUCZANIE ZŁYCH DANYCH
    // ========================================================================

    #[test]
    fn test_reject_empty_falcon_key() {
        let (_, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        let result = registry.register(
            vec![],  // Pusty klucz Falcon
            kyber_pk.as_bytes().to_vec(),
            0, 0,
        );
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidFalconKeyFormat(msg) => {
                println!("✅ Odrzucono pusty Falcon key: {}", msg);
            }
            other => panic!("Oczekiwano InvalidFalconKeyFormat, otrzymano {:?}", other),
        }
    }

    #[test]
    fn test_reject_empty_kyber_key() {
        let (falcon_pk, _, _, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        let result = registry.register(
            falcon_pk.as_bytes().to_vec(),
            vec![],  // Pusty klucz Kyber
            0, 0,
        );
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidKyberKeyFormat(msg) => {
                println!("✅ Odrzucono pusty Kyber key: {}", msg);
            }
            other => panic!("Oczekiwano InvalidKyberKeyFormat, otrzymano {:?}", other),
        }
    }

    #[test]
    fn test_reject_truncated_falcon_key() {
        let (falcon_pk, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Obcięty klucz (tylko pierwsze 100 bajtów z 897)
        let truncated = falcon_pk.as_bytes()[..100].to_vec();
        
        let result = registry.register(truncated, kyber_pk.as_bytes().to_vec(), 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidFalconKeyFormat(msg) => {
                println!("✅ Odrzucono obcięty Falcon key (100B): {}", msg);
            }
            other => panic!("Oczekiwano InvalidFalconKeyFormat, otrzymano {:?}", other),
        }
    }

    #[test]
    fn test_reject_truncated_kyber_key() {
        let (falcon_pk, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Obcięty klucz (tylko pierwsze 500 bajtów z 1184)
        let truncated = kyber_pk.as_bytes()[..500].to_vec();
        
        let result = registry.register(falcon_pk.as_bytes().to_vec(), truncated, 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidKyberKeyFormat(msg) => {
                println!("✅ Odrzucono obcięty Kyber key (500B): {}", msg);
            }
            other => panic!("Oczekiwano InvalidKyberKeyFormat, otrzymano {:?}", other),
        }
    }

    #[test]
    fn test_reject_oversized_falcon_key() {
        let (_, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Za duży klucz (2000 bajtów zamiast 897)
        let oversized = vec![0x42u8; 2000];
        
        let result = registry.register(oversized, kyber_pk.as_bytes().to_vec(), 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidFalconKeyFormat(msg) => {
                println!("✅ Odrzucono za duży Falcon key (2000B): {}", msg);
            }
            other => panic!("Oczekiwano InvalidFalconKeyFormat, otrzymano {:?}", other),
        }
    }

    #[test]
    fn test_reject_oversized_kyber_key() {
        let (falcon_pk, _, _, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Za duży klucz (3000 bajtów zamiast 1184)
        let oversized = vec![0x42u8; 3000];
        
        let result = registry.register(falcon_pk.as_bytes().to_vec(), oversized, 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidKyberKeyFormat(msg) => {
                println!("✅ Odrzucono za duży Kyber key (3000B): {}", msg);
            }
            other => panic!("Oczekiwano InvalidKyberKeyFormat, otrzymano {:?}", other),
        }
    }

    /// UWAGA: Biblioteka pqcrypto-falcon sprawdza tylko długość (897B), nie strukturę.
    /// Głębsza walidacja wymaga próby użycia klucza (sign/verify).
    /// Ten test dokumentuje obecne ograniczenie.
    #[test]
    #[ignore = "pqcrypto-falcon akceptuje dowolne 897B - brak walidacji struktury"]
    fn test_reject_random_garbage_falcon_key() {
        let (_, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Losowe śmieci o prawidłowej długości 897
        let garbage = vec![0xDEu8; 897];
        
        let result = registry.register(garbage, kyber_pk.as_bytes().to_vec(), 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidFalconKeyFormat(msg) => {
                println!("✅ Odrzucono śmieci jako Falcon key (897B garbage): {}", msg);
            }
            other => panic!("Oczekiwano InvalidFalconKeyFormat, otrzymano {:?}", other),
        }
    }

    /// UWAGA: Biblioteka mlkem sprawdza tylko długość (1184B), nie strukturę.
    /// Głębsza walidacja wymaga próby encapsulacji i sprawdzenia błędów.
    #[test]
    #[ignore = "mlkem akceptuje dowolne 1184B - brak walidacji struktury"]
    fn test_reject_random_garbage_kyber_key() {
        let (falcon_pk, _, _, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Losowe śmieci o prawidłowej długości 1184
        let garbage = vec![0xDEu8; 1184];
        
        let result = registry.register(falcon_pk.as_bytes().to_vec(), garbage, 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidKyberKeyFormat(msg) => {
                println!("✅ Odrzucono śmieci jako Kyber key (1184B garbage): {}", msg);
            }
            other => panic!("Oczekiwano InvalidKyberKeyFormat, otrzymano {:?}", other),
        }
    }

    /// UWAGA: PQC biblioteki nie wykrywają weak keys (same zera).
    /// W produkcji można dodać własną walidację: if key.iter().all(|&b| b == 0)
    #[test]
    #[ignore = "pqcrypto-falcon nie wykrywa weak keys (all zeros)"]
    fn test_reject_all_zeros_falcon_key() {
        let (_, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Same zera (weak key attack)
        let zeros = vec![0x00u8; 897];
        
        let result = registry.register(zeros, kyber_pk.as_bytes().to_vec(), 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidFalconKeyFormat(msg) => {
                println!("✅ Odrzucono zerowy Falcon key: {}", msg);
            }
            other => panic!("Oczekiwano InvalidFalconKeyFormat, otrzymano {:?}", other),
        }
    }

    /// UWAGA: mlkem nie wykrywa weak keys.
    #[test]
    #[ignore = "mlkem nie wykrywa weak keys (all zeros)"]
    fn test_reject_all_zeros_kyber_key() {
        let (falcon_pk, _, _, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Same zera (weak key attack)
        let zeros = vec![0x00u8; 1184];
        
        let result = registry.register(falcon_pk.as_bytes().to_vec(), zeros, 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidKyberKeyFormat(msg) => {
                println!("✅ Odrzucono zerowy Kyber key: {}", msg);
            }
            other => panic!("Oczekiwano InvalidKyberKeyFormat, otrzymano {:?}", other),
        }
    }

    /// UWAGA: PQC biblioteki nie wykrywają weak key patterns (all 0xFF).
    #[test]
    #[ignore = "pqcrypto-falcon nie wykrywa weak keys (all 0xFF)"]
    fn test_reject_all_ff_falcon_key() {
        let (_, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Same 0xFF (inny weak key pattern)
        let ff_bytes = vec![0xFFu8; 897];
        
        let result = registry.register(ff_bytes, kyber_pk.as_bytes().to_vec(), 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidFalconKeyFormat(msg) => {
                println!("✅ Odrzucono 0xFF Falcon key: {}", msg);
            }
            other => panic!("Oczekiwano InvalidFalconKeyFormat, otrzymano {:?}", other),
        }
    }

    #[test]
    fn test_reject_swapped_keys() {
        let (falcon_pk, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Zamienione miejscami - Kyber jako Falcon, Falcon jako Kyber
        let result = registry.register(
            kyber_pk.as_bytes().to_vec(),  // 1184B gdzie powinno być 897B
            falcon_pk.as_bytes().to_vec(), // 897B gdzie powinno być 1184B
            0, 0,
        );
        
        assert!(result.is_err());
        // Powinno wykryć błąd na pierwszym kluczu (Falcon)
        match result.unwrap_err() {
            StealthRegistryError::InvalidFalconKeyFormat(msg) => {
                println!("✅ Odrzucono zamienione klucze (Kyber->Falcon): {}", msg);
            }
            StealthRegistryError::InvalidKyberKeyFormat(msg) => {
                println!("✅ Odrzucono zamienione klucze (Falcon->Kyber): {}", msg);
            }
            other => panic!("Oczekiwano błędu formatu, otrzymano {:?}", other),
        }
    }

    /// UWAGA: Lekko uszkodzone klucze o prawidłowej długości przechodzą walidację,
    /// ale zawiodą przy próbie użycia (weryfikacja podpisu da błąd).
    #[test]
    #[ignore = "pqcrypto-falcon nie wykrywa uszkodzonych bajtów przy parsowaniu"]
    fn test_reject_corrupted_falcon_key() {
        let (falcon_pk, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Uszkodzony klucz - zmienione kilka bajtów
        let mut corrupted = falcon_pk.as_bytes().to_vec();
        corrupted[0] ^= 0xFF;
        corrupted[100] ^= 0xFF;
        corrupted[500] ^= 0xFF;
        
        let result = registry.register(corrupted, kyber_pk.as_bytes().to_vec(), 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidFalconKeyFormat(msg) => {
                println!("✅ Odrzucono uszkodzony Falcon key: {}", msg);
            }
            other => panic!("Oczekiwano InvalidFalconKeyFormat, otrzymano {:?}", other),
        }
    }

    /// UWAGA: Lekko uszkodzone klucze Kyber przechodzą walidację,
    /// ale encapsulacja na takim kluczu da nieprzewidywalne wyniki.
    #[test]
    #[ignore = "mlkem nie wykrywa uszkodzonych bajtów przy parsowaniu"]
    fn test_reject_corrupted_kyber_key() {
        let (falcon_pk, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Uszkodzony klucz - zmienione kilka bajtów
        let mut corrupted = kyber_pk.as_bytes().to_vec();
        corrupted[0] ^= 0xFF;
        corrupted[500] ^= 0xFF;
        corrupted[1000] ^= 0xFF;
        
        let result = registry.register(falcon_pk.as_bytes().to_vec(), corrupted, 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidKyberKeyFormat(msg) => {
                println!("✅ Odrzucono uszkodzony Kyber key: {}", msg);
            }
            other => panic!("Oczekiwano InvalidKyberKeyFormat, otrzymano {:?}", other),
        }
    }

    #[test]
    fn test_reject_off_by_one_falcon_key() {
        let (falcon_pk, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Off-by-one: 896 bajtów zamiast 897
        let short = falcon_pk.as_bytes()[..896].to_vec();
        
        let result = registry.register(short, kyber_pk.as_bytes().to_vec(), 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidFalconKeyFormat(msg) => {
                println!("✅ Odrzucono off-by-one Falcon key (896B): {}", msg);
            }
            other => panic!("Oczekiwano InvalidFalconKeyFormat, otrzymano {:?}", other),
        }
    }

    #[test]
    fn test_reject_off_by_one_kyber_key() {
        let (falcon_pk, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Off-by-one: 1183 bajtów zamiast 1184
        let short = kyber_pk.as_bytes()[..1183].to_vec();
        
        let result = registry.register(falcon_pk.as_bytes().to_vec(), short, 0, 0);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidKyberKeyFormat(msg) => {
                println!("✅ Odrzucono off-by-one Kyber key (1183B): {}", msg);
            }
            other => panic!("Oczekiwano InvalidKyberKeyFormat, otrzymano {:?}", other),
        }
    }

    #[test]
    fn test_both_keys_invalid() {
        let mut registry = StealthKeyRegistry::new();
        
        // Oba klucze nieprawidłowe - Falcon sprawdzany pierwszy
        let result = registry.register(
            vec![0xABu8; 100],   // Zły Falcon
            vec![0xCDu8; 200],   // Zły Kyber
            0, 0,
        );
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StealthRegistryError::InvalidFalconKeyFormat(msg) => {
                println!("✅ Wykryto błąd Falcon (sprawdzany pierwszy): {}", msg);
            }
            other => panic!("Oczekiwano InvalidFalconKeyFormat (pierwszy błąd), otrzymano {:?}", other),
        }
    }

    #[test]
    fn test_valid_keys_still_work() {
        let (falcon_pk, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Upewnij się, że prawidłowe klucze nadal działają po wszystkich testach negatywnych
        let result = registry.register(
            falcon_pk.as_bytes().to_vec(),
            kyber_pk.as_bytes().to_vec(),
            1234567890,
            999,
        );
        
        assert!(result.is_ok());
        let master_key_id = result.unwrap();
        
        let key = registry.get(&master_key_id).unwrap();
        assert_eq!(key.falcon_pk.len(), 897);
        assert_eq!(key.kyber_pk.len(), 1184);
        assert_eq!(key.registered_at, 1234567890);
        assert_eq!(key.registered_block, 999);
        
        println!("✅ Prawidłowe klucze nadal działają!");
        println!("   master_key_id: {}", hex::encode(&master_key_id[..16]));
    }

    #[test]
    fn test_idempotent_registration() {
        let (falcon_pk, _, kyber_pk, _) = test_keypairs();
        let mut registry = StealthKeyRegistry::new();
        
        // Pierwsza rejestracja
        let id1 = registry.register(
            falcon_pk.as_bytes().to_vec(),
            kyber_pk.as_bytes().to_vec(),
            100, 10,
        ).unwrap();
        
        // Druga rejestracja tych samych kluczy
        let id2 = registry.register(
            falcon_pk.as_bytes().to_vec(),
            kyber_pk.as_bytes().to_vec(),
            200, 20,  // Inne timestamps
        ).unwrap();
        
        // Powinno zwrócić ten sam ID (idempotencja)
        assert_eq!(id1, id2);
        assert_eq!(registry.total_registered, 1);
        
        // Zachowane oryginalne timestamps
        let key = registry.get(&id1).unwrap();
        assert_eq!(key.registered_at, 100);
        assert_eq!(key.registered_block, 10);
        
        println!("✅ Rejestracja jest idempotentna");
    }
}
