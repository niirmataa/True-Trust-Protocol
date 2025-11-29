// tt_node/src/stealth_pq.rs
#![forbid(unsafe_code)]

//! PQ Stealth Addresses & Encrypted Hints v2 (Falcon512 + Kyber768)
//!
//! Privacy-focused implementation with:
//! - Ephemeral scan tags (unlinkable hints)
//! - Constant-size padding (no metadata leaks)
//! - Replay protection (timestamp + hint_id)
//! - Proper AAD binding (recipient's addr_id)

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

use rand::rngs::OsRng;
use rand::RngCore;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
    Nonce,
};

use pqcrypto_falcon::falcon512;
use pqcrypto_kyber::kyber768 as mlkem;
use pqcrypto_traits::sign::PublicKey as PQSignPublicKey;
use pqcrypto_traits::kem::PublicKey as PQKemPublicKey;
use pqcrypto_traits::kem::SharedSecret;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::Hash32;
use crate::crypto::kmac as ck;
use crate::kyber_kem::{
    kyber_encapsulate,
    kyber_decapsulate,
    kyber_ct_to_bytes,
    kyber_ct_from_bytes,
    derive_aes_key_from_shared_secret,
    KyberSharedSecret,
};

/* ============================================================================
 * CONSTANTS
 * ========================================================================== */

/// Version tag for domain separation
const STEALTH_VERSION: &[u8] = b"TT-STEALTH-PQ.v2";

/// Domain separation for scan tag derivation
const SCAN_TAG_DOMAIN: &[u8] = b"TT-SCAN-TAG.v2";

/// Domain separation for hint_id derivation
const HINT_ID_DOMAIN: &[u8] = b"TT-HINT-ID.v2";

/// Padded payload size (constant to prevent size-based analysis)
const PADDED_PAYLOAD_SIZE: usize = 512;

/// Maximum memo size (bytes)
const MAX_MEMO_SIZE: usize = 256;

/// Maximum allowed timestamp skew (seconds) for replay protection
const MAX_TIMESTAMP_SKEW_SECS: u64 = 300; // 5 minutes

/* ============================================================================
 * ADDRESS + SECRETS
 * ========================================================================== */

/// Public stealth address (PQ):
/// - `spend_pk` — Falcon-512 (spending/signing)
/// - `scan_pk`  — Kyber-768 (scanning encrypted hints)
/// - `addr_id`  — fingerprint for internal use (NOT transmitted in hints)
#[derive(Clone)]
pub struct StealthAddressPQ {
    pub spend_pk: falcon512::PublicKey,
    pub scan_pk: mlkem::PublicKey,
    /// Internal address ID — used for AAD, NOT included in hints
    addr_id: Hash32,
}

/// Secret keys for stealth address
#[derive(Clone)]
pub struct StealthSecretsPQ {
    pub spend_sk: falcon512::SecretKey,
    pub scan_sk: mlkem::SecretKey,
    /// Cached addr_id for AAD verification
    addr_id: Hash32,
}

/// Compute address fingerprint from PQ public keys
pub fn compute_addr_id(
    spend_pk: &falcon512::PublicKey,
    scan_pk: &mlkem::PublicKey,
) -> Hash32 {
    use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};
    
    let mut h = Shake256::default();
    h.update(b"TT-ADDR-ID.v2");
    h.update(spend_pk.as_bytes());
    h.update(scan_pk.as_bytes());
    let mut rdr = h.finalize_xof();
    let mut out = [0u8; 32];
    rdr.read(&mut out);
    out
}

impl StealthAddressPQ {
    pub fn from_pks(
        spend_pk: falcon512::PublicKey,
        scan_pk: mlkem::PublicKey,
    ) -> Self {
        let addr_id = compute_addr_id(&spend_pk, &scan_pk);
        Self { spend_pk, scan_pk, addr_id }
    }

    pub fn id(&self) -> Hash32 {
        self.addr_id
    }
}

impl StealthSecretsPQ {
    pub fn from_sks(
        spend_sk: falcon512::SecretKey,
        scan_sk: mlkem::SecretKey,
        spend_pk: &falcon512::PublicKey,
        scan_pk: &mlkem::PublicKey,
    ) -> Self {
        let addr_id = compute_addr_id(spend_pk, scan_pk);
        Self { spend_sk, scan_sk, addr_id }
    }

    pub fn addr_id(&self) -> Hash32 {
        self.addr_id
    }
}

/* ============================================================================
 * PAYLOAD + HINT STRUCTURES
 * ========================================================================== */

/// Plaintext payload hidden inside stealth hint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthHintPayload {
    /// Blinding factor for commitments
    pub r_blind: [u8; 32],
    /// Payment value
    pub value: u64,
    /// Unix timestamp (replay protection)
    pub timestamp: u64,
    /// Unique hint identifier (replay protection)
    pub hint_id: [u8; 32],
    /// Memo message (max 256 bytes)
    pub memo: Vec<u8>,
}

/// Encrypted stealth hint (transmitted over network)
/// 
/// Privacy properties:
/// - `scan_tag`: Ephemeral, derived from shared_secret — UNLINKABLE
/// - `kem_ct`: Kyber ciphertext — reveals nothing about recipient
/// - `ciphertext`: Constant size (padded) — no length-based analysis
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthHint {
    /// Ephemeral scan tag (8 bytes) — unlinkable between hints
    pub scan_tag: [u8; 8],
    /// Kyber-768 ciphertext (1088 bytes)
    pub kem_ct: Vec<u8>,
    /// AES-GCM nonce (12 bytes)
    pub nonce: [u8; 12],
    /// Encrypted + padded payload (constant size)
    pub ciphertext: Vec<u8>,
}

impl StealthHint {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("StealthHint serialize")
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| anyhow!("invalid StealthHint: {e}"))
    }
}

/* ============================================================================
 * HELPER FUNCTIONS
 * ========================================================================== */

/// Derive ephemeral scan tag from shared secret (unlinkable per hint)
fn derive_scan_tag(shared_secret: &KyberSharedSecret) -> [u8; 8] {
    let full = ck::kmac256_derive_key(
        shared_secret.as_bytes(),
        SCAN_TAG_DOMAIN,
        b"",
    );
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&full[..8]);
    tag
}

/// Generate unique hint_id from shared_secret + randomness
fn generate_hint_id(shared_secret: &KyberSharedSecret) -> [u8; 32] {
    let mut random_part = [0u8; 32];
    OsRng.fill_bytes(&mut random_part);
    
    ck::kmac256_derive_key(
        shared_secret.as_bytes(),
        HINT_ID_DOMAIN,
        &random_part,
    )
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

/// Verify timestamp is within acceptable range
fn verify_timestamp(timestamp: u64) -> Result<()> {
    let now = current_timestamp();
    let diff = if now > timestamp {
        now - timestamp
    } else {
        timestamp - now
    };
    
    if diff > MAX_TIMESTAMP_SKEW_SECS {
        bail!(
            "timestamp too far from current time (diff: {}s, max: {}s)",
            diff,
            MAX_TIMESTAMP_SKEW_SECS
        );
    }
    Ok(())
}

/// Pad payload to constant size (prevents length-based analysis)
fn pad_payload(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > PADDED_PAYLOAD_SIZE - 8 {
        bail!(
            "payload too large: {} bytes (max: {})",
            data.len(),
            PADDED_PAYLOAD_SIZE - 8
        );
    }
    
    let mut padded = Vec::with_capacity(PADDED_PAYLOAD_SIZE);
    
    // Length prefix (8 bytes, little-endian)
    padded.extend_from_slice(&(data.len() as u64).to_le_bytes());
    
    // Actual data
    padded.extend_from_slice(data);
    
    // Random padding to constant size
    let padding_needed = PADDED_PAYLOAD_SIZE - padded.len();
    let mut padding = vec![0u8; padding_needed];
    OsRng.fill_bytes(&mut padding);
    padded.extend_from_slice(&padding);
    
    debug_assert_eq!(padded.len(), PADDED_PAYLOAD_SIZE);
    Ok(padded)
}

/// Remove padding and extract original payload
fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() != PADDED_PAYLOAD_SIZE {
        bail!(
            "invalid padded size: {} (expected: {})",
            padded.len(),
            PADDED_PAYLOAD_SIZE
        );
    }
    
    let len = u64::from_le_bytes(padded[..8].try_into().unwrap()) as usize;
    
    if len > PADDED_PAYLOAD_SIZE - 8 {
        bail!("invalid payload length marker: {}", len);
    }
    
    Ok(padded[8..8 + len].to_vec())
}

/// Build AAD from recipient's addr_id (proper binding)
fn build_aad(recipient_addr_id: &Hash32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(STEALTH_VERSION.len() + 32);
    aad.extend_from_slice(STEALTH_VERSION);
    aad.extend_from_slice(recipient_addr_id);
    aad
}

/* ============================================================================
 * BUILDER (SENDER SIDE)
 * ========================================================================== */

/// Builder for creating stealth hints
pub struct StealthHintBuilder {
    value: u64,
    memo: Vec<u8>,
    r_blind: Option<[u8; 32]>,
}

impl StealthHintBuilder {
    pub fn new(value: u64) -> Self {
        Self {
            value,
            memo: Vec::new(),
            r_blind: None,
        }
    }

    pub fn memo(mut self, memo: impl Into<Vec<u8>>) -> Result<Self> {
        let m = memo.into();
        if m.len() > MAX_MEMO_SIZE {
            bail!("memo too large: {} bytes (max: {})", m.len(), MAX_MEMO_SIZE);
        }
        self.memo = m;
        Ok(self)
    }

    pub fn r_blind(mut self, r: [u8; 32]) -> Self {
        self.r_blind = Some(r);
        self
    }

    pub fn build(self, recipient: &StealthAddressPQ) -> Result<StealthHint> {
        let r_blind = self.r_blind.unwrap_or_else(|| {
            let mut r = [0u8; 32];
            OsRng.fill_bytes(&mut r);
            r
        });

        build_stealth_hint_internal(
            recipient,
            r_blind,
            self.value,
            self.memo,
        )
    }
}

/// Internal hint construction
fn build_stealth_hint_internal(
    addr: &StealthAddressPQ,
    r_blind: [u8; 32],
    value: u64,
    memo: Vec<u8>,
) -> Result<StealthHint> {
    // 1) Kyber KEM: encapsulate to recipient's scan_pk
    let (ss, kem_ct) = kyber_encapsulate(&addr.scan_pk);

    // 2) Derive ephemeral scan tag (UNLINKABLE)
    let scan_tag = derive_scan_tag(&ss);

    // 3) Generate unique hint_id (replay protection)
    let hint_id = generate_hint_id(&ss);

    // 4) Build payload with timestamp
    let payload = StealthHintPayload {
        r_blind,
        value,
        timestamp: current_timestamp(),
        hint_id,
        memo,
    };

    // 5) Serialize and pad to constant size
    let payload_bytes = bincode::serialize(&payload)
        .map_err(|e| anyhow!("payload serialize failed: {e}"))?;
    let padded = pad_payload(&payload_bytes)?;

    // 6) Derive AES key — AAD = recipient's addr_id (FIX: proper binding)
    let aad = build_aad(&addr.addr_id);
    let aes_key = derive_aes_key_from_shared_secret(&ss, &aad);

    // 7) Generate nonce and encrypt
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|_| anyhow!("invalid AES key"))?;

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: &padded, aad: &aad })
        .map_err(|e| anyhow!("encryption failed: {e}"))?;

    // 8) Build hint (WITHOUT addr_id — unlinkable!)
    Ok(StealthHint {
        scan_tag,
        kem_ct: kyber_ct_to_bytes(&kem_ct).to_vec(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

/* ============================================================================
 * SCANNER / DECRYPTOR (RECEIVER SIDE)
 * ========================================================================== */

/// Result of scanning a hint
#[derive(Clone, Debug)]
pub enum ScanResult {
    /// Hint is for us, successfully decrypted
    Match(StealthHintPayload),
    /// Hint is not for us (scan_tag mismatch)
    NotForUs,
    /// Decryption failed
    DecryptionFailed(String),
    /// Timestamp outside acceptable range (possible replay)
    ReplayDetected(String),
    /// Hint already processed (duplicate hint_id)
    DuplicateHint,
}

/// Quick check if hint MIGHT be for us
pub fn hint_might_be_mine(
    secrets: &StealthSecretsPQ,
    hint: &StealthHint,
) -> bool {
    let kem_ct = match kyber_ct_from_bytes(&hint.kem_ct) {
        Ok(ct) => ct,
        Err(_) => return false,
    };

    let ss = match kyber_decapsulate(&kem_ct, &secrets.scan_sk) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let expected_tag = derive_scan_tag(&ss);
    expected_tag == hint.scan_tag
}

/// Decrypt stealth hint (full decryption with all checks)
pub fn decrypt_stealth_hint(
    secrets: &StealthSecretsPQ,
    hint: &StealthHint,
) -> ScanResult {
    // 1) Kyber decapsulate
    let kem_ct = match kyber_ct_from_bytes(&hint.kem_ct) {
        Ok(ct) => ct,
        Err(e) => return ScanResult::DecryptionFailed(format!("invalid kem_ct: {e}")),
    };

    let ss = match kyber_decapsulate(&kem_ct, &secrets.scan_sk) {
        Ok(s) => s,
        Err(e) => return ScanResult::DecryptionFailed(format!("decapsulate failed: {e}")),
    };

    // 2) Verify scan tag
    let expected_tag = derive_scan_tag(&ss);
    if expected_tag != hint.scan_tag {
        return ScanResult::NotForUs;
    }

    // 3) Derive AES key — AAD = our addr_id
    let aad = build_aad(&secrets.addr_id);
    let aes_key = derive_aes_key_from_shared_secret(&ss, &aad);

    // 4) Decrypt
    let cipher = match Aes256Gcm::new_from_slice(&aes_key) {
        Ok(c) => c,
        Err(_) => return ScanResult::DecryptionFailed("invalid AES key".into()),
    };

    let nonce = Nonce::from_slice(&hint.nonce);

    let padded = match cipher.decrypt(nonce, Payload { msg: &hint.ciphertext, aad: &aad }) {
        Ok(pt) => pt,
        Err(e) => return ScanResult::DecryptionFailed(format!("AES decrypt failed: {e}")),
    };

    // 5) Unpad
    let payload_bytes = match unpad_payload(&padded) {
        Ok(b) => b,
        Err(e) => return ScanResult::DecryptionFailed(format!("unpad failed: {e}")),
    };

    // 6) Deserialize
    let payload: StealthHintPayload = match bincode::deserialize(&payload_bytes) {
        Ok(p) => p,
        Err(e) => return ScanResult::DecryptionFailed(format!("deserialize failed: {e}")),
    };

    // 7) Verify timestamp (replay protection)
    if let Err(e) = verify_timestamp(payload.timestamp) {
        return ScanResult::ReplayDetected(e.to_string());
    }

    ScanResult::Match(payload)
}

/// Scan multiple hints and return matches
pub fn scan_hints(
    secrets: &StealthSecretsPQ,
    hints: &[StealthHint],
) -> Vec<(usize, StealthHintPayload)> {
    hints
        .iter()
        .enumerate()
        .filter_map(|(idx, hint)| {
            match decrypt_stealth_hint(secrets, hint) {
                ScanResult::Match(payload) => Some((idx, payload)),
                _ => None,
            }
        })
        .collect()
}

/// Scan hints with deduplication (full replay protection)
pub fn scan_hints_dedup(
    secrets: &StealthSecretsPQ,
    hints: &[StealthHint],
    seen_hint_ids: &mut std::collections::HashSet<[u8; 32]>,
) -> Vec<(usize, StealthHintPayload)> {
    hints
        .iter()
        .enumerate()
        .filter_map(|(idx, hint)| {
            match decrypt_stealth_hint(secrets, hint) {
                ScanResult::Match(payload) => {
                    if seen_hint_ids.contains(&payload.hint_id) {
                        None // Already processed
                    } else {
                        seen_hint_ids.insert(payload.hint_id);
                        Some((idx, payload))
                    }
                }
                _ => None,
            }
        })
        .collect()
}

/* ============================================================================
 * TESTS
 * ========================================================================== */

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> (StealthAddressPQ, StealthSecretsPQ) {
        let (falcon_pk, falcon_sk) = falcon512::keypair();
        let (scan_pk, scan_sk) = mlkem::keypair();

        let addr = StealthAddressPQ::from_pks(falcon_pk.clone(), scan_pk.clone());
        let secrets = StealthSecretsPQ::from_sks(falcon_sk, scan_sk, &falcon_pk, &scan_pk);

        (addr, secrets)
    }

    #[test]
    fn roundtrip_basic() {
        let (addr, secrets) = test_keypair();

        let hint = StealthHintBuilder::new(1000)
            .memo(b"hello".to_vec()).unwrap()
            .build(&addr)
            .unwrap();

        match decrypt_stealth_hint(&secrets, &hint) {
            ScanResult::Match(p) => {
                assert_eq!(p.value, 1000);
                assert_eq!(p.memo, b"hello");
            }
            other => panic!("expected Match, got {:?}", other),
        }
    }

    #[test]
    fn wrong_recipient_not_for_us() {
        let (addr, _) = test_keypair();
        let (_, other_secrets) = test_keypair();

        let hint = StealthHintBuilder::new(500).build(&addr).unwrap();

        match decrypt_stealth_hint(&other_secrets, &hint) {
            ScanResult::NotForUs => {}
            other => panic!("expected NotForUs, got {:?}", other),
        }
    }

    #[test]
    fn scan_tags_unlinkable() {
        let (addr, _) = test_keypair();

        let h1 = StealthHintBuilder::new(100).build(&addr).unwrap();
        let h2 = StealthHintBuilder::new(200).build(&addr).unwrap();

        // Tags MUST be different
        assert_ne!(h1.scan_tag, h2.scan_tag);
    }

    #[test]
    fn ciphertext_constant_size() {
        let (addr, _) = test_keypair();

        let h_empty = StealthHintBuilder::new(100).build(&addr).unwrap();
        let h_small = StealthHintBuilder::new(100)
            .memo(b"hi".to_vec()).unwrap()
            .build(&addr).unwrap();
        let h_large = StealthHintBuilder::new(100)
            .memo(vec![0x42; 200]).unwrap()
            .build(&addr).unwrap();

        // All ciphertexts same size
        assert_eq!(h_empty.ciphertext.len(), h_small.ciphertext.len());
        assert_eq!(h_small.ciphertext.len(), h_large.ciphertext.len());
    }

    #[test]
    fn dedup_prevents_replay() {
        let (addr, secrets) = test_keypair();

        let hint = StealthHintBuilder::new(999).build(&addr).unwrap();
        let hints = vec![hint.clone(), hint.clone()];

        let mut seen = std::collections::HashSet::new();
        let found = scan_hints_dedup(&secrets, &hints, &mut seen);

        // Only ONE result (second filtered as duplicate)
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn memo_too_large_rejected() {
        let result = StealthHintBuilder::new(100)
            .memo(vec![0u8; MAX_MEMO_SIZE + 1]);

        assert!(result.is_err());
    }
}