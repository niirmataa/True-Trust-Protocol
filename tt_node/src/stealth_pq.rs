// tt_node/src/stealth_pq.rs
#![forbid(unsafe_code)]

//! PQ stealth addresses & encrypted hints (Falcon512 + Kyber768)
//!
//! High-level idea:
//! - Adres stealth PQ = (Falcon_SPEND_PK, Kyber_SCAN_PK) + 32B fingerprint.
//! - Hint jest szyfrowany Kyberem (KEM) → shared_secret → AES-256-GCM.
//! - Klucze bierzemy z PQ walleta (Keyset) albo z zewnętrznych PK.
//!
//! Użycie (schematycznie):
//!   1) Odbiorca ma `Keyset` z walleta → `StealthAddressPQ::from_keyset`.
//!   2) Nadawca zna publiczne PQ klucze odbiorcy → `StealthAddressPQ::from_pks`.
//!   3) Nadawca woła `build_stealth_hint_for_address(...)` i wysyła `StealthHint`.
//!   4) Odbiorca skanuje noty, woła `decrypt_stealth_hint(...)` z własnymi secretami.
//
//! Uwaga: ten moduł NIE obsługuje jeszcze Merkle tree / NoteMetadata – to wyższa warstwa.
//! Tutaj jest czysty stealth kanał PQ.

use anyhow::{anyhow, Result};
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

use crate::core::Hash32;
use crate::hybrid_commit::pqc_fingerprint;
use crate::kyber_kem::{
    kyber_encapsulate,
    kyber_decapsulate,
    kyber_ct_to_bytes,
    kyber_ct_from_bytes,
    derive_aes_key_from_shared_secret,
};

#[cfg(feature = "wallet")]
use crate::wallet::wallet_cli::Keyset;

/* ============================================================================
 * Adres + sekrety
 * ========================================================================== */

/// Publiczny adres stealth PQ:
/// - `spend_pk`  – Falcon-512 (wydawanie / podpisy),
/// - `scan_pk`   – Kyber-768 (skanowanie zaszyfrowanych hintów),
/// - `addr_id`   – fingerprint PQC (32B), używany jako ID adresu.
///
/// Uwaga: specjalnie BEZ Serialize/Deserialize/Debug, bo PQ typy nie implementują tych traitów.
#[derive(Clone)]
pub struct StealthAddressPQ {
    pub spend_pk: falcon512::PublicKey,
    pub scan_pk: mlkem::PublicKey,
    pub addr_id: Hash32,
}

/// Sekrety do adresu stealth PQ:
/// - `spend_sk` – Falcon-512 SK,
/// - `scan_sk`  – Kyber-768 SK (do decaps).
///
/// Też bez serde/Debug – to czyste klucze tajne.
#[derive(Clone)]
pub struct StealthSecretsPQ {
    pub spend_sk: falcon512::SecretKey,
    pub scan_sk: mlkem::SecretKey,
}

/// Policz fingerprint adresu PQ (tak samo jak w `hybrid_commit`).
pub fn compute_addr_id(
    spend_pk: &falcon512::PublicKey,
    scan_pk: &mlkem::PublicKey,
) -> Hash32 {
    pqc_fingerprint(spend_pk.as_bytes(), scan_pk.as_bytes())
}

impl StealthAddressPQ {
    /// Utwórz adres stealth z podanych kluczy publicznych.
    pub fn from_pks(
        spend_pk: falcon512::PublicKey,
        scan_pk: mlkem::PublicKey,
    ) -> Self {
        let addr_id = compute_addr_id(&spend_pk, &scan_pk);
        Self {
            spend_pk,
            scan_pk,
            addr_id,
        }
    }

    /// 32-bajtowy identyfikator adresu (fingerprint PQC).
    pub fn id(&self) -> Hash32 {
        self.addr_id
    }

    /// Eksport PK w surowej formie (do JSON, RPC, itp.).
    pub fn export_pks(&self) -> (Vec<u8>, Vec<u8>) {
        (self.spend_pk.as_bytes().to_vec(), self.scan_pk.as_bytes().to_vec())
    }

    /// Helper: stwórz adres stealth z PQ walleta (Keyset).
    ///
    /// Uwaga: wymaga feature `wallet`.
    #[cfg(feature = "wallet")]
    pub fn from_keyset(ks: &Keyset) -> Self {
        let spend_pk = ks.falcon_pk.clone();
        let scan_pk  = ks.mlkem_pk.clone();
        StealthAddressPQ::from_pks(spend_pk, scan_pk)
    }
}

impl StealthSecretsPQ {
    pub fn from_sks(
        spend_sk: falcon512::SecretKey,
        scan_sk: mlkem::SecretKey,
    ) -> Self {
        Self { spend_sk, scan_sk }
    }

    /// Helper: sekrety stealth na podstawie PQ walleta.
    #[cfg(feature = "wallet")]
    pub fn from_keyset(ks: &Keyset) -> Self {
        Self {
            spend_sk: ks.falcon_sk.clone(),
            scan_sk: ks.mlkem_sk.clone(),
        }
    }
}

/* ============================================================================
 * Payload + hint
 * ========================================================================== */

/// To jest to, co chcemy ukryć w stealth hincie.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthHintPayload {
    /// 32-bajtowy blinding (np. do commitów Poseidona / Pedersen).
    pub r_blind: [u8; 32],
    /// Wartość (opcjonalnie można maskować wyżej, tu trzymamy plain).
    pub value: u64,
    /// Surowy memo (np. TLV, protobuf, itp.).
    pub memo: Vec<u8>,
}

/// Zaszyfrowany hint:
/// - `addr_id`   – fingerprint adresu (routing / szybki lookup),
/// - `kem_ct`    – Kyber ciphertext,
/// - `nonce`     – 12-bajtowy nonce AES-GCM,
/// - `ciphertext` – zaszyfrowany `StealthHintPayload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthHint {
    pub addr_id: Hash32,
    pub kem_ct: Vec<u8>,
    pub nonce: [u8; 12],
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
 * Budowa hinta (nadawca)
 * ========================================================================== */

/// Zbuduj stealth hint dla danego adresu PQ.
///
/// `aad` – dodatkowe AAD dla AES-GCM, np.:
///   - `c_out` (commitment noty),
///   - `net_id || tx_id`, itp.
pub fn build_stealth_hint_for_address(
    addr: &StealthAddressPQ,
    payload: &StealthHintPayload,
    aad: &[u8],
) -> Result<StealthHint> {
    // 1) Kyber KEM: shared_secret + ciphertext do scan_pk.
    let (ss, kem_ct) = kyber_encapsulate(&addr.scan_pk);

    // 2) KDF -> 32B klucz AES z użyciem KMAC256 (Twoje kyber_kem.rs).
    let mut ctx = Vec::with_capacity(16 + aad.len());
    ctx.extend_from_slice(b"TT-STEALTH-PQ.v1");
    ctx.extend_from_slice(aad);
    let aes_key = derive_aes_key_from_shared_secret(&ss, &ctx);

    // 3) Nonce dla AES-GCM.
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 4) Szyfrowanie payloadu.
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|_| anyhow!("invalid AES-256 key derived from Kyber ss"))?;
    let pt = bincode::serialize(payload)
        .map_err(|e| anyhow!("StealthHintPayload serialize failed: {e}"))?;

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &pt,
                aad,
            },
        )
        .map_err(|e| anyhow!("stealth hint encrypt failed: {e}"))?;

    // 5) Złożenie struktury.
    let kem_ct_bytes = kyber_ct_to_bytes(&kem_ct).to_vec();

    Ok(StealthHint {
        addr_id: addr.addr_id,
        kem_ct: kem_ct_bytes,
        nonce: nonce_bytes,
        ciphertext: ct,
    })
}

/* ============================================================================
 * Odszyfrowanie hinta (odbiorca)
 * ========================================================================== */

/// Spróbuj odszyfrować stealth hint mając sekrety odbiorcy.
///
/// Zwraca `StealthHintPayload` jeśli:
///  - Kyber decapsulate się zgodzi z `scan_sk`,
///  - KDF + AES-GCM się powiedzie,
///  - bincode deserializacja payloadu jest poprawna.
pub fn decrypt_stealth_hint(
    secrets: &StealthSecretsPQ,
    hint: &StealthHint,
    aad: &[u8],
) -> Result<StealthHintPayload> {
    // 1) Kyber ciphertext → SharedSecret.
    let kem_ct = kyber_ct_from_bytes(&hint.kem_ct)?;
    let ss = kyber_decapsulate(&kem_ct, &secrets.scan_sk)?;

    // 2) Ten sam kontekst co przy enkrypcji.
    let mut ctx = Vec::with_capacity(16 + aad.len());
    ctx.extend_from_slice(b"TT-STEALTH-PQ.v1");
    ctx.extend_from_slice(aad);
    let aes_key = derive_aes_key_from_shared_secret(&ss, &ctx);

    // 3) AES-GCM decrypt.
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|_| anyhow!("invalid AES-256 key derived from Kyber ss"))?;
    let nonce = Nonce::from_slice(&hint.nonce);

    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &hint.ciphertext,
                aad,
            },
        )
        .map_err(|e| anyhow!("stealth hint decrypt failed: {e}"))?;

    let payload: StealthHintPayload =
        bincode::deserialize(&pt).map_err(|e| anyhow!("invalid stealth payload: {e}"))?;

    Ok(payload)
}

/* ============================================================================
 * Prosty test end-to-end (feature-agnostic)
 * ========================================================================== */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stealth_pq_roundtrip() {
        // Symulujemy Keyset (bez wallet feature).
        let (falcon_pk, falcon_sk) = falcon512::keypair();
        let (scan_pk, scan_sk) = mlkem::keypair();

        let addr = StealthAddressPQ::from_pks(falcon_pk, scan_pk);
        let secrets = StealthSecretsPQ::from_sks(falcon_sk, scan_sk);

        let mut r = [0u8; 32];
        OsRng.fill_bytes(&mut r);

        let payload = StealthHintPayload {
            r_blind: r,
            value: 42,
            memo: b"hello stealth pq".to_vec(),
        };

        let aad = b"example-AAD-ctx";

        let hint = build_stealth_hint_for_address(&addr, &payload, aad)
            .expect("build hint");
        let dec = decrypt_stealth_hint(&secrets, &hint, aad)
            .expect("decrypt hint");

        assert_eq!(dec.value, 42);
        assert_eq!(dec.memo, b"hello stealth pq".to_vec());
        assert_eq!(dec.r_blind, payload.r_blind);
    }
}
