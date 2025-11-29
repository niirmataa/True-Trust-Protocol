#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use pqcrypto_falcon::falcon512;

use crate::pqc_verification::{
    Hash32,
    NoteMetadata,
    PrivateNoteEntry,
    PqcVerificationContext,
    compute_pqc_fingerprint,
};
use pqcrypto_traits::sign::PublicKey as PQPublicKey;

/// Prywatny stan not (Merkle, nullifiery, metadane).
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct StatePriv {
    /// Merkle root drzewa not (jeśli używasz).
    pub notes_root: Hash32,
    /// Liczba not.
    pub notes_count: u64,
    /// Frontier do incrementalnego Merkle (jeśli używasz).
    pub frontier: Vec<Hash32>,
    /// Już wydane nullifiery.
    pub nullifiers: HashSet<Hash32>,
    /// Wszystkie znane noty prywatne (prosto jako wektor).
    pub notes: Vec<PrivateNoteEntry>,

    #[serde(skip)]
    pub path: Option<PathBuf>,
}

impl StatePriv {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(p: impl AsRef<Path>) -> Result<Self> {
        let path = p.as_ref();
        if !path.exists() {
            let mut s = Self::default();
            s.path = Some(path.to_path_buf());
            s.persist()?;
            return Ok(s);
        }
        let buf = std::fs::read(path)?;
        let mut s: Self = serde_json::from_slice(&buf)?;
        s.path = Some(path.to_path_buf());
        Ok(s)
    }

    pub fn save(&self, p: impl AsRef<Path>) -> Result<()> {
        let buf = serde_json::to_vec_pretty(self)?;
        std::fs::write(p.as_ref(), buf)?;
        Ok(())
    }

    pub fn persist(&self) -> Result<()> {
        if let Some(ref p) = self.path {
            self.save(p)?;
        }
        Ok(())
    }

    pub fn insert_nullifier(&mut self, nf: Hash32) -> bool {
        self.nullifiers.insert(nf)
    }

    pub fn has_nullifier(&self, nf: &Hash32) -> bool {
        self.nullifiers.contains(nf)
    }

    /// Dodaj albo nadpisz notę.
    pub fn upsert_note(&mut self, entry: PrivateNoteEntry) {
        if let Some(existing) = self
            .notes
            .iter_mut()
            .find(|e| e.nullifier == entry.nullifier)
        {
            *existing = entry;
        } else {
            self.notes.push(entry);
            self.notes_count = self.notes.len() as u64;
        }
    }

    /// Prosta paginacja: zwraca [start, start+limit) not.
    pub fn get_private_notes_range(&self, start: u64, limit: u64) -> Vec<PrivateNoteEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let start_idx = usize::try_from(start).unwrap_or(usize::MAX);
        let end_idx = start_idx.saturating_add(limit as usize);
        self.notes
            .iter()
            .skip(start_idx)
            .take(end_idx.saturating_sub(start_idx))
            .cloned()
            .collect()
    }
}

/// Implementacja PQC-verification context na bazie `StatePriv`.
impl PqcVerificationContext for StatePriv {
    fn load_note(&self, nullifier: &Hash32) -> Result<NoteMetadata> {
        self.notes
            .iter()
            .find(|e| &e.nullifier == nullifier)
            .map(|e| e.meta.clone())
            .ok_or_else(|| anyhow!("Note not found for nullifier {}", hex::encode(nullifier)))
    }

    fn load_falcon_pk(&self, fp: &Hash32) -> Result<falcon512::PublicKey> {
        // Szukamy not, które zawierają zakodowany Falcon + ML-KEM pk i
        // odtwarzamy fingerprint.
        for entry in &self.notes {
            if let (Some(ref falcon_bytes), Some(ref mlkem_bytes)) =
                (&entry.meta.falcon_pk, &entry.meta.mlkem_pk)
            {
                let computed = compute_pqc_fingerprint(falcon_bytes, mlkem_bytes);
                if &computed == fp {
                    let pk = falcon512::PublicKey::from_bytes(falcon_bytes)
                        .map_err(|_| anyhow!("Invalid stored Falcon public key bytes"))?;
                    return Ok(pk);
                }
            }
        }
        Err(anyhow!("Falcon PK not found for given PQC fingerprint"))
    }

    fn is_nullifier_spent(&self, nullifier: &Hash32) -> Result<bool> {
        Ok(self.nullifiers.contains(nullifier))
    }

    fn mark_nullifier_spent(&mut self, nullifier: &Hash32) -> Result<()> {
        self.nullifiers.insert(*nullifier);
        Ok(())
    }
}
