//! Public Key Registry - eliminuje PK z transakcji
//!
//! Problem: Falcon-512 PK (897B) + Kyber-768 PK (1184B) = 2081B per TX
//! Rozwiązanie: Rejestruj raz, potem używaj key_id (32B)
//! Oszczędność: 2049B per TX = 72% redukcja!
//!
//! # Architektura
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    KEY REGISTRY                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │  key_id (32B) ──► falcon_pk (897B) + kyber_pk (1184B)       │
//! │                                                              │
//! │  address (32B) ──► key_id (32B) [szybki lookup]             │
//! └─────────────────────────────────────────────────────────────┘
//!
//! TX przed:  [from][to][amount][fee][nonce][falcon_pk][kyber_pk][sig]
//!            = ~2850B
//!
//! TX po:     [from][to][amount][fee][nonce][key_id][sig]
//!            = ~786B
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};
use serde::{Serialize, Deserialize};

/// Zarejestrowany klucz publiczny
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisteredKey {
    /// Falcon-512 public key (897 bytes)
    pub falcon_pk: Vec<u8>,
    /// Kyber-768 public key (1184 bytes)
    pub kyber_pk: Vec<u8>,
    /// Timestamp rejestracji
    pub registered_at: u64,
    /// Blok w którym zarejestrowano (0 = genesis/pending)
    pub registered_block: u64,
}

impl RegisteredKey {
    /// Rozmiar kluczy w bajtach
    pub fn size(&self) -> usize {
        self.falcon_pk.len() + self.kyber_pk.len()
    }
}

/// Globalny rejestr kluczy publicznych
/// Thread-safe dzięki RwLock
#[derive(Default)]
pub struct PublicKeyRegistry {
    /// key_id -> RegisteredKey
    keys: HashMap<[u8; 32], RegisteredKey>,
    /// address -> key_id (szybki lookup)
    addr_to_key: HashMap<[u8; 32], [u8; 32]>,
    /// Statystyki
    total_registered: u64,
    total_bytes_saved: u64,
}

impl PublicKeyRegistry {
    /// Nowy pusty rejestr
    pub fn new() -> Self {
        Self::default()
    }

    /// Oblicz key_id z kluczy publicznych (deterministyczny)
    /// 
    /// key_id = SHAKE256("TT.v7.KEY_ID" || falcon_pk || kyber_pk)[0..32]
    pub fn compute_key_id(falcon_pk: &[u8], kyber_pk: &[u8]) -> [u8; 32] {
        let mut h = Shake256::default();
        h.update(b"TT.v7.KEY_ID");
        h.update(falcon_pk);
        h.update(kyber_pk);
        let mut id = [0u8; 32];
        h.finalize_xof().read(&mut id);
        id
    }

    /// Oblicz adres z kluczy (dla kompatybilności)
    pub fn compute_address(falcon_pk: &[u8], kyber_pk: &[u8]) -> [u8; 32] {
        let mut h = Shake256::default();
        h.update(b"TT.v7.ADDR");
        h.update(falcon_pk);
        h.update(kyber_pk);
        let mut addr = [0u8; 32];
        h.finalize_xof().read(&mut addr);
        addr
    }

    /// Zarejestruj klucze (jednorazowo per adres)
    /// 
    /// Zwraca key_id lub błąd jeśli już zarejestrowane z innymi kluczami
    pub fn register(
        &mut self,
        falcon_pk: Vec<u8>,
        kyber_pk: Vec<u8>,
        timestamp: u64,
        block_height: u64,
    ) -> Result<[u8; 32], KeyRegistryError> {
        // Walidacja rozmiarów
        if falcon_pk.len() != 897 {
            return Err(KeyRegistryError::InvalidFalconKeySize(falcon_pk.len()));
        }
        if kyber_pk.len() != 1184 {
            return Err(KeyRegistryError::InvalidKyberKeySize(kyber_pk.len()));
        }

        let key_id = Self::compute_key_id(&falcon_pk, &kyber_pk);
        let addr = Self::compute_address(&falcon_pk, &kyber_pk);

        // Sprawdź czy już zarejestrowane
        if let Some(existing) = self.keys.get(&key_id) {
            // Już istnieje - OK jeśli te same klucze
            if existing.falcon_pk == falcon_pk && existing.kyber_pk == kyber_pk {
                return Ok(key_id);
            }
            // Kolizja key_id (praktycznie niemożliwe z SHAKE256)
            return Err(KeyRegistryError::KeyIdCollision(key_id));
        }

        // Sprawdź czy adres nie ma już innych kluczy
        if let Some(&existing_key_id) = self.addr_to_key.get(&addr) {
            if existing_key_id != key_id {
                return Err(KeyRegistryError::AddressAlreadyRegistered(addr));
            }
        }

        // Rejestruj
        let _key_size = falcon_pk.len() + kyber_pk.len();
        self.keys.insert(key_id, RegisteredKey {
            falcon_pk,
            kyber_pk,
            registered_at: timestamp,
            registered_block: block_height,
        });
        self.addr_to_key.insert(addr, key_id);
        
        self.total_registered += 1;

        Ok(key_id)
    }

    /// Zapisz użycie key_id w TX (każde użycie = 2049B oszczędności)
    pub fn record_usage(&mut self) {
        // key_size (2081B) - key_id (32B) = 2049B saved per TX
        self.total_bytes_saved += 2049;
    }

    /// Pobierz klucze po key_id
    pub fn get(&self, key_id: &[u8; 32]) -> Option<&RegisteredKey> {
        self.keys.get(key_id)
    }

    /// Pobierz key_id po adresie
    pub fn get_key_id_for_addr(&self, addr: &[u8; 32]) -> Option<[u8; 32]> {
        self.addr_to_key.get(addr).copied()
    }

    /// Pobierz klucze po adresie
    pub fn get_by_addr(&self, addr: &[u8; 32]) -> Option<&RegisteredKey> {
        self.addr_to_key.get(addr)
            .and_then(|key_id| self.keys.get(key_id))
    }

    /// Czy adres jest zarejestrowany?
    pub fn is_registered(&self, addr: &[u8; 32]) -> bool {
        self.addr_to_key.contains_key(addr)
    }

    /// Czy key_id istnieje?
    pub fn has_key_id(&self, key_id: &[u8; 32]) -> bool {
        self.keys.contains_key(key_id)
    }

    /// Statystyki
    pub fn stats(&self) -> RegistryStats {
        RegistryStats {
            total_registered: self.total_registered,
            total_keys: self.keys.len() as u64,
            total_bytes_stored: self.keys.values()
                .map(|k| k.size() as u64)
                .sum(),
            estimated_bytes_saved: self.total_bytes_saved,
        }
    }

    /// Eksport do serializacji
    pub fn export(&self) -> Vec<(Vec<u8>, Vec<u8>, u64, u64)> {
        self.keys.values()
            .map(|k| (
                k.falcon_pk.clone(),
                k.kyber_pk.clone(),
                k.registered_at,
                k.registered_block,
            ))
            .collect()
    }

    /// Import z serializacji
    pub fn import(&mut self, entries: Vec<(Vec<u8>, Vec<u8>, u64, u64)>) -> Result<usize, KeyRegistryError> {
        let mut imported = 0;
        for (falcon_pk, kyber_pk, timestamp, block) in entries {
            match self.register(falcon_pk, kyber_pk, timestamp, block) {
                Ok(_) => imported += 1,
                Err(KeyRegistryError::KeyIdCollision(_)) => {
                    // Już istnieje - ignoruj
                }
                Err(e) => return Err(e),
            }
        }
        Ok(imported)
    }

    /// Zapisz registry do pliku (z kompresją zstd)
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), std::io::Error> {
        let data = self.export();
        let serialized = bincode::serialize(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let compressed = crate::tx_compression::compress(&serialized)?;
        std::fs::write(path, compressed)
    }

    /// Wczytaj registry z pliku
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let compressed = std::fs::read(path)?;
        let serialized = crate::tx_compression::decompress(&compressed)?;
        let entries: Vec<(Vec<u8>, Vec<u8>, u64, u64)> = bincode::deserialize(&serialized)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut registry = Self::new();
        registry.import(entries)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(registry)
    }
}

/// Thread-safe wrapper
pub type SharedKeyRegistry = Arc<RwLock<PublicKeyRegistry>>;

/// Utwórz nowy shared registry
pub fn new_shared_registry() -> SharedKeyRegistry {
    Arc::new(RwLock::new(PublicKeyRegistry::new()))
}

/// Statystyki rejestru
#[derive(Debug, Clone)]
pub struct RegistryStats {
    pub total_registered: u64,
    pub total_keys: u64,
    pub total_bytes_stored: u64,
    pub estimated_bytes_saved: u64,
}

impl std::fmt::Display for RegistryStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KeyRegistry: {} keys, {:.1} KB stored, ~{:.1} KB saved",
            self.total_keys,
            self.total_bytes_stored as f64 / 1024.0,
            self.estimated_bytes_saved as f64 / 1024.0,
        )
    }
}

/// Błędy rejestru
#[derive(Debug, Clone)]
pub enum KeyRegistryError {
    InvalidFalconKeySize(usize),
    InvalidKyberKeySize(usize),
    KeyIdCollision([u8; 32]),
    AddressAlreadyRegistered([u8; 32]),
    KeyNotFound([u8; 32]),
}

impl std::fmt::Display for KeyRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFalconKeySize(s) => write!(f, "Invalid Falcon key size: {} (expected 897)", s),
            Self::InvalidKyberKeySize(s) => write!(f, "Invalid Kyber key size: {} (expected 1184)", s),
            Self::KeyIdCollision(id) => write!(f, "Key ID collision: {}", hex::encode(&id[..8])),
            Self::AddressAlreadyRegistered(a) => write!(f, "Address already registered: {}", hex::encode(&a[..8])),
            Self::KeyNotFound(id) => write!(f, "Key not found: {}", hex::encode(&id[..8])),
        }
    }
}

impl std::error::Error for KeyRegistryError {}

// ============================================================================
// KOMPAKTOWE TRANSAKCJE
// ============================================================================

/// Kompaktowa transakcja - używa key_id zamiast pełnych kluczy
/// 
/// Rozmiar: ~786B vs ~2850B = 72% oszczędności!
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactSimpleTx {
    /// Adres nadawcy (32B)
    pub from: [u8; 32],
    /// Adres odbiorcy (32B)
    pub to: [u8; 32],
    /// Kwota (8B)
    pub amount: u64,
    /// Opłata (8B)
    pub fee: u64,
    /// Nonce (8B)
    pub nonce: u64,
    /// Key ID nadawcy - referencja do rejestru (32B zamiast 2081B!)
    pub sender_key_id: [u8; 32],
    /// Podpis Falcon (~666B) - tego nie unikniemy
    pub falcon_sig: Vec<u8>,
}

impl CompactSimpleTx {
    /// Utwórz i podpisz nową transakcję
    pub fn sign(
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        fee: u64,
        nonce: u64,
        sender_key_id: [u8; 32],
        falcon_sk: &crate::falcon_sigs::FalconSecretKey,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut tx = Self {
            from,
            to,
            amount,
            fee,
            nonce,
            sender_key_id,
            falcon_sig: vec![],
        };
        let msg = tx.signing_message();
        let signed = crate::falcon_sigs::falcon_sign(&msg, falcon_sk)?;
        tx.falcon_sig = signed.signed_message_bytes.clone();
        Ok(tx)
    }

    /// Weryfikuj podpis używając registry
    pub fn verify(&self, registry: &PublicKeyRegistry) -> Result<bool, KeyRegistryError> {
        let key = registry.get(&self.sender_key_id)
            .ok_or(KeyRegistryError::KeyNotFound(self.sender_key_id))?;
        
        let pk = crate::falcon_sigs::falcon_pk_from_bytes(&key.falcon_pk)
            .map_err(|_| KeyRegistryError::InvalidFalconKeySize(key.falcon_pk.len()))?;
        
        let msg = self.signing_message();
        Ok(crate::falcon_sigs::falcon_verify_bytes(&msg, &self.falcon_sig, &pk).is_ok())
    }

    /// Rozmiar w bajtach
    pub fn size(&self) -> usize {
        32 + 32 + 8 + 8 + 8 + 32 + self.falcon_sig.len()
    }

    /// Oszczędność vs pełna TX
    pub fn savings_vs_full() -> usize {
        // Pełna TX: 32 + 32 + 8 + 8 + 8 + 897 + 1184 + 666 = ~2835B
        // Kompaktowa: 32 + 32 + 8 + 8 + 8 + 32 + 666 = ~786B
        2835 - 786 // = 2049B
    }

    /// Oblicz TX ID
    pub fn tx_id(&self) -> [u8; 32] {
        use sha3::{Sha3_256, Digest};
        let mut h = Sha3_256::new();
        Digest::update(&mut h, &self.from);
        Digest::update(&mut h, &self.to);
        Digest::update(&mut h, &self.amount.to_le_bytes());
        Digest::update(&mut h, &self.fee.to_le_bytes());
        Digest::update(&mut h, &self.nonce.to_le_bytes());
        Digest::update(&mut h, &self.sender_key_id);
        h.finalize().into()
    }

    /// Message do podpisu
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(120);
        msg.extend_from_slice(&self.from);
        msg.extend_from_slice(&self.to);
        msg.extend_from_slice(&self.amount.to_le_bytes());
        msg.extend_from_slice(&self.fee.to_le_bytes());
        msg.extend_from_slice(&self.nonce.to_le_bytes());
        msg.extend_from_slice(&self.sender_key_id);
        msg
    }
}

// ============================================================================
// BATCH TRANSFERS
// ============================================================================

/// Pojedynczy output w batchu
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferOutput {
    /// Adres odbiorcy (32B)
    pub to: [u8; 32],
    /// Kwota (8B)
    pub amount: u64,
}

/// Batch transferów od jednego nadawcy
/// 
/// Dla 10 odbiorców:
/// - Pojedyncze TX: 10 × 786B = 7860B
/// - Batch: 32 + 32 + (10 × 40) + 8 + 8 + 666 = 1146B
/// - Oszczędność: 85%!
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchTransfer {
    /// Adres nadawcy (32B) - dla spójności z CompactSimpleTx
    pub from: [u8; 32],
    /// Key ID nadawcy (32B)
    pub sender_key_id: [u8; 32],
    /// Lista odbiorców i kwot
    pub outputs: Vec<TransferOutput>,
    /// Łączna opłata (8B)
    pub total_fee: u64,
    /// Nonce (8B)
    pub nonce: u64,
    /// JEDEN podpis Falcon dla całego batcha (~666B)
    pub falcon_sig: Vec<u8>,
}

impl BatchTransfer {
    /// Utwórz i podpisz nowy batch
    pub fn sign(
        from: [u8; 32],
        sender_key_id: [u8; 32],
        outputs: Vec<TransferOutput>,
        total_fee: u64,
        nonce: u64,
        falcon_sk: &crate::falcon_sigs::FalconSecretKey,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut batch = Self {
            from,
            sender_key_id,
            outputs,
            total_fee,
            nonce,
            falcon_sig: vec![],
        };
        let msg = batch.signing_message();
        let signed = crate::falcon_sigs::falcon_sign(&msg, falcon_sk)?;
        batch.falcon_sig = signed.signed_message_bytes.clone();
        Ok(batch)
    }

    /// Weryfikuj podpis używając registry
    pub fn verify(&self, registry: &PublicKeyRegistry) -> Result<bool, KeyRegistryError> {
        let key = registry.get(&self.sender_key_id)
            .ok_or(KeyRegistryError::KeyNotFound(self.sender_key_id))?;
        
        let pk = crate::falcon_sigs::falcon_pk_from_bytes(&key.falcon_pk)
            .map_err(|_| KeyRegistryError::InvalidFalconKeySize(key.falcon_pk.len()))?;
        
        let msg = self.signing_message();
        Ok(crate::falcon_sigs::falcon_verify_bytes(&msg, &self.falcon_sig, &pk).is_ok())
    }

    /// Rozmiar w bajtach
    pub fn size(&self) -> usize {
        32 + 32 + (self.outputs.len() * 40) + 8 + 8 + self.falcon_sig.len()
    }

    /// Oszczędność vs pojedyncze TX
    pub fn savings_percent(&self) -> f64 {
        let individual_size = self.outputs.len() * 786; // CompactSimpleTx
        let batch_size = self.size();
        (1.0 - (batch_size as f64 / individual_size as f64)) * 100.0
    }

    /// Łączna kwota wszystkich outputów
    pub fn total_amount(&self) -> u64 {
        self.outputs.iter().map(|o| o.amount).sum()
    }

    /// Message do podpisu
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(64 + self.outputs.len() * 40 + 16);
        msg.extend_from_slice(&self.from);
        msg.extend_from_slice(&self.sender_key_id);
        for out in &self.outputs {
            msg.extend_from_slice(&out.to);
            msg.extend_from_slice(&out.amount.to_le_bytes());
        }
        msg.extend_from_slice(&self.total_fee.to_le_bytes());
        msg.extend_from_slice(&self.nonce.to_le_bytes());
        msg
    }

    /// Oblicz batch ID
    pub fn batch_id(&self) -> [u8; 32] {
        use sha3::{Sha3_256, Digest};
        let mut h = Sha3_256::new();
        Digest::update(&mut h, &self.signing_message());
        h.finalize().into()
    }
}

// ============================================================================
// TESTY
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_falcon_pk() -> Vec<u8> {
        vec![0x42u8; 897]
    }

    fn dummy_kyber_pk() -> Vec<u8> {
        vec![0x43u8; 1184]
    }

    #[test]
    fn test_key_id_deterministic() {
        let falcon = dummy_falcon_pk();
        let kyber = dummy_kyber_pk();

        let id1 = PublicKeyRegistry::compute_key_id(&falcon, &kyber);
        let id2 = PublicKeyRegistry::compute_key_id(&falcon, &kyber);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_register_and_get() {
        let mut registry = PublicKeyRegistry::new();
        let falcon = dummy_falcon_pk();
        let kyber = dummy_kyber_pk();

        let key_id = registry.register(falcon.clone(), kyber.clone(), 1000, 0).unwrap();

        let retrieved = registry.get(&key_id).unwrap();
        assert_eq!(retrieved.falcon_pk, falcon);
        assert_eq!(retrieved.kyber_pk, kyber);
    }

    #[test]
    fn test_register_duplicate_ok() {
        let mut registry = PublicKeyRegistry::new();
        let falcon = dummy_falcon_pk();
        let kyber = dummy_kyber_pk();

        let key_id1 = registry.register(falcon.clone(), kyber.clone(), 1000, 0).unwrap();
        let key_id2 = registry.register(falcon.clone(), kyber.clone(), 2000, 1).unwrap();

        assert_eq!(key_id1, key_id2);
    }

    #[test]
    fn test_invalid_key_size() {
        let mut registry = PublicKeyRegistry::new();

        let result = registry.register(vec![0u8; 100], dummy_kyber_pk(), 0, 0);
        assert!(matches!(result, Err(KeyRegistryError::InvalidFalconKeySize(100))));

        let result = registry.register(dummy_falcon_pk(), vec![0u8; 100], 0, 0);
        assert!(matches!(result, Err(KeyRegistryError::InvalidKyberKeySize(100))));
    }

    #[test]
    fn test_get_by_addr() {
        let mut registry = PublicKeyRegistry::new();
        let falcon = dummy_falcon_pk();
        let kyber = dummy_kyber_pk();

        registry.register(falcon.clone(), kyber.clone(), 1000, 0).unwrap();

        let addr = PublicKeyRegistry::compute_address(&falcon, &kyber);
        let retrieved = registry.get_by_addr(&addr).unwrap();
        assert_eq!(retrieved.falcon_pk, falcon);
    }

    #[test]
    fn test_compact_tx_size() {
        let tx = CompactSimpleTx {
            from: [0u8; 32],
            to: [1u8; 32],
            amount: 1000,
            fee: 10,
            nonce: 1,
            sender_key_id: [2u8; 32],
            falcon_sig: vec![0u8; 666],
        };

        assert_eq!(tx.size(), 32 + 32 + 8 + 8 + 8 + 32 + 666);
        println!("CompactSimpleTx size: {} bytes", tx.size());
        println!("Savings vs full TX: {} bytes (72%)", CompactSimpleTx::savings_vs_full());
    }

    #[test]
    fn test_batch_transfer_savings() {
        let batch = BatchTransfer {
            from: [0u8; 32],
            sender_key_id: [0u8; 32],
            outputs: (0..10).map(|i| TransferOutput {
                to: [i as u8; 32],
                amount: 100,
            }).collect(),
            total_fee: 50,
            nonce: 1,
            falcon_sig: vec![0u8; 666],
        };

        println!("Batch size: {} bytes", batch.size());
        println!("10 individual TX: {} bytes", 10 * 786);
        println!("Savings: {:.1}%", batch.savings_percent());

        assert!(batch.savings_percent() > 80.0);
    }

    #[test]
    fn test_stats() {
        let mut registry = PublicKeyRegistry::new();
        
        for i in 0..5 {
            let mut falcon = dummy_falcon_pk();
            falcon[0] = i;
            let mut kyber = dummy_kyber_pk();
            kyber[0] = i;
            registry.register(falcon, kyber, i as u64 * 1000, i as u64).unwrap();
        }

        let stats = registry.stats();
        println!("{}", stats);
        assert_eq!(stats.total_keys, 5);
        assert_eq!(stats.total_bytes_stored, 5 * (897 + 1184));
    }

    #[test]
    fn test_record_usage() {
        let mut registry = PublicKeyRegistry::new();
        
        // Zarejestruj klucz
        registry.register(dummy_falcon_pk(), dummy_kyber_pk(), 0, 0).unwrap();
        
        // Początkowe saved = 0
        assert_eq!(registry.stats().estimated_bytes_saved, 0);
        
        // Symuluj 10 TX używających tego key_id
        for _ in 0..10 {
            registry.record_usage();
        }
        
        // 10 * 2049B = 20490B saved
        assert_eq!(registry.stats().estimated_bytes_saved, 10 * 2049);
        println!("After 10 TX: {} bytes saved", registry.stats().estimated_bytes_saved);
    }

    #[test]
    fn test_persistence() {
        let mut registry = PublicKeyRegistry::new();
        
        // Zarejestruj kilka kluczy
        for i in 0..3 {
            let mut falcon = dummy_falcon_pk();
            falcon[0] = i;
            let mut kyber = dummy_kyber_pk();
            kyber[0] = i;
            registry.register(falcon, kyber, i as u64 * 1000, i as u64).unwrap();
        }

        // Zapisz do pliku
        let temp_path = std::path::PathBuf::from("/tmp/test_key_registry.bin");
        registry.save_to_file(&temp_path).unwrap();
        
        // Wczytaj do nowego registry
        let loaded = PublicKeyRegistry::load_from_file(&temp_path).unwrap();
        
        // Sprawdz że dane są takie same
        assert_eq!(loaded.stats().total_keys, 3);
        
        // Cleanup
        std::fs::remove_file(&temp_path).ok();
        println!("Persistence test passed!");
    }

    #[test]
    fn test_sign_verify_real_falcon_keys() {
        use crate::falcon_sigs::{falcon_keypair, falcon_pk_to_bytes};
        
        let mut registry = PublicKeyRegistry::new();
        
        // Generuj prawdziwe klucze Falcon
        let (pk, sk) = falcon_keypair();
        let falcon_pk_bytes = falcon_pk_to_bytes(&pk).to_vec();
        let kyber_pk = dummy_kyber_pk(); // dummy kyber for this test
        
        // Zarejestruj
        let key_id = registry.register(falcon_pk_bytes.clone(), kyber_pk.clone(), 0, 0).unwrap();
        let from = PublicKeyRegistry::compute_address(&falcon_pk_bytes, &kyber_pk);
        
        println!("Generated real Falcon-512 keypair");
        println!("  key_id: {}", hex::encode(&key_id[..8]));
        println!("  from: {}", hex::encode(&from[..8]));
        
        // Podpisz TX prawdziwym kluczem
        let tx = CompactSimpleTx::sign(
            from,
            [1u8; 32], // to
            1000,      // amount
            10,        // fee
            1,         // nonce
            key_id,
            &sk,
        ).unwrap();
        
        println!("  tx_id: {}", hex::encode(&tx.tx_id()[..8]));
        println!("  sig_len: {} bytes", tx.falcon_sig.len());
        
        // Weryfikuj - powinno przejsc
        let valid = tx.verify(&registry).unwrap();
        assert!(valid, "Valid signature should verify");
        println!("  ✅ Signature verified!");
        
        // Zmodyfikuj TX - powinno sie NIE zweryfikowac
        let mut bad_tx = tx.clone();
        bad_tx.amount = 9999; // zmien kwote
        let invalid = bad_tx.verify(&registry).unwrap();
        assert!(!invalid, "Modified TX should NOT verify");
        println!("  ✅ Modified TX correctly rejected!");
        
        // Zly key_id - powinno dac KeyNotFound
        let mut wrong_key_tx = tx.clone();
        wrong_key_tx.sender_key_id = [0xFFu8; 32];
        let result = wrong_key_tx.verify(&registry);
        assert!(matches!(result, Err(KeyRegistryError::KeyNotFound(_))));
        println!("  ✅ Wrong key_id correctly returns KeyNotFound!");
        
        println!("Real Falcon keys test passed!");
    }
}
