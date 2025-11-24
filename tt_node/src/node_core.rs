#![forbid(unsafe_code)]

//! NodeCore – minimalny „silnik” noda TRUE_TRUST
//!
//! Ten moduł spina:
//! - magazyn łańcucha (`ChainStore`),
//! - mechanizm konsensusu PRO (`ConsensusPro`),
//! - prosty mempool (`TxPool`),
//! - podstawowe API dla RPC / CLI:
//!   - pobieranie wysokości łańcucha,
//!   - najlepszego bloku,
//!   - liczby peerów,
//!   - wrzucanie transakcji do mempoola.
//!
//! Uwaga: pełny prywatny ledger (bilanse z not STARK/PQC) to osobna warstwa.
//! Tutaj mamy tylko hooking pod SignedStarkTx, żeby można było
//! pokazać end-to-end: wallet → STARK tx → podpis Falcon → RPC → node.

// zewnętrzne
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

// wewnętrzne
use crate::chain_store::ChainStore;
use crate::consensus_pro::ConsensusPro;
use crate::core::{shake256_bytes, Hash32};
use crate::node_id::NodeId;
use crate::tx_stark::SignedStarkTx;

/// Bardzo prosty mempool – trzyma surowe bajty transakcji.
/// W demo wystarczy, żeby pokazać przepływ end-to-end.
pub struct TxPool {
    transactions: Vec<Vec<u8>>,
}

impl TxPool {
    /// Nowa, pusta kolejka transakcji.
    pub fn new() -> Self {
        TxPool {
            transactions: Vec::new(),
        }
    }

    /// Dodaj transakcję w formie bajtów.
    pub fn add(&mut self, tx_bytes: Vec<u8>) -> Result<()> {
        self.transactions.push(tx_bytes);
        Ok(())
    }

    /// Liczba transakcji w mempoolu.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }
}

/// Konfiguracja noda (lokalna, nie-consensusowa).
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Katalog danych (łańcuch, stan, itp.).
    pub data_dir: PathBuf,
    /// Identyfikator sieci (np. "tt-mainnet", "tt-testnet").
    pub chain_id: String,
    /// Docelowy czas bloku w milisekundach.
    pub block_time_ms: u64,
}

/// Główna struktura „silnika” noda.
pub struct NodeCore {
    /// Magazyn łańcucha bloków.
    pub chain_store: Arc<RwLock<ChainStore>>,
    /// Stan konsensusu PRO.
    pub consensus: Arc<RwLock<ConsensusPro>>,
    /// Mempool z transakcjami.
    pub tx_pool: Arc<RwLock<TxPool>>,
    /// Konfiguracja lokalna noda.
    pub config: NodeConfig,
    /// Czy ten węzeł jest walidatorem.
    pub is_validator: bool,
    /// Liczba peerów (aktualizowana przez warstwę P2P).
    peer_count: Arc<RwLock<usize>>,
}

impl NodeCore {
    /// Utwórz nowy węzeł (bez uruchamiania sieci / RPC).
    ///
    /// `is_validator = true` oznacza, że node może brać udział w konsensusie.
    pub fn new(data_dir: PathBuf, is_validator: bool) -> Result<Self> {
        let chain_store = Arc::new(RwLock::new(ChainStore::new()));
        let consensus = Arc::new(RwLock::new(ConsensusPro::new_default()));
        let tx_pool = Arc::new(RwLock::new(TxPool::new()));

        let config = NodeConfig {
            data_dir,
            chain_id: "tt-localnet".to_string(),
            block_time_ms: 6000,
        };

        let peer_count = Arc::new(RwLock::new(0usize));

        Ok(NodeCore {
            chain_store,
            consensus,
            tx_pool,
            config,
            is_validator,
            peer_count,
        })
    }

    /// Zainicjalizuj stan genesis na podstawie danych wejściowych.
    ///
    /// Na razie stub – dla demo wystarczy, że API istnieje.
    pub async fn init_genesis(&self, genesis_data: &[u8]) -> Result<()> {
        // TODO: sparsować `genesis_data` i zbudować blok genesis / stan początkowy.
        // Żeby nie mieć warninga o nieużywanej zmiennej:
        let _ = genesis_data;
        Ok(())
    }

    /// Start „silnika” – w wersji demo nic nie robi, ale
    /// można tu dodać timery, produkcję bloków itd.
    pub async fn start(&self) -> Result<()> {
        // TODO: pętla produkcji bloków, gossip P2P, itp.
        Ok(())
    }

    /// Zatrzymaj node – w demo tylko placeholder.
    pub async fn stop(&self) -> Result<()> {
        Ok(())
    }

    /// Wysokość łańcucha wg lokalnego `ChainStore`.
    pub async fn get_chain_height(&self) -> u64 {
        self.chain_store.read().await.get_height()
    }

    /// Hash najlepszego (tip) bloku wg lokalnego `ChainStore`.
    pub async fn get_best_block_hash(&self) -> Hash32 {
        self.chain_store.read().await.get_best_block_hash()
    }

    /// Aktualna liczba peerów (ustawiana przez warstwę P2P).
    pub async fn get_peer_count(&self) -> usize {
        *self.peer_count.read().await
    }

    /// Ustaw liczbę peerów – wołane przez P2P.
    pub async fn set_peer_count(&self, count: usize) {
        let mut pc = self.peer_count.write().await;
        *pc = count;
    }

    /// Wrzucenie „surowej” transakcji do mempoola.
    ///
    /// Hash transakcji liczony jako SHAKE256(tx_bytes) → Hash32.
    pub async fn submit_transaction(&self, tx_bytes: &[u8]) -> Result<Hash32> {
        let id = shake256_bytes(tx_bytes);
        self.tx_pool
            .write()
            .await
            .add(tx_bytes.to_vec())?;
        Ok(id)
    }

    /// Wrzucenie podpisanej transakcji STARK (Falcon + STARK).
    ///
    /// - weryfikuje podpis Falcon nad całą strukturą,
    /// - weryfikuje dowody STARK (range, sum itp. – wg `TransactionStark::verify_all_proofs`),
    /// - po sukcesie wrzuca zserializowanego `SignedStarkTx` do mempoola
    ///   i zwraca `tx_id` (Hash32) z `TransactionStark::id()`.
    pub async fn submit_signed_stark_tx(&self, stx: &SignedStarkTx) -> Result<Hash32> {
        // 1) Falcon + STARK
        stx.verify_all()?;

        // 2) Id transakcji (deterministyczny hash z `TransactionStark`)
        let id = stx.tx.id();

        // 3) Zapisujemy całą strukturę w mempoolu w formie binarnej
        let bytes = bincode::serialize(stx)?;
        self.tx_pool.write().await.add(bytes)?;

        Ok(id)
    }

    /// Stub do pokazywania API `GetBalance` w RPC.
    ///
    /// Prawdziwy prywatny bilans z not STARK/Kyber wymaga skanowania
    /// historii z kluczami oglądania – to robi portfel, nie node.
    ///
    /// Tu node może ewentualnie trzymać:
    /// - publiczne saldo „klasyczne”,
    /// - albo statystyki dla prezentacji.
    ///
    /// Na razie zwraca 0, żeby API się kompilowało i było demonstracyjne.
    pub async fn get_balance(&self, _id: &NodeId) -> u128 {
        0
    }
}
