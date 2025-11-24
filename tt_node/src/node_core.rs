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
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

// wewnętrzne
use crate::chain_store::ChainStore;
use crate::consensus_pro::ConsensusPro;
use crate::core::{shake256_bytes, Hash32};
use crate::node_id::NodeId;
use crate::tx_stark::SignedStarkTx;
use anyhow::{Result, anyhow, ensure};
use crate::falcon_sigs::{falcon_verify_block, falcon_pk_from_bytes};

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
    /// Utwórz nowy rdzeń noda. `is_validator` określa, czy węzeł ma produkować bloki.
    pub fn new(data_dir: PathBuf, is_validator: bool) -> Result<Self> {
        let config = NodeConfig {
            data_dir,
            chain_id: "tt-devnet".to_string(),
            block_time_ms: 6_000,
        };

        let chain_store = Arc::new(RwLock::new(ChainStore::new()));
        let consensus = Arc::new(RwLock::new(ConsensusPro::new_default()));
        let tx_pool = Arc::new(RwLock::new(TxPool::new()));
        let peer_count = Arc::new(RwLock::new(0usize));

        Ok(Self {
            chain_store,
            consensus,
            tx_pool,
            config,
            is_validator,
            peer_count,
        })
    }

    /// Inicjalizacja stanu genesis na podstawie pliku/bajtu.
    /// Na razie: miejsce na logikę, żeby node ruszył bez błędów.
    pub async fn init_genesis(&self, genesis_data: &[u8]) -> Result<()> {
        println!(
            "[NodeCore] init_genesis() – TODO parse genesis ({} bajtów)",
            genesis_data.len()
        );
        // TODO: sparsować genesis_data, zbudować blok genesis, wstawić do ChainStore.
        Ok(())
    }

    /// Start pętli produkcji bloków / sync (placeholder).
    pub async fn start(&self) -> Result<()> {
        println!(
            "[NodeCore] start() – pętla bloków / sync jeszcze niezaimplementowana (stub)."
        );
        // Tutaj później:
        // - pętla slotów
        // - wybór lidera z ConsensusPro
        // - tworzenie bloków z tx_pool
        // - broadcast przez P2P
        Ok(())
    }

    /// Graceful shutdown (na razie tylko log).
    pub async fn stop(&self) -> Result<()> {
        println!("[NodeCore] stop() – graceful shutdown stub.");
        Ok(())
    }

    /// Zwraca wysokość łańcucha z ChainStore.
    pub async fn get_chain_height(&self) -> u64 {
        let store = self.chain_store.read().await;
        store.get_height()
    }

    /// Zwraca hash najlepszego znanego bloku.
    pub async fn get_best_block_hash(&self) -> Hash32 {
        let store = self.chain_store.read().await;
        store.get_best_block_hash()
    }

    /// Aktualna liczba peerów (ustawiana przez warstwę P2P).
    pub async fn get_peer_count(&self) -> usize {
        *self.peer_count.read().await
    }

    /// Ustaw liczbę peerów – będzie wołane z P2PNetwork.
    pub async fn set_peer_count(&self, count: usize) {
        let mut pc = self.peer_count.write().await;
        *pc = count;
    }

    /// Proste przyjęcie surowej transakcji (bez STARK) – wrzucamy do mempoola i zwracamy txid.
    pub async fn submit_transaction(&self, tx_bytes: &[u8]) -> Result<Hash32> {
        let mut pool = self.tx_pool.write().await;
        pool.add(tx_bytes.to_vec())?;

        // txid = SHAKE256( tx_bytes )
        let tx_id = crate::core::shake256_bytes(tx_bytes);
        println!(
            "[NodeCore] submit_transaction() – tx mempooled, id={}",
            hex::encode(tx_id)
        );

        Ok(tx_id)
    }

    /// Dummy balance – na razie 0, żeby RPC miało co zwrócić.
    pub async fn get_balance(&self, _id: &NodeId) -> u128 {
        // TODO: podpiąć do prawdziwego stanu kont
        0
    }

    /// Przyjęcie podpisanej transakcji STARK-owej:
    /// - parsujemy TransactionStark
    /// - opcjonalnie weryfikujemy dowody
    /// - wrzucamy do mempoola
    /// - zwracamy txid
    pub async fn submit_signed_stark_tx(&self, stx: &SignedStarkTx) -> Result<Hash32> {
        // 1) Parsujemy wewnętrzną transakcję
        let tx = stx
            .parse_tx()
            .map_err(|e| anyhow!("parse Stark tx failed: {e}"))?;

        // 2) Weryfikujemy dowody (na razie tylko log; możesz dodać enforce)
        let (ok, total) = tx.verify_all_proofs();
        println!(
            "[NodeCore] submit_signed_stark_tx() – STARK proofs: {}/{} ok",
            ok, total
        );

        // 3) Liczymy txid
        let tx_id = stx
            .tx_id()
            .map_err(|e| anyhow!("computing tx_id for Stark tx failed: {e}"))?;

        // 4) Wrzucamy zserializowaną transakcję do mempoola
        let bytes = tx.to_bytes();
        let mut pool = self.tx_pool.write().await;
        pool.add(bytes)?;

        println!(
            "[NodeCore] Stark tx mempooled, id={}",
            hex::encode(tx_id)
        );

        Ok(tx_id)
    }
}
