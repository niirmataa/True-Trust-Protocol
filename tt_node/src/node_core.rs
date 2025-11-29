#![forbid(unsafe_code)]

//! NodeCore – „silnik” noda TRUE_TRUST z prostym PQ-ledgerem
//!
//! Spina:
//! - magazyn łańcucha (`ChainStore`),
//! - mechanizm konsensusu PRO (`ConsensusPro`),
//! - prosty mempool (`TxPool`),
//! - prosty publiczny ledger (`SimpleLedger`),
//! - podstawowe API dla RPC / CLI:
//!   - pobieranie wysokości łańcucha,
//!   - najlepszego bloku,
//!   - liczby peerów,
//!   - wrzucanie prostych transakcji do mempoola,
//!   - odczyt balansu,
//!   - przyjęcie SignedStarkTx (STARK + PQC).
//!
//! Uwaga: to jest *publiczny* ledger „account-based”, niezależny od
//! prywatnych not STARK/PQC – te są obsługiwane osobno przez warstwę
//! `pqc_verification` + `state_priv` + `tx_stark`.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::{anyhow, ensure, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::chain_store::ChainStore;
use crate::consensus_pro::ConsensusPro;
use crate::core::{shake256_bytes, Hash32};
use crate::node_id::NodeId;
use crate::tx_stark::SignedStarkTx;

/* =============================================================================
 * Prosty mempool
 * ============================================================================= */

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

    /// Czy mempool jest pusty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

/* =============================================================================
 * Prosty PQ-ledger (publiczny)
 * ============================================================================= */

/// Prosta transakcja PQ-ledgera.
///
/// To jest *publiczny* model: from / to / amount / fee.
/// Pola z podpisem PQ są trzymane jako bytes, żeby serde działało.
/// Weryfikacja podpisu może być zrobiona w innym module (np. RPC),
/// tutaj zakładamy, że dostaliśmy już „autoryzowaną” transakcję.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimplePqTx {
    /// Nadawca – 32-bajtowy identyfikator (np. raw ttq/NodeId).
    pub from: NodeId,
    /// Odbiorca – 32-bajtowy identyfikator.
    pub to: NodeId,
    /// Kwota w najdrobniejszych jednostkach.
    pub amount: u128,
    /// Fee (na razie można „spalić” albo kiedyś przekazać walidatorowi).
    pub fee: u128,
    /// Nonce (na potrzeby idempotencji / anti-replay, później można użyć).
    pub nonce: u64,
    /// Falcon public key bytes nadawcy (opcjonalnie do weryfikacji).
    pub falcon_pk: Vec<u8>,
    /// Falcon signature bytes nadawcy (np. nad tx_id lub canonical-blob).
    pub falcon_sig: Vec<u8>,
}

impl SimplePqTx {
    /// Zwraca kanoniczne bytes transakcji do hash/txid.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        // Tu używamy bincode – ważne, żeby to było deterministyczne.
        bincode::serialize(self).expect("SimplePqTx serialization must not fail")
    }

    /// Liczy txid = SHAKE256(domain || canonical_bytes).
    /// 
    /// Domain separator zapobiega cross-type replay attacks.
    pub fn tx_id(&self) -> Hash32 {
        use tiny_keccak::{Shake, Hasher};
        let mut sh = Shake::v256();
        sh.update(b"TT.v1.NODE_CORE_SIMPLE_PQ_TX");
        sh.update(&self.to_canonical_bytes());
        let mut out = [0u8; 32];
        sh.finalize(&mut out);
        out
    }
}

/// Bardzo prosty ledger: account → balance.
#[derive(Default)]
pub struct SimpleLedger {
    balances: HashMap<NodeId, u128>,
}

impl SimpleLedger {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
        }
    }

    /// Pobierz balans (0 jeśli konto nie istnieje).
    pub fn get_balance(&self, who: &NodeId) -> u128 {
        *self.balances.get(who).unwrap_or(&0)
    }

    /// Zwiększ balans – saturating_add na wypadek przepełnienia.
    pub fn credit(&mut self, who: &NodeId, amount: u128) {
        let e = self.balances.entry(*who).or_insert(0);
        *e = e.saturating_add(amount);
    }

    /// Zmniejsz balans – z kontrolą, że nie schodzimy poniżej zera.
    pub fn debit(&mut self, who: &NodeId, amount: u128) -> Result<()> {
        let e = self.balances.entry(*who).or_insert(0);
        ensure!(*e >= amount, "insufficient balance");
        *e -= amount;
        Ok(())
    }

    /// Zastosuj prostą transakcję:
    /// - sprawdź kwoty,
    /// - zdebetuj nadawcę o (amount + fee),
    /// - zakredytuj odbiorcę o `amount`,
    /// - fee na razie jest „spalone” (można później dodać „fee_sink”).
    pub fn apply_simple_tx(&mut self, tx: &SimplePqTx) -> Result<()> {
        ensure!(tx.amount > 0, "amount must be > 0");
        ensure!(
            tx.from != tx.to,
            "from and to must be different for SimplePqTx"
        );

        let total = tx
            .amount
            .checked_add(tx.fee)
            .ok_or_else(|| anyhow!("amount + fee overflow"))?;

        self.debit(&tx.from, total)?;
        self.credit(&tx.to, tx.amount);

        Ok(())
    }
}

/* =============================================================================
 * NodeConfig / NodeCore
 * ============================================================================= */

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
    /// Prosty publiczny ledger.
    pub ledger: Arc<RwLock<SimpleLedger>>,
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
        let ledger = Arc::new(RwLock::new(SimpleLedger::new()));
        let peer_count = Arc::new(RwLock::new(0usize));

        Ok(Self {
            chain_store,
            consensus,
            tx_pool,
            ledger,
            config,
            is_validator,
            peer_count,
        })
    }

    /// Inicjalizacja stanu genesis na podstawie pliku/bajtu.
    /// Na razie: placeholder, żeby node ruszył bez błędów.
    pub async fn init_genesis(&self, genesis_data: &[u8]) -> Result<()> {
        println!(
            "[NodeCore] init_genesis() – TODO: parse genesis ({} bajtów)",
            genesis_data.len()
        );

        // Przykład: gdybyś chciał dać „premine” dla jakiegoś address_id:
        // let some_id: NodeId = [0u8; 32];
        // let mut ledger = self.ledger.write().await;
        // ledger.credit(&some_id, 1_000_000_000);

        Ok(())
    }

    /// Start pętli produkcji bloków / sync (placeholder).
    pub async fn start(&self) -> Result<()> {
        println!(
            "[NodeCore] start() – pętla bloków / sync jeszcze niezaimplementowana (stub)."
        );
        // Tutaj później:
        //  - pętla slotów,
        //  - wybór lidera z ConsensusPro,
        //  - tworzenie bloków z tx_pool,
        //  - broadcast przez P2P,
        //  - commit do ChainStore + aktualizacja ledgeru.
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

    /// Proste przyjęcie surowej transakcji (legacy / debug) – wrzucamy do mempoola i zwracamy txid.
    ///
    /// Uwaga: to *nie* dotyka ledgeru – po prostu blob bajtów → mempool.
    pub async fn submit_transaction(&self, tx_bytes: &[u8]) -> Result<Hash32> {
        let mut pool = self.tx_pool.write().await;
        pool.add(tx_bytes.to_vec())?;

        // txid = SHAKE256(tx_bytes)
        let tx_id = shake256_bytes(tx_bytes);
        println!(
            "[NodeCore] submit_transaction() – tx mempooled, id={}",
            hex::encode(tx_id)
        );

        Ok(tx_id)
    }

    /// Zwraca balans konta z prostego PQ-ledgera.
    pub async fn get_balance(&self, id: &NodeId) -> u128 {
        let ledger = self.ledger.read().await;
        ledger.get_balance(id)
    }

    /// Zastosuj prostą publiczną transakcję PQ (SimplePqTx).
    ///
    /// - aktualizuje ledger,
    /// - wrzuca transakcję (kanoniczne bytes) do mempoola,
    /// - zwraca txid (SHAKE256 po kanonicznych bytes).
    ///
    /// Weryfikacja podpisu PQ może być zrobiona *przed* wywołaniem
    /// (np. w RPC, używając `falcon_sigs` i `falcon_pk_from_bytes`).
    pub async fn apply_simple_pq_tx(&self, tx: &SimplePqTx) -> Result<Hash32> {
        // 1) aktualizacja ledgeru
        {
            let mut ledger = self.ledger.write().await;
            ledger
                .apply_simple_tx(tx)
                .map_err(|e| anyhow!("apply_simple_tx failed: {e}"))?;
        }

        // 2) kanoniczne bytes + txid
        let canonical = tx.to_canonical_bytes();
        let tx_id = shake256_bytes(&canonical);

        // 3) wrzucamy do mempoola
        {
            let mut pool = self.tx_pool.write().await;
            pool.add(canonical)?;
        }

        println!(
            "[NodeCore] apply_simple_pq_tx() – tx mempooled, id={}",
            hex::encode(tx_id)
        );

        Ok(tx_id)
    }

    /// Przyjęcie podpisanej transakcji STARK-owej:
    ///  - parsujemy TransactionStark,
    ///  - weryfikujemy dowody (na razie tylko log; można później wymusić),
    ///  - wrzucamy do mempoola *publiczną* reprezentację transakcji,
    ///  - zwracamy txid.
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
