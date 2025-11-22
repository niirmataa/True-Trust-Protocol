// Plik: tt_node/src/main.rs
#![forbid(unsafe_code)]

// Importy CLI i błędów
use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use std::collections::HashMap;

// --- GŁÓWNE KOMPONENTY TWOJEGO PROJEKTU ---
// Zakładamy, że te moduły istnieją w `lib.rs` lub `src/`
use tt_node::consensus_pro::{ConsensusPro, ValidatorId, Q, ONE_Q};
use tt_node::node_id::NodeId;
use tt_node::tx_stark::{TransactionStark, TxOutputStark};
use tt_node::wallet::api as wallet_api; // API Twojego portfela tt_priv_cli
use tt_node::falcon_sigs::{FalconPublicKey, FalconSecretKey};
use tt_node::kyber_kem::{KyberPublicKey, KyberSecretKey};

// Importy asynchroniczne
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, RwLock};

// --- DEFINICJA STANU WĘZŁA ---

/// Tożsamość PQC węzła, załadowana z zaszyfrowanego portfela.
/// Przechowywana w Arc, aby mogła być bezpiecznie współdzielona.
#[derive(Clone)]
struct NodeIdentity {
    node_id: NodeId, // = adrres = hash(falcon_pk)
    falcon_pk: FalconPublicKey,
    falcon_sk: FalconSecretKey,
    kyber_pk: KyberPublicKey,
    kyber_sk: KyberSecretKey,
}

/// Prosty stan konta (balans + nonce)
/// W prawdziwym systemie byłoby to UTXO, ale trzymajmy się modelu kont.
#[derive(Clone, Debug, Default)]
struct AccountState {
    balance: u128,
    nonce: u64,
}

/// Główny, współdzielony stan całego węzła.
/// Dostęp do niego odbywa się przez Arc<RwLock<...>>.
struct AppState {
    /// Tożsamość tego węzła
    identity: Arc<NodeIdentity>,
    /// Silnik konsensusu (RTT PRO)
    consensus: ConsensusPro,
    /// Baza danych stanu (konta)
    state_db: HashMap<NodeId, AccountState>,
    /// Pula niepotwierdzonych transakcji
    mempool: HashMap<NodeId, TransactionStark>, // HashMapa dla łatwej weryfikacji nonce
}

/// Typ pomocniczy dla współdzielonego stanu
type SharedState = Arc<RwLock<AppState>>;

// Implementacja logiki biznesowej (Warstwa Wykonawcza)
impl AppState {
    /// Weryfikuje transakcję (dowody STARK + stan) i dodaje ją do mempool.
    /// To jest wywoływane przez RPC i P2P.
    ///
    /// 💥 TO JEST JEDEN Z PUNKTÓW INTEGRACJI Z WINTERFELL 💥
    fn verify_and_add_to_mempool(&mut self, tx: TransactionStark) -> Result<()> {
        // 1. Weryfikacja kryptograficzna (STARK)
        // Zakładamy, że `tx.verify_all_proofs()` jest już zintegrowane z WINTERFELL
        let (valid_proofs, total_proofs) = tx.verify_all_proofs();
        if valid_proofs != total_proofs {
            bail!("Invalid STARK proof in transaction");
        }

        // 2. Weryfikacja stanu (Ekonomiczna)
        // TODO: Potrzebujemy sposobu na identyfikację nadawcy transakcji
        // Na razie zakładamy, że transakcja ma pole `sender_id: NodeId`
        let sender_id = tx.inputs[0].prev_output_id; // Przykładowe użycie pola
        let sender_state = self.state_db.entry(sender_id).or_default();

        if tx.nonce != sender_state.nonce {
            bail!("Invalid nonce: expected {}, got {}", sender_state.nonce, tx.nonce);
        }
        
        // TODO: Weryfikacja balansu (musimy zdeszyfrować inputy, co jest trudne)
        // W systemie UTXO sprawdzalibyśmy, czy inputy istnieją.
        // W systemie poufnym musimy polegać na dowodzie STARK, że suma(in) == suma(out) + fee
        
        println!("[Execution] ✅ TX {} verified (proofs ok, nonce ok)", hex::encode(&tx.id()[..4]));

        // 3. Dodanie do mempool
        self.mempool.insert(tx.id(), tx);
        Ok(())
    }

    /// Przetwarza cały blok, weryfikuje i aplikuje transakcje do stanu.
    /// Wywoływane przez konsensus (gdy tworzymy blok) lub P2P (gdy otrzymujemy).
    ///
    /// 💥 TO JEST DRUGI PUNKT INTEGRACJI Z WINTERFELL 💥
    fn process_block(&mut self, block: &SimpleBlock) -> Result<()> {
        println!("[Execution] Processing block {}...", block.height);
        let mut quality_points = 0.0;

        // 1. Weryfikacja podpisu bloku (Falcon)
        // TODO: Weryfikacja podpisu Falcon `block.signature` vs `block.hash`

        for tx in &block.transactions {
            // 2. Weryfikacja STARK (Winterfell)
            let (valid_proofs, total_proofs) = tx.verify_all_proofs();
            if valid_proofs != total_proofs {
                eprintln!("[Execution] ❌ Block invalid: TX {} has bad STARK proof", hex::encode(&tx.id()[..4]));
                // TODO: Ukaranie lidera (ujemna jakość)
                self.consensus.record_quality(block.proposer, 0); // Ukaranie
                bail!("Block contains invalid STARK proof");
            }

            // 3. Aplikowanie transakcji do stanu
            let sender_id = tx.inputs[0].prev_output_id; // Uproszczenie
            let state = self.state_db.entry(sender_id).or_default();
            
            if tx.nonce != state.nonce {
                eprintln!("[Execution] ❌ Block invalid: TX {} has bad nonce", hex::encode(&tx.id()[..4]));
                self.consensus.record_quality(block.proposer, 0); // Ukaranie
                bail!("Block contains invalid nonce");
            }
            
            // TODO: Aplikowanie zmian balansu
            // state.balance -= tx.total_value();
            state.nonce += 1;
            
            quality_points += 1.0; // Punkt za każdą poprawną transakcję
        }

        // 4. Nagroda dla lidera (feedback do konsensusu)
        // Obliczamy `quality_q` na podstawie liczby przetworzonych transakcji
        let final_quality = (quality_points / 10.0).min(1.0); // Przykładowa normalizacja
        let quality_q = (final_quality * ONE_Q as f64) as Q;
        
        self.consensus.record_quality(block.proposer, quality_q);
        
        println!("[Consensus] ✅ Block {} applied. Proposer {} rewarded with quality {}.", 
            block.height, 
            hex::encode(&block.proposer[..4]),
            final_quality
        );
        Ok(())
    }
}

/// Prosta struktura bloku (do demonstracji)
#[derive(Clone)]
struct SimpleBlock {
    height: u64,
    proposer: NodeId,
    transactions: Vec<TransactionStark>,
    // TODO: Dodać podpis Falcon
    // signature: FalconSignature, 
}

// --- MODUŁY WĘZŁA ---

/// Moduł RPC: Obsługuje komendy od użytkownika (np. `send`, `balance`)
mod rpc {
    use super::{SharedState, TransactionStark};
    use axum::{
        extract::State,
        routing::{get, post},
        Json, Router,
    };
    use std::net::SocketAddr;
    use tokio::sync::mpsc;
    use anyhow::Result;

    /// Uruchamia serwer RPC (HTTP)
    pub async fn run_server(
        state: SharedState,
        tx_sender: mpsc::Sender<TransactionStark>,
        port: u16,
    ) {
        let app = Router::new()
            .route("/balance", get(get_balance))
            .route("/send_tx", post(post_send_tx))
            .with_state((state, tx_sender));

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        println!("[RPC] 🚀 Serwer RPC nasłuchuje na http://{}", addr);

        if let Err(e) = axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
        {
            eprintln!("[RPC] ❌ Błąd serwera RPC: {}", e);
        }
    }

    /// Handler: Zwraca balans
    async fn get_balance(
        State((state, _)): State<(SharedState, mpsc::Sender<TransactionStark>)>,
    ) -> Json<String> {
        let app_state = state.read().await;
        let my_balance = app_state.state_db.get(&app_state.identity.node_id)
            .map_or(0, |s| s.balance);
        
        Json(format!("Balans: {} TT", my_balance))
    }

    /// Handler: Przyjmuje i kolejkuje nową transakcję
    async fn post_send_tx(
        State((_, tx_sender)): State<(SharedState, mpsc::Sender<TransactionStark>)>,
        Json(tx): Json<TransactionStark>,
    ) -> Json<String> {
        println!("[RPC] 📨 Otrzymano nową transakcję przez RPC...");
        if let Err(e) = tx_sender.send(tx).await {
            return Json(format!("Błąd kolejkowania transakcji: {}", e));
        }
        Json("Transakcja przyjęta do mempool".to_string())
    }
}

/// Moduł P2P: Zarządza połączeniami z innymi węzłami
mod p2p {
    use super::{SharedState, TransactionStark, SimpleBlock};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    // TODO: Zaimportować Twój protokół P2PMessage i logikę handshake PQC
    // use tt_node::p2p_transport_pq::{P2PMessage, SecureChannel};

    /// Uruchamia główny listener P2P
    pub async fn run_listener(
        state: SharedState,
        tx_sender: mpsc::Sender<TransactionStark>,
        port: u16,
    ) -> Result<()> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await
            .with_context(|| format!("Nie można uruchomić listenera P2P na {}", addr))?;
        
        println!("[P2P] 🌐 Nasłuchiwanie na połączenia peer-to-peer na {}", addr);

        loop {
            let (socket, addr) = listener.accept().await?;
            println!("[P2P] 🔌 Nowe połączenie przychodzące od: {}", addr);

            // Klonujemy zasoby dla nowego zadania
            let peer_state = state.clone();
            let peer_tx_sender = tx_sender.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, peer_state, peer_tx_sender).await {
                    eprintln!("[P2P] ❌ Błąd połączenia z {}: {}", addr, e);
                }
            });
        }
    }

    /// Obsługuje pojedyncze połączenie P2P (po handshaku)
    async fn handle_connection(
        stream: TcpStream,
        state: SharedState,
        tx_sender: mpsc::Sender<TransactionStark>,
    ) -> Result<()> {
        let identity = state.read().await.identity.clone();

        // --- KROK 1: Handshake PQC ---
        println!("[P2P] 🤝 Rozpoczynanie handshake'u PQC (Falcon+Kyber)...");
        // TODO: Zintegrować logikę `p2p_transport_pq`
        // let secure_channel = p2p::perform_handshake(stream, &identity).await?;
        println!("[P2P] ✅ Handshake PQC pomyślny!");

        // --- KROK 2: Pętla odczytu wiadomości ---
        loop {
            // TODO: Odczytaj `P2PMessage` z `secure_channel`
            // let message = secure_channel.read_message().await?;
            
            // Symulacja odczytu wiadomości
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let message: Option<String> = None; // Zastąp prawdziwym odczytem

            match message {
                // Some(P2PMessage::NewTransactionStark(tx)) => {
                //     println!("[P2P] 📨 Otrzymano nową transakcję od peera...");
                //     if let Err(e) = tx_sender.send(tx).await {
                //         eprintln!("[P2P] ❌ Błąd kolejkowania transakcji od peera: {}", e);
                //     }
                // }
                // Some(P2PMessage::NewBlock(block)) => {
                //     println!("[P2P] 📬 Otrzymano nowy blok od peera...");
                //     let mut app_state = state.write().await;
                //     if let Err(e) = app_state.process_block(&block) {
                //         eprintln!("[P2P] ❌ Błąd przetwarzania bloku od peera: {}", e);
                //         // TODO: Ukarać peera
                //     }
                // }
                None => {
                    println!("[P2P] 🔌 Peer się rozłączył.");
                    return Ok(());
                }
                _ => { /* Obsługa innych wiadomości P2P */ }
            }
        }
    }
}

/// Moduł Konsensusu: Uruchamia logikę RTT PRO, weryfikację i tworzenie bloków
mod consensus {
    use super::{SharedState, TransactionStark, SimpleBlock, AppState};
    use tokio::sync::mpsc;
    use tokio::time::{interval, Duration};

    const SLOT_DURATION: Duration = Duration::from_secs(5); // Czas slotu

    /// Uruchamia główną pętlę konsensusu i przetwarzania mempool
    pub async fn run_loop(
        state: SharedState,
        mut tx_receiver: mpsc::Receiver<TransactionStark>,
    ) {
        println!("[Consensus] 🚀 Silnik konsensusu (RTT PRO) uruchomiony.");
        
        // --- Zadanie 1: Przetwarzanie Mempool (Warstwa Wykonawcza) ---
        // To zadanie odbiera transakcje z RPC i P2P, weryfikuje je i dodaje do mempool
        let state_clone = state.clone();
        let mempool_task = tokio::spawn(async move {
            while let Some(tx) = tx_receiver.recv().await {
                let mut app_state = state_clone.write().await;
                if let Err(e) = app_state.verify_and_add_to_mempool(tx) {
                    eprintln!("[Mempool] ❌ Odrzucono transakcję: {}", e);
                }
            }
        });

        // --- Zadanie 2: Pętla Konsensusu (Tworzenie Bloków) ---
        let mut consensus_ticker = interval(SLOT_DURATION);
        let mut current_slot = 0u64;

        loop {
            consensus_ticker.tick().await;
            current_slot += 1;
            println!("[Consensus] ⏰ Slot {}", current_slot);

            let mut app_state = state.write().await;
            
            // 1. Wybierz lidera na ten slot
            let beacon = [0u8; 32]; // TODO: Zintegrować z VRF / RandomX
            let leader_id = app_state.consensus.select_leader(beacon);

            if leader_id.is_none() {
                eprintln!("[Consensus] ⚠️  Brak walidatorów do wyboru lidera!");
                continue;
            }
            
            let leader_id = leader_id.unwrap();
            let my_id = app_state.identity.node_id;

            // 2. Sprawdź, czy to my jesteśmy liderem
            if leader_id == my_id {
                println!("[Consensus] 👑 Jesteśmy liderem slotu {}! Tworzenie bloku...", current_slot);
                
                // 3. Stwórz blok z transakcji w mempool
                let txs: Vec<TransactionStark> = app_state.mempool.values().cloned().collect();
                if txs.is_empty() {
                    println!("[Consensus] 😴 Mempool jest pusty, pomijam tworzenie bloku.");
                    continue;
                }

                let block = SimpleBlock {
                    height: current_slot, // Uproszczenie
                    proposer: my_id,
                    transactions: txs,
                };
                
                // 4. Przetwórz blok (aplikuj do stanu, nagródź siebie)
                // Ta funkcja zweryfikuje STARKi i zaktualizuje `quality_q`
                if let Err(e) = app_state.process_block(&block) {
                    // To nie powinno się zdarzyć, jeśli sami tworzymy blok
                    eprintln!("[Consensus] ❌ KRYTYCZNY BŁĄD: Nie udało się przetworzyć własnego bloku: {}", e);
                } else {
                    // 5. Wyczyść mempool
                    app_state.mempool.clear();

                    // 6. Rozgłoś blok do sieci
                    println!("[Consensus] 📢 Rozgłaszanie bloku {} do sieci...", block.height);
                    // TODO: Dodać logikę rozgłaszania do modułu P2P
                    // p2p_manager.broadcast(P2PMessage::NewBlock(block)).await;
                }
            }
        }
    }
}

// --- LOGIKA KLIENTA RPC ---

/// Logika klienta dla komendy `send`
async fn rpc_client_send_tx(rpc_port: u16, to_address: String, amount: u64) -> Result<()> {
    println!("[Client] 💸 Przygotowywanie transakcji STARK...");
    
    // TODO: To jest miejsce na wywołanie logiki z `advanced_node` CLI
    // 1. Załaduj portfel nadawcy (`tt_priv_cli`)
    // 2. Pobierz klucz publiczny odbiorcy (Kyber)
    // 3. Wygeneruj dowód STARK (Winterfell)
    // 4. Stwórz `TransactionStark`
    
    // Na razie symulujemy pustą transakcję
    let tx = TransactionStark {
        inputs: vec![], // Uproszczenie
        outputs: vec![], // Uproszczenie
        fee: 10,
        nonce: 0, // Węzeł i tak to sprawdzi
        timestamp: 0,
    };

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/send_tx", rpc_port);
    
    println!("[Client] 🚀 Wysyłanie transakcji do węzła RPC...");
    
    let res = client.post(&url)
        .json(&tx)
        .send()
        .await
        .context("Nie udało się połączyć z serwerem RPC")?;

    if res.status().is_success() {
        let body = res.text().await?;
        println!("[Client] ✅ Sukces: {}", body);
    } else {
        bail!("[Client] ❌ Błąd serwera RPC: {}", res.status());
    }
    
    Ok(())
}

/// Logika klienta dla komendy `balance`
async fn rpc_client_check_balance(rpc_port: u16) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/balance", rpc_port);

    let res = client.get(&url)
        .send()
        .await
        .context("Nie udało się połączyć z serwerem RPC")?;
    
    if res.status().is_success() {
        let body = res.text().await?;
        println!("[Client] 💰 {}", body);
    } else {
        bail!("[Client] ❌ Błąd serwera RPC: {}", res.status());
    }
    
    Ok(())
}

// --- GŁÓWNA FUNKCJA MAIN ---

#[derive(Parser)]
#[command(name = "tt_node")]
#[command(about = "TRUE_TRUST Node - PQC + STARKs + RTT Consensus")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Uruchamia węzeł (serwer P2P i RPC)
    Start {
        /// Zaszyfrowany plik portfela (tt_priv_cli)
        #[arg(short, long)]
        wallet: PathBuf,
        
        /// Port P2P
        #[arg(short, long, default_value_t = 9000)]
        port: u16,

        /// Port RPC
        #[arg(short, long, default_value_t = 8080)]
        rpc_port: u16,

        /// Początkowi peerzy (oddzieleni przecinkami)
        #[arg(long)]
        peers: Option<String>,
    },
    /// Wysyła transakcję do działającego węzła
    Send {
        /// Port RPC węzła
        #[arg(short, long, default_value_t = 8080)]
        rpc_port: u16,

        /// Adres odbiorcy (hex)
        #[arg(short, long)]
        to: String,

        /// Kwota
        #[arg(short, long)]
        amount: u64,
    },
    /// Sprawdza balans (łączy się z RPC)
    Balance {
        /// Port RPC węzła
        #[arg(short, long, default_value_t = 8080)]
        rpc_port: u16,
    },
}

/// Główny punkt wejścia
fn main() -> Result<()> {
    // Uruchomienie runtime'u Tokio
    let rt = Runtime::new().context("Nie udało się uruchomić Tokio runtime")?;

    // Przekazanie sterowania do asynchronicznej funkcji `main`
    rt.block_on(async {
        let cli = Cli::parse();
        let result = match cli.command {
            Commands::Start { wallet, port, rpc_port, peers } => {
                start_node(wallet, port, rpc_port, peers).await
            }
            Commands::Send { rpc_port, to, amount } => {
                rpc_client_send_tx(rpc_port, to, amount).await
            }
            Commands::Balance { rpc_port } => {
                rpc_client_check_balance(rpc_port).await
            }
        };

        if let Err(e) = result {
            eprintln!("❌ Błąd: {:?}", e);
            std::process::exit(1);
        }
    })
}

/// Główna funkcja uruchamiająca węzeł
async fn start_node(
    wallet_path: PathBuf,
    p2p_port: u16,
    rpc_port: u16,
    peers: Option<String>,
) -> Result<()> {

    // 1. Załaduj tożsamość z zaszyfrowanego portfela
    println!("[Init] 🔐 Ładowanie portfela PQC z {}...", wallet_path.display());
    // Funkcja `get_all_keys_from_wallet` poprosi o hasło
    let (falcon_pk, falcon_sk, kyber_pk, kyber_sk, node_id) = 
        wallet_api::get_all_keys_from_wallet(&wallet_path, None)
            .context("Nie udało się załadować kluczy z portfela. Użyj `tt_priv_cli` aby go stworzyć.")?;

    let identity = Arc::new(NodeIdentity {
        node_id,
        falcon_pk,
        falcon_sk,
        kyber_pk,
        kyber_sk,
    });
    println!("[Init] ✅ Tożsamość załadowana. Node ID: {}", hex::encode(&node_id[..4]));

    // 2. Zainicjuj stan (Genesis)
    let mut state_db = HashMap::new();
    // Daj samemu sobie stan początkowy (genesis)
    state_db.insert(node_id, AccountState { balance: 1_000_000, nonce: 0 });

    let mut consensus = ConsensusPro::new_default();
    // Zarejestruj siebie jako walidatora (z wagą 100)
    consensus.register_validator(node_id, 100);
    consensus.update_all_trust(); // Oblicz początkowy trust

    let app_state = Arc::new(RwLock::new(AppState {
        identity: identity.clone(),
        consensus,
        state_db,
        mempool: HashMap::new(),
    }));
    println!("[Init] ✅ Stan Genesis i konsensus (RTT PRO) gotowe.");

    // 3. Stwórz kanały komunikacyjne
    // Kolejka na transakcje przychodzące z RPC i P2P
    let (tx_sender, tx_receiver) = mpsc::channel::<TransactionStark>(256);

    // 4. Uruchom wszystkie podsystemy jako osobne zadania (Tasks)

    // Zadanie 1: Serwer RPC
    let rpc_state = app_state.clone();
    let rpc_tx_sender = tx_sender.clone();
    tokio::spawn(async move {
        rpc::run_server(rpc_state, rpc_tx_sender, rpc_port).await;
    });

    // Zadanie 2: Listener P2P
    let p2p_state = app_state.clone();
    let p2p_tx_sender = tx_sender.clone();
    tokio::spawn(async move {
        if let Err(e) = p2p::run_listener(p2p_state, p2p_tx_sender, p2p_port).await {
            eprintln!("[P2P] ❌ Krytyczny błąd listenera P2P: {}", e);
        }
    });
    
    // Zadanie 3: Połącz się z początkowymi peerami
    if let Some(peer_list) = peers {
        // TODO: Dodać logikę łączenia się z peerami
        println!("[P2P] 🔗 Łączenie z peerami: {}", peer_list);
    }
    
    // Zadanie 4 (Główne): Uruchom pętlę konsensusu i mempool
    // Ta funkcja przejmuje główny wątek
    println!("[Init] ✅ Uruchamianie pętli konsensusu...");
    consensus::run_loop(app_state, tx_receiver).await;

    Ok(())
}
