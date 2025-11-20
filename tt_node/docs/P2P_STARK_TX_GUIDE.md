# Przewodnik: Transakcje STARK przez P2P z Kyber

## Przegląd

Ten przewodnik pokazuje jak wysyłać transakcje STARK (`TransactionStark`) przez sieć P2P z użyciem szyfrowania Kyber-768.

## Architektura

```
┌─────────────┐                    ┌─────────────┐
│   Node A    │                    │   Node B    │
│             │                    │             │
│ 1. Create   │                    │             │
│    STARK TX │                    │             │
│             │                    │             │
│ 2. Verify   │                    │             │
│    Proofs   │                    │             │
│             │                    │             │
│ 3. Send via │  ────────────────> │ 4. Receive  │
│    Secure   │  (Kyber encrypted) │    & Verify │
│    Channel  │                    │             │
│             │                    │             │
└─────────────┘                    └─────────────┘
```

## Warstwy bezpieczeństwa

1. **STARK Proofs**: Weryfikują, że kwoty są w poprawnym zakresie
2. **Kyber-768 Encryption**: Szyfruje wartości w transakcji (tylko odbiorca może odszyfrować)
3. **Secure P2P Channel**: Każde połączenie P2P używa Kyber KEM do negocjacji klucza sesji
4. **XChaCha20-Poly1305**: Szyfruje wiadomości P2P na poziomie transportu

## Użycie

### 1. Podstawowe użycie - Broadcast do wszystkich peerów

```rust
use tt_node::p2p::P2PNetwork;
use tt_node::p2p::tx_broadcast::broadcast_stark_tx;
use tt_node::tx_stark::{TransactionStark, TxOutputStark};
use tt_node::kyber_kem::kyber_keypair;

// Utwórz transakcję STARK
let (recipient_kyber_pk, _) = kyber_keypair();
let recipient: NodeId = [0x02; 32];
let output = TxOutputStark::new_confidential(
    1000, // kwota
    recipient,
    &recipient_kyber_pk,
)?;

let tx = TransactionStark {
    inputs: vec![],
    outputs: vec![output],
    fee: 10,
    nonce: 1,
    timestamp: now(),
};

// Wyślij do wszystkich peerów
let peer_count = broadcast_stark_tx(&network, tx).await?;
println!("Wysłano do {} peerów", peer_count);
```

### 2. Wysyłanie do konkretnego peera

```rust
use tt_node::p2p::tx_broadcast::send_stark_tx_to_peer;

// Wyślij do konkretnego peera
let peer_id: NodeId = [0x03; 32];
send_stark_tx_to_peer(&network, &peer_id, tx).await?;
```

### 3. Obsługa przychodzących transakcji

W handlerze wiadomości P2P:

```rust
use tt_node::p2p::tx_broadcast::handle_incoming_stark_tx;
use tt_node::p2p::P2PMessage;

match message {
    P2PMessage::NewTransactionStark { tx } => {
        handle_incoming_stark_tx(tx, sender_id)?;
        // Dodaj do mempool, zweryfikuj balans, etc.
    }
    _ => {}
}
```

### 4. Pełny przykład z obsługą wiadomości

```rust
use tt_node::p2p::{P2PNetwork, P2PMessage};
use tt_node::p2p::tx_broadcast::{broadcast_stark_tx, handle_incoming_stark_tx};

// Nasłuchuj wiadomości
let network_clone = Arc::clone(&network);
tokio::spawn(async move {
    let mut rx = network_clone.message_rx.read().await.take().unwrap();
    while let Some((sender_id, msg)) = rx.recv().await {
        match msg {
            P2PMessage::NewTransactionStark { tx } => {
                if let Err(e) = handle_incoming_stark_tx(tx, sender_id) {
                    eprintln!("Błąd obsługi STARK TX: {}", e);
                }
            }
            _ => {}
        }
    }
});

// Wyślij transakcję
broadcast_stark_tx(&network, my_tx).await?;
```

## Format wiadomości P2P

### NewTransactionStark

```rust
P2PMessage::NewTransactionStark {
    tx: TransactionStark {
        inputs: Vec<TxInputStark>,
        outputs: Vec<TxOutputStark>,  // Zawiera STARK proofs + Kyber encryption
        fee: u64,
        nonce: u64,
        timestamp: u64,
    }
}
```

### TransactionStark struktura

- **inputs**: Wejścia transakcji (z podpisami Falcon)
- **outputs**: Wyjścia z:
  - `value_commitment`: Hash zobowiązania do wartości
  - `stark_proof`: Dowód STARK że wartość jest w zakresie
  - `recipient`: Adres odbiorcy
  - `encrypted_value`: Zaszyfrowana wartość (nonce || AEAD || KyberCT)

## Bezpieczeństwo

### ✅ Co jest chronione:

1. **Wartości transakcji**: Szyfrowane Kyber-768, tylko odbiorca może odszyfrować
2. **STARK Proofs**: Weryfikują poprawność bez ujawniania wartości
3. **Transport P2P**: Każde połączenie ma własny klucz sesji (Kyber KEM)
4. **Autentykacja**: Falcon-512 podpisy dla wejść transakcji

### ⚠️ Uwagi:

- STARK proofs są weryfikowane przed wysłaniem
- Każdy peer weryfikuje proofs przed akceptacją
- Secure channel zapewnia forward secrecy (ephemeral Kyber keys)

## Przykład uruchomienia

```bash
# Terminal 1: Node A
cargo run --example p2p_stark_tx

# Terminal 2: Node B (w innym katalogu lub z innym portem)
# Połącz się z Node A i wyślij transakcję
```

## Debugowanie

Włącz logi P2P:

```rust
env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
```

Zobaczysz:
- `[P2P] ✅ Sent STARK transaction to peer ...`
- `[P2P] 📨 Received STARK transaction from peer ...`
- `[P2P] ✅ Transaction verified: TX ID = ...`

## API Reference

### `broadcast_stark_tx(network, tx) -> Result<usize>`
Wysyła transakcję STARK do wszystkich połączonych peerów.

### `send_stark_tx_to_peer(network, peer_id, tx) -> Result<()>`
Wysyła transakcję STARK do konkretnego peera.

### `handle_incoming_stark_tx(tx, sender_id) -> Result<()>`
Obsługuje przychodzącą transakcję STARK (weryfikuje proofs).

### `request_stark_txs(network, peer_id) -> Result<()>`
Prosi peera o listę transakcji STARK z mempool.

### `send_stark_txs_list(network, peer_id, txs) -> Result<()>`
Wysyła listę transakcji STARK do peera (odpowiedź na request).

