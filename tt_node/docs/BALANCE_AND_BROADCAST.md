# Sprawdzanie Balance i Przesyłanie Transakcji

## Przegląd

Ten dokument wyjaśnia:
1. **Jak sprawdzić balance konta** (lokalny i z sieci)
2. **Jak przesyłać transakcje przez sieć P2P**
3. **Czy potrzebujesz działającego node'a**

## 1. Sprawdzanie Balance

### Lokalny Balance (bez node'a)

Możesz sprawdzić lokalny balance bez działającego node'a:

```bash
advanced_node.exe balance --wallet my_wallet.dat
```

**Co to pokazuje:**
- Balance z lokalnego pliku `wallet.state.json`
- Nonce (numer transakcji)
- Adres portfela

**Uwaga:** To jest **lokalny** balance, nie z blockchaina!

### Balance z Blockchaina (wymaga node'a)

Aby sprawdzić prawdziwy balance z blockchaina, potrzebujesz działającego node'a:

```bash
# Terminal 1: Uruchom node
tt_node.exe run --port 8080

# Terminal 2: Sprawdź balance
advanced_node.exe balance --wallet my_wallet.dat --node 127.0.0.1:8080
```

**Status:** Query z node'a jest w trakcie implementacji. Na razie pokazuje lokalny balance.

## 2. Przesyłanie Transakcji przez Sieć

### Czy potrzebujesz działającego node'a?

**TAK** - aby przesyłać transakcje przez sieć P2P, potrzebujesz działającego node'a.

### Jak to działa:

#### Krok 1: Utwórz transakcję (bez node'a)

Możesz utworzyć transakcję **bez** działającego node'a:

```bash
advanced_node.exe send-confidential \
    --from sender_wallet.dat \
    --to-wallet recipient_wallet.dat \
    --amount 1000 \
    --output tx.json
```

To tworzy plik `tx.json` z zaszyfrowaną transakcją.

#### Krok 2: Wyślij przez sieć (wymaga node'a)

Aby wysłać transakcję przez sieć P2P, potrzebujesz działającego node'a:

```bash
# Terminal 1: Uruchom node
tt_node.exe run --port 8080

# Terminal 2: Wyślij transakcję
advanced_node.exe broadcast --tx tx.json --node 127.0.0.1:8080
```

**Co się dzieje:**
1. Node łączy się z innymi peerami przez P2P
2. Transakcja jest weryfikowana (STARK proofs)
3. Transakcja jest broadcastowana do wszystkich peerów
4. Transakcja trafia do mempool
5. Transakcja jest włączana do bloku przez validatora

### Alternatywa: Ręczne przesyłanie

Jeśli nie masz działającego node'a, możesz:

1. Utworzyć transakcję lokalnie
2. Przesłać plik `tx.json` do kogoś z działającym node'em
3. Ta osoba może dodać transakcję do sieci

## 3. Architektura

### Bez Node'a

```
┌─────────────────┐
│  advanced_node  │
│  (wallet CLI)   │
└────────┬────────┘
         │
         ├─► Utwórz transakcję (tx.json)
         ├─► Sprawdź lokalny balance
         └─► Zarządzaj portfelem
```

**Możesz:**
- ✅ Utworzyć transakcję
- ✅ Sprawdzić lokalny balance
- ✅ Zarządzać portfelem
- ❌ Wysłać przez sieć P2P
- ❌ Sprawdzić balance z blockchaina

### Z Node'em

```
┌─────────────────┐      ┌──────────────┐      ┌──────────────┐
│  advanced_node  │─────►│   tt_node    │─────►│  P2P Network │
│  (wallet CLI)   │      │  (full node) │      │  (peers)     │
└─────────────────┘      └──────────────┘      └──────────────┘
         │                       │
         │                       ├─► Blockchain
         │                       ├─► Mempool
         │                       └─► State
         │
         └─► Query balance
```

**Możesz:**
- ✅ Utworzyć transakcję
- ✅ Wysłać przez sieć P2P
- ✅ Sprawdzić balance z blockchaina
- ✅ Query stanu blockchaina

## 4. Przykłady Użycia

### Przykład 1: Pełny Workflow

```bash
# 1. Utwórz portfele
tt_wallet.exe wallet-init --file alice.dat
tt_wallet.exe wallet-init --file bob.dat

# 2. Sprawdź lokalny balance
advanced_node.exe balance --wallet alice.dat
# Output: Local Balance: 10000 TT

# 3. Utwórz transakcję
advanced_node.exe send-confidential \
    --from alice.dat \
    --to-wallet bob.dat \
    --amount 500 \
    --output tx.json

# 4. Uruchom node (w osobnym terminalu)
tt_node.exe run --port 8080

# 5. Wyślij transakcję
advanced_node.exe broadcast --tx tx.json --node 127.0.0.1:8080

# 6. Sprawdź balance z node'a
advanced_node.exe balance --wallet alice.dat --node 127.0.0.1:8080
```

### Przykład 2: Tylko Utworzenie Transakcji

```bash
# Możesz utworzyć transakcję bez node'a
advanced_node.exe send-confidential \
    --from my_wallet.dat \
    --to-wallet recipient.dat \
    --amount 1000 \
    --output tx.json

# Plik tx.json zawiera gotową transakcję
# Możesz go przesłać później przez node'a
```

### Przykład 3: Sprawdzenie Balance

```bash
# Lokalny balance (bez node'a)
advanced_node.exe balance --wallet my_wallet.dat

# Balance z blockchaina (wymaga node'a)
advanced_node.exe balance --wallet my_wallet.dat --node 127.0.0.1:8080
```

## 5. FAQ

### Q: Czy mogę przesyłać transakcje bez node'a?

**A:** Możesz **utworzyć** transakcję bez node'a, ale aby **wysłać** ją przez sieć P2P, potrzebujesz działającego node'a.

### Q: Jak sprawdzić prawdziwy balance?

**A:** 
1. Uruchom node: `tt_node.exe run --port 8080`
2. Query balance: `advanced_node.exe balance --wallet wallet.dat --node 127.0.0.1:8080`

**Status:** Query z node'a jest w trakcie implementacji.

### Q: Czy mogę użyć zdalnego node'a?

**A:** Tak! Możesz połączyć się z dowolnym node'em w sieci:

```bash
advanced_node.exe balance --wallet wallet.dat --node 192.168.1.100:8080
advanced_node.exe broadcast --tx tx.json --node 192.168.1.100:8080
```

### Q: Co jeśli nie mam node'a?

**A:** Możesz:
1. Utworzyć transakcję lokalnie
2. Przesłać plik `tx.json` do kogoś z node'em
3. Ta osoba doda transakcję do sieci

### Q: Jak uruchomić node?

**A:**
```bash
# Podstawowy node
tt_node.exe run --port 8080

# Z dodatkowymi opcjami
tt_node.exe run --port 8080 --data-dir ./node_data
```

## 6. Status Implementacji

| Funkcja | Status | Uwagi |
|---------|--------|-------|
| Utworzenie transakcji | ✅ Gotowe | Działa bez node'a |
| Lokalny balance | ✅ Gotowe | Z pliku state.json |
| Broadcast przez P2P | 🚧 W trakcie | Wymaga node'a |
| Query balance z node'a | 🚧 W trakcie | Wymaga node'a |
| RPC API | 📋 Planowane | Dla light clients |

## 7. Przyszłe Ulepszenia

### Light Client

W przyszłości będzie możliwe:
- Sprawdzanie balance bez pełnego node'a
- Wysyłanie transakcji przez light client
- Query blockchaina przez RPC

### RPC API

Planowany RPC API pozwoli:
- Query balance przez HTTP
- Wysyłanie transakcji przez HTTP
- Query stanu blockchaina

## 8. Podsumowanie

**Bez node'a możesz:**
- ✅ Utworzyć transakcję
- ✅ Sprawdzić lokalny balance
- ✅ Zarządzać portfelem

**Z node'em możesz:**
- ✅ Wszystko powyżej +
- ✅ Wysłać transakcję przez sieć P2P
- ✅ Sprawdzić balance z blockchaina
- ✅ Query stanu blockchaina

**Rekomendacja:** Uruchom lokalny node dla pełnej funkcjonalności, lub użyj zdalnego node'a w sieci.

