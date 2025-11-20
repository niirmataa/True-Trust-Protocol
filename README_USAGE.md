# TRUE_TRUST - Instrukcja Użycia

## 🎮 Dostępne Programy

### 1. `tt_wallet.exe` - Pełny Portfel PQC
**Status:** ✅ W pełni funkcjonalny

```powershell
# Utwórz portfel
.\target\release\tt_wallet.exe wallet-init --file my_wallet.dat

# Zobacz adres
.\target\release\tt_wallet.exe wallet-addr --file my_wallet.dat

# Zmień hasło
.\target\release\tt_wallet.exe wallet-rekey --file my_wallet.dat

# Shamir secret sharing (3-z-5)
.\target\release\tt_wallet.exe shards-create --file my_wallet.dat --out-dir ./shards --m 3 --n 5

# Odzyskaj z shardów
.\target\release\tt_wallet.exe shards-recover --input shard-1-of-5.json,shard-2-of-5.json,shard-3-of-5.json --out recovered.dat
```

### 2. `simple_node.exe` - Prosty Node CLI
**Status:** ✅ Funkcjonalny (bez live P2P)

```powershell
# Utwórz portfel
.\target\release\simple_node.exe new-wallet --output alice.json --name "Alice"

# Zobacz informacje
.\target\release\simple_node.exe info --wallet alice.json

# Lista wszystkich portfeli
.\target\release\simple_node.exe list-wallets --dir .

# Wyślij transakcję
.\target\release\simple_node.exe send \
  --from alice.json \
  --to a1b2c3d4e5f67890... \
  --amount 1000 \
  --output tx_alice_to_bob.json

# Weryfikuj transakcję
.\target\release\simple_node.exe verify \
  --tx tx_alice_to_bob.json \
  --wallet alice.json

# Utwórz mempool (pula transakcji)
.\target\release\simple_node.exe create-mempool \
  --txs "tx1.json,tx2.json,tx3.json" \
  --output mempool.json
```

### 3. `mining_demo.exe` - Kompletny Mining Pipeline
**Status:** ✅ W pełni funkcjonalny

```powershell
.\target\release\examples\mining_demo.exe
```

**Co robi:**
- Inicjalizuje RandomX dataset (2GB, ~60s)
- Tworzy 3 walidatorów
- Kopie 3 bloki z PoW
- Weryfikuje każdy blok
- Dystrybuuje nagrody

### 4. `tt_node.exe` - Główny Node
**Status:** ✅ Podstawowe funkcje

```powershell
# Informacje o node
.\target\release\tt_node.exe info --crypto

# Demo konsensusu
.\target\release\tt_node.exe consensus-demo --validators 5 --rounds 10

# Benchmarki crypto
.\target\release\tt_node.exe benchmark

# Test wszystkiego
.\target\release\tt_node.exe test-all
```

---

## 📖 Przykładowe Scenariusze

### Scenariusz 1: Prosty Transfer

```powershell
# 1. Utwórz 3 portfele
.\target\release\simple_node.exe new-wallet -o alice.json -n Alice
.\target\release\simple_node.exe new-wallet -o bob.json -n Bob
.\target\release\simple_node.exe new-wallet -o carol.json -n Carol

# 2. Zobacz adresy
.\target\release\simple_node.exe info -w alice.json
.\target\release\simple_node.exe info -w bob.json
.\target\release\simple_node.exe info -w carol.json

# Zapisz adresy:
# Alice: a1b2c3...
# Bob:   d4e5f6...
# Carol: g7h8i9...

# 3. Alice → Bob: 500 TT
.\target\release\simple_node.exe send \
  --from alice.json \
  --to d4e5f6... \
  --amount 500 \
  --output tx1.json

# 4. Bob → Carol: 200 TT
.\target\release\simple_node.exe send \
  --from bob.json \
  --to g7h8i9... \
  --amount 200 \
  --output tx2.json

# 5. Weryfikuj
.\target\release\simple_node.exe verify --tx tx1.json --wallet alice.json
.\target\release\simple_node.exe verify --tx tx2.json --wallet bob.json

# 6. Utwórz mempool
.\target\release\simple_node.exe create-mempool \
  --txs "tx1.json,tx2.json" \
  --output mempool.json

# 7. Zobacz nowe salda
.\target\release\simple_node.exe info -w alice.json  # 10000 - 500 - 10(fee) = 9490
.\target\release\simple_node.exe info -w bob.json    # 10000 + 500 - 200 - 10 = 10290
.\target\release\simple_node.exe info -w carol.json  # 10000 + 200 = 10200
```

### Scenariusz 2: Test Mining

```powershell
# Uruchom pełny pipeline
.\target\release\examples\mining_demo.exe

# Obserwuj:
# - Inicjalizację RandomX (60s)
# - Setup walidatorów
# - Mining bloków (~2-10s każdy)
# - Weryfikację PoW
# - Dystrybucję nagród
```

### Scenariusz 3: Bezpieczny Backup (Shamir)

```powershell
# 1. Utwórz portfel
.\target\release\tt_wallet.exe wallet-init --file important.dat

# 2. Podziel na 5 części (potrzeba 3)
.\target\release\tt_wallet.exe shards-create \
  --file important.dat \
  --out-dir ./backup \
  --m 3 \
  --n 5

# 3. Rozdaj shardy różnym osobom/miejscom
# backup/shard-1-of-5.json → USB stick
# backup/shard-2-of-5.json → Email
# backup/shard-3-of-5.json → Cloud
# backup/shard-4-of-5.json → Paper backup
# backup/shard-5-of-5.json → Hardware wallet

# 4. Odzyskaj (potrzeba 3 z 5)
.\target\release\tt_wallet.exe shards-recover \
  --input "backup/shard-1-of-5.json,backup/shard-3-of-5.json,backup/shard-4-of-5.json" \
  --out recovered.dat
```

---

## 🔧 Rozwiązywanie Problemów

### "Insufficient balance"
Każdy portfel startuje z 10000 TT. Pamiętaj o fee (10 TT).

### "Invalid address length"
Adresy muszą być 64 znaki hex (32 bajty).

### "Signature verification failed"
Sprawdź czy używasz właściwego portfela do weryfikacji.

### Mining zbyt wolny
Normalne! RandomX wymaga ~200-500 H/s na CPU.
Dostosuj difficulty w `mining_demo.rs` dla testów.

---

## 📚 Więcej Info

- `WALLET_USAGE.md` - Szczegóły portfela
- `MINING_GUIDE.md` - Mining i consensus
- `PROJECT_STATUS.md` - Status projektu
- `FINAL_SETUP.md` - Setup i troubleshooting

---

**TRUE_TRUST Protocol**
*Post-Quantum Blockchain | Built with Rust 🦀*

