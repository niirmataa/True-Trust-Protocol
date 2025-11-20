# TRUE-TRUST PROTOCOL - Pełna struktura skompilowanego systemu

## 📦 Workspace Structure

```
TRUE-TRUST-PROTOCOL/
├── Cargo.toml (workspace root)
├── Cargo.lock
├── target/release/          # Skompilowane pliki (release mode)
│   ├── lib*.rlib           # Biblioteki Rust
│   ├── *.exe               # Pliki wykonywalne
│   ├── *.pdb               # Debug symbols
│   └── examples/           # Skompilowane przykłady
└── [projekty członków workspace]
    ├── tt_node/            # Główny projekt węzła
    └── falcon_seeded/      # Biblioteka Falcon z seeded PRNG
```

---

## 🏗️ SKOMPILOWANE KOMPONENTY

### 📚 Biblioteki (Libraries - `.rlib`)

#### 1. `libtt_node.rlib`
**Główna biblioteka węzła blockchain** zawierająca wszystkie moduły:

##### Moduły Core:
- **`core`** - Bloki, hasze, podstawowe struktury
- **`chain_store`** - Przechowywanie blockchain
- **`state_priv`** - Prywatny stan (zkSNARK-ready)
- **`transaction`** - Transakcje podstawowe
- **`node_id`** - Identyfikacja węzłów

##### Kryptografia Post-Quantum:
- **`falcon_sigs`** - Podpisy Falcon-512
- **`kyber_kem`** - Key Exchange ML-KEM (Kyber-768)
- **`crypto_kmac_consensus`** - KMAC dla konsensusu
- **`hybrid_commit`** - Hybrid commitments (Pedersen + PQC)
- **`crypto`** - Moduły kryptograficzne (KMAC, KDF)

##### Konsensus i Proof of Work:
- **`randomx_full`** - RandomX PoW (quantum-safe)
- **`consensus_weights`** - Wagi konsensusu (integer)
- **`consensus_pro`** - ConsensusPro (quality metrics)
- **`golden_trio`** - Golden Trio Consensus Model
- **`rtt_pro`** - RTT Pro (trust/reputation)

##### Zero-Knowledge Proofs:
- **`stark_full`** - STARK proofs (Winterfell)
- **`stark_security`** - Bezpieczeństwo STARK
- **`tx_stark`** - Transakcje ze STARK proofs
- **`snapshot_pro`** - Snapshot proofs
- **`snapshot_witness`** - Witness generation
- **`winterfell_range`** - Winterfell range proofs

##### Verifikacja PQC:
- **`pqc_verification`** - Warstwa weryfikacji post-quantum

##### P2P Networking:
- **`p2p`** - Moduł P2P
  - `mod.rs` - Main P2P module
  - `message.rs` - Protokół wiadomości
  - `network.rs` - Sieć P2P
  - `secure.rs` - Bezpieczne połączenia
  - `tx_broadcast.rs` - Broadcast transakcji

##### Node Core:
- **`node_core`** - Główna logika węzła

##### Wallet (optional feature):
- **`wallet`** - Portfel kryptograficzny
  - `wallet_cli.rs` - CLI portfela
  - `wallet_core.rs` - Logika portfela
  - `wallet_secure.rs` - Bezpieczeństwo portfela

#### 2. `libfalcon_seeded.rlib`
**Biblioteka Falcon z deterministycznym PRNG**
- Implementacja Falcon-512 z seeded random number generator
- Używa PQClean
- Build script dla kompilacji C

---

### 🚀 Wykonywalne Binaries (`.exe`)

#### 1. `tt_node.exe` - **Główny węzeł blockchain**
**Lokalizacja:** `tt_node/src/main.rs`

**Funkcje:**
- Validator mode - węzeł walidujący
- Full node mode - pełny węzeł nie-walidujący
- Light client mode (future)
- Demo mode - demonstracje
- Mining - RandomX PoW
- Consensus participation
- P2P networking

**Komendy CLI:**
```bash
tt_node start              # Uruchom węzeł
tt_node mine               # Mining
tt_node validate           # Tryb walidatora
tt_node demo               # Demostracje
```

#### 2. `simple_node.exe` - **Prosty węzeł interaktywny**
**Lokalizacja:** `tt_node/src/bin/simple_node.rs`

**Funkcje:**
- Manualne tworzenie portfeli
- Generowanie adresów
- Wysyłanie transakcji
- Bez automatycznego P2P (ręczna kontrola)
- Interaktywny CLI

**Użycie:**
```bash
simple_node create-wallet
simple_node generate-address
simple_node send-tx
```

#### 3. `advanced_node.exe` - **Zaawansowany węzeł z STARK**
**Lokalizacja:** `tt_node/src/bin/advanced_node.rs`

**Funkcje:**
- STARK range proofs
- Kyber-encrypted values
- Confidential transactions
- Secret channels
- Pełna prywatność transakcji

**Użycie:**
```bash
advanced_node create-wallet
advanced_node send-private-tx
advanced_node verify-stark
```

#### 4. `tt_wallet.exe` - **Portfel kryptograficzny (TTQ)**
**Lokalizacja:** `tt_node/src/bin/wallet.rs`  
**Feature flag:** `--features wallet`

**Funkcje:**
- Portfel Post-Quantum (v5)
- Tylko PQC: Falcon512 + ML-KEM (Kyber768)
- Brak ECC (zero Ed25519/X25519)
- AEAD: AES-GCM-SIV / XChaCha20-Poly1305
- KDF: Argon2id z lokalnym pepperem
- Shamir M-of-N secret sharing
- Adresy: `ttq:` (Bech32m)

**Komendy:**
```bash
tt_wallet create
tt_wallet show-balance
tt_wallet send
tt_wallet backup
```

#### 5. `node.exe` - **Alternatywny węzeł**
**Lokalizacja:** `tt_node/src/bin/node.rs`

#### 6. `verify_privacy.exe` - **Weryfikacja prywatności**
**Lokalizacja:** `tt_node/src/bin/verify_privacy.rs`

---

### 📝 Przykłady (Examples - w `target/release/examples/`)

#### 1. `mining_demo.exe`
**Lokalizacja:** `tt_node/examples/mining_demo.rs`
- Demonstracja RandomX mining
- Testy Proof of Work
- Benchmarking

#### 2. `multi_node.exe`
**Lokalizacja:** `tt_node/examples/multi_node.rs`
- Symulacja wielu węzłów
- Testy P2P
- Testy konsensusu

#### 3. `p2p_stark_tx.exe`
**Lokalizacja:** `tt_node/examples/p2p_stark_tx.rs`
- Transakcje STARK przez P2P
- Broadcast z ZK proofs
- Testy prywatności

#### 4. `e2e_demo.exe`
**Lokalizacja:** `tt_node/examples/e2e_demo.rs`
- End-to-end demonstracje
- Pełny przepływ transakcji

#### 5. `e2e_full_test.exe`
**Lokalizacja:** `tt_node/examples/e2e_full_test.rs`
- Kompleksowe testy E2E
- Wszystkie funkcje systemu

#### 6. `consensus_rewards_test.exe`
**Lokalizacja:** `tt_node/examples/consensus_rewards_test.rs`
- Testy nagród konsensusu
- Golden Trio model

#### 7. `test_all_features.exe`
**Lokalizacja:** `tt_node/examples/test_all_features.rs`
- Test wszystkich funkcji
- Integration tests

---

## 🔧 Zależności Główne

### Kryptografia:
- `pqcrypto-falcon` - Falcon-512 podpisy
- `pqcrypto-kyber` - ML-KEM (Kyber-768)
- `pqcrypto-traits` - Traity PQC
- `aes-gcm`, `aes-gcm-siv` - Szyfrowanie symetryczne
- `chacha20poly1305` - ChaCha20-Poly1305
- `sha2`, `sha3` - Hash functions
- `merlin` - Transcript dla ZK

### Blockchain:
- `serde`, `bincode` - Serializacja
- `hex` - Hex encoding
- `zeroize` - Secure memory erasure

### Networking:
- `tokio` - Async runtime
- Full features: networking, timers, I/O

### ZK Proofs:
- `winterfell` (optional) - STARK framework
- Feature flag: `winterfell_v2`

### CLI:
- `clap` - Command-line parsing
- `env_logger` - Logging
- `chrono` - Daty/czasy

### Wallet:
- `rpassword` - Password input
- `dirs` - System directories
- `bech32` - Address encoding
- `sharks` - Shamir secret sharing
- `argon2` - Password hashing

---

## 📊 Architektura Systemu

```
┌─────────────────────────────────────────────────────────┐
│                    tt_node.exe                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   P2P Net    │  │  Consensus   │  │    Mining    │ │
│  │   (tokio)    │  │  (Golden)    │  │  (RandomX)   │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  STARK ZK    │  │  PQC Crypto  │  │   Chain DB   │ │
│  │  (Winterfell)│  │ (Falcon/KEM) │  │  (Store)     │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
                          ▲
                          │ uses
                          ▼
┌─────────────────────────────────────────────────────────┐
│              libtt_node.rlib                            │
│  (wszystkie moduły: core, crypto, consensus, p2p, ...)  │
└─────────────────────────────────────────────────────────┘
                          ▲
                          │ uses
                          ▼
┌─────────────────────────────────────────────────────────┐
│          libfalcon_seeded.rlib                          │
│      (Falcon-512 z deterministycznym PRNG)              │
└─────────────────────────────────────────────────────────┘
```

---

## 🔨 Kompilacja

### Debug Mode:
```bash
cargo build
```
**Output:** `target/debug/`

### Release Mode (zoptymalizowany):
```bash
cargo build --release
```
**Output:** `target/release/`

### Z feature flags:
```bash
# Z wallet support
cargo build --release --features wallet

# Z Winterfell STARK
cargo build --release --features winterfell_v2

# Z seeded Falcon
cargo build --release --features seeded_falcon

# Wszystkie features
cargo build --release --features "wallet,winterfell_v2,seeded_falcon"
```

### Profile Release (z Cargo.toml):
```toml
[profile.release]
opt-level = 3      # Maksymalna optymalizacja
lto = true         # Link-time optimization
codegen-units = 1  # Jeden unit dla LTO
strip = true       # Usuń debug symbols (oszczędność miejsca)
```

---

## 📦 Rozmiary Plików (przybliżone)

### Release binaries:
- `tt_node.exe` - ~5-10 MB (zależnie od features)
- `simple_node.exe` - ~3-5 MB
- `advanced_node.exe` - ~5-8 MB
- `tt_wallet.exe` - ~3-5 MB
- `libtt_node.rlib` - ~50-100 MB (library)
- `libfalcon_seeded.rlib` - ~10-20 MB (library)

### Examples:
- Każdy example: ~2-5 MB

---

## 🎯 Główne Funkcje Systemu

### 1. **Post-Quantum Security**
   - Falcon-512 podpisy cyfrowe
   - ML-KEM (Kyber-768) key exchange
   - Quantum-safe hash functions

### 2. **Zero-Knowledge Privacy**
   - STARK range proofs
   - Confidential transactions
   - Merkle tree commitments

### 3. **Consensus**
   - Golden Trio Model
   - RandomX PoW (quantum-safe)
   - Quality-based slashing

### 4. **P2P Networking**
   - Async networking (Tokio)
   - Secure channels
   - Transaction broadcast

### 5. **Wallet System**
   - Quantum-safe addresses (ttq:)
   - Shamir secret sharing
   - Secure key storage

---

## 🚀 Uruchomienie Systemu

### 1. Uruchom pełny węzeł:
```bash
.\target\release\tt_node.exe start --port 8333
```

### 2. Mining:
```bash
.\target\release\tt_node.exe mine
```

### 3. Prosty węzeł (interaktywny):
```bash
.\target\release\simple_node.exe create-wallet
```

### 4. Zaawansowany węzeł (STARK):
```bash
.\target\release\advanced_node.exe create-wallet
```

### 5. Portfel:
```bash
.\target\release\tt_wallet.exe create
```

### 6. Przykłady:
```bash
.\target\release\examples\mining_demo.exe
.\target\release\examples\e2e_demo.exe
```

---

## 📚 Moduły Eksportowane (Public API)

Biblioteka `libtt_node.rlib` eksportuje następujące moduły publiczne:

```rust
pub mod core;
pub mod chain_store;
pub mod state_priv;
pub mod randomx_full;
pub mod falcon_sigs;
pub mod kyber_kem;
pub mod crypto_kmac_consensus;
pub mod hybrid_commit;
pub mod node_id;
pub mod rtt_pro;
pub mod golden_trio;
pub mod consensus_weights;
pub mod consensus_pro;
pub mod snapshot_pro;
pub mod snapshot_witness;
pub mod stark_security;
pub mod stark_full;
pub mod tx_stark;
pub mod crypto;
pub mod pqc_verification;
pub mod p2p;
pub mod node_core;
pub mod transaction;

#[cfg(feature = "wallet")]
pub mod wallet;
```

---

## ✅ Status Kompilacji

**Release mode:** ✅ Kompiluje się poprawnie
**Debug mode:** ✅ Kompiluje się poprawnie
**Warnings:** ⚠️ Niektóre unused variables (niekrytyczne)
**Errors:** ❌ Brak błędów kompilacji

---

*Ostatnia aktualizacja: 2024*

