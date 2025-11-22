# Advanced Node - tt_wallet w Akcji!

## 🌟 Co to jest `advanced_node`?

`advanced_node` to wersja węzła TRUE_TRUST, która **zawsze** korzysta z szyfrowanych
portfeli `tt_wallet` oraz łączy STARK range proofs z szyfrowaniem Kyber-768.
Klucze nigdy nie są przechowywane w plaintext, a saldo i nonce trzymamy w
lekko wagowym pliku stanu (`*.state.json`).

### ✅ STARK Range Proofs
- Dowodzą, że kwota transakcji jest w poprawnym zakresie
- Bez ujawniania dokładnej kwoty
- Oparte o `tx_stark.rs`

### ✅ Kyber Encryption
- Kwoty są szyfrowane Kyber-768 (KEM)
- Tylko odbiorca może odszyfrować kwotę
- Pełna poufność transakcji

### ✅ tt_wallet Integration
- Portfele szyfrowane (Argon2id/KMAC + AES-GCM-SIV/XChaCha20-Poly1305)
- Obsługa pepper policy i Shamir Secret Sharing
- Jedna ścieżka dla kluczy: tylko pliki `.dat` tworzone przez `tt_wallet`

### ✅ Secret Channels
- Kyber KEM dla utworzenia shared secret
- Szyfrowane kanały komunikacji P2P

---

## ⚙️ Kompilacja (wymaga feature `wallet`)

```
cargo build --release --bin advanced_node --features wallet
```

> `advanced_node` ma ustawione `required-features = ["wallet"]`, więc kompilacja
> bez feature `wallet` zakończy się błędem.

---

## 📖 Workflow z `tt_wallet`

### 1. Utwórz szyfrowany portfel (`tt_wallet`)

```bash
# Nowy portfel (wprowadź hasło)
cargo run --release --bin tt_wallet --features wallet -- wallet-init --file alice.dat
cargo run --release --bin tt_wallet --features wallet -- wallet-init --file bob.dat
```

### 2. Sprawdź adresy portfeli

```bash
cargo run --release --bin tt_wallet --features wallet -- wallet-addr --file alice.dat
cargo run --release --bin tt_wallet --features wallet -- wallet-addr --file bob.dat
```

### 3. Zainicjalizuj plik stanu (balance/nonce)

Portfel jest szyfrowany w `*.dat`, natomiast saldo i nonce trzymamy w lekkim
pliku stanu obok portfela:

```bash
./target/release/advanced_node new-wallet --output alice.dat --name "Alice"
./target/release/advanced_node new-wallet --output bob.dat   --name "Bob"
```

**Wynik:** tworzy się `alice.dat.state.json` i `bob.dat.state.json` z domyślnym
saldo (10_000 TT) i nonce=0.

### 4. Wyślij poufną transakcję (STARK + Kyber, klucze z tt_wallet)

```bash
./target/release/advanced_node send-confidential \
  --from alice.dat \
  --to-wallet bob.dat \
  --amount 500 \
  --output tx_confidential.json
```

**Co się dzieje:**
1. `advanced_node` prosi o hasło do `alice.dat` i `bob.dat` (jeśli wymagane przez politykę portfela).
2. Ładuje klucze Falcon/Kyber **bezpośrednio z szyfrowanych plików tt_wallet**.
3. Tworzy `TransactionStark` z zaszyfrowaną kwotą (Kyber-768) i STARK range proof.
4. Aktualizuje `alice.dat.state.json` (saldo - kwota - opłata, nonce +1).

### 5. Odszyfruj transakcję jako odbiorca

```bash
./target/release/advanced_node decrypt-tx \
  --tx tx_confidential.json \
  --wallet bob.dat
```

**Wynik na konsoli:**
```
Output 1:
  Recipient: a1b2c3d4...
  → This output is for YOU!
  ✅ Decrypted amount: 500 TT
  ✅ Commitment verified!
```

### 6. Zweryfikuj STARK proofs (każdy obserwator)

```bash
./target/release/advanced_node verify-proofs --tx tx_confidential.json
```

### 7. Utwórz secret channel (Kyber KEM)

```bash
./target/release/advanced_node create-channel \
  --wallet alice.dat \
  --peer bob.dat \
  --output channel_alice_bob.json
```

**Zapisuje:** ciphertext Kyber i metadane uczestników. Wspólny sekret można
użyć do AES-256-GCM dla komunikacji P2P.

---

## 🔐 Co gdzie jest przechowywane?

| Plik                        | Zawartość                            |
|-----------------------------|--------------------------------------|
| `*.dat` (tt_wallet)         | ZASZYFROWANE klucze Falcon + Kyber   |
| `*.dat.state.json`          | Niezaszyfrowany stan (balance, nonce)|
| `tx_confidential.json`      | Transakcja z wyjściami STARK + Kyber |
| `channel_*.json`            | Ciphertext Kyber dla shared secret   |

> Jeśli potrzebujesz również szyfrować stan, przechowuj `*.state.json` w bezpiecznym
> miejscu lub użyj własnego szyfrowania plików.

---

## 🆚 Porównanie z `simple_node`

| Feature | simple_node | advanced_node (tt_wallet) |
|---------|-------------|----------------------------|
| Przechowywanie kluczy | JSON plaintext | **Szyfrowane tt_wallet** |
| Amount Visible | ✅ Tak | ❌ **Ukryte (Kyber)** |
| STARK Proofs | ❌ Brak | ✅ **Tak** |
| Secret Channels | ❌ Brak | ✅ **Tak** |
| Zarządzanie saldo | W pamięci | Plik stanu obok portfela |

---

## 🛠️ Migracja ze starych portfeli JSON

1. **Wyeksportuj** klucze ze starego portfela (ręcznie lub własnym skryptem).
2. **Utwórz nowy** portfel `tt_wallet wallet-init --file nowy.dat`.
3. **Zaimportuj** klucze do `tt_wallet` (lub użyj `wallet-rekey` jeśli dostępne).
4. Zainicjalizuj plik stanu: `advanced_node new-wallet --output nowy.dat --name "Nowy"`.

---

## ✅ Szybkie komendy (Windows, release)

```powershell
# Kompilacja
cargo build --release --bin advanced_node --features wallet

# Info o portfelu (hasło wymagane)
./target/release/advanced_node.exe info --wallet alice.dat

# Wysyłka poufna
./target/release/advanced_node.exe send-confidential `
  --from alice.dat `
  --to-wallet bob.dat `
  --amount 250 `
  --output tx.json

# Odszyfrowanie
./target/release/advanced_node.exe decrypt-tx --tx tx.json --wallet bob.dat
```

