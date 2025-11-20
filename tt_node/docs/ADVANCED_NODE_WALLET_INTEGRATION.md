# Integracja Advanced Node z tt_wallet

## Przegląd

`advanced_node` teraz używa szyfrowanych portfeli z `tt_wallet` zamiast własnej implementacji. To zapewnia:

- ✅ **Szyfrowane przechowywanie kluczy** (AES-GCM-SIV / XChaCha20-Poly1305)
- ✅ **KDF z Argon2id** lub KMAC256
- ✅ **Pepper policy** dla dodatkowej ochrony
- ✅ **Shamir Secret Sharing** (M-of-N backup)
- ✅ **Bezpieczne zarządzanie hasłami**

## Workflow

### 1. Utworzenie portfela

**Użyj `tt_wallet` do utworzenia szyfrowanego portfela:**

```bash
# Utwórz nowy portfel
tt_wallet.exe wallet-init --file my_wallet.dat

# Zobacz adres portfela
tt_wallet.exe wallet-addr --file my_wallet.dat
```

### 2. Użycie z advanced_node

**Wszystkie komendy `advanced_node` teraz używają portfeli z `tt_wallet`:**

```bash
# Pokaż informacje o portfelu
advanced_node.exe info --wallet my_wallet.dat

# Wyślij poufną transakcję
advanced_node.exe send-confidential \
    --from my_wallet.dat \
    --to-wallet recipient_wallet.dat \
    --amount 1000 \
    --output tx.json

# Odszyfruj otrzymaną transakcję
advanced_node.exe decrypt-tx --tx tx.json --wallet my_wallet.dat

# Zweryfikuj STARK proofs
advanced_node.exe verify-proofs --tx tx.json

# Utwórz secret channel
advanced_node.exe create-channel \
    --wallet my_wallet.dat \
    --peer peer_wallet.dat \
    --output channel.json
```

## Struktura plików

```
my_wallet.dat          # Szyfrowany portfel (tt_wallet format)
my_wallet.dat.state.json  # Stan portfela (balance, nonce) - opcjonalny
```

**Uwaga:** `state.json` jest oddzielnym plikiem do przechowywania stanu (balance, nonce). Klucze są zawsze w szyfrowanym `wallet.dat`.

## Bezpieczeństwo

### Co jest szyfrowane:

- ✅ **Falcon-512 secret key** - klucz podpisywania
- ✅ **Kyber-768 secret key** - klucz KEM
- ✅ **Master seed (32 bytes)** - główny seed dla Shamir

### Co NIE jest szyfrowane:

- ⚠️ **State file** (`*.state.json`) - zawiera balance i nonce, ale NIE zawiera kluczy prywatnych

**Rekomendacja:** Jeśli chcesz szyfrować również state, możesz użyć `tt_wallet wallet-export` do eksportu kluczy i przechowywania ich w bezpiecznym miejscu.

## Przykład użycia

### Krok 1: Utwórz portfele

```bash
# Portfel nadawcy
tt_wallet.exe wallet-init --file alice_wallet.dat
# (wprowadź hasło)

# Portfel odbiorcy  
tt_wallet.exe wallet-init --file bob_wallet.dat
# (wprowadź hasło)
```

### Krok 2: Sprawdź adresy

```bash
tt_wallet.exe wallet-addr --file alice_wallet.dat
tt_wallet.exe wallet-addr --file bob_wallet.dat
```

### Krok 3: Wyślij poufną transakcję

```bash
advanced_node.exe send-confidential \
    --from alice_wallet.dat \
    --to-wallet bob_wallet.dat \
    --amount 500 \
    --output tx_confidential.json
```

**Co się dzieje:**
1. `advanced_node` prosi o hasło do `alice_wallet.dat`
2. Ładuje klucze Falcon i Kyber z szyfrowanego portfela
3. Tworzy transakcję STARK z szyfrowaną wartością (Kyber-768)
4. Zapisuje transakcję do `tx_confidential.json`
5. Aktualizuje `alice_wallet.dat.state.json` (balance, nonce)

### Krok 4: Odbierz i odszyfruj transakcję

```bash
advanced_node.exe decrypt-tx \
    --tx tx_confidential.json \
    --wallet bob_wallet.dat
```

**Co się dzieje:**
1. `advanced_node` prosi o hasło do `bob_wallet.dat`
2. Ładuje klucz Kyber z portfela
3. Odszyfrowuje wartość transakcji (tylko Bob może to zrobić!)
4. Weryfikuje commitment

## Backup i Recovery

### Eksport kluczy (ostrożnie!)

```bash
# Eksportuj publiczne klucze (bezpieczne)
tt_wallet.exe wallet-export --file my_wallet.dat

# Eksportuj SECRET keys (TYLKO dla backup!)
tt_wallet.exe wallet-export --file my_wallet.dat --secret --out backup.json
```

### Shamir Secret Sharing

```bash
# Utwórz 3-of-5 shards
tt_wallet.exe shards-create \
    --file my_wallet.dat \
    --out-dir ./shards \
    --m 3 \
    --n 5

# Odzyskaj z 3 shards
tt_wallet.exe shards-recover \
    --input shards/shard1.json,shards/shard2.json,shards/shard3.json \
    --out recovered_wallet.dat
```

## Migracja ze starego formatu

Jeśli masz stare portfele `advanced_node` (JSON bez szyfrowania):

1. **Eksportuj klucze** ze starego portfela
2. **Utwórz nowy portfel** z `tt_wallet wallet-init`
3. **Zaimportuj klucze** (wymaga modyfikacji `tt_wallet` lub ręcznego procesu)

**Lub** użyj `tt_wallet wallet-rekey` do zmiany hasła/formatu.

## API Reference

### `wallet::api::load_wallet_keyset(wallet_path, password)`
Ładuje wszystkie klucze z szyfrowanego portfela.

### `wallet::api::get_all_keys_from_wallet(wallet_path, password)`
Zwraca: `(FalconPK, FalconSK, KyberPK, KyberSK, NodeId)`

### `wallet::api::get_falcon_keys_from_wallet(wallet_path, password)`
Zwraca tylko klucze Falcon.

### `wallet::api::get_kyber_keys_from_wallet(wallet_path, password)`
Zwraca tylko klucze Kyber.

### `wallet::api::get_wallet_address(wallet_path, password)`
Zwraca NodeId (adres) portfela.

## Różnice od starej wersji

| Stara wersja | Nowa wersja |
|--------------|-------------|
| JSON bez szyfrowania | Szyfrowany format (AES/XChaCha) |
| Klucze w plaintext | Klucze zaszyfrowane hasłem |
| `AdvancedWallet` struct | Używa `tt_wallet` format |
| `wallet.save()` | `tt_wallet wallet-init` |
| `wallet.load()` | `wallet::api::load_wallet_keyset()` |

## Bezpieczeństwo - Best Practices

1. ✅ **Używaj silnych haseł** (min. 16 znaków, mieszane znaki)
2. ✅ **Włącz pepper policy** (domyślnie: `os-local`)
3. ✅ **Używaj Shamir Secret Sharing** dla backup
4. ✅ **Nie przechowuj state.json** w tym samym miejscu co wallet.dat
5. ✅ **Regularnie zmieniaj hasła** (`tt_wallet wallet-rekey`)
6. ⚠️ **Nie commituj wallet.dat** do git!

## Troubleshooting

### "Failed to decrypt wallet (wrong password?)"
- Sprawdź czy używasz poprawnego hasła
- Sprawdź czy plik nie jest uszkodzony
- Spróbuj `tt_wallet wallet-addr --file wallet.dat` aby zweryfikować

### "Wallet file not found"
- Upewnij się że podałeś pełną ścieżkę
- Sprawdź czy plik istnieje: `ls wallet.dat`

### "Insufficient balance"
- Sprawdź `advanced_node info --wallet wallet.dat`
- Balance jest w `wallet.dat.state.json` (jeśli istnieje)

