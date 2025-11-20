# Advanced Node - tx_stark.rs w Akcji!

## 🌟 Co to jest `advanced_node`?

To jest **PRAWDZIWA** implementacja z:

### ✅ STARK Range Proofs
- Dowodzi że wartość transakcji jest w poprawnym zakresie
- Bez ujawniania dokładnej kwoty
- Używa naszego `stark_full.rs`

### ✅ Kyber Encryption
- Wartości transakcji są **zaszyfrowane** Kyber-768
- Tylko odbiorca może odszyfrować kwotę
- Pełna poufność

### ✅ Confidential Transactions
- Struktury z `tx_stark.rs`
- `TxOutputStark` - output z STARK proof + Kyber encryption
- `TransactionStark` - pełna transakcja

### ✅ Secret Channels
- Kyber KEM dla utworzenia shared secret
- Szyfrowane kanały komunikacji
- P2P encryption

---

## 📖 Użycie

### 1. Utwórz Zaawansowany Portfel
```powershell
.\target\release\advanced_node.exe new-wallet \
  --output alice_adv.json \
  --name "Alice Advanced"
```

**Zawiera:**
- Falcon-512 (podpisy)
- Kyber-768 (KEM, encryption)

### 2. Zobacz Info
```powershell
.\target\release\advanced_node.exe info --wallet alice_adv.json
```

### 3. Wyślij Poufną Transakcję
```powershell
# Najpierw utwórz portfel odbiorcy
.\target\release\advanced_node.exe new-wallet -o bob_adv.json -n "Bob Advanced"

# Wyślij CONFIDENTIAL transaction
.\target\release\advanced_node.exe send-confidential \
  --from alice_adv.json \
  --to-wallet bob_adv.json \
  --amount 500 \
  --output tx_confidential.json
```

**Co się dzieje:**
1. ✅ Kwota (500) jest szyfrowana Kyber-768
2. ✅ STARK proof dowodzi że 500 ∈ [0, 2^64)
3. ✅ Commitment bind value + blinding
4. ✅ Tylko Bob może odszyfrować

### 4. Odszyfruj Transakcję (jako odbiorca)
```powershell
.\target\release\advanced_node.exe decrypt-tx \
  --tx tx_confidential.json \
  --wallet bob_adv.json
```

**Wynik:**
```
Output 1:
  Recipient: a1b2c3d4...
  → This output is for YOU!
  ✅ Decrypted amount: 500 TT
  ✅ Commitment verified!
```

### 5. Weryfikuj STARK Proofs (jako observer)
```powershell
.\target\release\advanced_node.exe verify-proofs \
  --tx tx_confidential.json
```

**Każdy może zweryfikować że:**
- ✅ Wartości są w poprawnym zakresie
- ✅ STARK proofs są poprawne
- ❌ ALE nie może zobaczyć dokładnych kwot!

### 6. Utwórz Secret Channel
```powershell
.\target\release\advanced_node.exe create-channel \
  --wallet alice_adv.json \
  --peer bob_adv.json \
  --output channel_alice_bob.bin
```

**Utworzy:**
- Shared secret (Kyber KEM)
- Zaszyfrowany kanał
- Może być użyty do AES-256-GCM

---

## 🔐 Bezpieczeństwo

### Encryption Stack:
```
Kwota (500 TT)
    ↓
[STARK Proof] ← Dowodzi: value ∈ [0, 2^64)
    ↓
[Commitment] ← SHA3(value || blinding || recipient)
    ↓
[Kyber KEM] ← Encapsulate do recipient PK
    ↓
[XChaCha20-Poly1305] ← Szyfruj (value || blinding)
    ↓
[Encrypted Output] ← Tylko recipient może odszyfrować
```

### Properties:
- ✅ **Confidentiality:** Kyber-768 (128-bit PQ)
- ✅ **Integrity:** STARK proofs
- ✅ **Authentication:** Falcon-512 signatures
- ✅ **Range Validity:** STARK range proofs
- ✅ **Zero Knowledge:** Nikt nie widzi kwoty (poza odbiorcą)

---

## 🆚 Porównanie z simple_node

| Feature | simple_node | advanced_node |
|---------|-------------|---------------|
| Transactions | Plain | **Confidential** |
| Amount Visible | ✅ Yes | ❌ **Encrypted** |
| STARK Proofs | ❌ No | ✅ **Yes** |
| Kyber Encryption | ❌ No | ✅ **Yes** |
| Secret Channels | ❌ No | ✅ **Yes** |
| Complexity | Simple | Advanced |
| Privacy | None | **Full** |

---

## 🎯 Use Cases

### simple_node
- Testowanie podstaw
- Nauka transakcji
- Prosty transfer

### advanced_node
- **Confidential transactions**
- Privacy-preserving transfers
- Zero-knowledge proofs
- Secure P2P channels
- Production use

---

## 🔬 Techniczne Detale

### tx_stark.rs Components:

```rust
pub struct TxOutputStark {
    pub value_commitment: Hash32,      // SHA3 commitment
    pub stark_proof: Vec<u8>,          // Range proof
    pub recipient: Hash32,             // Recipient address
    pub encrypted_value: Vec<u8>,      // Kyber encrypted
}
```

**Proces:**
1. `value_commitment = SHA3(value || blinding || recipient)`
2. `stark_proof = STARK_Prove(value ∈ [0, 2^64), commitment)`
3. `(shared_secret, ct) = Kyber_Encaps(recipient_pk)`
4. `encrypted_value = XChaCha20(value || blinding, key=KDF(shared_secret))`

### Verification:
```rust
// Anyone can verify:
assert!(STARK_Verify(stark_proof, commitment));

// Only recipient can decrypt:
(value, blinding) = Decrypt(encrypted_value, kyber_sk);
assert_eq!(commitment, SHA3(value || blinding || recipient));
```

---

## 🚀 Następne Kroki

**Status Bieżący:**
- ✅ `tx_stark.rs` - Pełna implementacja
- ✅ `advanced_node` - CLI gotowe
- 🔄 P2P - Borrowing issue (do naprawy)

**Gdy naprawimy P2P:**
1. Live confidential tx broadcasting
2. Secret channel P2P communication
3. Multi-node privacy network
4. Mixer service

---

**TRUE_TRUST Advanced Node**
*Privacy-Preserving | Post-Quantum | Zero-Knowledge*

