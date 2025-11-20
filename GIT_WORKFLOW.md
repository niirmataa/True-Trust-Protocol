# Git Workflow - TRUE_TRUST Development

## 📊 Current Branch Structure

```
main
  └── feature/advanced-p2p-stark  ← YOU ARE HERE (nowa gałąź)
```

## ✅ Co właśnie zrobiliśmy:

### 1. Utworzono nową gałąź
```bash
git checkout -b feature/advanced-p2p-stark
```

### 2. Dodano wszystkie nowe pliki
- ✅ `advanced_node.rs` - CLI z tx_stark.rs
- ✅ `simple_node.rs` - Prosty CLI
- ✅ `multi_node.rs` - Multi-node test
- ✅ `transaction.rs` - System transakcji
- ✅ `p2p/message.rs` - Protokół P2P
- ✅ Dokumentacja (3 pliki .md)

### 3. Zcommitowano zmiany
```
Commit: 307baa5
Message: "feat: Add advanced features - P2P, STARK transactions, and CLI tools"
Files: 13 changed, 2544+ lines
```

---

## 🔄 Workflow

### MAIN (chroniony)
```
✅ Zawiera:
- tt_wallet (działa 100%)
- mining_demo (działa 100%)
- consensus (działa 100%)
- randomx (działa 100%)
```

### FEATURE BRANCH (rozwój)
```
🔄 Zawiera wszystko z main PLUS:
- advanced_node (tx_stark)
- simple_node (basic TX)
- P2P networking (WIP)
- transaction system
```

---

## 🎯 Dalsze Kroki

### 1. Napraw P2P na feature branch
```bash
# Jesteś już na feature/advanced-p2p-stark
# Naprawiamy borrowing issue w p2p/mod.rs
```

### 2. Test i Weryfikacja
```bash
# Gdy naprawimy:
cargo build --release --bin advanced_node
cargo test

# Test wszystkich funkcji:
cargo run --bin advanced_node -- new-wallet -o test.json -n Test
```

### 3. Merge do main (gdy gotowe)
```bash
# Tylko gdy wszystko działa:
git checkout main
git merge feature/advanced-p2p-stark
git push origin main
```

---

## 🛡️ Bezpieczeństwo

### ✅ MAIN jest chroniony
- Wszystkie zmiany na feature branches
- Merge tylko działającego kodu
- Zawsze można wrócić do stabilnej wersji

### 🔧 Feature branch
- Swobodne eksperymenty
- Można łamać i naprawiać
- Nie wpływa na main

---

## 📝 Git Commands Cheat Sheet

### Przełączanie gałęzi
```bash
# Wróć do main
git checkout main

# Wróć do feature
git checkout feature/advanced-p2p-stark

# Zobacz które gałęzie masz
git branch -a
```

### Zapisywanie zmian
```bash
# Dodaj pliki
git add .

# Commit
git commit -m "opis zmian"

# Push do GitHub
git push origin feature/advanced-p2p-stark
```

### Cofanie zmian (na feature branch)
```bash
# Cofnij uncommited changes
git restore .

# Cofnij ostatni commit (zachowaj zmiany)
git reset --soft HEAD~1

# Hard reset (UWAGA: traci zmiany!)
git reset --hard HEAD~1
```

### Synchronizacja
```bash
# Pobierz zmiany z main do feature
git checkout feature/advanced-p2p-stark
git merge main

# Lub rebase (czystszy history)
git rebase main
```

---

## 🔍 Status Projektu

### Branch: main
```
✅ STABLE - Wszystko działa
- Wallet: 100%
- Mining: 100%
- Consensus: 100%
- Crypto: 100%
```

### Branch: feature/advanced-p2p-stark  
```
🔄 IN PROGRESS
- ✅ advanced_node: Kod gotowy
- ✅ simple_node: Kod gotowy
- ✅ transaction: Implementacja gotowa
- ❌ P2P: Borrowing issue (do naprawy)
- ✅ Dokumentacja: Kompletna
```

---

## 🎮 Co teraz?

### Opcja A: Kontynuuj na feature branch
```bash
# Napraw P2P borrowing issue
# Test wszystkich funkcji
# Merge do main gdy gotowe
```

### Opcja B: Pracuj równolegle
```bash
# Main: Używaj stabilnych funkcji
git checkout main
cargo run --release --example mining_demo

# Feature: Rozwijaj nowe funkcje
git checkout feature/advanced-p2p-stark
# Pracuj nad P2P i advanced_node
```

---

## 📊 Stan Commitów

```
main:
  ├─ 1809aa1 PQQ
  ├─ 384e445 Initial commit
  └─ ...

feature/advanced-p2p-stark:
  ├─ 307baa5 feat: Add advanced features... ← NEW
  ├─ 1809aa1 PQQ
  ├─ 384e445 Initial commit
  └─ ...
```

---

**Jesteś bezpieczny!** Main jest nienaruszony, możemy eksperymentować na feature branch! 🚀

