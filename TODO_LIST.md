# TODO List - TRUE TRUST Protocol

**Generated:** 2025-11-24
**Branches analyzed:**
- `niirmataa-true-trust` (current development)
- `claude/review-true-trust-protocol-0165PvHeA4qAAwPZzP6w4az1` (review branch)

---

## 🚨 CRITICAL - Brakujące Funkcje (Kompilacja się nie uda)

### 1. ❌ RPC Secure - Missing Functions
**Location:** `tt_node/src/rpc/rpc_secure.rs`
**Branch:** `niirmataa-true-trust`

Funkcje są **wywoływane** ale **nie istnieją**:

```rust
// Line 327
tokio::spawn(async move { s.cleanup_sessions_task().await });

// Line 331
tokio::spawn(async move { s.key_rotation_task().await });
```

**Problem:** Kompilator zgłosi błąd:
```
error[E0599]: no method named `cleanup_sessions_task` found for struct `SecureRpcServer`
error[E0599]: no method named `key_rotation_task` found for struct `SecureRpcServer`
```

**Wymagane implementacje:**

```rust
impl SecureRpcServer {
    /// Clean up expired sessions periodically
    async fn cleanup_sessions_task(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;

            let mut sessions = self.sessions.write().await;
            let now = Instant::now();

            sessions.retain(|_, state| {
                now.duration_since(state.created_at) < SESSION_TIMEOUT
            });

            println!("🧹 Cleaned up expired sessions");
        }
    }

    /// Rotate node identity keys periodically
    async fn key_rotation_task(&self) {
        loop {
            tokio::time::sleep(KEY_ROTATION_INTERVAL).await;

            // Regenerate identity keys
            let mut identity = self.identity.write().await;
            *identity = NodeIdentity::generate();
            drop(identity);

            *self.last_key_rotation.write().await = Instant::now();

            println!("🔄 Node identity keys rotated");
        }
    }
}
```

### 2. ❌ Module Structure Issues
**Location:** `tt_node/src/`
**Branch:** `niirmataa-true-trust`

**Problemy:**

1. **Dziwny plik:** `tx_stark_signed..rs` (podwójna kropka!)
   ```bash
   mv tt_node/src/tx_stark_signed..rs tt_node/src/tx_stark_signed.rs
   ```

2. **Brak re-exportu `SignedStarkTx`:**
   ```rust
   // tt_node/src/tx_stark.rs (dodać na końcu)
   pub use crate::tx_stark_signed::SignedStarkTx;
   ```

3. **Brak modułu w lib.rs:**
   ```rust
   // tt_node/src/lib.rs (dodać)
   pub mod tx_stark_signed;
   ```

---

## 🔴 HIGH PRIORITY - Funkcjonalność Podstawowa

### 3. P2P Network Layer - Niekompletny
**Location:** `tt_node/src/p2p/mod.rs`
**Status:** 🟡 Stub/Skeleton only

```rust
// Line 53 - TODO: Accept connections
pub async fn start(&self) -> Result<()> {
    let addr = format!("0.0.0.0:{}", self.port);
    let listener = TcpListener::bind(&addr).await
        .context("Failed to bind P2P port")?;

    println!("P2P listening on {}", addr);

    // TODO: Accept connections  ⚠️

    Ok(())
}

// Line 64 - TODO: Perform handshake
pub async fn connect(&self, address: &str) -> Result<()> {
    let stream = TcpStream::connect(address).await
        .context("Failed to connect to peer")?;

    // TODO: Perform handshake  ⚠️

    Ok(())
}

// Line 73 - TODO: Send message
pub async fn broadcast(&self, message: &[u8]) -> Result<()> {
    let peers = self.peers.read().await;
    for (node_id, peer) in peers.iter() {
        // TODO: Send message  ⚠️
    }
    Ok(())
}
```

**Wymagane:**
- Pętla akceptacji połączeń
- Integracja z `SecureChannel` z `p2p/secure.rs`
- Routing wiadomości między peerami
- Peer discovery mechanism
- Heartbeat / keepalive

### 4. NodeCore - Genesis i Block Production
**Location:** `tt_node/src/node_core.rs`
**Status:** 🟡 Stubs

```rust
// Line 116 - TODO: Parse and apply genesis state
pub async fn init_genesis(&self, genesis_data: &[u8]) -> Result<()> {
    // TODO: sparsować `genesis_data` i zbudować blok genesis / stan początkowy.
    let _ = genesis_data; // unused variable warning suppression
    Ok(())
}

// Line 125 - TODO: Start block production / syncing
pub async fn start(&self) -> Result<()> {
    // TODO: pętla produkcji bloków, gossip P2P, itp.
    Ok(())
}

// Line 127 - TODO: Graceful shutdown
pub async fn stop(&self) -> Result<()> {
    // TODO: Graceful shutdown
    Ok(())
}
```

**Wymagane:**
- Parser genesis JSON/binary
- Inicjalizacja stanu genesis w ChainStore
- Pętla produkcji bloków (dla walidatorów)
- Sync protocol (dla full nodes)
- Graceful shutdown sequence

### 5. RPC Key Renegotiation
**Location:** `tt_node/src/rpc/rpc_secure.rs:484`
**Status:** 🟡 Comment only

```rust
if last_renegotiation.elapsed() > MIN_RENEGOTIATION_INTERVAL
    && channel.should_renegotiate()
{
    // TODO: renegocjacja kluczy  ⚠️
    last_renegotiation = Instant::now();
}
```

**Wymagane:**
- Re-run PQ handshake
- Atomic channel swap
- Handle in-flight messages during rotation

---

## 🟡 MEDIUM PRIORITY - Kryptografia

### 6. STARK Proofs - Placeholder Implementation
**Location:** `tt_node/src/stark_full.rs`
**Status:** 🟡 Returns dummy data

```rust
// Line 26 - TODO: Implement STARK proof generation
pub fn prove(&self, _witness: &[u8]) -> Result<Vec<u8>> {
    // TODO: Implement STARK proof generation
    Ok(vec![0u8; 256]) // Placeholder proof
}

// Line 32 - TODO: Implement actual STARK range proof
pub fn prove_range_with_commitment(value: u64, commitment: &[u8; 32]) -> STARKProof {
    // TODO: Implement actual STARK range proof
    let mut proof_bytes = vec![0u8; 256];
    proof_bytes[0..8].copy_from_slice(&value.to_le_bytes());
    proof_bytes[8..40].copy_from_slice(commitment);
    STARKProof { proof_bytes }
}

// Line 50 - TODO: Implement STARK proof verification
pub fn verify(&self, _proof: &[u8]) -> Result<bool> {
    // TODO: Implement STARK proof verification
    Ok(true) // Placeholder - always valid ⚠️
}

// Line 56 - TODO: Implement actual verification
pub fn verify_proof(proof: &STARKProof) -> bool {
    // TODO: Implement actual verification
    proof.proof_bytes.len() == 256 // Just check size ⚠️
}
```

**Status:** Zależne od integracji Winterfell

**Wymagane:**
- Implementacja Winterfell AIR dla range proofs
- Integracja z Poseidon hash
- Proper serialization/deserialization
- Security parameter tuning

### 7. Falcon Key Validator
**Location:** `tt_node/src/falcon_key_validator.rs:444`
**Status:** 🟡 Incomplete validation

```rust
// TODO: Verify: h = g/f mod q (NTT-based check)
// This requires computing f^(-1) mod q and checking h*f = g mod q.
```

**Wymagane:**
- NTT domain operations
- Modular inverse computation
- Proper q-modulus arithmetic

---

## 🟢 LOW PRIORITY - Infrastructure

### 8. Keystore Loading
**Location:** `tt_node/src/main.rs:204`
**Status:** 🟡 Uses random keys

```rust
println!("🔑 Loading validator keys from: {}", ks.display());
// TODO: Load from keystore
falcon_sigs::falcon_keypair() // Random keys instead! ⚠️
```

**Wymagane:**
- Encrypted keystore format (JSON/TOML)
- Password derivation (Argon2)
- Key loading/saving API

### 9. Transaction Types
**Location:** `tt_node/src/core.rs:66`
**Status:** 🟡 Uses raw bytes

```rust
/// TODO: docelowo transakcje będą prawdziwym typem, nie Vec<u8>.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Block {
    pub height: u64,
    pub prev_hash: Hash32,
    pub timestamp: u64,
    pub transactions: Vec<Vec<u8>>, // ⚠️ Should be Vec<Transaction>
}
```

**Wymagane:**
- Proper `Transaction` struct with typed fields
- Signature verification in transaction validation
- Fee calculation
- Nonce/sequence number tracking

### 10. STARK Public API
**Location:** `tt_node/src/tx_stark.rs:15`
**Status:** 🟡 Comment only

```rust
// TODO: Add public API to stark_goldilocks and use that
```

**Wymagane:**
- Expose clean API from `stark_goldilocks` module
- Documentation for STARK interface
- Example usage

---

## 📊 Summary Statistics

| Priority | Count | Status |
|----------|-------|--------|
| 🚨 CRITICAL | 2 | Blokują kompilację |
| 🔴 HIGH | 5 | Blokują użycie produkcyjne |
| 🟡 MEDIUM | 3 | Bezpieczeństwo/funkcjonalność |
| 🟢 LOW | 3 | Infrastruktura/quality of life |
| **TOTAL** | **13** | **Requires ~4-6 weeks work** |

---

## 🎯 Recommended Order of Implementation

### Phase 1: Compilation Fixes (Days 1-3)
1. ✅ Fix `tx_stark_signed..rs` filename
2. ✅ Add `cleanup_sessions_task()` and `key_rotation_task()`
3. ✅ Fix module structure and imports
4. ✅ Verify `cargo build --features winterfell` succeeds

### Phase 2: Core Functionality (Week 1-2)
5. ✅ Complete P2P layer (connection handling, handshake integration)
6. ✅ Implement genesis parsing and initialization
7. ✅ Add block production loop for validators
8. ✅ Implement sync protocol for full nodes

### Phase 3: Security Hardening (Week 2-3)
9. ✅ Implement RPC key renegotiation
10. ✅ Add keystore encryption/loading
11. ✅ Complete Falcon key validator
12. ✅ Add comprehensive testing

### Phase 4: STARK Integration (Week 3-4)
13. ✅ Integrate Winterfell for real STARK proofs
14. ✅ Implement proper transaction types
15. ✅ Add STARK verification to consensus
16. ✅ Performance tuning

---

## 📝 Notes

- **Branch `niirmataa-true-trust`** ma więcej TODO niż główny branch
- Większość TODO to **kluczowe funkcje**, nie drobne ulepszenia
- Kod ma **świetne podstawy kryptograficzne**, ale **niekompletną implementację**
- Bez naprawienia Phase 1, **kod się nie skompiluje**
- Bez Phase 2, **system nie będzie działał**

---

**Last Updated:** 2025-11-24
**Next Review:** After Phase 1 completion
