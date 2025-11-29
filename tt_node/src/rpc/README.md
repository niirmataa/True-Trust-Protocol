# Secure Post-Quantum RPC

Moduł RPC dla TRUE_TRUST wykorzystujący **ten sam protokół kryptograficzny** co transport P2P.

## 🔐 Architektura bezpieczeństwa

### Protokół PQ (identyczny jak P2P)

```
┌─────────────────────────────────────────┐
│  IDENTYFIKACJA                          │
│  • Falcon-512 (długoterminowe klucze)  │
│  • Node ID = SHA256(Falcon PK)         │
└─────────────────────────────────────────┘
         ▼
┌─────────────────────────────────────────┐
│  WYMIANA KLUCZY                         │
│  • ML-KEM-768 (Kyber) ephemeral        │
│  • Perfect Forward Secrecy             │
└─────────────────────────────────────────┘
         ▼
┌─────────────────────────────────────────┐
│  SZYFROWANIE                            │
│  • XChaCha20-Poly1305 AEAD             │
│  • Oddzielne klucze: k_c2s, k_s2c      │
│  • Liczniki nonce per kierunek         │
└─────────────────────────────────────────┘
         ▼
┌─────────────────────────────────────────┐
│  INTEGRALNOŚĆ                           │
│  • SHA3-256 transcript hashing         │
│  • KMAC256-XOF key derivation          │
└─────────────────────────────────────────┘
```

### Handshake (3-way mutual auth)

```
Client                          Server
  |                               |
  |  ClientHello                  |
  |  - Falcon PK                  |
  |  - Kyber PK                   |
  |  - Nonce                      |
  |------------------------------>|
  |                               | ✓ Verify version
  |                               | ✓ KEM encapsulate
  |                               | ✓ Sign transcript
  |  ServerHello                  |
  |  - Falcon PK                  |
  |  - Kyber CT                   |
  |  - Falcon signature           |
  |<------------------------------|
  | ✓ Verify signature            |
  | ✓ KEM decapsulate             |
  | ✓ Derive session key          |
  |  ClientFinished               |
  |  - Falcon signature           |
  |------------------------------>|
  |                               | ✓ Verify signature
  |                               |
  | <== SECURE CHANNEL ==>        |
  |                               |
  |  RPC Request (encrypted)      |
  |------------------------------>|
  |  RPC Response (encrypted)     |
  |<------------------------------|
```

## 📦 Moduły

### `rpc_secure.rs` - PQ Secure RPC (✅ PRODUKCJA)

**ZALECANE DO UŻYTKU PRODUKCYJNEGO**

```rust
use tt_node::rpc::SecureRpcServer;
use tt_node::rpc::rpc_secure::rpc_identity_from_keys;

// Wygeneruj klucze PQ
let (falcon_pk, falcon_sk) = falcon_keypair();
let (kyber_pk, kyber_sk) = kyber_keypair();

let identity = rpc_identity_from_keys(
    falcon_pk,
    falcon_sk,
    kyber_pk,
    kyber_sk
);

// Uruchom secure RPC
let server = SecureRpcServer::new(9999, identity, is_validator, node);
server.start().await?;
```

- ✅ Falcon-512 authentication
- ✅ Kyber-768 key exchange
- ✅ XChaCha20-Poly1305 encryption
- ✅ Forward secrecy
- ✅ Mutual authentication

## 🔧 API RPC

### Dostępne metody

| Metoda | Request | Response | Opis |
|--------|---------|----------|------|
| `GetStatus` | - | `{node_id, is_validator, height}` | Status węzła |
| `GetChainInfo` | - | `{height, best_block_hash}` | Info o blockchainie |
| `GetPeerCount` | - | `{count}` | Liczba peerów |
| `SubmitTransaction` | `{tx_hex}` | `{tx_id, accepted}` | Wyślij transakcję |

### Przykład klienta

```rust
use tt_node::rpc::SecureRpcClient;
use tt_node::rpc::rpc_secure::{RpcRequest, rpc_identity_from_keys};

// Setup
let identity = rpc_identity_from_keys(/* ... */);
let server_addr = "127.0.0.1:9999".parse()?;
let mut client = SecureRpcClient::new(server_addr, identity);

// Connect (PQ handshake)
client.connect().await?;

// Make requests
let resp = client.request(RpcRequest::GetStatus).await?;
println!("Status: {:?}", resp);

let resp = client.request(RpcRequest::SubmitTransaction {
    tx_hex: hex::encode(tx_bytes)
}).await?;
println!("TX submitted: {:?}", resp);

// Disconnect
client.close().await?;
```

## 🧪 Testowanie

### Uruchom demo

```bash
# Secure RPC demo
cargo run --example secure_rpc_demo

# Oczekiwany output:
# 🔐 Setting up secure RPC server...
# 🔐 Setting up secure RPC client...
# 📡 Testing RPC calls over secure channel...
# ✅ All RPC calls succeeded!
```

### Unit testy

```bash
cargo test --lib rpc
```

## 🔒 Właściwości bezpieczeństwa

### Osiągnięte

- ✅ **Post-quantum security**: Kyber-768 (NIST L3) + Falcon-512 (NIST L1)
- ✅ **Forward secrecy**: Ephemeral Kyber KEM per sesja
- ✅ **Mutual authentication**: Oba końce podpisują transcript
- ✅ **Replay protection**: Unique nonces + timestamps
- ✅ **Transcript integrity**: SHA3-256 hash chain
- ✅ **AEAD confidentiality**: XChaCha20-Poly1305
- ✅ **AEAD authenticity**: Poly1305 MAC
- ✅ **Session limits**: Max 1M messages per session
- ✅ **Zeroize**: Wszystkie wrażliwe klucze

### Porównanie z innymi protokołami

| Protokół | PQ-Safe | Forward Secrecy | Mutual Auth | Uwagi |
|----------|---------|-----------------|-------------|-------|
| **TRUE_TRUST RPC** | ✅ | ✅ | ✅ | Falcon + Kyber + XChaCha20 |
| TLS 1.3 (classic) | ❌ | ✅ | ✅ | Podatny na quantum |
| TLS 1.3 + Kyber | ⚠️ | ✅ | ✅ | Hybrid, ale ECC baseline |
| HTTP | ❌ | ❌ | ❌ | Plaintext |
| WireGuard | ❌ | ✅ | ❌ | ChaCha20 ale ECC KX |

## 📊 Performance

### Handshake

- **Falcon-512 sign**: ~10 ms
- **Falcon-512 verify**: ~0.2 ms
- **Kyber-768 encapsulate**: ~0.2 ms
- **Kyber-768 decapsulate**: ~0.3 ms
- **Total handshake**: ~11 ms (amortized over session)

### Per-message

- **XChaCha20-Poly1305 encrypt/decrypt**: ~0.1 ms per KB
- **Overhead**: 16 bytes (Poly1305 tag) + 4 bytes (length prefix)

### Limits

- **Max message size**: 10 MB
- **Max messages per session**: 1,000,000
- **Session renegotiation**: Automatyczne po przekroczeniu limitu

## 🚀 Roadmap

### v1.0 (obecny)

- ✅ Secure channel z P2P crypto
- ✅ Basic RPC methods
- ✅ Client & Server
- ✅ Example demo

### v1.1 (planned)

- [ ] Streaming RPC (długo żyjące połączenia)
- [ ] Batch requests (multiple RPC w jednym message)
- [ ] Kompresja (zstd dla dużych payloadów)
- [ ] Rate limiting per node ID

### v2.0 (future)

- [ ] gRPC-compatible API
- [ ] WebSocket support dla przeglądarek
- [ ] Metrics & monitoring dashboards
- [ ] Circuit breakers & health checks

## 📝 Licencja

Apache 2.0 - Ten sam co cały projekt TRUE_TRUST.

## 🤝 Contributing

Jeśli chcesz dodać nowe metody RPC:

1. Dodaj wariant do `RpcRequest` enum w `rpc_secure.rs`
2. Dodaj wariant do `RpcResponse` enum
3. Zaimplementuj handler w `SecureRpcServer::process_request()`
4. Dodaj metodę do `NodeCore` jeśli potrzebna
5. Zaktualizuj tę dokumentację
6. Dodaj test do `examples/secure_rpc_demo.rs`

---

**Zawsze używaj `SecureRpcServer` - zapewnia PQ-secure transport.**
