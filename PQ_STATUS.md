# Status post-kwantowy (PQ)

Projekt korzysta wyłącznie z algorytmów odpornych na komputery kwantowe w ścieżce konsensusu, podpisów i szyfrowania danych użytkownika:

- **Podpisy bloków i transakcji**: Falcon-512 (NIST PQA, ~128-bit bezpieczeństwa PQ).
- **Szyfrowanie wartości i kanały P2P**: Kyber-768 jako KEM (NIST PQA) do negocjacji kluczy sesji oraz kapsułowania kluczy dla danych poufnych.
- **Wallet / tt_wallet**: generuje i przechowuje klucze Falcon/Kyber w zaszyfrowanych plikach, używanych przez `advanced_node` w całym cyklu życia transakcji.
- **Brak klasycznych algorytmów** w ścieżce podpisów lub wymiany kluczy (ECDSA/Ed25519/RSA nie są używane).

## Jak zbudować w pełni PQ

1. Włącz feature `wallet`, aby `advanced_node` zawsze korzystał z tt_wallet (klucze Falcon/Kyber):
   ```bash
   cargo build --release --features wallet
   cargo test --all --features wallet
   ```
2. Dla przykładowych transakcji STARK przez P2P (Kyber + Falcon):
   ```bash
   cargo run --example p2p_stark_tx --features wallet
   ```
3. Gotowe binaria (przykłady, node): wszystkie używają Falcon/Kyber do podpisów i kanałów.

## Co nie jest PQ

- **RandomX (PoW)** jest odporne na ASIC, ale nie zapewnia odporności na Grovera dla całego PoW — nie wpływa jednak na podpisy, szyfrowanie ani konsensus deterministyczny.

## Podsumowanie

W aktualnym stanie projekt jest "PQ-full" dla kluczowych ścieżek kryptograficznych: podpisy, szyfrowanie wartości i kanały P2P korzystają wyłącznie z Falcon-512 i Kyber-768. Upewnij się, że budujesz z `--features wallet`, aby korzystać z tt_wallet i utrzymać spójny zestaw kluczy post-kwantowych w węźle.
