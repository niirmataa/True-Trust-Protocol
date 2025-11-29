//! Zaawansowane testy bezpieczeństwa dla True Trust Protocol
//!
//! Kategorie testów:
//! 1. Walidacja kluczy PQC (Falcon, Kyber)
//! 2. Ataki na stealth addresses
//! 3. Próby fałszowania podpisów
//! 4. Ataki na szyfrowanie sender ID
//! 5. Replay attacks
//! 6. Timing attacks (basic)
//! 7. Fuzzing-style random inputs
//!
//! Uruchom: `cargo test --test security_tests --release -- --nocapture`

use tt_node::stealth_registry::{
    StealthKeyRegistry, StealthRegistryError,
    RecipientStealthOutput, SenderChangeOutput, EncryptedSenderId,
    PrivateCompactTx, ViewKey,
    scan_recipient_output, scan_sender_change, ScanResult,
};
use tt_node::falcon_sigs::{
    falcon_verify_bytes,
    falcon_pk_from_bytes,
};

use pqcrypto_falcon::falcon512;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::sign::{PublicKey as SignPK, SecretKey as SignSK, DetachedSignature};
use pqcrypto_traits::kem::{PublicKey as KemPK, SecretKey as KemSK, SharedSecret, Ciphertext};

use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn generate_falcon_keypair() -> (falcon512::PublicKey, falcon512::SecretKey) {
    falcon512::keypair()
}

fn generate_kyber_keypair() -> (kyber768::PublicKey, kyber768::SecretKey) {
    kyber768::keypair()
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

// ============================================================================
// 1. TESTY WALIDACJI KLUCZY PQC
// ============================================================================

mod key_validation {
    use super::*;

    #[test]
    fn test_falcon_key_length_validation() {
        let (pk, _) = generate_falcon_keypair();
        let (kyber_pk, _) = generate_kyber_keypair();
        let mut registry = StealthKeyRegistry::new();

        // Test różnych nieprawidłowych długości
        let invalid_lengths = [0, 1, 100, 500, 896, 898, 1000, 2000];
        
        for len in invalid_lengths {
            let bad_key = vec![0x42u8; len];
            let result = registry.register(
                bad_key,
                kyber_pk.as_bytes().to_vec(),
                0, 0,
            );
            
            assert!(result.is_err(), 
                "Powinno odrzucić Falcon key o długości {}", len);
            
            match result.unwrap_err() {
                StealthRegistryError::InvalidFalconKeyFormat(_) => {
                    // OK - oczekiwany błąd
                }
                other => panic!("Nieoczekiwany błąd dla len={}: {:?}", len, other),
            }
        }
        
        println!("✅ Falcon key length validation: {} przypadków odrzuconych", invalid_lengths.len());
    }

    #[test]
    fn test_kyber_key_length_validation() {
        let (falcon_pk, _) = generate_falcon_keypair();
        let mut registry = StealthKeyRegistry::new();

        let invalid_lengths = [0, 1, 100, 500, 1000, 1183, 1185, 2000, 3000];
        
        for len in invalid_lengths {
            let bad_key = vec![0x42u8; len];
            let result = registry.register(
                falcon_pk.as_bytes().to_vec(),
                bad_key,
                0, 0,
            );
            
            assert!(result.is_err(), 
                "Powinno odrzucić Kyber key o długości {}", len);
        }
        
        println!("✅ Kyber key length validation: {} przypadków odrzuconych", invalid_lengths.len());
    }

    #[test]
    fn test_swapped_key_types_rejected() {
        let (falcon_pk, _) = generate_falcon_keypair();
        let (kyber_pk, _) = generate_kyber_keypair();
        let mut registry = StealthKeyRegistry::new();

        // Próba zarejestrowania kluczy w złej kolejności
        let result = registry.register(
            kyber_pk.as_bytes().to_vec(),  // Kyber jako Falcon (1184B vs 897B)
            falcon_pk.as_bytes().to_vec(), // Falcon jako Kyber (897B vs 1184B)
            0, 0,
        );
        
        assert!(result.is_err(), "Powinno odrzucić zamienione klucze");
        println!("✅ Zamienione typy kluczy odrzucone");
    }

    #[test]
    fn test_duplicate_registration_idempotent() {
        let (falcon_pk, _) = generate_falcon_keypair();
        let (kyber_pk, _) = generate_kyber_keypair();
        let mut registry = StealthKeyRegistry::new();

        // Pierwsza rejestracja
        let id1 = registry.register(
            falcon_pk.as_bytes().to_vec(),
            kyber_pk.as_bytes().to_vec(),
            1000, 100,
        ).unwrap();

        // Próba ponownej rejestracji
        let id2 = registry.register(
            falcon_pk.as_bytes().to_vec(),
            kyber_pk.as_bytes().to_vec(),
            2000, 200,  // Inne timestamps
        ).unwrap();

        assert_eq!(id1, id2, "Duplikat powinien zwrócić ten sam ID");
        
        // Sprawdź że zachowano oryginalne timestamps
        let key = registry.get(&id1).unwrap();
        assert_eq!(key.registered_at, 1000);
        assert_eq!(key.registered_block, 100);
        
        println!("✅ Idempotentna rejestracja działa poprawnie");
    }
}

// ============================================================================
// 2. TESTY ATAKÓW NA STEALTH ADDRESSES
// ============================================================================

mod stealth_attacks {
    use super::*;

    #[test]
    fn test_stealth_outputs_unlinkable() {
        let (kyber_pk, _) = generate_kyber_keypair();
        
        // Generuj wiele outputów dla tego samego odbiorcy
        let mut stealth_keys = HashSet::new();
        let mut view_tags = HashSet::new();
        let mut kem_cts = HashSet::new();
        
        for _ in 0..100 {
            let (output, _) = RecipientStealthOutput::generate(&kyber_pk).unwrap();
            stealth_keys.insert(output.stealth_key);
            view_tags.insert(output.view_tag);
            kem_cts.insert(output.kem_ct.clone());
        }
        
        // Wszystkie powinny być unikalne
        assert_eq!(stealth_keys.len(), 100, "Stealth keys muszą być unikalne");
        assert_eq!(view_tags.len(), 100, "View tags muszą być unikalne");
        assert_eq!(kem_cts.len(), 100, "KEM ciphertexts muszą być unikalne");
        
        println!("✅ 100 stealth outputs jest całkowicie unlinkable");
    }

    #[test]
    fn test_wrong_key_cannot_scan() {
        let (recipient_pk, recipient_sk) = generate_kyber_keypair();
        let (_attacker_pk, attacker_sk) = generate_kyber_keypair();
        
        // Generuj output dla recipient
        let (output, _) = RecipientStealthOutput::generate(&recipient_pk).unwrap();
        
        // Prawdziwy odbiorca może skanować
        match scan_recipient_output(&output, &recipient_sk) {
            ScanResult::Match { .. } => { /* OK */ }
            ref other => panic!("Recipient powinien móc skanować: {:?}", other),
        }
        
        // Atakujący NIE może skanować
        match scan_recipient_output(&output, &attacker_sk) {
            ScanResult::NotForUs => { /* OK - oczekiwane */ }
            ScanResult::Match { .. } => panic!("Atakujący NIE powinien móc skanować!"),
            ScanResult::Error(ref _e) => { /* Też OK - błąd dekapsulacji */ }
        }
        
        println!("✅ Zły klucz nie może skanować stealth outputs");
    }

    #[test]
    fn test_sender_change_only_sender_can_recover() {
        let (_, sender_sk) = generate_kyber_keypair();
        let (_, attacker_sk) = generate_kyber_keypair();
        
        let nonce = 12345u64;
        let output = SenderChangeOutput::generate(&sender_sk, nonce);
        
        // Sender może odtworzyć
        assert!(scan_sender_change(&output, &sender_sk), 
            "Sender powinien móc odtworzyć swój change");
        
        // Atakujący NIE może odtworzyć
        assert!(!scan_sender_change(&output, &attacker_sk),
            "Atakujący NIE powinien móc odtworzyć change");
        
        println!("✅ Tylko sender może odtworzyć change output");
    }

    #[test]
    fn test_view_tag_collision_resistance() {
        let (kyber_pk, _) = generate_kyber_keypair();
        
        // Generuj dużo view tags i sprawdź kolizje
        let mut view_tags = HashSet::new();
        let iterations = 10000;
        
        for _ in 0..iterations {
            let (output, _) = RecipientStealthOutput::generate(&kyber_pk).unwrap();
            view_tags.insert(output.view_tag);
        }
        
        let collision_rate = 1.0 - (view_tags.len() as f64 / iterations as f64);
        
        println!("View tags: {} unikalnych z {} (kolizje: {:.4}%)", 
            view_tags.len(), iterations, collision_rate * 100.0);
        
        // Przy 8-byte view tag kolizje są bardzo rzadkie
        assert!(collision_rate < 0.01, 
            "Zbyt wiele kolizji view tags: {:.2}%", collision_rate * 100.0);
        
        println!("✅ View tag collision resistance OK");
    }
}

// ============================================================================
// 3. TESTY FAŁSZOWANIA PODPISÓW
// ============================================================================

mod signature_attacks {
    use super::*;

    #[test]
    fn test_signature_verification_rejects_wrong_key() {
        let (pk1, sk1) = generate_falcon_keypair();
        let (pk2, _sk2) = generate_falcon_keypair();
        
        let message = b"Test message for signature verification";
        let sig = falcon512::detached_sign(message, &sk1);
        
        // Weryfikacja z prawidłowym kluczem
        assert!(falcon512::verify_detached_signature(&sig, message, &pk1).is_ok(),
            "Prawidłowy klucz powinien zweryfikować");
        
        // Weryfikacja z ZŁYM kluczem
        assert!(falcon512::verify_detached_signature(&sig, message, &pk2).is_err(),
            "Zły klucz NIE powinien zweryfikować");
        
        println!("✅ Weryfikacja odrzuca podpis z złym kluczem");
    }

    #[test]
    fn test_signature_verification_rejects_modified_message() {
        let (pk, sk) = generate_falcon_keypair();
        
        let message = b"Original message content";
        let sig = falcon512::detached_sign(message, &sk);
        
        // Zmodyfikowana wiadomość
        let modified = b"Modified message content";
        
        assert!(falcon512::verify_detached_signature(&sig, modified, &pk).is_err(),
            "Zmodyfikowana wiadomość NIE powinna się zweryfikować");
        
        println!("✅ Weryfikacja odrzuca zmodyfikowaną wiadomość");
    }

    #[test]
    fn test_signature_verification_rejects_truncated_signature() {
        let (pk, sk) = generate_falcon_keypair();
        
        let message = b"Test message";
        let sig = falcon512::detached_sign(message, &sk);
        let sig_bytes = sig.as_bytes();
        
        // Obcięty podpis
        for truncate_len in [1, 10, 100, sig_bytes.len() / 2] {
            let truncated = &sig_bytes[..sig_bytes.len() - truncate_len];
            
            // Próba weryfikacji obciętego podpisu powinna się nie powieść
            // (falcon_verify_bytes sprawdza długość)
            let pk_converted = falcon_pk_from_bytes(pk.as_bytes()).unwrap();
            let result = falcon_verify_bytes(message, truncated, &pk_converted);
            
            assert!(result.is_err(), 
                "Obcięty podpis (-{}B) NIE powinien się zweryfikować", truncate_len);
        }
        
        println!("✅ Obcięte podpisy odrzucone");
    }

    #[test]
    fn test_signature_verification_rejects_corrupted_signature() {
        let (pk, sk) = generate_falcon_keypair();
        
        let message = b"Test message for corruption test";
        let sig = falcon512::detached_sign(message, &sk);
        let mut sig_bytes = sig.as_bytes().to_vec();
        
        // Uszkodź różne pozycje w podpisie
        let positions = [0, 100, 300, sig_bytes.len() / 2, sig_bytes.len() - 1];
        
        for pos in positions {
            let original = sig_bytes[pos];
            sig_bytes[pos] ^= 0xFF;  // Flip all bits
            
            let pk_converted = falcon_pk_from_bytes(pk.as_bytes()).unwrap();
            let result = falcon_verify_bytes(message, &sig_bytes, &pk_converted);
            
            assert!(result.is_err(), 
                "Uszkodzony podpis (pozycja {}) NIE powinien się zweryfikować", pos);
            
            sig_bytes[pos] = original;  // Przywróć
        }
        
        println!("✅ Uszkodzone podpisy odrzucone");
    }

    #[test]
    fn test_cannot_forge_signature_with_random_bytes() {
        let (pk, _) = generate_falcon_keypair();
        let message = b"Message to forge";
        
        // Próbuj sfałszować podpis losowymi bajtami
        for _ in 0..100 {
            let fake_sig = random_bytes(666);  // Typowa długość podpisu Falcon
            
            let pk_converted = falcon_pk_from_bytes(pk.as_bytes()).unwrap();
            let result = falcon_verify_bytes(message, &fake_sig, &pk_converted);
            
            assert!(result.is_err(), "Losowy 'podpis' NIE powinien się zweryfikować");
        }
        
        println!("✅ 100 losowych 'podpisów' odrzuconych");
    }
}

// ============================================================================
// 4. TESTY ATAKÓW NA SZYFROWANIE SENDER ID
// ============================================================================

mod sender_id_attacks {
    use super::*;

    #[test]
    fn test_encrypted_sender_id_decryption_with_wrong_key() {
        let (recipient_pk, _recipient_sk) = generate_kyber_keypair();
        let sender_id = [0x42u8; 32];
        
        // Encrypt z jednym shared secret
        let (ss1, _ct1) = kyber768::encapsulate(&recipient_pk);
        let encrypted = EncryptedSenderId::encrypt(&sender_id, &ss1).unwrap();
        
        // Próba decrypt z INNYM shared secret
        let (ss2, _ct2) = kyber768::encapsulate(&recipient_pk);
        let result = encrypted.decrypt(&ss2);
        
        // Powinno albo fail, albo dać zły wynik
        match result {
            Ok(decrypted) => {
                assert_ne!(decrypted, sender_id, 
                    "Zły klucz nie powinien odszyfrować poprawnie");
            }
            Err(_) => {
                // OK - decrypt failed (auth tag mismatch)
            }
        }
        
        println!("✅ Zły shared secret nie może odszyfrować sender ID");
    }

    #[test]
    fn test_encrypted_sender_id_tamper_detection() {
        let (recipient_pk, _) = generate_kyber_keypair();
        let sender_id = [0x42u8; 32];
        
        let (ss, _) = kyber768::encapsulate(&recipient_pk);
        let mut encrypted = EncryptedSenderId::encrypt(&sender_id, &ss).unwrap();
        
        // Tamper z ciphertextem
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }
        
        // Decrypt powinien wykryć manipulację (AES-GCM auth tag)
        let result = encrypted.decrypt(&ss);
        assert!(result.is_err(), 
            "Zmanipulowany ciphertext powinien być wykryty");
        
        println!("✅ Tamper detection działa (AES-GCM auth tag)");
    }

    #[test]
    fn test_encrypted_sender_id_nonce_reuse_different_ciphertext() {
        let (recipient_pk, _) = generate_kyber_keypair();
        let sender_id = [0x42u8; 32];
        
        let (ss, _) = kyber768::encapsulate(&recipient_pk);
        
        // Ten sam sender_id, ten sam ss, ale różne szyfrowania
        let enc1 = EncryptedSenderId::encrypt(&sender_id, &ss).unwrap();
        let enc2 = EncryptedSenderId::encrypt(&sender_id, &ss).unwrap();
        
        // Nonce powinien być różny za każdym razem
        assert_ne!(enc1.nonce, enc2.nonce, 
            "Nonce musi być unikalny dla każdego szyfrowania");
        
        // Ciphertext też powinien być różny
        assert_ne!(enc1.ciphertext, enc2.ciphertext,
            "Ciphertext powinien być różny dzięki różnemu nonce");
        
        println!("✅ Każde szyfrowanie używa unikalnego nonce");
    }
}

// ============================================================================
// 5. TESTY REPLAY ATTACKS
// ============================================================================

mod replay_attacks {
    use super::*;

    #[test]
    fn test_tx_nonce_uniqueness() {
        let (falcon_pk, falcon_sk) = generate_falcon_keypair();
        let (kyber_pk, kyber_sk) = generate_kyber_keypair();
        let (recipient_pk, _) = generate_kyber_keypair();
        
        let mut registry = StealthKeyRegistry::new();
        let sender_id = registry.register(
            falcon_pk.as_bytes().to_vec(),
            kyber_pk.as_bytes().to_vec(),
            0, 0,
        ).unwrap();

        let mut tx_ids = HashSet::new();
        let mut tx_nonces = HashSet::new();
        
        // Generuj wiele TX z tymi samymi parametrami
        for i in 0..50 {
            let tx = PrivateCompactTx::create(
                &falcon_sk,
                &kyber_sk,
                sender_id,
                &recipient_pk,
                1000,  // Ta sama kwota
                10,    // Ta sama opłata
                i,     // Różny change_nonce
            ).unwrap();
            
            tx_ids.insert(tx.tx_id());
            tx_nonces.insert(tx.tx_nonce);
        }
        
        assert_eq!(tx_ids.len(), 50, "TX IDs muszą być unikalne");
        assert_eq!(tx_nonces.len(), 50, "TX nonces muszą być unikalne");
        
        println!("✅ 50 transakcji ma unikalne ID i nonce (replay protection)");
    }

    #[test]
    fn test_same_params_different_outputs() {
        let (falcon_pk, falcon_sk) = generate_falcon_keypair();
        let (kyber_pk, kyber_sk) = generate_kyber_keypair();
        let (recipient_pk, _) = generate_kyber_keypair();
        
        let mut registry = StealthKeyRegistry::new();
        let sender_id = registry.register(
            falcon_pk.as_bytes().to_vec(),
            kyber_pk.as_bytes().to_vec(),
            0, 0,
        ).unwrap();

        let tx1 = PrivateCompactTx::create(
            &falcon_sk, &kyber_sk, sender_id, &recipient_pk,
            1000, 10, 1,
        ).unwrap();

        let tx2 = PrivateCompactTx::create(
            &falcon_sk, &kyber_sk, sender_id, &recipient_pk,
            1000, 10, 2,  // Tylko change_nonce różny
        ).unwrap();

        // Wszystkie stealth komponenty muszą być różne
        assert_ne!(tx1.recipient_stealth.stealth_key, tx2.recipient_stealth.stealth_key);
        assert_ne!(tx1.recipient_stealth.kem_ct, tx2.recipient_stealth.kem_ct);
        assert_ne!(tx1.sender_change.stealth_key, tx2.sender_change.stealth_key);
        assert_ne!(tx1.encrypted_sender_id.ciphertext, tx2.encrypted_sender_id.ciphertext);
        assert_ne!(tx1.falcon_sig, tx2.falcon_sig);
        
        println!("✅ Identyczne parametry generują różne TX (no replay)");
    }
}

// ============================================================================
// 6. TESTY TIMING ATTACKS (BASIC)
// ============================================================================

mod timing_attacks {
    use super::*;
    use std::time::Instant;

    /// UWAGA: Testy timingowe są z natury niestabilne (scheduler, turbo boost, VM).
    /// Mogą być flaky na obciążonych maszynach CI.
    /// Rozluźnione asercje (0.2x - 5.0x) powinny wystarczyć dla sanity check.
    /// Dla pełnej analizy constant-time użyj narzędzi jak dudect lub ctgrind.
    #[test]
    fn test_signature_verification_constant_time_ish() {
        let (pk, sk) = generate_falcon_keypair();
        let message = b"Timing attack test message";
        let valid_sig = falcon512::detached_sign(message, &sk);
        
        // Pomiar czasu dla prawidłowego podpisu
        let mut valid_times = Vec::new();
        for _ in 0..100 {
            let start = Instant::now();
            let _ = falcon512::verify_detached_signature(&valid_sig, message, &pk);
            valid_times.push(start.elapsed().as_nanos());
        }
        
        // Pomiar czasu dla nieprawidłowego podpisu (zmieniona wiadomość)
        let wrong_message = b"Wrong message for timing test";
        let mut invalid_times = Vec::new();
        for _ in 0..100 {
            let start = Instant::now();
            let _ = falcon512::verify_detached_signature(&valid_sig, wrong_message, &pk);
            invalid_times.push(start.elapsed().as_nanos());
        }
        
        let valid_avg: u128 = valid_times.iter().sum::<u128>() / valid_times.len() as u128;
        let invalid_avg: u128 = invalid_times.iter().sum::<u128>() / invalid_times.len() as u128;
        
        let ratio = valid_avg as f64 / invalid_avg as f64;
        
        println!("Valid sig avg: {} ns", valid_avg);
        println!("Invalid sig avg: {} ns", invalid_avg);
        println!("Ratio: {:.2}", ratio);
        
        // Sprawdź czy różnica nie jest zbyt duża
        // Note: To nie jest pełny test constant-time, ale basic sanity check.
        // Rozluźnione granice (0.2 - 5.0) dla stabilności na różnych platformach.
        assert!(ratio > 0.2 && ratio < 5.0, 
            "Zbyt duża różnica czasowa: {:.2}x (możliwy timing attack)", ratio);
        
        println!("✅ Basic timing check OK (ratio: {:.2})", ratio);
    }

    #[test]
    fn test_kem_decapsulation_constant_time_ish() {
        let (pk, sk) = generate_kyber_keypair();
        let (_, valid_ct) = kyber768::encapsulate(&pk);
        
        // Pomiar dla prawidłowego ciphertext
        let mut valid_times = Vec::new();
        for _ in 0..100 {
            let start = Instant::now();
            let _ = kyber768::decapsulate(&valid_ct, &sk);
            valid_times.push(start.elapsed().as_nanos());
        }
        
        // Pomiar dla losowego "ciphertext"
        let random_ct_bytes = random_bytes(1088);
        let invalid_ct = kyber768::Ciphertext::from_bytes(&random_ct_bytes).unwrap();
        
        let mut invalid_times = Vec::new();
        for _ in 0..100 {
            let start = Instant::now();
            let _ = kyber768::decapsulate(&invalid_ct, &sk);
            invalid_times.push(start.elapsed().as_nanos());
        }
        
        let valid_avg: u128 = valid_times.iter().sum::<u128>() / valid_times.len() as u128;
        let invalid_avg: u128 = invalid_times.iter().sum::<u128>() / invalid_times.len() as u128;
        
        let ratio = valid_avg as f64 / invalid_avg as f64;
        
        println!("Valid CT decaps avg: {} ns", valid_avg);
        println!("Invalid CT decaps avg: {} ns", invalid_avg);
        println!("Ratio: {:.2}", ratio);
        
        // Kyber powinien być constant-time by design.
        // Rozluźnione granice dla stabilności na VM/CI.
        assert!(ratio > 0.2 && ratio < 5.0,
            "Zbyt duża różnica czasowa: {:.2}x", ratio);
        
        println!("✅ KEM decapsulation timing check OK");
    }
}

// ============================================================================
// 7. FUZZING-STYLE RANDOM INPUTS
// ============================================================================
//
// UWAGA: Biblioteki PQC (pqcrypto-falcon, pqcrypto-kyber) NIE walidują
// struktury kluczy - akceptują dowolne bajty o poprawnej długości.
// Te testy sprawdzają, że nasz kod NIE PANIKUJE na losowych danych,
// a nie że odrzuca strukturalnie niepoprawne klucze.

mod fuzzing {
    use super::*;

    #[test]
    fn test_registry_handles_random_garbage() {
        let mut registry = StealthKeyRegistry::new();
        
        // Próbuj zarejestrować losowe śmieci różnych długości.
        // Registry powinno odrzucić złe długości, ale NIE waliduje struktury.
        for _ in 0..100 {
            let random_falcon = random_bytes(rand::random::<usize>() % 2000);
            let random_kyber = random_bytes(rand::random::<usize>() % 3000);
            
            let result = registry.register(random_falcon, random_kyber, 0, 0);
            
            // Nie powinno panikować - powinno zwrócić błąd (zła długość) lub OK (trafiono 897/1184B)
            match result {
                Ok(_) => {
                    // Może się udać jeśli trafiliśmy w prawidłowe długości
                    // (bardzo mało prawdopodobne)
                }
                Err(_) => {
                    // OK - oczekiwane dla losowych danych
                }
            }
        }
        
        println!("✅ Registry nie panikuje na losowych danych");
    }

    #[test]
    fn test_scan_handles_corrupted_output() {
        let (_, sk) = generate_kyber_keypair();
        
        // Stwórz zmanipulowane outputy
        for _ in 0..50 {
            let corrupted_output = RecipientStealthOutput {
                stealth_key: random_bytes(32).try_into().unwrap(),
                view_tag: random_bytes(8).try_into().unwrap(),
                kem_ct: random_bytes(1088),
            };
            
            // Nie powinno panikować
            let result = scan_recipient_output(&corrupted_output, &sk);
            
            match result {
                ScanResult::Match { .. } => {
                    // Bardzo mało prawdopodobne z losowymi danymi
                }
                ScanResult::NotForUs => {
                    // Oczekiwane
                }
                ScanResult::Error(_) => {
                    // Też OK
                }
            }
        }
        
        println!("✅ Skanowanie nie panikuje na uszkodzonych outputach");
    }

    #[test]
    fn test_signature_verify_handles_garbage() {
        let (pk, _) = generate_falcon_keypair();
        let message = b"Test message";
        
        // Próbuj zweryfikować losowe "podpisy"
        for _ in 0..50 {
            let garbage_sig = random_bytes(rand::random::<usize>() % 1000 + 100);
            
            let pk_converted = falcon_pk_from_bytes(pk.as_bytes()).unwrap();
            let result = falcon_verify_bytes(message, &garbage_sig, &pk_converted);
            
            // Nie powinno panikować
            assert!(result.is_err(), "Losowe bajty nie powinny być prawidłowym podpisem");
        }
        
        println!("✅ Weryfikacja podpisu nie panikuje na śmieciach");
    }

    #[test]
    fn test_encrypted_sender_id_handles_garbage_decrypt() {
        let (pk, _) = generate_kyber_keypair();
        let (ss, _) = kyber768::encapsulate(&pk);
        
        // Stwórz zmanipulowane encrypted sender IDs
        for _ in 0..50 {
            let garbage_encrypted = EncryptedSenderId {
                nonce: random_bytes(12).try_into().unwrap(),
                ciphertext: random_bytes(48),
            };
            
            // Nie powinno panikować
            let result = garbage_encrypted.decrypt(&ss);
            
            match result {
                Ok(_) => {
                    // Bardzo mało prawdopodobne
                }
                Err(_) => {
                    // Oczekiwane - auth tag mismatch
                }
            }
        }
        
        println!("✅ Decryption nie panikuje na śmieciach");
    }
}

// ============================================================================
// 8. EDGE CASES I BOUNDARY CONDITIONS
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_zero_amount_transaction() {
        let (falcon_pk, falcon_sk) = generate_falcon_keypair();
        let (kyber_pk, kyber_sk) = generate_kyber_keypair();
        let (recipient_pk, _) = generate_kyber_keypair();
        
        let mut registry = StealthKeyRegistry::new();
        let sender_id = registry.register(
            falcon_pk.as_bytes().to_vec(),
            kyber_pk.as_bytes().to_vec(),
            0, 0,
        ).unwrap();

        // TX z zerowymi kwotami
        let tx = PrivateCompactTx::create(
            &falcon_sk, &kyber_sk, sender_id, &recipient_pk,
            0,  // Zero amount
            0,  // Zero fee
            1,
        ).unwrap();
        
        assert_eq!(tx.amount, 0);
        assert_eq!(tx.fee, 0);
        
        println!("✅ Zero amount TX działa");
    }

    #[test]
    fn test_max_amount_transaction() {
        let (falcon_pk, falcon_sk) = generate_falcon_keypair();
        let (kyber_pk, kyber_sk) = generate_kyber_keypair();
        let (recipient_pk, _) = generate_kyber_keypair();
        
        let mut registry = StealthKeyRegistry::new();
        let sender_id = registry.register(
            falcon_pk.as_bytes().to_vec(),
            kyber_pk.as_bytes().to_vec(),
            0, 0,
        ).unwrap();

        // TX z maksymalnymi kwotami
        let tx = PrivateCompactTx::create(
            &falcon_sk, &kyber_sk, sender_id, &recipient_pk,
            u64::MAX,  // Max amount
            u64::MAX,  // Max fee
            1,
        ).unwrap();
        
        assert_eq!(tx.amount, u64::MAX);
        assert_eq!(tx.fee, u64::MAX);
        
        println!("✅ Max amount TX działa");
    }

    #[test]
    fn test_large_nonce_values() {
        let (_, kyber_sk) = generate_kyber_keypair();
        
        // Test z różnymi wartościami nonce
        let nonces = [0u64, 1, u64::MAX, u64::MAX / 2, 12345678901234567890];
        
        for nonce in nonces {
            let output = SenderChangeOutput::generate(&kyber_sk, nonce);
            let (recovered_key, recovered_tag) = SenderChangeOutput::recover(&kyber_sk, &output);
            
            assert_eq!(output.stealth_key, recovered_key);
            assert_eq!(output.view_tag, recovered_tag);
        }
        
        println!("✅ Duże wartości nonce działają poprawnie");
    }

    #[test]
    fn test_empty_registry_get() {
        let registry = StealthKeyRegistry::new();
        let fake_id = [0x42u8; 32];
        
        assert!(registry.get(&fake_id).is_none());
        
        println!("✅ Pusty registry zwraca None dla nieistniejącego klucza");
    }
}

// ============================================================================
// 9. INTEGRATION TESTS
// ============================================================================

mod integration {
    use super::*;

    #[test]
    fn test_full_private_tx_flow() {
        // Setup
        let (sender_falcon_pk, sender_falcon_sk) = generate_falcon_keypair();
        let (sender_kyber_pk, sender_kyber_sk) = generate_kyber_keypair();
        let (recipient_kyber_pk, recipient_kyber_sk) = generate_kyber_keypair();
        
        let mut registry = StealthKeyRegistry::new();
        let sender_id = registry.register(
            sender_falcon_pk.as_bytes().to_vec(),
            sender_kyber_pk.as_bytes().to_vec(),
            1000, 100,
        ).unwrap();

        // 1. Sender tworzy TX
        let tx = PrivateCompactTx::create(
            &sender_falcon_sk,
            &sender_kyber_sk,
            sender_id,
            &recipient_kyber_pk,
            5000,
            50,
            1,
        ).unwrap();

        // 2. Recipient skanuje i znajduje TX
        let recipient_view_key = ViewKey::from_secrets(&recipient_kyber_sk, [0u8; 32]);
        let scan_result = recipient_view_key.scan_as_recipient(&tx).unwrap();
        
        assert_eq!(scan_result.amount, 5000);
        assert_eq!(scan_result.sender_master_key_id.unwrap(), sender_id);

        // 3. Sender skanuje change
        let sender_view_key = ViewKey::from_secrets(&sender_kyber_sk, sender_id);
        assert!(sender_view_key.scan_as_sender(&tx).is_some());

        // 4. Third party NIE może nic zobaczyć
        let (_, third_party_sk) = generate_kyber_keypair();
        let third_party_view = ViewKey::from_secrets(&third_party_sk, [0u8; 32]);
        assert!(third_party_view.scan_as_recipient(&tx).is_none());
        assert!(third_party_view.scan_as_sender(&tx).is_none());

        // 5. Weryfikacja podpisu
        assert!(tx.verify_with_sender_id(&sender_id, &registry).unwrap());

        println!("✅ Pełny flow prywatnej transakcji działa");
    }

    #[test]
    fn test_multiple_recipients_same_sender() {
        let (sender_falcon_pk, sender_falcon_sk) = generate_falcon_keypair();
        let (sender_kyber_pk, sender_kyber_sk) = generate_kyber_keypair();
        
        let mut registry = StealthKeyRegistry::new();
        let sender_id = registry.register(
            sender_falcon_pk.as_bytes().to_vec(),
            sender_kyber_pk.as_bytes().to_vec(),
            0, 0,
        ).unwrap();

        // Generuj wielu odbiorców
        let recipients: Vec<_> = (0..10)
            .map(|_| generate_kyber_keypair())
            .collect();

        // Wyślij do każdego
        let mut txs = Vec::new();
        for (i, (recipient_pk, _)) in recipients.iter().enumerate() {
            let tx = PrivateCompactTx::create(
                &sender_falcon_sk,
                &sender_kyber_sk,
                sender_id,
                recipient_pk,
                (i as u64 + 1) * 100,
                10,
                i as u64,
            ).unwrap();
            txs.push(tx);
        }

        // Każdy recipient może skanować TYLKO swoją TX
        for (i, ((_, recipient_sk), tx)) in recipients.iter().zip(txs.iter()).enumerate() {
            let view_key = ViewKey::from_secrets(recipient_sk, [0u8; 32]);
            
            // Może skanować swoją
            let result = view_key.scan_as_recipient(tx).unwrap();
            assert_eq!(result.amount, (i as u64 + 1) * 100);
            
            // NIE może skanować innych
            for (j, other_tx) in txs.iter().enumerate() {
                if i != j {
                    assert!(view_key.scan_as_recipient(other_tx).is_none(),
                        "Recipient {} nie powinien móc skanować TX {}", i, j);
                }
            }
        }

        println!("✅ 10 odbiorców, każdy widzi tylko swoje TX");
    }
}
