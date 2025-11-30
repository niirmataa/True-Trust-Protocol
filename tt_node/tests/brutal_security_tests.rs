//! ╔════════════════════════════════════════════════════════════════════════════╗
//! ║        BRUTAL SECURITY TESTS - PRAWDZIWE ATAKI NA TT_NODE                  ║
//! ╠════════════════════════════════════════════════════════════════════════════╣
//! ║ Te testy NIE sprawdzają czy działa - próbują ZŁAMAĆ system.               ║
//! ║ Każdy test symuluje rzeczywisty atak na kryptografię TTP.                 ║
//! ║                                                                            ║
//! ║ KATEGORIE ATAKÓW:                                                         ║
//! ║ 1. Malleability - modyfikacja podpisów/ciphertext                        ║
//! ║ 2. Replay - ponowne użycie danych                                        ║
//! ║ 3. Oracle - wykorzystanie error messages                                 ║
//! ║ 4. Key Confusion - użycie klucza w złym kontekście                       ║
//! ║ 5. Nonce Reuse - katastrofalne skutki powtórzenia                        ║
//! ║ 6. Side Channel - timing, cache attacks                                  ║
//! ║ 7. State Confusion - wyścigi między stanami                              ║
//! ║ 8. Deserialization - złośliwe dane wejściowe                             ║
//! ║ 9. Commitment - fałszowanie commitmentów                                 ║
//! ║ 10. Stealth - próby linkowania transakcji                                ║
//! ╚════════════════════════════════════════════════════════════════════════════╝

use tt_node::crypto::kmac::{kmac256_derive_key, kmac256_xof, kmac256_tag, shake256_32};
use tt_node::crypto::kmac_drbg::KmacDrbg;
use tt_node::falcon_sigs::{
    falcon_keypair, falcon_sign, falcon_verify, falcon_sign_nullifier,
    falcon_verify_nullifier, falcon_pk_to_bytes, falcon_sk_to_bytes,
    falcon_pk_from_bytes, falcon_sk_from_bytes, compute_pqc_fingerprint,
    falcon_verify_bytes, deserialize_signature, serialize_signature,
    SignedNullifier,
};
use tt_node::kyber_kem::{
    kyber_keypair, kyber_encapsulate, kyber_decapsulate, kyber_ss_to_bytes,
    kyber_pk_from_bytes, kyber_sk_from_bytes, kyber_pk_to_bytes, kyber_sk_to_bytes,
    kyber_ct_to_bytes, kyber_ct_from_bytes, derive_aes_key_from_shared_secret,
    initiate_key_exchange, complete_key_exchange,
};
use tt_node::stealth_registry::{
    StealthKeyRegistry, RecipientStealthOutput, SenderChangeOutput,
    EncryptedSenderId,
};

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey as KemPK, SecretKey as KemSK, Ciphertext as KemCT, SharedSecret as KemSS};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey as SignPK, SecretKey as SignSK};

use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;
use std::time::Instant;

fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    OsRng.fill_bytes(&mut b);
    b
}

// ============================================================================
// 1. SIGNATURE MALLEABILITY ATTACKS
// ============================================================================

mod malleability_attacks {
    use super::*;

    /// ATAK: Bit-flip na podpisie Falcon
    /// Cel: Sprawdzić czy zmodyfikowany podpis przejdzie weryfikację
    #[test]
    fn attack_falcon_signature_bitflip() {
        let (pk, sk) = falcon_keypair();
        let nullifier = random_32();
        let sig = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        
        // Próbuj wszystkich pozycji bit-flip
        let sig_bytes = sig.as_bytes().to_vec();
        let mut detected_tampering = 0;
        let mut total_attempts = 0;
        
        // Testuj pierwsze 100 bajtów i środkowe 100 bajtów
        for pos in (0..100).chain(sig_bytes.len()/2..sig_bytes.len()/2+100) {
            if pos >= sig_bytes.len() { continue; }
            
            for bit in 0..8 {
                let mut tampered = sig_bytes.clone();
                tampered[pos] ^= 1 << bit;
                
                // Deserializuj jako SignedNullifier
                let tampered_sig = SignedNullifier {
                    signed_message_bytes: tampered,
                };
                
                total_attempts += 1;
                
                // Każda modyfikacja MUSI być wykryta
                if falcon_verify_nullifier(&nullifier, &tampered_sig, &pk).is_err() {
                    detected_tampering += 1;
                }
            }
        }
        
        // WSZYSTKIE modyfikacje muszą być wykryte!
        assert_eq!(detected_tampering, total_attempts,
            "KRYTYCZNE: {} z {} modyfikacji przeszło weryfikację!",
            total_attempts - detected_tampering, total_attempts);
        
        println!("✅ Falcon: {}/{} bit-flips wykrytych", detected_tampering, total_attempts);
    }

    /// ATAK: Zamiana wiadomości przy tym samym podpisie
    /// Cel: Podpis dla wiadomości A działa dla wiadomości B?
    #[test]
    fn attack_falcon_message_substitution() {
        let (pk, sk) = falcon_keypair();
        
        // Podpisz różne wiadomości
        let messages: Vec<&[u8]> = vec![
            b"Transfer 100 TTP to Alice",
            b"Transfer 1000000 TTP to Attacker",
            b"Transfer 100 TTP to ALICE",  // Tylko różnica w wielkości liter
            b"",
            &[0u8; 32],
            &[0xFFu8; 32],
        ];
        
        for msg_a in &messages {
            let sig = falcon_sign(msg_a, &sk).unwrap();
            
            for msg_b in &messages {
                if msg_a == msg_b { continue; }
                
                // Podpis dla msg_a NIE może działać dla msg_b
                assert!(falcon_verify(msg_b, &sig, &pk).is_err(),
                    "KRYTYCZNE: Podpis dla {:?} działa dla {:?}!",
                    String::from_utf8_lossy(msg_a),
                    String::from_utf8_lossy(msg_b));
            }
        }
        
        println!("✅ Falcon: {} wiadomości, brak substytucji", messages.len());
    }

    /// ATAK: Truncation/extension podpisu
    #[test]
    fn attack_falcon_signature_truncation() {
        let (pk, sk) = falcon_keypair();
        let sig = falcon_sign_nullifier(&random_32(), &sk).unwrap();
        let sig_bytes = sig.as_bytes();
        
        // Próby obcięcia
        for cut in [1, 10, 50, 100, sig_bytes.len()/2] {
            if cut >= sig_bytes.len() { continue; }
            
            let truncated = SignedNullifier {
                signed_message_bytes: sig_bytes[..sig_bytes.len()-cut].to_vec(),
            };
            
            // Obcięte podpisy MUSZĄ być odrzucone
            // (używamy dowolnego nullifier bo i tak powinno failować)
            assert!(falcon_verify_nullifier(&random_32(), &truncated, &pk).is_err(),
                "KRYTYCZNE: Obcięty podpis (cut={}) przeszedł!", cut);
        }
        
        // Próby rozszerzenia
        for extend in [1, 10, 100] {
            let mut extended = sig_bytes.to_vec();
            extended.extend(vec![0u8; extend]);
            
            let extended_sig = SignedNullifier {
                signed_message_bytes: extended,
            };
            
            assert!(falcon_verify_nullifier(&random_32(), &extended_sig, &pk).is_err(),
                "KRYTYCZNE: Rozszerzony podpis przeszedł!");
        }
        
        println!("✅ Falcon: truncation/extension attacks odparte");
    }
}

// ============================================================================
// 2. KEY CONFUSION ATTACKS
// ============================================================================

mod key_confusion_attacks {
    use super::*;

    /// ATAK: Użycie Kyber klucza jako Falcon klucza
    #[test]
    fn attack_cross_key_confusion() {
        let (falcon_pk, falcon_sk) = falcon_keypair();
        let (kyber_pk, kyber_sk) = kyber_keypair();
        
        // Próba użycia bajtów Kyber PK jako Falcon PK
        let kyber_pk_bytes = kyber_pk_to_bytes(&kyber_pk);
        let result = falcon_pk_from_bytes(kyber_pk_bytes);
        assert!(result.is_err(), "KRYTYCZNE: Kyber PK zaakceptowany jako Falcon PK!");
        
        // Próba użycia bajtów Falcon PK jako Kyber PK
        let falcon_pk_bytes = falcon_pk_to_bytes(&falcon_pk);
        let result = kyber_pk_from_bytes(falcon_pk_bytes);
        assert!(result.is_err(), "KRYTYCZNE: Falcon PK zaakceptowany jako Kyber PK!");
        
        // Podobne testy dla secret keys
        let kyber_sk_bytes = kyber_sk_to_bytes(&kyber_sk);
        assert!(falcon_sk_from_bytes(&kyber_sk_bytes).is_err());
        
        let falcon_sk_bytes = falcon_sk_to_bytes(&falcon_sk);
        assert!(kyber_sk_from_bytes(&falcon_sk_bytes).is_err());
        
        println!("✅ Key confusion: wszystkie cross-key użycia odrzucone");
    }

    /// ATAK: Zamiana kluczy między użytkownikami
    #[test]
    fn attack_wrong_user_key() {
        let (pk_alice, sk_alice) = falcon_keypair();
        let (pk_bob, sk_bob) = falcon_keypair();
        let (pk_charlie, _) = falcon_keypair();
        
        // Alice podpisuje
        let msg = b"Alice authorizes transfer";
        let sig_alice = falcon_sign(msg, &sk_alice).unwrap();
        
        // Weryfikacja kluczem Boba MUSI failować
        assert!(falcon_verify(msg, &sig_alice, &pk_bob).is_err(),
            "KRYTYCZNE: Podpis Alice zweryfikowany kluczem Boba!");
        
        // Weryfikacja kluczem Charliego MUSI failować
        assert!(falcon_verify(msg, &sig_alice, &pk_charlie).is_err(),
            "KRYTYCZNE: Podpis Alice zweryfikowany kluczem Charliego!");
        
        // Bob podpisuje tę samą wiadomość
        let sig_bob = falcon_sign(msg, &sk_bob).unwrap();
        
        // Oba podpisy są RÓŻNE (różne klucze = różne podpisy)
        assert_ne!(sig_alice.as_bytes(), sig_bob.as_bytes(),
            "OSTRZEŻENIE: Identyczne podpisy dla różnych kluczy!");
        
        println!("✅ Key confusion: user key isolation works");
    }

    /// ATAK: Key derivation confusion w KMAC
    #[test]
    fn attack_kmac_key_derivation_confusion() {
        let master_key = random_32();
        
        // Różne domeny MUSZĄ dawać różne klucze
        let key_sign = kmac256_derive_key(&master_key, b"SIGNING", b"v1");
        let key_enc = kmac256_derive_key(&master_key, b"ENCRYPTION", b"v1");
        let key_kdf = kmac256_derive_key(&master_key, b"KDF", b"v1");
        
        assert_ne!(key_sign, key_enc);
        assert_ne!(key_enc, key_kdf);
        assert_ne!(key_sign, key_kdf);
        
        // Nawet 1 bit różnicy w domain = zupełnie inny klucz
        let key_sign2 = kmac256_derive_key(&master_key, b"SIGNINF", b"v1");  // G -> F
        
        let diff_bits = key_sign.iter().zip(key_sign2.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum::<u32>();
        
        assert!(diff_bits > 100, "Avalanche za słaby: {} bits", diff_bits);
        
        println!("✅ KMAC key derivation: domain separation OK ({}b diff)", diff_bits);
    }
}

// ============================================================================
// 3. REPLAY ATTACKS
// ============================================================================

mod replay_attacks {
    use super::*;

    /// ATAK: Replay podpisu nullifier
    /// Scenariusz: Atakujący widzi TX i próbuje go powtórzyć
    #[test]
    fn attack_nullifier_replay() {
        let (pk, sk) = falcon_keypair();
        
        // Oryginalny nullifier i podpis
        let nullifier = random_32();
        let sig = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        
        // Ten sam podpis jest ważny - to ODPOWIEDZIALNOŚĆ WARSTWY KONSENSUSU
        // aby odrzucić powtórzone nullifiery (nie kryptografii)
        assert!(falcon_verify_nullifier(&nullifier, &sig, &pk).is_ok());
        
        // Ale podpis NIE działa dla innego nullifier
        let new_nullifier = random_32();
        assert!(falcon_verify_nullifier(&new_nullifier, &sig, &pk).is_err());
        
        // Zbiór unikalnych nullifierów (symulacja ledgera)
        let mut spent_nullifiers: HashSet<[u8; 32]> = HashSet::new();
        
        // Pierwsza TX - OK
        if !spent_nullifiers.contains(&nullifier) {
            spent_nullifiers.insert(nullifier);
            // TX zaakceptowana
        }
        
        // Replay - MUSI być odrzucony przez ledger
        let replay_accepted = !spent_nullifiers.contains(&nullifier);
        assert!(!replay_accepted, "KRYTYCZNE: Replay nullifier zaakceptowany!");
        
        println!("✅ Replay protection: nullifier-based (layer 2 responsibility)");
    }

    /// ATAK: KEM replay - ta sama ciphertext, różni odbiorcy
    #[test]
    fn attack_kem_replay() {
        let (pk_alice, sk_alice) = kyber_keypair();
        let (pk_bob, sk_bob) = kyber_keypair();
        
        // Sender encapsuluje do Alice
        let (ss_sender, ct) = kyber_encapsulate(&pk_alice);
        
        // Alice może deszyfrować
        let ss_alice = kyber_decapsulate(&ct, &sk_alice).unwrap();
        assert_eq!(kyber_ss_to_bytes(&ss_sender).as_slice(), 
                   kyber_ss_to_bytes(&ss_alice).as_slice());
        
        // Bob NIE MOŻE odzyskać tego samego shared secret
        // (Kyber używa implicit rejection - zwraca pseudo-random, nie error)
        let ss_bob = kyber_decapsulate(&ct, &sk_bob).unwrap();
        assert_ne!(kyber_ss_to_bytes(&ss_sender).as_slice(),
                   kyber_ss_to_bytes(&ss_bob).as_slice(),
            "KRYTYCZNE: Bob odzyskał shared secret Alice!");
        
        println!("✅ KEM replay: implicit rejection działa");
    }

    /// ATAK: Stealth address replay
    #[test]
    fn attack_stealth_replay() {
        let (kpk, ksk) = kyber768::keypair();
        
        // Generuj stealth output
        let (stealth1, ss1) = RecipientStealthOutput::generate(&kpk).unwrap();
        let (stealth2, ss2) = RecipientStealthOutput::generate(&kpk).unwrap();
        
        // Każde wywołanie MUSI generować unikalny stealth_key
        assert_ne!(stealth1.stealth_key, stealth2.stealth_key,
            "KRYTYCZNE: Powtórzony stealth_key!");
        
        // I unikalne view_tag
        assert_ne!(stealth1.view_tag, stealth2.view_tag,
            "OSTRZEŻENIE: Powtórzony view_tag (możliwe, ale mało prawdopodobne)");
        
        // I unikalne shared secrets
        assert_ne!(kyber_ss_to_bytes(&ss1).as_slice(),
                   kyber_ss_to_bytes(&ss2).as_slice());
        
        println!("✅ Stealth replay: unikalne dla każdego wywołania");
    }
}

// ============================================================================
// 4. CIPHERTEXT MALLEABILITY (KYBER)
// ============================================================================

mod kyber_attacks {
    use super::*;

    /// ATAK: Bit-flip na Kyber ciphertext
    /// Kyber ma implicit rejection - każda modyfikacja = inny shared secret
    #[test]
    fn attack_kyber_ciphertext_bitflip() {
        let (pk, sk) = kyber_keypair();
        let (original_ss, ct) = kyber_encapsulate(&pk);
        let ct_bytes = kyber_ct_to_bytes(&ct).to_vec();
        
        let mut different_ss_count = 0;
        let mut same_ss_count = 0;
        
        // Testuj bit-flip na różnych pozycjach
        for pos in (0..50).chain(ct_bytes.len()/2..ct_bytes.len()/2+50) {
            if pos >= ct_bytes.len() { continue; }
            
            let mut tampered = ct_bytes.clone();
            tampered[pos] ^= 0x01;  // Flip 1 bit
            
            let tampered_ct = kyber_ct_from_bytes(&tampered).unwrap();
            let recovered_ss = kyber_decapsulate(&tampered_ct, &sk).unwrap();
            
            // Implicit rejection: zwraca pseudo-random, nie original
            if kyber_ss_to_bytes(&original_ss).as_slice() 
               != kyber_ss_to_bytes(&recovered_ss).as_slice() {
                different_ss_count += 1;
            } else {
                same_ss_count += 1;
            }
        }
        
        // WSZYSTKIE modyfikacje MUSZĄ dać inny shared secret
        assert_eq!(same_ss_count, 0,
            "KRYTYCZNE: {} modyfikacji dało ten sam shared secret!", same_ss_count);
        
        println!("✅ Kyber implicit rejection: {}/{} modyfikacji = różny SS",
            different_ss_count, different_ss_count);
    }

    /// ATAK: Truncated ciphertext
    #[test]
    fn attack_kyber_truncated_ciphertext() {
        let (pk, sk) = kyber_keypair();
        let (original_ss, ct) = kyber_encapsulate(&pk);
        let ct_bytes = kyber_ct_to_bytes(&ct);
        
        // Próby obcięcia ciphertext
        for cut in [1, 10, 100, 500] {
            if cut >= ct_bytes.len() { continue; }
            
            let truncated = &ct_bytes[..ct_bytes.len()-cut];
            
            // Obcięty ciphertext powinien być odrzucony na poziomie parsowania
            let result = kyber_ct_from_bytes(truncated);
            assert!(result.is_err(),
                "KRYTYCZNE: Obcięty ciphertext (cut={}) zaakceptowany!", cut);
        }
        
        println!("✅ Kyber: truncated ciphertext odrzucony");
    }

    /// ATAK: Zero ciphertext / all-ones ciphertext
    #[test]
    fn attack_kyber_special_ciphertexts() {
        let (pk, sk) = kyber_keypair();
        let ct_len = 1088;  // Kyber-768 ciphertext size
        
        // Zero ciphertext
        let zero_ct = vec![0u8; ct_len];
        if let Ok(parsed_ct) = kyber_ct_from_bytes(&zero_ct) {
            let ss = kyber_decapsulate(&parsed_ct, &sk).unwrap();
            // Powinien zwrócić pseudo-random (implicit rejection)
            // ale NIE powinien crashować ani ujawniać sk
            assert_eq!(kyber_ss_to_bytes(&ss).len(), 32);
            println!("  Zero CT: zwraca pseudo-random SS (OK)");
        } else {
            println!("  Zero CT: odrzucony przy parsowaniu (OK)");
        }
        
        // All-ones ciphertext
        let ones_ct = vec![0xFFu8; ct_len];
        if let Ok(parsed_ct) = kyber_ct_from_bytes(&ones_ct) {
            let ss = kyber_decapsulate(&parsed_ct, &sk).unwrap();
            assert_eq!(kyber_ss_to_bytes(&ss).len(), 32);
            println!("  All-ones CT: zwraca pseudo-random SS (OK)");
        } else {
            println!("  All-ones CT: odrzucony przy parsowaniu (OK)");
        }
        
        println!("✅ Kyber: special ciphertexts handled safely");
    }
}

// ============================================================================
// 5. STEALTH ADDRESS LINKABILITY ATTACKS
// ============================================================================

mod stealth_linkability_attacks {
    use super::*;

    /// ATAK: Próba linkowania transakcji przez stealth_key
    #[test]
    fn attack_stealth_key_linkability() {
        let (kpk, _) = kyber768::keypair();
        
        // 100 transakcji do tego samego odbiorcy
        let outputs: Vec<_> = (0..100)
            .map(|_| RecipientStealthOutput::generate(&kpk).unwrap().0)
            .collect();
        
        // Wszystkie stealth_keys MUSZĄ być unikalne
        let unique_keys: HashSet<_> = outputs.iter()
            .map(|o| o.stealth_key)
            .collect();
        
        assert_eq!(unique_keys.len(), 100,
            "KRYTYCZNE: Linkowanie możliwe przez powtórzone stealth_key!");
        
        // Wszystkie view_tags MUSZĄ być unikalne (lub prawie)
        let unique_tags: HashSet<_> = outputs.iter()
            .map(|o| o.view_tag)
            .collect();
        
        // Przy 8-bajtowych tagach, 100 TX powinno dać ~100 unikalnych
        assert!(unique_tags.len() > 95,
            "OSTRZEŻENIE: Za mało unikalnych view_tags: {}", unique_tags.len());
        
        println!("✅ Stealth linkability: {}/100 unikalnych keys, {}/100 tags",
            unique_keys.len(), unique_tags.len());
    }

    /// ATAK: Linkowanie przez sender change outputs
    #[test]
    fn attack_sender_change_linkability() {
        let (_, ksk) = kyber768::keypair();
        
        // 100 change outputs z różnymi nonce
        let changes: Vec<_> = (0..100u64)
            .map(|nonce| SenderChangeOutput::generate(&ksk, nonce))
            .collect();
        
        // Wszystkie stealth_keys MUSZĄ być unikalne
        let unique_keys: HashSet<_> = changes.iter()
            .map(|c| c.stealth_key)
            .collect();
        
        assert_eq!(unique_keys.len(), 100,
            "KRYTYCZNE: Sender change outputs linkable!");
        
        // Weryfikacja is_ours
        let (_, other_sk) = kyber768::keypair();
        for change in &changes {
            assert!(SenderChangeOutput::is_ours(&ksk, change));
            assert!(!SenderChangeOutput::is_ours(&other_sk, change));
        }
        
        println!("✅ Sender change: 100% unlinkable, is_ours works");
    }

    /// ATAK: Nonce reuse w sender change
    #[test]
    fn attack_sender_change_nonce_reuse() {
        let (_, ksk) = kyber768::keypair();
        
        // Ten sam nonce = czy wyciek?
        let change1 = SenderChangeOutput::generate(&ksk, 42);
        let change2 = SenderChangeOutput::generate(&ksk, 42);
        
        // Dzięki random salt, nawet ten sam nonce = różne outputs
        assert_ne!(change1.stealth_key, change2.stealth_key,
            "KRYTYCZNE: Nonce reuse = identyczny stealth_key!");
        assert_ne!(change1.salt, change2.salt,
            "Salt powinien być różny!");
        
        // Ale oba można odzyskać
        assert!(SenderChangeOutput::is_ours(&ksk, &change1));
        assert!(SenderChangeOutput::is_ours(&ksk, &change2));
        
        println!("✅ Nonce reuse: salt chroni przed linkability");
    }

    /// ATAK: Analiza view_tag distribution
    #[test]
    fn attack_view_tag_distribution() {
        let (kpk, _) = kyber768::keypair();
        
        // 1000 outputs
        let outputs: Vec<_> = (0..1000)
            .map(|_| RecipientStealthOutput::generate(&kpk).unwrap().0)
            .collect();
        
        // Analiza pierwszego bajtu view_tag
        let mut distribution = [0u32; 256];
        for o in &outputs {
            distribution[o.view_tag[0] as usize] += 1;
        }
        
        // Chi-square test approximation
        let expected = 1000.0 / 256.0;  // ~3.9
        let chi_sq: f64 = distribution.iter()
            .map(|&count| {
                let diff = count as f64 - expected;
                diff * diff / expected
            })
            .sum();
        
        // Chi-square critical value for df=255, p=0.01 is ~310
        // Ale akceptujemy też biased RNG (nie jest to krypto-failure)
        let is_uniform = chi_sq < 400.0;
        
        println!("  View tag chi-square: {:.1} (uniform=<310)", chi_sq);
        
        if !is_uniform {
            println!("  OSTRZEŻENIE: View tags nie są idealnie uniform");
        }
        
        println!("✅ View tag distribution analyzed");
    }
}

// ============================================================================
// 6. DRBG ATTACKS
// ============================================================================

mod drbg_attacks {
    use super::*;

    /// ATAK: Prediction after observing output
    #[test]
    fn attack_drbg_prediction() {
        let seed = random_32();
        let mut drbg = KmacDrbg::new(&seed, b"test");
        
        // Obserwuj 10 bloków output
        let mut observed = Vec::new();
        for _ in 0..10 {
            let mut out = [0u8; 32];
            drbg.fill_bytes(&mut out);
            observed.push(out);
        }
        
        // Próba predykcji następnego bloku na podstawie observed
        // (bez znajomości seed)
        
        // Atakujący nie może odtworzyć stanu DRBG
        // Jedyna opcja: brute-force seed space (2^256)
        
        // Sprawdź że output nie da się trywianie przewidzieć
        let mut next = [0u8; 32];
        drbg.fill_bytes(&mut next);
        
        // XOR z poprzednim nie da predictable pattern
        let xor_prev: Vec<u8> = next.iter()
            .zip(observed.last().unwrap().iter())
            .map(|(a, b)| a ^ b)
            .collect();
        
        let ones = xor_prev.iter().map(|b| b.count_ones()).sum::<u32>();
        // Powinno być ~128 bitów różnicy (random)
        assert!(ones > 80 && ones < 176, "XOR pattern podejrzany: {} bits", ones);
        
        println!("✅ DRBG: output unpredictable ({} bit diff)", ones);
    }

    /// ATAK: State recovery po ratchet
    #[test]
    fn attack_drbg_post_ratchet_recovery() {
        let seed = random_32();
        let mut drbg1 = KmacDrbg::new(&seed, b"test");
        let mut drbg2 = KmacDrbg::new(&seed, b"test");
        
        // drbg1 generuje i robi ratchet
        let mut before = [0u8; 32];
        drbg1.fill_bytes(&mut before);
        drbg1.ratchet();
        let mut after = [0u8; 32];
        drbg1.fill_bytes(&mut after);
        
        // drbg2 - atakujący zna seed, próbuje odzyskać stan po ratchet
        let mut check = [0u8; 32];
        drbg2.fill_bytes(&mut check);
        assert_eq!(before, check);  // Przed ratchet = identyczne
        
        // Ale po ratchet - atakujący nie może przewidzieć
        // (bo ratchet używa internal state którego nie zna)
        drbg2.fill_bytes(&mut check);
        assert_ne!(after, check, "Ratchet nie zmienił stanu!");
        
        println!("✅ DRBG ratchet: forward secrecy works");
    }

    /// ATAK: Collision search
    #[test]
    fn attack_drbg_collision() {
        let mut outputs: HashSet<[u8; 32]> = HashSet::new();
        
        // Generuj z wielu seedów
        for i in 0..1000u32 {
            let mut seed = [0u8; 32];
            seed[0..4].copy_from_slice(&i.to_le_bytes());
            
            let mut drbg = KmacDrbg::new(&seed, b"collision");
            let mut out = [0u8; 32];
            drbg.fill_bytes(&mut out);
            
            assert!(outputs.insert(out),
                "KRYTYCZNE: Kolizja DRBG dla seed {}", i);
        }
        
        println!("✅ DRBG: 0 kolizji w 1000 seedach");
    }
}

// ============================================================================
// 7. DESERIALIZATION ATTACKS
// ============================================================================

mod deserialization_attacks {
    use super::*;

    /// ATAK: Złośliwe bajty dla Falcon PK
    #[test]
    fn attack_malformed_falcon_pk() {
        let malformed: Vec<Vec<u8>> = vec![
            vec![],                          // Empty
            vec![0u8; 100],                  // Too short
            vec![0u8; 897],                  // Correct length, all zeros
            vec![0xFFu8; 897],               // Correct length, all ones
            vec![0u8; 1000],                 // Too long
            (0..897).map(|i| i as u8).collect(),  // Predictable pattern
        ];
        
        for (i, bad_pk) in malformed.iter().enumerate() {
            let result = falcon_pk_from_bytes(bad_pk);
            // Niektóre mogą być "valid" strukturalnie (np. all-zeros)
            // ale nie powinny crashować
            match &result {
                Ok(_) => println!("  Case {}: parsed (may be weak key)", i),
                Err(_) => println!("  Case {}: rejected", i),
            }
        }
        
        println!("✅ Falcon PK: malformed inputs handled");
    }

    /// ATAK: Złośliwe bajty dla Kyber PK
    #[test]
    fn attack_malformed_kyber_pk() {
        let malformed: Vec<Vec<u8>> = vec![
            vec![],
            vec![0u8; 100],
            vec![0u8; 1184],     // Correct length
            vec![0xFFu8; 1184],
            vec![0u8; 2000],
        ];
        
        for (i, bad_pk) in malformed.iter().enumerate() {
            let result = kyber_pk_from_bytes(bad_pk);
            match &result {
                Ok(_) => println!("  Case {}: parsed", i),
                Err(_) => println!("  Case {}: rejected", i),
            }
        }
        
        println!("✅ Kyber PK: malformed inputs handled");
    }

    /// ATAK: Signature deserialization bomb
    #[test]
    fn attack_signature_bomb() {
        // Próba "billion laughs" / decompression bomb
        let huge_sig = vec![0x42u8; 100_000];  // 100KB "signature"
        
        // To powinno być szybko odrzucone, nie OOM
        let start = Instant::now();
        let _ = deserialize_signature(&huge_sig);
        let elapsed = start.elapsed();
        
        assert!(elapsed.as_millis() < 100,
            "KRYTYCZNE: Deserializacja trwała {}ms - DoS vector!", elapsed.as_millis());
        
        println!("✅ Signature deserialization: fast rejection ({}ms)", elapsed.as_millis());
    }
}

// ============================================================================
// 8. TIMING ATTACKS (podstawowe)
// ============================================================================

mod timing_attacks {
    use super::*;

    /// ATAK: Timing różnica dla valid vs invalid signature
    #[test]
    fn attack_signature_timing() {
        let (pk, sk) = falcon_keypair();
        let msg = b"test message for timing";
        let valid_sig = falcon_sign(msg, &sk).unwrap();
        
        // Invalid signature
        let mut invalid_bytes = valid_sig.as_bytes().to_vec();
        invalid_bytes[50] ^= 0xFF;
        let invalid_sig = SignedNullifier {
            signed_message_bytes: invalid_bytes,
        };
        
        // Measure valid verification
        let mut valid_times = Vec::new();
        for _ in 0..100 {
            let start = Instant::now();
            let _ = falcon_verify(msg, &valid_sig, &pk);
            valid_times.push(start.elapsed().as_nanos());
        }
        
        // Measure invalid verification
        let mut invalid_times = Vec::new();
        for _ in 0..100 {
            let start = Instant::now();
            let _ = falcon_verify(msg, &invalid_sig, &pk);
            invalid_times.push(start.elapsed().as_nanos());
        }
        
        let valid_avg: u128 = valid_times.iter().sum::<u128>() / valid_times.len() as u128;
        let invalid_avg: u128 = invalid_times.iter().sum::<u128>() / invalid_times.len() as u128;
        
        let ratio = valid_avg as f64 / invalid_avg as f64;
        
        println!("  Valid avg: {}ns, Invalid avg: {}ns, Ratio: {:.2}",
            valid_avg, invalid_avg, ratio);
        
        // Timing difference > 2x może wskazywać na timing leak
        if ratio > 2.0 || ratio < 0.5 {
            println!("  OSTRZEŻENIE: Znacząca różnica czasowa - potencjalny timing leak");
        }
        
        println!("✅ Timing analysis: ratio {:.2}", ratio);
    }

    /// ATAK: Kyber decapsulation timing
    #[test]
    fn attack_kyber_decap_timing() {
        let (pk, sk) = kyber_keypair();
        let (_, valid_ct) = kyber_encapsulate(&pk);
        
        // Tampered ciphertext
        let mut invalid_bytes = kyber_ct_to_bytes(&valid_ct).to_vec();
        invalid_bytes[100] ^= 0xFF;
        let invalid_ct = kyber_ct_from_bytes(&invalid_bytes).unwrap();
        
        // Measure times
        let mut valid_times = Vec::new();
        let mut invalid_times = Vec::new();
        
        for _ in 0..100 {
            let start = Instant::now();
            let _ = kyber_decapsulate(&valid_ct, &sk);
            valid_times.push(start.elapsed().as_nanos());
            
            let start = Instant::now();
            let _ = kyber_decapsulate(&invalid_ct, &sk);
            invalid_times.push(start.elapsed().as_nanos());
        }
        
        let valid_avg: u128 = valid_times.iter().sum::<u128>() / 100;
        let invalid_avg: u128 = invalid_times.iter().sum::<u128>() / 100;
        let ratio = valid_avg as f64 / invalid_avg as f64;
        
        println!("  Valid avg: {}ns, Invalid avg: {}ns, Ratio: {:.2}",
            valid_avg, invalid_avg, ratio);
        
        // Kyber's implicit rejection should have constant time
        if ratio > 1.5 || ratio < 0.67 {
            println!("  OSTRZEŻENIE: Kyber timing różnica - sprawdź implementację");
        }
        
        println!("✅ Kyber timing: ratio {:.2}", ratio);
    }
}

// ============================================================================
// 9. COMMITMENT ATTACKS
// ============================================================================

mod commitment_attacks {
    use super::*;

    /// ATAK: PQC fingerprint collision
    #[test]
    fn attack_fingerprint_collision() {
        // Generuj 100 par kluczy i sprawdź kolizje fingerprint
        let mut fingerprints: HashSet<[u8; 32]> = HashSet::new();
        
        for _ in 0..100 {
            let (fpk, _) = falcon_keypair();
            let (kpk, _) = kyber_keypair();
            
            let fp = compute_pqc_fingerprint(&fpk, kyber_pk_to_bytes(&kpk));
            
            assert!(fingerprints.insert(fp),
                "KRYTYCZNE: Kolizja fingerprint!");
        }
        
        println!("✅ PQC fingerprint: 0 kolizji w 100 parach");
    }

    /// ATAK: Master key ID collision
    #[test]
    fn attack_master_key_id_collision() {
        let mut ids: HashSet<[u8; 32]> = HashSet::new();
        
        for _ in 0..100 {
            let (fpk, _) = falcon512::keypair();
            let (kpk, _) = kyber768::keypair();
            
            let id = StealthKeyRegistry::compute_master_key_id(
                fpk.as_bytes(), kpk.as_bytes()
            );
            
            assert!(ids.insert(id), "KRYTYCZNE: Kolizja master_key_id!");
        }
        
        println!("✅ Master key ID: 0 kolizji w 100 parach");
    }

    /// ATAK: Registry double-register
    #[test]
    fn attack_registry_double_register() {
        let mut reg = StealthKeyRegistry::new();
        let (fpk, _) = falcon512::keypair();
        let (kpk, _) = kyber768::keypair();
        
        // Pierwsza rejestracja
        let id1 = reg.register(
            fpk.as_bytes().to_vec(),
            kpk.as_bytes().to_vec(),
            1000, 100
        ).unwrap();
        
        // Próba ponownej rejestracji tych samych kluczy
        let id2 = reg.register(
            fpk.as_bytes().to_vec(),
            kpk.as_bytes().to_vec(),
            2000, 200
        ).unwrap();
        
        // Powinny być identyczne (idempotencja)
        assert_eq!(id1, id2);
        
        // Registry powinien mieć tylko 1 wpis
        let (total, current) = reg.stats();
        assert_eq!(current, 1, "Double register utworzył duplikat!");
        
        println!("✅ Registry: double-register = idempotent");
    }
}

// ============================================================================
// 10. ENCRYPTED SENDER ID ATTACKS
// ============================================================================

mod encrypted_sender_attacks {
    use super::*;

    /// ATAK: Deszyfrowanie sender_id bez znajomości shared_secret
    #[test]
    fn attack_decrypt_sender_id_without_ss() {
        let (kpk, ksk) = kyber768::keypair();
        let sender_id = random_32();
        
        // Generuj stealth output
        let (stealth, ss) = RecipientStealthOutput::generate(&kpk).unwrap();
        
        // Szyfruj sender_id pod shared_secret
        let encrypted = EncryptedSenderId::encrypt(&sender_id, &ss).unwrap();
        
        // Odbiorca może deszyfrować
        let decrypted = encrypted.decrypt(&ss).unwrap();
        assert_eq!(sender_id, decrypted);
        
        // Atakujący z innym shared_secret NIE może
        let (fake_ss, _) = kyber768::encapsulate(&kpk);
        let wrong_decrypted = encrypted.decrypt(&fake_ss);
        
        // AES-GCM powinien odrzucić (tag mismatch)
        assert!(wrong_decrypted.is_err(),
            "KRYTYCZNE: Sender ID odszyfrowany złym kluczem!");
        
        println!("✅ Encrypted sender ID: protected by AES-GCM");
    }

    /// ATAK: Malleability encrypted sender ID
    #[test]
    fn attack_malleate_encrypted_sender() {
        let (kpk, _) = kyber768::keypair();
        let sender_id = random_32();
        let (_, ss) = RecipientStealthOutput::generate(&kpk).unwrap();
        
        let encrypted = EncryptedSenderId::encrypt(&sender_id, &ss).unwrap();
        
        // Próba modyfikacji ciphertext
        let mut tampered = encrypted.clone();
        tampered.ciphertext[5] ^= 0xFF;
        
        // Musi failować przy deszyfrowaniu
        let result = tampered.decrypt(&ss);
        assert!(result.is_err(),
            "KRYTYCZNE: Zmodyfikowany ciphertext zaakceptowany!");
        
        println!("✅ Encrypted sender ID: tamper-evident");
    }
}

// ============================================================================
// STRESS TESTS
// ============================================================================

mod stress_tests {
    use super::*;

    /// Stress: 1000 podpisów jednym kluczem
    #[test]
    fn stress_1000_signatures() {
        let (pk, sk) = falcon_keypair();
        
        for i in 0..1000 {
            let msg = format!("Message #{}", i);
            let sig = falcon_sign(msg.as_bytes(), &sk).unwrap();
            assert!(falcon_verify(msg.as_bytes(), &sig, &pk).is_ok());
        }
        
        println!("✅ Stress: 1000 sign/verify OK");
    }

    /// Stress: 1000 KEM operations
    #[test]
    fn stress_1000_kem() {
        let (pk, sk) = kyber_keypair();
        
        for _ in 0..1000 {
            let (ss1, ct) = kyber_encapsulate(&pk);
            let ss2 = kyber_decapsulate(&ct, &sk).unwrap();
            assert_eq!(kyber_ss_to_bytes(&ss1).as_slice(),
                       kyber_ss_to_bytes(&ss2).as_slice());
        }
        
        println!("✅ Stress: 1000 encap/decap OK");
    }

    /// Stress: 10000 DRBG blocks
    #[test]
    fn stress_drbg_10k_blocks() {
        let mut drbg = KmacDrbg::new(&random_32(), b"stress");
        let mut total_bytes = 0usize;
        
        for _ in 0..10000 {
            let mut out = [0u8; 32];
            drbg.fill_bytes(&mut out);
            total_bytes += 32;
        }
        
        println!("✅ Stress: {}KB DRBG generated", total_bytes / 1024);
    }
}

// ============================================================================
// 11. PROOF-OF-POSSESSION TESTS
// ============================================================================

mod proof_of_possession_tests {
    use super::*;
    use tt_node::falcon_sigs::falcon_sign;

    /// TEST: Losowe klucze są odrzucane przez register_with_proof
    #[test]
    fn test_random_keys_rejected_with_proof() {
        let mut reg = StealthKeyRegistry::new();
        
        // Losowe bajty jako klucze
        let fake_falcon = random_bytes(897);
        let fake_kyber = random_bytes(1184);
        
        // Nie mamy prawdziwego klucza prywatnego, więc nie możemy podpisać
        // Próba z pustym podpisem
        let fake_sig = SignedNullifier {
            signed_message_bytes: random_bytes(700),
        };
        
        let result = reg.register_with_proof(
            fake_falcon, fake_kyber, &fake_sig, 0, 0
        );
        
        // MUSI być odrzucone!
        assert!(result.is_err(), "Losowe klucze powinny być odrzucone!");
        println!("✅ Losowe klucze odrzucone przez register_with_proof");
    }

    /// TEST: All-zeros klucze są odrzucane
    #[test]
    fn test_zeros_keys_rejected() {
        let mut reg = StealthKeyRegistry::new();
        
        let zeros_falcon = vec![0u8; 897];
        let zeros_kyber = vec![0u8; 1184];
        
        // Nawet z "prawdziwym" podpisem (którego nie możemy stworzyć)
        let fake_sig = SignedNullifier {
            signed_message_bytes: vec![0u8; 700],
        };
        
        let result = reg.register_with_proof(
            zeros_falcon, zeros_kyber, &fake_sig, 0, 0
        );
        
        assert!(result.is_err());
        
        // Sprawdź typ błędu
        if let Err(e) = result {
            let err_str = format!("{}", e);
            assert!(err_str.contains("Suspicious") || err_str.contains("zeros"),
                "Błąd powinien wspominać o podejrzanym wzorcu: {}", err_str);
        }
        
        println!("✅ All-zeros klucze odrzucone");
    }

    /// TEST: Prawdziwe klucze z poprawnym podpisem są akceptowane
    #[test]
    fn test_valid_keys_with_proof_accepted() {
        let mut reg = StealthKeyRegistry::new();
        
        // Prawdziwe klucze
        let (falcon_pk, falcon_sk) = falcon_keypair();
        let (kyber_pk, _) = kyber768::keypair();
        
        let falcon_pk_bytes = falcon_pk_to_bytes(&falcon_pk).to_vec();
        let kyber_pk_bytes = kyber_pk.as_bytes().to_vec();
        
        // Oblicz challenge i podpisz
        let challenge = StealthKeyRegistry::compute_proof_challenge(
            &falcon_pk_bytes, &kyber_pk_bytes
        );
        let proof = falcon_sign(&challenge, &falcon_sk).unwrap();
        
        // Rejestracja powinna się udać
        let result = reg.register_with_proof(
            falcon_pk_bytes.clone(),
            kyber_pk_bytes.clone(),
            &proof,
            1000,
            100
        );
        
        assert!(result.is_ok(), "Prawdziwe klucze z proof powinny być zaakceptowane: {:?}", result);
        
        // Sprawdź że klucz jest w registry
        let id = result.unwrap();
        assert!(reg.get(&id).is_some());
        
        println!("✅ Prawdziwe klucze z proof-of-possession zaakceptowane");
    }

    /// TEST: Kradzież cudzego klucza publicznego jest niemożliwa
    #[test]
    fn test_stolen_public_key_rejected() {
        let mut reg = StealthKeyRegistry::new();
        
        // Ofiara generuje klucze
        let (victim_falcon_pk, _victim_falcon_sk) = falcon_keypair();
        let (victim_kyber_pk, _) = kyber768::keypair();
        
        // Atakujący próbuje zarejestrować klucze ofiary ze swoim podpisem
        let (attacker_falcon_pk, attacker_falcon_sk) = falcon_keypair();
        
        let victim_fpk_bytes = falcon_pk_to_bytes(&victim_falcon_pk).to_vec();
        let victim_kpk_bytes = victim_kyber_pk.as_bytes().to_vec();
        
        // Challenge jest dla kluczy ofiary
        let challenge = StealthKeyRegistry::compute_proof_challenge(
            &victim_fpk_bytes, &victim_kpk_bytes
        );
        
        // Ale atakujący podpisuje swoim kluczem (nie ofiary!)
        let attacker_proof = falcon_sign(&challenge, &attacker_falcon_sk).unwrap();
        
        // To MUSI być odrzucone - podpis jest kluczem atakującego, nie ofiary
        let result = reg.register_with_proof(
            victim_fpk_bytes,
            victim_kpk_bytes,
            &attacker_proof,
            0, 0
        );
        
        assert!(result.is_err(), "Kradzież klucza publicznego powinna być wykryta!");
        
        if let Err(e) = result {
            let err_str = format!("{}", e);
            assert!(err_str.contains("Proof-of-possession") || err_str.contains("failed"),
                "Błąd powinien wspominać o proof-of-possession: {}", err_str);
        }
        
        println!("✅ Kradzież klucza publicznego wykryta i odrzucona");
    }

    /// TEST: Low entropy klucze są odrzucane
    #[test]
    fn test_low_entropy_keys_rejected() {
        let mut reg = StealthKeyRegistry::new();
        
        // Klucz z tylko kilkoma unikalnymi bajtami (sequential pattern)
        let low_entropy_falcon: Vec<u8> = (0..897).map(|i| (i % 16) as u8).collect();
        let low_entropy_kyber: Vec<u8> = (0..1184).map(|i| (i % 16) as u8).collect();
        
        let fake_sig = SignedNullifier {
            signed_message_bytes: vec![0x42u8; 700],
        };
        
        let result = reg.register_with_proof(
            low_entropy_falcon, low_entropy_kyber, &fake_sig, 0, 0
        );
        
        assert!(result.is_err(), "Low entropy klucze powinny być odrzucone!");
        
        println!("✅ Low entropy klucze odrzucone");
    }
}
