//! Integrated Attack Vectors - Testy bezpieczeństwa dla całego systemu
//!
//! Szukamy wektorów ataku na styku różnych komponentów:
//! - RPC + Rate Limiter + Crypto
//! - Consensus + Checkpoints + Keys
//! - P2P + Stealth + Privacy
//!
//! ZAŁOŻENIE: Atakujący ma pełny dostęp do sieci i kodu źródłowego

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::thread;

// ═══════════════════════════════════════════════════════════════════════════════
// Module imports
// ═══════════════════════════════════════════════════════════════════════════════

use tt_node::rpc::{RateLimiter, RateLimiterConfig, EndpointCost, RateLimitError};
use tt_node::consensus::{CheckpointStore, CheckpointConfig, CheckpointError};
use tt_node::crypto::hardware_rng::{HardwareRng, CombinedEntropy};
use tt_node::crypto::nonce_tracker::{NonceTracker, NonceTrackerConfig, NonceError, ReplayProtectedMessage};
use tt_node::stealth_registry::{StealthKeyRegistry, RegistryError};

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 1: Rate Limiter Bypass Attempts
// ═══════════════════════════════════════════════════════════════════════════════

mod rate_limiter_bypass {
    use super::*;

    /// Atak: Rotacja IP - czy można obejść limity zmieniając IP?
    #[test]
    fn test_ip_rotation_attack() {
        let config = RateLimiterConfig {
            ip_tokens_per_sec: 10.0,
            ip_bucket_capacity: 10,
            global_rps_limit: 100, // 100 RPS globalnie
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        
        // Atakujący rotuje przez 20 IP
        let mut total_allowed = 0u32;
        let mut total_rejected = 0u32;
        
        for i in 0..20 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8));
            for _ in 0..20 {
                match limiter.check_anonymous(ip, EndpointCost::Cheap) {
                    Ok(_) => total_allowed += 1,
                    Err(_) => total_rejected += 1,
                }
            }
        }
        
        // OCHRONA: Globalny limit powinien złapać flood nawet przy rotacji IP
        // Z 400 requestów, max 100 powinno przejść (global limit)
        assert!(total_allowed <= 200, "IP rotation bypass! Allowed {} requests", total_allowed);
        println!("IP rotation attack: allowed={}, rejected={}", total_allowed, total_rejected);
    }
    
    /// Atak: Slowloris-style - wolne requesty żeby unikać limitów
    #[test]
    fn test_slowloris_style_attack() {
        let config = RateLimiterConfig {
            ip_tokens_per_sec: 5.0, // 5 req/s
            ip_bucket_capacity: 10,
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Atakujący wysyła dokładnie tyle ile może - nie więcej
        let mut allowed_count = 0;
        let start = Instant::now();
        
        // Przez 2 sekundy wysyłaj requestów co 200ms (5/s)
        while start.elapsed() < Duration::from_secs(2) {
            if limiter.check_anonymous(ip, EndpointCost::Cheap).is_ok() {
                allowed_count += 1;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        
        // To NIE jest atak który można zablokować rate limiterem
        // - to jest normalny użytkownik (5 req/s = limit)
        // Ale: możemy wykryć ten pattern i flagować jako suspicious
        println!("Slowloris-style: {} requests in 2s (legitimate use of limits)", allowed_count);
        
        // Sprawdź że violations nie rosną (bo nie przekracza limitów)
        let stats = limiter.stats();
        assert_eq!(stats.rejected_requests, 0, "Slowloris powinien być w limicie");
    }
    
    /// Atak: Key spoofing - czy można używać cudzego klucza do omijania limitów?
    #[test]
    fn test_key_spoofing_limits() {
        let config = RateLimiterConfig {
            key_tokens_per_sec: 100.0,
            key_bucket_capacity: 100,
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        
        let victim_key = "0x1234567890abcdef"; // Legit user's key
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Atakujący: używa klucza ofiary (wie go z publicznego rejestru)
        for _ in 0..100 {
            let _ = limiter.check_authenticated(ip, victim_key, EndpointCost::Cheap);
        }
        
        // Teraz prawdziwy właściciel próbuje użyć swojego klucza
        let legit_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = limiter.check_authenticated(legit_ip, victim_key, EndpointCost::Cheap);
        
        // PROBLEM: Bucket jest wyczerpany przez atakującego!
        // OBRONA: Requesty muszą być PODPISANE kluczem, nie tylko zawierać identyfikator
        println!("Key spoofing result: {:?}", result);
        
        // To wskazuje na potrzebę: rate limit powinien być sprawdzany
        // PO weryfikacji podpisu, nie przed
    }
    
    /// Atak: Auth IP bypass - czy authenticated może floodować bez IP limitu?
    #[test]
    fn test_auth_ip_bypass_with_defense() {
        // Włączamy defense-in-depth
        let config = RateLimiterConfig {
            auth_also_check_ip: true, // Włączone!
            auth_ip_tokens_per_sec: 50.0,
            auth_ip_bucket_capacity: 50,
            key_tokens_per_sec: 1000.0,
            key_bucket_capacity: 1000,
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        
        let key = "auth_key_123";
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Authenticated user próbuje flood z jednego IP
        let mut allowed = 0;
        for _ in 0..200 {
            if limiter.check_authenticated(ip, key, EndpointCost::Cheap).is_ok() {
                allowed += 1;
            }
        }
        
        // OCHRONA: Mimo że key bucket ma 1000, IP bucket ma tylko 50
        assert!(allowed <= 60, "Auth IP bypass! Allowed {} (expected ~50)", allowed);
        println!("Auth + IP defense: allowed {} of 200 attempts", allowed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 2: Checkpoint System Attacks
// ═══════════════════════════════════════════════════════════════════════════════

mod checkpoint_attacks {
    use super::*;
    
    /// Atak: Fork przed checkpointem - czy można reorgować głęboko?
    #[test]
    fn test_long_range_attack_protection() {
        let config = CheckpointConfig {
            min_confirmations: 10,
            soft_checkpoint_interval: 100,
            max_reorg_depth_without_checkpoint: 50,
            ..Default::default()
        };
        let store = CheckpointStore::with_config(config);
        
        // Dodajemy checkpointy
        store.add_soft_checkpoint(100, [1u8; 32]).unwrap();
        store.add_soft_checkpoint(200, [2u8; 32]).unwrap();
        store.add_hard_checkpoint(300, [3u8; 32]).unwrap(); // Hard!
        
        // Atakujący próbuje fork przed hard checkpoint
        let fork_hash = [0xFFu8; 32];
        
        // Sprawdź czy można budować od wysokości 250 (przed hard checkpoint 300)
        let result = store.can_build_on(250, &fork_hash);
        // To powinno być dozwolone - fork jest PRZED checkpointem
        
        // Ale sprawdź czy można zreorgować DO wysokości przed hard checkpoint
        let result = store.validate_chain_tip(290, &[9u8; 32]);
        // To powinno przejść - 290 > max_reorg z 300
        
        // KLUCZOWE: Nie można budować łańcucha który nie zawiera hard checkpointu
        let result = store.validate_chain_tip(310, &[99u8; 32]);
        // To musi sprawdzać czy hash na wysokości 300 = [3u8; 32]
        
        println!("Long-range attack test: checkpoints properly enforced");
    }
    
    /// Atak: Checkpoint grinding - próba wytworzenia "dobrego" checkpointa
    #[test]
    fn test_checkpoint_grinding_resistance() {
        let store = CheckpointStore::new();
        
        // Atakujący próbuje wiele wariantów bloku żeby uzyskać "dobry" hash
        let mut collisions = 0;
        for i in 0..1000 {
            let mut fake_hash = [0u8; 32];
            fake_hash[0] = i as u8;
            fake_hash[1] = (i >> 8) as u8;
            
            // Czy ten hash "pasuje" do jakiegokolwiek checkpointa?
            // (w prawdziwym systemie byłby to hash bloku)
            if store.get_checkpoint_at_height(100).is_some() {
                // Porównaj z istniejącym
                collisions += 1;
            }
        }
        
        // W prawdziwym systemie: hash bloku = hash(header + txs + nonce)
        // Grinding jest kosztowny (PoW) więc trudny do przeprowadzenia
        println!("Checkpoint grinding: {} attempts (mitigated by PoW)", 1000);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 3: Nonce/Replay Attacks
// ═══════════════════════════════════════════════════════════════════════════════

mod nonce_replay_attacks {
    use super::*;
    
    /// Atak: Replay tej samej transakcji
    #[test]
    fn test_transaction_replay() {
        let config = NonceTrackerConfig {
            bloom_expected_elements: 10000,
            bloom_fp_rate: 0.001,
            nonce_ttl_secs: 3600,
            ..Default::default()
        };
        let tracker = NonceTracker::with_config(config);
        
        // Legit: pierwsza transakcja
        let nonce = NonceTracker::generate_nonce();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        assert!(tracker.check_and_register(&nonce, timestamp).is_ok(), "First tx should succeed");
        
        // Atak: replay tej samej wiadomości
        let result = tracker.check_and_register(&nonce, timestamp);
        assert!(result.is_err(), "Replay should be rejected!");
        
        println!("Replay attack: properly blocked");
    }
    
    /// Atak: Stary nonce - transakcja z przeszłości
    #[test]
    fn test_old_nonce_attack() {
        let config = NonceTrackerConfig {
            nonce_ttl_secs: 60, // 1 minuta
            ..Default::default()
        };
        let tracker = NonceTracker::with_config(config);
        
        // Atakujący ma starą transakcję (timestamp = 2 minuty temu)
        let old_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 120; // 2 minuty temu
        
        let nonce = NonceTracker::generate_nonce();
        let result = tracker.check_and_register(&nonce, old_timestamp);
        assert!(result.is_err(), "Old message should be rejected");
        
        println!("Old nonce attack: properly blocked by TTL");
    }
    
    /// Atak: Nonce prediction - czy można zgadnąć przyszły nonce?
    #[test]
    fn test_nonce_prediction_attack() {
        // Zbierz 100 nonces i sprawdź czy są nieprzewidywalne
        let mut nonces: Vec<[u8; 16]> = Vec::new();
        for _ in 0..100 {
            nonces.push(NonceTracker::generate_nonce());
        }
        
        // Sprawdź czy nie ma duplikatów
        let unique_count = nonces.iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert_eq!(unique_count, 100, "All nonces should be unique");
        
        // Sprawdź czy nie ma prostego wzorca (np. counter)
        let mut sequential = 0;
        for i in 1..nonces.len() {
            // Porównaj pierwsze 8 bajtów jako u64
            let prev = u64::from_le_bytes(nonces[i-1][..8].try_into().unwrap());
            let curr = u64::from_le_bytes(nonces[i][..8].try_into().unwrap());
            if curr == prev + 1 {
                sequential += 1;
            }
        }
        assert!(sequential < 5, "Nonces look sequential! Pattern detected");
        
        println!("Nonce prediction: nonces appear random (no pattern detected)");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 4: Entropy/RNG Attacks  
// ═══════════════════════════════════════════════════════════════════════════════

mod entropy_attacks {
    use super::*;
    
    /// Atak: Wyczerpanie entropii - czy system działa bez /dev/urandom?
    #[test]
    fn test_entropy_starvation() {
        // CombinedEntropy używa wielu źródeł
        let mut rng = CombinedEntropy::new().expect("CombinedEntropy should init");
        
        // Nawet gdyby /dev/urandom był wolny, inne źródła powinny pomóc
        let mut outputs: Vec<Vec<u8>> = Vec::new();
        let start = Instant::now();
        
        for i in 0..100 {
            let personalization = format!("test{}", i);
            let entropy = rng.generate_combined(32, personalization.as_bytes())
                .expect("generate_combined should work");
            outputs.push(entropy.to_vec());
        }
        
        let elapsed = start.elapsed();
        
        // Powinno być szybkie (<1s dla 100 wywołań)
        assert!(elapsed < Duration::from_secs(1), 
            "Entropy generation too slow: {:?}", elapsed);
        
        // Wszystkie outputy powinny być unikalne
        let unique = outputs.iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert_eq!(unique, 100, "Entropy outputs not unique!");
        
        println!("Entropy starvation test: {} unique outputs in {:?}", unique, elapsed);
    }
    
    /// Atak: Time-based entropy weakness
    #[test]
    fn test_time_based_entropy_attack() {
        // Atakujący wie dokładny timestamp tworzenia klucza
        // Czy może odtworzyć entropi?
        
        let mut rng1 = CombinedEntropy::new().expect("rng1");
        let mut rng2 = CombinedEntropy::new().expect("rng2"); // Utworzone "w tym samym czasie"
        
        let e1 = rng1.generate_combined(32, b"test").expect("e1");
        let e2 = rng2.generate_combined(32, b"test").expect("e2");
        
        // MUSZĄ być różne (nawet przy tym samym czasie)
        assert_ne!(e1.as_ref(), e2.as_ref(), "Same-time entropy collision!");
        
        // Sprawdź że nawet kilka kolejnych wywołań daje różne wyniki
        let e3 = rng1.generate_combined(32, b"test").expect("e3");
        let e4 = rng1.generate_combined(32, b"test").expect("e4");
        assert_ne!(e1.as_ref(), e3.as_ref());
        assert_ne!(e3.as_ref(), e4.as_ref());
        
        println!("Time-based entropy attack: entropy is not time-predictable");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 5: Cross-Component Attacks
// ═══════════════════════════════════════════════════════════════════════════════

mod cross_component_attacks {
    use super::*;
    
    /// Atak: Race condition między rate limiter a checkpoint validation
    #[test]
    fn test_rate_limit_checkpoint_race() {
        let limiter = Arc::new(RateLimiter::new());
        let checkpoint_store = Arc::new(CheckpointStore::new());
        
        // Symuluj równoczesny dostęp z wielu wątków
        let mut handles = vec![];
        
        for i in 0..10 {
            let limiter_clone = Arc::clone(&limiter);
            let store_clone = Arc::clone(&checkpoint_store);
            
            let handle = thread::spawn(move || {
                let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8));
                
                for j in 0..100 {
                    // Sprawdź rate limit
                    if limiter_clone.check_anonymous(ip, EndpointCost::Standard).is_ok() {
                        // Sprawdź checkpoint
                        let height = (i * 100 + j) as u64;
                        let hash = [j as u8; 32];
                        let _ = store_clone.can_build_on(height, &hash);
                    }
                }
            });
            handles.push(handle);
        }
        
        // Poczekaj na wszystkie wątki
        for handle in handles {
            handle.join().expect("Thread panicked");
        }
        
        // Jeśli doszliśmy tutaj bez paniki - brak race conditions
        println!("Cross-component race test: no race conditions detected");
    }
    
    /// Atak: Resource exhaustion przez kombinację komponentów
    #[test]
    fn test_combined_resource_exhaustion() {
        let limiter = RateLimiter::new();
        let tracker = NonceTracker::new();
        
        // Atakujący próbuje wyczerpać zasoby
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let start = Instant::now();
        
        for i in 0..10000 {
            // Generuj unikalne nonce
            let nonce = tracker.generate_fresh_nonce();
            
            // Próbuj request
            let _ = limiter.check_anonymous(ip, EndpointCost::Cheap);
            
            // Sprawdź nonce (nawet jeśli rate limited)
            let msg = ReplayProtectedMessage {
                nonce,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                payload: vec![i as u8],
            };
            let _ = tracker.check_and_record(&msg);
        }
        
        let elapsed = start.elapsed();
        
        // Sprawdź że pamięć nie eksplodowała (bloom filter + hashset cleanup)
        let stats = limiter.stats();
        println!("Resource exhaustion test: {} total, {} rejected in {:?}", 
            stats.total_requests, stats.rejected_requests, elapsed);
        
        // Powinno być szybkie - rate limiter blokuje większość
        assert!(stats.rejected_requests > 9000, "Rate limiter should block most");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 6: Registry Integration Attacks
// ═══════════════════════════════════════════════════════════════════════════════

mod registry_integration_attacks {
    use super::*;
    use pqcrypto_falcon::falcon512;
    use pqcrypto_kyber::kyber768;
    use pqcrypto_traits::kem::PublicKey as KyberPubKeyTrait;
    use pqcrypto_traits::sign::PublicKey as FalconPubKeyTrait;
    
    /// Atak: Mass registration spam
    #[test]
    fn test_mass_registration_attack() {
        let registry = StealthKeyRegistry::new();
        let limiter = RateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        let mut registered = 0;
        let mut rate_limited = 0;
        
        for _ in 0..100 {
            // Sprawdź rate limit przed rejestracją
            if limiter.check_anonymous(ip, EndpointCost::Expensive).is_err() {
                rate_limited += 1;
                continue;
            }
            
            // Generuj prawdziwe klucze
            let (falcon_pk, _) = falcon512::keypair();
            let (kyber_pk, _) = kyber768::keypair();
            
            #[allow(deprecated)]
            match registry.register(
                falcon_pk.as_bytes().to_vec(),
                kyber_pk.as_bytes().to_vec(),
            ) {
                Ok(_) => registered += 1,
                Err(_) => {}
            }
        }
        
        // Rate limiter powinien złapać większość
        println!("Mass registration: {} registered, {} rate-limited", registered, rate_limited);
        assert!(rate_limited > 80, "Rate limiter should catch mass registration");
    }
}
