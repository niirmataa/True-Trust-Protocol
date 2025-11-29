//! Prawdziwe testy ataków na węzeł TTP
//!
//! Testuje rzeczywiste funkcje z tt_node:
//! - ConsensusPro: sybil attacks, stake manipulation, leader selection
//! - TrustGraph: vouch manipulation, trust grinding
//! - Falcon signatures (via pqcrypto directly)
//!
//! Uruchom: `cargo test --test node_attack_tests --release -- --nocapture`

use tt_node::consensus_pro::{ConsensusPro, ValidatorId};
use tt_node::rtt_pro::{TrustGraph, RTTConfig, Vouch, q_from_f64, q_to_f64, ONE_Q, Epoch};

use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature, SignedMessage};

use sha3::{Sha3_256, Digest};
use rand::rngs::OsRng;
use rand::RngCore;

// ============================================================================
// HELPERS
// ============================================================================

fn random_validator_id() -> ValidatorId {
    let mut id = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    id
}

fn sha3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ============================================================================
// 1. SYBIL ATTACK TESTS - Prawdziwe testy na ConsensusPro
// ============================================================================

mod sybil_attacks {
    use super::*;

    /// Test: Sybil nodes bez stake'u nie mają wpływu na consensus
    #[test]
    fn test_sybil_without_stake_has_no_weight() {
        let mut consensus = ConsensusPro::new_default();
        
        let honest = random_validator_id();
        consensus.register_validator(honest, 1_000_000);
        
        let sybils: Vec<ValidatorId> = (0..100).map(|_| {
            let id = random_validator_id();
            consensus.register_validator(id, 0);
            id
        }).collect();
        
        consensus.recompute_all_stake_q();
        
        for sybil in &sybils {
            let weight = consensus.compute_validator_weight(sybil).unwrap_or(0);
            assert_eq!(weight, 0, "Sybil bez stake'u nie powinien mieć wagi");
        }
        
        let honest_weight = consensus.compute_validator_weight(&honest).unwrap_or(0);
        assert!(honest_weight > 0, "Uczciwy walidator powinien mieć wagę");
        
        println!("✅ Sybil attack blocked: 100 sybils have 0 weight, honest has {}", honest_weight);
    }

    /// Test: Sybil nodes z małym stake'iem mają proporcjonalnie małą wagę
    #[test]
    fn test_sybil_stake_dilution() {
        let mut consensus = ConsensusPro::new_default();
        
        let honest_stake = 100_000u128;
        let honest_nodes: Vec<ValidatorId> = (0..10).map(|_| {
            let id = random_validator_id();
            consensus.register_validator(id, honest_stake);
            id
        }).collect();
        
        let sybil_stake = 1_000u128;
        let sybil_nodes: Vec<ValidatorId> = (0..100).map(|_| {
            let id = random_validator_id();
            consensus.register_validator(id, sybil_stake);
            id
        }).collect();
        
        consensus.recompute_all_stake_q();
        
        let total_sybil_weight: u128 = sybil_nodes.iter()
            .filter_map(|id| consensus.compute_validator_weight(id))
            .sum();
        
        let one_honest_weight = consensus.compute_validator_weight(&honest_nodes[0]).unwrap_or(0);
        
        let ratio = total_sybil_weight as f64 / one_honest_weight as f64;
        assert!(ratio > 0.9 && ratio < 1.1, 
            "Sybil stake dilution: ratio = {:.2}, expected ~1.0", ratio);
        
        println!("✅ Sybil stake dilution works: 100 sybils = {:.2}x one honest", ratio);
    }

    /// Test: Nowy walidator bez historii ma niski trust
    #[test]
    fn test_new_validator_low_trust() {
        let config = RTTConfig::default();
        let trust_graph = TrustGraph::new(config);
        
        let new_validator = random_validator_id();
        let trust = trust_graph.get_trust(&new_validator);
        
        assert!(trust < ONE_Q / 2, 
            "Nowy walidator bez historii powinien mieć niski trust, ma: {}", 
            q_to_f64(trust));
        
        println!("✅ New validator has low trust: {:.4}", q_to_f64(trust));
    }
}

// ============================================================================
// 2. LEADER SELECTION ATTACKS
// ============================================================================

mod leader_selection_attacks {
    use super::*;

    #[test]
    fn test_leader_selection_deterministic() {
        let mut consensus = ConsensusPro::new_default();
        
        for i in 0..10 {
            let mut id = [0u8; 32];
            id[0] = i;
            consensus.register_validator(id, 100_000);
        }
        consensus.recompute_all_stake_q();
        
        let beacon = sha3_hash(b"slot_12345_randomness");
        
        let leader1 = consensus.select_leader(beacon);
        let leader2 = consensus.select_leader(beacon);
        
        assert_eq!(leader1, leader2, "Leader selection must be deterministic");
        println!("✅ Leader selection is deterministic");
    }

    #[test]
    fn test_leader_selection_varies_with_beacon() {
        let mut consensus = ConsensusPro::new_default();
        
        for i in 0..20u8 {
            let mut id = [0u8; 32];
            id[0] = i;
            consensus.register_validator(id, 100_000);
        }
        consensus.recompute_all_stake_q();
        
        let mut leaders = std::collections::HashSet::new();
        
        for i in 0..100u32 {
            let beacon = sha3_hash(&i.to_le_bytes());
            if let Some(leader) = consensus.select_leader(beacon) {
                leaders.insert(leader);
            }
        }
        
        assert!(leaders.len() > 5, 
            "Leader selection should vary, got only {} unique leaders", leaders.len());
        
        println!("✅ Leader selection varies: {} unique leaders from 100 beacons", leaders.len());
    }

    #[test]
    fn test_zero_stake_never_leader() {
        let mut consensus = ConsensusPro::new_default();
        
        let zero_stake = random_validator_id();
        consensus.register_validator(zero_stake, 0);
        
        let with_stake = random_validator_id();
        consensus.register_validator(with_stake, 1_000_000);
        
        consensus.recompute_all_stake_q();
        
        for i in 0..1000u32 {
            let beacon = sha3_hash(&i.to_le_bytes());
            if let Some(leader) = consensus.select_leader(beacon) {
                assert_ne!(leader, zero_stake, 
                    "Zero stake validator should never be selected as leader");
            }
        }
        
        println!("✅ Zero stake validator never selected as leader in 1000 tries");
    }
}

// ============================================================================
// 3. TRUST MANIPULATION ATTACKS
// ============================================================================

mod trust_attacks {
    use super::*;

    #[test]
    fn test_self_vouch_ignored() {
        let config = RTTConfig::default();
        let mut trust_graph = TrustGraph::new(config);
        
        let attacker = random_validator_id();
        
        let trust_before = trust_graph.get_trust(&attacker);
        
        let self_vouch = Vouch {
            voucher: attacker,
            vouchee: attacker,
            strength: ONE_Q,
            created_at: 1 as Epoch,
        };
        
        let accepted = trust_graph.add_vouch(self_vouch);
        let trust_after = trust_graph.get_trust(&attacker);
        
        if accepted {
            assert_eq!(trust_before, trust_after, 
                "Self-vouch should not increase trust");
        }
        
        println!("✅ Self-vouch blocked: accepted={}, trust before={:.4}, after={:.4}", 
            accepted, q_to_f64(trust_before), q_to_f64(trust_after));
    }

    #[test]
    fn test_vouch_from_untrusted_has_low_impact() {
        let config = RTTConfig::default();
        let mut trust_graph = TrustGraph::new(config);
        
        let untrusted_voucher = random_validator_id();
        let target = random_validator_id();
        
        let trust_before = trust_graph.get_trust(&target);
        
        let vouch = Vouch {
            voucher: untrusted_voucher,
            vouchee: target,
            strength: ONE_Q,
            created_at: 1 as Epoch,
        };
        
        trust_graph.add_vouch(vouch);
        trust_graph.update_trust(target);
        
        let trust_after = trust_graph.get_trust(&target);
        
        let increase = q_to_f64(trust_after) - q_to_f64(trust_before);
        assert!(increase < 0.1, 
            "Vouch from untrusted should have low impact, got increase: {:.4}", increase);
        
        println!("✅ Vouch from untrusted has low impact: +{:.4}", increase);
    }

    #[test]
    fn test_quality_affects_trust() {
        let config = RTTConfig::default();
        let mut trust_graph = TrustGraph::new(config);
        
        let good_validator = random_validator_id();
        let bad_validator = random_validator_id();
        
        for _ in 0..100 {
            trust_graph.record_quality(good_validator, q_from_f64(0.95));
        }
        
        for _ in 0..100 {
            trust_graph.record_quality(bad_validator, q_from_f64(0.1));
        }
        
        trust_graph.update_trust(good_validator);
        trust_graph.update_trust(bad_validator);
        
        let good_trust = trust_graph.get_trust(&good_validator);
        let bad_trust = trust_graph.get_trust(&bad_validator);
        
        assert!(good_trust > bad_trust, 
            "Good validator should have higher trust than bad one");
        
        println!("✅ Quality affects trust: good={:.4}, bad={:.4}", 
            q_to_f64(good_trust), q_to_f64(bad_trust));
    }
}

// ============================================================================
// 4. SIGNATURE ATTACKS - Prawdziwe testy na Falcon
// ============================================================================

mod signature_attacks {
    use super::*;

    #[test]
    fn test_wrong_key_signature_rejected() {
        let (pk1, sk1) = falcon512::keypair();
        let (pk2, _sk2) = falcon512::keypair();
        
        let message = b"block_header_data";
        let signed_msg = falcon512::sign(message, &sk1);
        
        let opened1 = falcon512::open(&signed_msg, &pk1);
        assert!(opened1.is_ok(), "Correct key should verify");
        assert_eq!(opened1.unwrap(), message);
        
        let opened2 = falcon512::open(&signed_msg, &pk2);
        assert!(opened2.is_err(), "Wrong key must reject signature");
        
        println!("✅ Wrong key signature rejected");
    }

    #[test]
    fn test_corrupted_signature_rejected() {
        let (pk, sk) = falcon512::keypair();
        
        let message = b"important transaction data";
        let signed_msg = falcon512::sign(message, &sk);
        
        let mut corrupted_bytes = signed_msg.as_bytes().to_vec();
        if corrupted_bytes.len() > 100 {
            corrupted_bytes[50] ^= 0xFF;
            corrupted_bytes[100] ^= 0xFF;
        }
        
        // Próba parsowania i weryfikacji
        let parsed = falcon512::SignedMessage::from_bytes(&corrupted_bytes);
        match parsed {
            Ok(sm) => {
                let verify = falcon512::open(&sm, &pk);
                assert!(verify.is_err(), "Corrupted signature should not verify");
                println!("✅ Corrupted signature rejected (verify failed)");
            }
            Err(_) => {
                println!("✅ Corrupted signature rejected (parse failed)");
            }
        }
    }

    #[test]
    fn test_random_signature_rejected() {
        let (pk, _sk) = falcon512::keypair();
        
        let mut fake_sig = vec![0u8; 1500];
        OsRng.fill_bytes(&mut fake_sig);
        
        let parsed = falcon512::SignedMessage::from_bytes(&fake_sig);
        
        match parsed {
            Ok(sm) => {
                let verify = falcon512::open(&sm, &pk);
                assert!(verify.is_err(), "Random bytes must not verify");
            }
            Err(_) => {
                // Parse failed - that's also acceptable
            }
        }
        
        println!("✅ Random signature rejected");
    }

    #[test]
    fn test_detached_signature_verification() {
        let (pk, sk) = falcon512::keypair();
        
        let message = b"block header for signing";
        let signature = falcon512::detached_sign(message, &sk);
        
        let valid = falcon512::verify_detached_signature(&signature, message, &pk);
        assert!(valid.is_ok(), "Valid signature should verify");
        
        let wrong_msg = b"different message";
        let invalid = falcon512::verify_detached_signature(&signature, wrong_msg, &pk);
        assert!(invalid.is_err(), "Wrong message must fail verification");
        
        println!("✅ Detached signature API works correctly");
    }
}

// ============================================================================
// 5. CONSENSUS WEIGHT CALCULATION
// ============================================================================

mod weight_attacks {
    use super::*;

    #[test]
    fn test_weight_proportional_to_stake() {
        let mut consensus = ConsensusPro::new_default();
        
        let small = random_validator_id();
        let medium = random_validator_id();
        let large = random_validator_id();
        
        consensus.register_validator(small, 10_000);
        consensus.register_validator(medium, 100_000);
        consensus.register_validator(large, 1_000_000);
        
        consensus.recompute_all_stake_q();
        
        let w_small = consensus.compute_validator_weight(&small).unwrap_or(0);
        let w_medium = consensus.compute_validator_weight(&medium).unwrap_or(0);
        let w_large = consensus.compute_validator_weight(&large).unwrap_or(0);
        
        assert!(w_small < w_medium, "Small stake should have less weight than medium");
        assert!(w_medium < w_large, "Medium stake should have less weight than large");
        
        let ratio_lm = w_large as f64 / w_medium as f64;
        let ratio_ms = w_medium as f64 / w_small as f64;
        
        assert!(ratio_lm > 5.0 && ratio_lm < 15.0, 
            "Large/medium ratio should be ~10, got {:.2}", ratio_lm);
        assert!(ratio_ms > 5.0 && ratio_ms < 15.0, 
            "Medium/small ratio should be ~10, got {:.2}", ratio_ms);
        
        println!("✅ Weight proportional to stake: L/M={:.1}, M/S={:.1}", ratio_lm, ratio_ms);
    }

    #[test]
    fn test_removed_validator_has_no_weight() {
        let mut consensus = ConsensusPro::new_default();
        
        let validator = random_validator_id();
        consensus.register_validator(validator, 1_000_000);
        consensus.recompute_all_stake_q();
        
        let weight_before = consensus.compute_validator_weight(&validator);
        assert!(weight_before.is_some() && weight_before.unwrap() > 0);
        
        consensus.remove_validator(&validator);
        
        let weight_after = consensus.compute_validator_weight(&validator);
        assert!(weight_after.is_none() || weight_after.unwrap() == 0,
            "Removed validator should have no weight");
        
        println!("✅ Removed validator has no weight");
    }

    #[test]
    fn test_stake_update_changes_weight() {
        let mut consensus = ConsensusPro::new_default();
        
        // Need multiple validators so stake_q is not always 100%
        let validator = random_validator_id();
        consensus.register_validator(validator, 100_000);
        
        // Add 4 more validators with fixed stake
        for i in 0..4u8 {
            let mut id = [0u8; 32];
            id[0] = i;
            consensus.register_validator(id, 100_000);
        }
        consensus.recompute_all_stake_q();
        
        let weight_100k = consensus.compute_validator_weight(&validator).unwrap_or(0);
        
        // Increase stake 10x
        consensus.update_stake_raw(&validator, 1_000_000);
        consensus.recompute_all_stake_q();
        
        let weight_1m = consensus.compute_validator_weight(&validator).unwrap_or(0);
        
        assert!(weight_1m > weight_100k, 
            "Weight should increase with stake: {} -> {}", weight_100k, weight_1m);
        
        println!("✅ Stake update changes weight: {} -> {}", weight_100k, weight_1m);
    }
}
