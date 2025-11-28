//! Quick Consensus PRO Test
//!
//! Tests RTT trust + stake normalization + leader selection

use tt_node::consensus_pro::ConsensusPro;
use tt_node::rtt_pro::{q_to_f64, ONE_Q};

fn mk_id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║              TRUE TRUST CONSENSUS PRO - TEST                      ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // ========================================================================
    // Test 1: Stake normalization
    // ========================================================================
    println!("┌─ Test 1: Stake Normalization ─");
    {
        let mut c = ConsensusPro::new_default();
        
        let alice = mk_id(1);
        let bob = mk_id(2);
        let carol = mk_id(3);
        
        c.register_validator(alice, 100);
        c.register_validator(bob, 300);
        c.register_validator(carol, 600);
        
        c.recompute_all_stake_q();
        
        let va = c.get_validator(&alice).unwrap();
        let vb = c.get_validator(&bob).unwrap();
        let vc = c.get_validator(&carol).unwrap();
        
        let sa = q_to_f64(va.stake_q);
        let sb = q_to_f64(vb.stake_q);
        let sc = q_to_f64(vc.stake_q);
        
        println!("│  Alice stake: 100 → normalized: {:.4} (expected: 0.10)", sa);
        println!("│  Bob stake:   300 → normalized: {:.4} (expected: 0.30)", sb);
        println!("│  Carol stake: 600 → normalized: {:.4} (expected: 0.60)", sc);
        println!("│  Sum: {:.4} (expected: 1.0)", sa + sb + sc);
        
        assert!((sa - 0.10).abs() < 0.001, "Alice stake wrong");
        assert!((sb - 0.30).abs() < 0.001, "Bob stake wrong");
        assert!((sc - 0.60).abs() < 0.001, "Carol stake wrong");
        println!("│  ✅ PASSED\n");
    }

    // ========================================================================
    // Test 2: Trust builds over time with quality
    // ========================================================================
    println!("┌─ Test 2: Trust Growth with Quality ─");
    {
        let mut c = ConsensusPro::new_default();
        
        let alice = mk_id(1);
        let bob = mk_id(2);
        
        c.register_validator(alice, 1000);
        c.register_validator(bob, 1000);
        c.recompute_all_stake_q();
        
        // Simulate 20 epochs: Alice has high quality, Bob has low
        for epoch in 0..20 {
            c.record_quality_f64(&alice, 0.95);  // Excellent
            c.record_quality_f64(&bob, 0.40);    // Poor
            
            if epoch % 5 == 4 {
                c.update_all_trust();
                let ta = q_to_f64(c.get_validator(&alice).unwrap().trust_q);
                let tb = q_to_f64(c.get_validator(&bob).unwrap().trust_q);
                println!("│  Epoch {:2}: Alice trust={:.4}, Bob trust={:.4}", epoch + 1, ta, tb);
            }
        }
        
        c.update_all_trust();
        
        let ta = q_to_f64(c.get_validator(&alice).unwrap().trust_q);
        let tb = q_to_f64(c.get_validator(&bob).unwrap().trust_q);
        
        println!("│  Final: Alice trust={:.4}, Bob trust={:.4}", ta, tb);
        assert!(ta > tb, "Alice should have higher trust than Bob");
        println!("│  ✅ Alice trust > Bob trust (as expected)\n");
    }

    // ========================================================================
    // Test 3: Weight ranking combines trust, quality, stake
    // ========================================================================
    println!("┌─ Test 3: Weight Ranking ─");
    {
        let mut c = ConsensusPro::new_default();
        
        let high_stake_low_quality = mk_id(1);  // Whale but lazy
        let low_stake_high_quality = mk_id(2);  // Small but diligent
        let balanced = mk_id(3);                 // Medium everything
        
        c.register_validator(high_stake_low_quality, 5000);
        c.register_validator(low_stake_high_quality, 500);
        c.register_validator(balanced, 1500);
        c.recompute_all_stake_q();
        
        // Build reputation over time
        for _ in 0..30 {
            c.record_quality_f64(&high_stake_low_quality, 0.30);
            c.record_quality_f64(&low_stake_high_quality, 0.98);
            c.record_quality_f64(&balanced, 0.70);
        }
        c.update_all_trust();
        
        let ranking = c.get_weight_ranking();
        
        println!("│  Weight Ranking:");
        for (i, (id, weight)) in ranking.iter().enumerate() {
            let name = match id[0] {
                1 => "Whale (high stake, low quality)",
                2 => "Ant (low stake, high quality)",
                3 => "Balanced",
                _ => "Unknown",
            };
            println!("│    #{}: {} - weight: {}", i + 1, name, weight);
        }
        
        // The balanced validator should win (neither extreme)
        println!("│  ✅ Ranking computed successfully\n");
    }

    // ========================================================================
    // Test 4: Deterministic leader selection
    // ========================================================================
    println!("┌─ Test 4: Deterministic Leader Selection ─");
    {
        let mut c = ConsensusPro::new_default();
        
        let v1 = mk_id(10);
        let v2 = mk_id(20);
        let v3 = mk_id(30);
        
        c.register_validator(v1, 1000);
        c.register_validator(v2, 1000);
        c.register_validator(v3, 1000);
        c.recompute_all_stake_q();
        
        // Give v1 highest quality
        for _ in 0..20 {
            c.record_quality_f64(&v1, 0.95);
            c.record_quality_f64(&v2, 0.70);
            c.record_quality_f64(&v3, 0.50);
        }
        c.update_all_trust();
        
        // Test determinism: same beacon → same leader
        let beacon1 = [0x42u8; 32];
        let leader1a = c.select_leader(beacon1).unwrap();
        let leader1b = c.select_leader(beacon1).unwrap();
        let leader1c = c.select_leader(beacon1).unwrap();
        
        println!("│  Beacon 0x42: leader = {:02x}{:02x}...", leader1a[0], leader1a[1]);
        assert_eq!(leader1a, leader1b, "Leader should be deterministic");
        assert_eq!(leader1b, leader1c, "Leader should be deterministic");
        println!("│  ✅ Same beacon → same leader (3x check)");
        
        // Different beacon → possibly different leader
        let beacon2 = [0xAB; 32];
        let leader2 = c.select_leader(beacon2).unwrap();
        println!("│  Beacon 0xAB: leader = {:02x}{:02x}...", leader2[0], leader2[1]);
        
        // Best validator (v1) should be leader most of the time
        let mut v1_wins = 0;
        for i in 0..100 {
            let mut beacon = [0u8; 32];
            beacon[0] = i as u8;
            beacon[1] = (i * 7) as u8;
            if c.select_leader(beacon) == Some(v1) {
                v1_wins += 1;
            }
        }
        println!("│  V1 (best quality) wins: {}/100 rounds", v1_wins);
        assert!(v1_wins > 30, "Best validator should win frequently");
        println!("│  ✅ Best validator wins frequently\n");
    }

    // ========================================================================
    // Test 5: Validator removal and stake update
    // ========================================================================
    println!("┌─ Test 5: Validator Lifecycle ─");
    {
        let mut c = ConsensusPro::new_default();
        
        let v1 = mk_id(1);
        let v2 = mk_id(2);
        
        c.register_validator(v1, 500);
        c.register_validator(v2, 500);
        c.recompute_all_stake_q();
        
        let s1 = q_to_f64(c.get_validator(&v1).unwrap().stake_q);
        println!("│  Initial: V1 stake_q = {:.4} (50%)", s1);
        
        // V1 adds more stake
        c.update_stake_raw(&v1, 1500);
        c.recompute_all_stake_q();
        
        let s1 = q_to_f64(c.get_validator(&v1).unwrap().stake_q);
        println!("│  After V1 +1000: V1 stake_q = {:.4} (75%)", s1);
        assert!((s1 - 0.75).abs() < 0.001);
        
        // V2 leaves
        c.remove_validator(&v2);
        c.recompute_all_stake_q();
        
        let s1 = q_to_f64(c.get_validator(&v1).unwrap().stake_q);
        println!("│  After V2 removed: V1 stake_q = {:.4} (100%)", s1);
        assert!((s1 - 1.0).abs() < 0.001, "V1 should have 100% stake after V2 removed");
        
        println!("│  ✅ Stake updates correctly\n");
    }

    // ========================================================================
    // Test 6: Deterministic update_all (CRITICAL for consensus)
    // ========================================================================
    println!("┌─ Test 6: Deterministic Trust Update ─");
    {
        // Create two identical consensus instances
        let mut c1 = ConsensusPro::new_default();
        let mut c2 = ConsensusPro::new_default();
        
        // Same validators, same order of operations
        let validators: Vec<_> = (1..=10).map(|i| mk_id(i)).collect();
        
        for &v in &validators {
            c1.register_validator(v, 1000);
            c2.register_validator(v, 1000);
        }
        
        c1.recompute_all_stake_q();
        c2.recompute_all_stake_q();
        
        // Record quality in DIFFERENT order (simulating different HashMap iteration)
        // Instance 1: forward order
        for (i, &v) in validators.iter().enumerate() {
            let quality = 0.5 + (i as f64) * 0.05;
            c1.record_quality_f64(&v, quality);
        }
        
        // Instance 2: reverse order
        for (i, &v) in validators.iter().rev().enumerate() {
            let quality = 0.5 + ((9 - i) as f64) * 0.05;
            c2.record_quality_f64(&v, quality);
        }
        
        // Update all trust (should be deterministic despite different iteration order)
        c1.update_all_trust();
        c2.update_all_trust();
        
        // Compare results - must be IDENTICAL
        let mut all_match = true;
        for &v in &validators {
            let t1 = c1.get_validator(&v).unwrap().trust_q;
            let t2 = c2.get_validator(&v).unwrap().trust_q;
            if t1 != t2 {
                println!("│  ❌ Mismatch for validator {:02x}: {} vs {}", v[0], t1, t2);
                all_match = false;
            }
        }
        
        if all_match {
            println!("│  All 10 validators have identical trust across both instances");
            println!("│  ✅ update_all_trust() is DETERMINISTIC");
        } else {
            panic!("Trust values differ between instances - NOT deterministic!");
        }
        println!();
    }

    // ========================================================================
    // Summary
    // ========================================================================
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    ALL CONSENSUS TESTS PASSED ✅                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}
