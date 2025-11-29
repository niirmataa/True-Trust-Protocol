#![forbid(unsafe_code)]

//! E2E Test: 3 Nodes Mining with RandomX
//!
//! Realistyczny test z:
//! - 3 nodami o różnych stake'ach (345, 980, 150 TT)
//! - RandomX mining z niską trudnością (demo)
//! - Różne zasoby CPU (symulowane przez limity iteracji)
//! - Consensus PRO: Trust + Quality + Stake
//! - Weryfikacja wyboru lidera i fork-choice

use std::collections::HashMap;
use std::time::Instant;

use tt_node::consensus_pro::{ConsensusPro, StakeRaw};
use tt_node::consensus_weights::{compute_final_weight_q, select_leader_deterministic};
use tt_node::core::{Hash32, BlockHeader, now_ts, shake256_bytes};
use tt_node::node_id::NodeId;
use tt_node::randomx_pow::{RandomXConfig, RandomXEngine, mine};
use tt_node::rtt_pro::{q_from_f64, q_to_f64, Q};

/* ============================================================================
   TEST CONFIGURATION
   ============================================================================ */

/// Łatwy target dla demo (dużo zer = łatwiejsze)
/// ~16 leading zeros = bardzo łatwe dla testu
const EASY_TARGET: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00, 0x00, // ~12 bits difficulty
];

/// Realistyczne stake'i (nie okrągłe liczby)
const STAKE_NODE_A: StakeRaw = 345;   // mały staker
const STAKE_NODE_B: StakeRaw = 980;   // duży staker  
const STAKE_NODE_C: StakeRaw = 150;   // micro staker

/// Symulowane limity CPU (maks iteracji na blok)
const CPU_LIMIT_LOW: u64 = 10_000;      // słaby laptop
const CPU_LIMIT_MEDIUM: u64 = 50_000;   // średni PC
const CPU_LIMIT_HIGH: u64 = 100_000;    // mocny rig

/* ============================================================================
   NODE SIMULATION
   ============================================================================ */

/// Symulowany node do testu
struct TestNode {
    id: NodeId,
    name: String,
    stake: StakeRaw,
    cpu_limit: u64,
    blocks_mined: u64,
    total_hashes: u64,
    successful_mines: u64,
}

impl TestNode {
    fn new(name: &str, stake: StakeRaw, cpu_limit: u64) -> Self {
        // Generuj deterministyczny NodeId z nazwy
        let mut id = [0u8; 32];
        let name_bytes = name.as_bytes();
        id[..name_bytes.len().min(32)].copy_from_slice(&name_bytes[..name_bytes.len().min(32)]);
        
        Self {
            id,
            name: name.to_string(),
            stake,
            cpu_limit,
            blocks_mined: 0,
            total_hashes: 0,
            successful_mines: 0,
        }
    }
    
    /// Symuluje kopanie - zwraca Some((nonce, hash)) jeśli sukces
    fn try_mine(
        &mut self,
        engine: &RandomXEngine,
        header: &[u8],
        target: &[u8; 32],
    ) -> Option<(u64, [u8; 32])> {
        let start = Instant::now();
        
        match mine(engine, header, target, self.cpu_limit) {
            Ok(Some((nonce, hash))) => {
                self.successful_mines += 1;
                self.total_hashes += nonce + 1;
                let elapsed = start.elapsed();
                println!(
                    "  ⛏️  {} znalazł blok! nonce={}, czas={:?}, h/s={:.0}",
                    self.name,
                    nonce,
                    elapsed,
                    (nonce + 1) as f64 / elapsed.as_secs_f64()
                );
                Some((nonce, hash))
            }
            Ok(None) => {
                self.total_hashes += self.cpu_limit;
                None
            }
            Err(e) => {
                eprintln!("  ❌ {} błąd RandomX: {}", self.name, e);
                None
            }
        }
    }
}

/* ============================================================================
   TESTS
   ============================================================================ */

/// Test główny: 3 nody kopią bloki przez kilka rund
#[test]
#[ignore] // Wymaga RandomX - uruchom z: cargo test e2e_multi_node -- --ignored --nocapture
fn test_three_nodes_mining_consensus() {
    println!("\n🚀 E2E Test: 3 Nodes Mining with RandomX\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // === SETUP ===
    
    // Inicjalizuj RandomX w trybie light (mniej RAM, ~256MB)
    let config = RandomXConfig {
        use_large_pages: false,
        secure_jit: false,
        full_mem: false, // Light mode dla testu
    };
    
    println!("📦 Inicjalizacja RandomX (light mode)...");
    let engine = match RandomXEngine::new_light(b"TT-TESTNET-EPOCH-0", config) {
        Ok(e) => {
            println!("  ✅ RandomX VM gotowy (flags: {:?})", e.vm_flags());
            e
        }
        Err(e) => {
            eprintln!("  ❌ Nie można zainicjalizować RandomX: {}", e);
            eprintln!("  ℹ️  Upewnij się że masz zainstalowane zależności RandomX");
            panic!("RandomX init failed");
        }
    };
    
    // Twórz nody z realistycznymi stake'ami
    let mut nodes = vec![
        TestNode::new("Alice", STAKE_NODE_A, CPU_LIMIT_MEDIUM),  // 345 TT, średni CPU
        TestNode::new("Bob", STAKE_NODE_B, CPU_LIMIT_HIGH),      // 980 TT, mocny CPU
        TestNode::new("Carol", STAKE_NODE_C, CPU_LIMIT_LOW),     // 150 TT, słaby CPU
    ];
    
    println!("\n📊 Konfiguracja nodów:");
    println!("  {:12} {:>10} {:>15} {:>10}", "Node", "Stake (TT)", "CPU Limit", "Stake %");
    println!("  {}", "─".repeat(50));
    
    let total_stake: StakeRaw = nodes.iter().map(|n| n.stake).sum();
    for n in &nodes {
        let pct = n.stake as f64 / total_stake as f64 * 100.0;
        println!("  {:12} {:>10} {:>15} {:>9.1}%", n.name, n.stake, n.cpu_limit, pct);
    }
    println!("  {:12} {:>10}", "TOTAL", total_stake);
    
    // === CONSENSUS SETUP ===
    
    let mut consensus = ConsensusPro::new_default();
    
    // Rejestruj walidatorów
    for n in &nodes {
        consensus.register_validator(n.id, n.stake);
    }
    
    // Ustaw początkowy trust (wszyscy zaczynają od 0.5)
    for n in &nodes {
        consensus.trust_graph.genesis_set_trust(n.id, q_from_f64(0.5));
    }
    
    // Ustaw jakość (quality) - symulacja Golden Trio
    // Bob ma najlepszą jakość, Carol najgorszą
    consensus.record_quality(&nodes[0].id, q_from_f64(0.7)); // Alice
    consensus.record_quality(&nodes[1].id, q_from_f64(0.9)); // Bob
    consensus.record_quality(&nodes[2].id, q_from_f64(0.6)); // Carol
    
    // Przelicz wszystko
    consensus.recompute_all_stake_q();
    
    // === MINING SIMULATION ===
    
    println!("\n⛏️  Symulacja kopania ({} rund):\n", 5);
    
    let mut parent_hash: Hash32 = [0u8; 32];
    let mut block_authors: Vec<String> = Vec::new();
    
    for slot in 1..=5u64 {
        println!("━━━ Slot {} ━━━", slot);
        
        // Wybierz lidera zgodnie z consensus
        // Format: (NodeId, trust_q, quality_q, stake_q)
        let weights: Vec<(NodeId, Q, Q, Q)> = nodes.iter()
            .map(|n| {
                let v = consensus.get_validator(&n.id).unwrap();
                (n.id, v.trust_q, v.quality_q, v.stake_q)
            })
            .collect();
        
        // Seed dla lidera = hash(parent || slot)
        let mut seed_data = Vec::new();
        seed_data.extend_from_slice(&parent_hash);
        seed_data.extend_from_slice(&slot.to_le_bytes());
        let beacon = shake256_bytes(&seed_data);
        
        let leader_id = select_leader_deterministic(beacon, &weights)
            .expect("No validators");
        
        let leader_weight = {
            let v = consensus.get_validator(&leader_id).unwrap();
            compute_final_weight_q(v.trust_q, v.quality_q, v.stake_q)
        };
        let leader_name = nodes.iter()
            .find(|n| n.id == leader_id)
            .map(|n| n.name.as_str())
            .unwrap_or("?");
        
        // Weight is u128
        println!("  🎯 Lider slotu: {} (weight: {})", 
            leader_name,
            leader_weight
        );
        
        // Buduj header bloku
        let header = BlockHeader {
            parent: parent_hash,
            height: slot,
            author: leader_id,
            task_seed: beacon,
            timestamp: now_ts(),
            parent_state_hash: [0u8; 32],
            result_state_hash: [0u8; 32],
        };
        let header_bytes = bincode::serialize(&header).unwrap();
        
        // Kopanie - lider ma pierwszeństwo, ale inni też mogą próbować
        let mut winner: Option<(String, u64, [u8; 32])> = None;
        
        // Najpierw lider próbuje
        let leader_node = nodes.iter_mut().find(|n| n.id == leader_id).unwrap();
        if let Some((nonce, hash)) = leader_node.try_mine(&engine, &header_bytes, &EASY_TARGET) {
            winner = Some((leader_node.name.clone(), nonce, hash));
            leader_node.blocks_mined += 1;
        }
        
        // Jeśli lider nie znalazł, inni mogą (fork simulation)
        if winner.is_none() {
            for node in nodes.iter_mut().filter(|n| n.id != leader_id) {
                if let Some((nonce, hash)) = node.try_mine(&engine, &header_bytes, &EASY_TARGET) {
                    // Jeśli nie-lider znajdzie, to jest potencjalny fork
                    println!("  ⚠️  Fork! {} znalazł blok mimo że nie jest liderem", node.name);
                    winner = Some((node.name.clone(), nonce, hash));
                    node.blocks_mined += 1;
                    break;
                }
            }
        }
        
        match winner {
            Some((name, _nonce, hash)) => {
                parent_hash = hash;
                block_authors.push(name.clone());
                println!("  ✅ Blok #{} by {}", slot, name);
                
                // Aktualizuj quality dla autora (pozytywna akcja) - wpływa na trust przez record_quality
                let author_id = nodes.iter().find(|n| n.name == name).unwrap().id;
                let v = consensus.get_validator(&author_id).unwrap();
                let new_quality = v.quality_q.saturating_add(q_from_f64(0.05)); // +5% quality
                consensus.record_quality(&author_id, new_quality.min(q_from_f64(1.0)));
            }
            None => {
                println!("  ⏭️  Brak bloku w tym slocie (timeout)");
                block_authors.push("SKIP".to_string());
            }
        }
        println!();
    }
    
    // === RESULTS ===
    
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📊 WYNIKI:\n");
    
    println!("  {:12} {:>10} {:>12} {:>12} {:>10}", 
        "Node", "Bloki", "Hashrate", "Sukces %", "Końc. Trust");
    println!("  {}", "─".repeat(60));
    
    for n in &nodes {
        let success_rate = if n.total_hashes > 0 {
            n.successful_mines as f64 / (n.total_hashes as f64 / n.cpu_limit as f64) * 100.0
        } else {
            0.0
        };
        let final_trust = q_to_f64(consensus.trust_graph.get_trust(&n.id));
        
        println!("  {:12} {:>10} {:>12} {:>11.1}% {:>10.3}",
            n.name,
            n.blocks_mined,
            format!("{} h", n.total_hashes),
            success_rate,
            final_trust
        );
    }
    
    println!("\n  Kolejność bloków: {:?}", block_authors);
    
    // === ASSERTS ===
    
    // Przynajmniej niektóre bloki powinny być wykopane
    let total_blocks: u64 = nodes.iter().map(|n| n.blocks_mined).sum();
    assert!(total_blocks > 0, "Powinien być wykopany przynajmniej 1 blok");
    
    // Bob (największy stake + najlepsza jakość) powinien mieć przewagę
    // ale to nie jest gwarantowane przez RandomX randomness
    println!("\n✅ Test zakończony pomyślnie!\n");
}

/// Test weryfikacji RandomX hash
#[test]
#[ignore]
fn test_randomx_hash_verification() {
    println!("\n🔍 Test weryfikacji RandomX hash\n");
    
    let config = RandomXConfig {
        use_large_pages: false,
        secure_jit: false,
        full_mem: false,
    };
    
    let engine = RandomXEngine::new_light(b"TT-VERIFY-TEST", config)
        .expect("RandomX init failed");
    
    let input = b"test block header data";
    let hash1 = engine.hash(input).expect("hash failed");
    let hash2 = engine.hash(input).expect("hash failed");
    
    // Ten sam input = ten sam hash
    assert_eq!(hash1, hash2, "Deterministyczny hash");
    
    // Różny input = różny hash
    let hash3 = engine.hash(b"different data").expect("hash failed");
    assert_ne!(hash1, hash3, "Różne dane = różne hashe");
    
    println!("  ✅ Hash deterministyczny i unikalny");
    println!("  Hash1: {}...", hex::encode(&hash1[..8]));
    println!("  Hash3: {}...", hex::encode(&hash3[..8]));
}

/// Test fork-choice rule z wagami
#[test]
fn test_fork_choice_with_weights() {
    println!("\n⚖️  Test fork-choice rule\n");
    
    // Symuluj 2 konkurujące bloki od różnych walidatorów
    let mut consensus = ConsensusPro::new_default();
    
    let alice: NodeId = [1u8; 32];
    let bob: NodeId = [2u8; 32];
    
    consensus.register_validator(alice, 345);
    consensus.register_validator(bob, 980);
    consensus.recompute_all_stake_q();
    
    // Bob ma więcej stake'a, więc jego blok powinien wygrać fork
    let alice_weight = {
        let v = consensus.get_validator(&alice).unwrap();
        compute_final_weight_q(v.trust_q, v.quality_q, v.stake_q)
    };
    
    let bob_weight = {
        let v = consensus.get_validator(&bob).unwrap();
        compute_final_weight_q(v.trust_q, v.quality_q, v.stake_q)
    };
    
    // Weight is u128, convert to f64 for display
    println!("  Alice (345 TT): weight = {}", alice_weight);
    println!("  Bob   (980 TT): weight = {}", bob_weight);
    
    // Fork-choice: większa waga wygrywa
    assert!(bob_weight > alice_weight, "Bob (więcej stake) powinien mieć większą wagę");
    
    println!("\n  ✅ Fork-choice rule działa poprawnie");
}

/// Test dystrybucji liderów
#[test]
fn test_leader_distribution() {
    println!("\n🎲 Test dystrybucji liderów\n");
    
    let mut consensus = ConsensusPro::new_default();
    
    // 3 walidatorzy z różnymi stake'ami
    let nodes = [
        ([1u8; 32], 345u128),  // ~23%
        ([2u8; 32], 980u128),  // ~66%
        ([3u8; 32], 150u128),  // ~10%
    ];
    
    for (id, stake) in &nodes {
        consensus.register_validator(*id, *stake);
    }
    consensus.recompute_all_stake_q();
    
    // Symuluj 100 slotów i licz liderów
    let mut leader_counts: HashMap<NodeId, u32> = HashMap::new();
    
    for slot in 0..100u64 {
        // Format: (NodeId, trust_q, quality_q, stake_q)
        let weights: Vec<(NodeId, Q, Q, Q)> = nodes.iter()
            .map(|(id, _)| {
                let v = consensus.get_validator(id).unwrap();
                (*id, v.trust_q, v.quality_q, v.stake_q)
            })
            .collect();
        
        // Pseudo-losowy beacon
        let beacon = shake256_bytes(&slot.to_le_bytes());
        let leader = select_leader_deterministic(beacon, &weights)
            .expect("No validators");
        
        *leader_counts.entry(leader).or_insert(0) += 1;
    }
    
    println!("  Dystrybucja liderów w 100 slotach:");
    let total: StakeRaw = nodes.iter().map(|(_, s)| s).sum();
    for (id, stake) in &nodes {
        let count = *leader_counts.get(id).unwrap_or(&0);
        let expected_pct = *stake as f64 / total as f64 * 100.0;
        let actual_pct = count as f64;
        println!("    Node {:02x}... (stake {}): {} liderów ({:.0}%, expected ~{:.0}%)", 
            id[0], stake, count, actual_pct, expected_pct);
    }
    
    // Bob (największy stake) powinien być liderem częściej
    let bob_count = *leader_counts.get(&[2u8; 32]).unwrap_or(&0);
    assert!(bob_count > 30, "Bob (66% stake) powinien być liderem >30% razy");
    
    println!("\n  ✅ Dystrybucja liderów koreluje ze stake'iem");
}
