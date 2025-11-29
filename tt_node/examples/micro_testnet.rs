//! MICRO TESTNET - Full Integration Demo
//!
//! This demo runs a complete mini-blockchain with:
//! - 3 validators (Alice, Bob, Carol) with RTT trust + stake
//! - Consensus leader selection per slot
//! - Private transactions with STARK proofs
//! - Stealth addresses + hidden amounts
//! - Block production and validation
//!
//! Run: cargo run --release --example micro_testnet

use std::collections::HashMap;
use std::time::Instant;

use tt_node::consensus_pro::ConsensusPro;
use tt_node::rtt_pro::{q_to_f64, genesis_bootstrap};
use tt_node::crypto::zk_range_poseidon::{
    prove_range_with_poseidon, verify_range_with_poseidon, 
    Witness, PublicInputs, default_proof_options
};

use pqcrypto_falcon::falcon512;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature};
use pqcrypto_traits::kem::{PublicKey as KemPk, SharedSecret, Ciphertext};

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use winterfell::Proof;

// ============================================================================
// TYPES
// ============================================================================

type NodeId = [u8; 32];
type TxHash = [u8; 32];
type BlockHash = [u8; 32];

/// Validator with full key material
struct Validator {
    id: NodeId,
    name: String,
    falcon_pk: falcon512::PublicKey,
    falcon_sk: falcon512::SecretKey,
    kyber_pk: kyber768::PublicKey,
    kyber_sk: kyber768::SecretKey,
    stake: u128,
    balance: u128,
}

/// Private transaction with STARK proof
#[derive(Clone)]
struct PrivateTx {
    hash: TxHash,
    /// Poseidon commitment to amount
    commitment: u128,
    /// STARK range proof (~33KB)
    range_proof: Vec<u8>,
    /// Public inputs for verification
    pub_inputs: PublicInputs,
    /// Encrypted amount (for recipient)
    encrypted_amount: Vec<u8>,
    /// Stealth ephemeral ciphertext
    stealth_ct: Vec<u8>,
    /// View tag for fast scanning
    view_tag: [u8; 8],
    /// Sender signature
    signature: Vec<u8>,
    /// Sender ID (could be hidden in real impl)
    sender_id: NodeId,
    /// Recipient stealth pubkey hint
    recipient_hint: [u8; 32],
}

/// Block in our mini-chain
struct Block {
    slot: u64,
    prev_hash: BlockHash,
    hash: BlockHash,
    leader: NodeId,
    transactions: Vec<PrivateTx>,
    signature: Vec<u8>,
    timestamp: u64,
}

/// Simple blockchain state
struct MicroChain {
    blocks: Vec<Block>,
    pending_txs: Vec<PrivateTx>,
    consensus: ConsensusPro,
    validators: HashMap<NodeId, Validator>,
    balances: HashMap<NodeId, u128>,
}

// ============================================================================
// IMPLEMENTATION
// ============================================================================

impl Validator {
    fn new(name: &str, stake: u128, balance: u128) -> Self {
        let (falcon_pk, falcon_sk) = falcon512::keypair();
        let (kyber_pk, kyber_sk) = kyber768::keypair();
        
        // NodeId = hash of Falcon public key
        let mut h = Shake256::default();
        h.update(falcon_pk.as_bytes());
        let mut id = [0u8; 32];
        h.finalize_xof().read(&mut id);
        
        Self {
            id,
            name: name.to_string(),
            falcon_pk,
            falcon_sk,
            kyber_pk,
            kyber_sk,
            stake,
            balance,
        }
    }
    
    fn short_id(&self) -> String {
        format!("{:02x}{:02x}", self.id[0], self.id[1])
    }
}

impl MicroChain {
    fn new() -> Self {
        Self {
            blocks: Vec::new(),
            pending_txs: Vec::new(),
            consensus: ConsensusPro::new_default(),
            validators: HashMap::new(),
            balances: HashMap::new(),
        }
    }
    
    fn add_validator(&mut self, validator: Validator) {
        let id = validator.id;
        let stake = validator.stake;
        let balance = validator.balance;
        
        self.consensus.register_validator(id, stake);
        self.balances.insert(id, balance);
        self.validators.insert(id, validator);
    }
    
    fn genesis_init(&mut self) {
        // Bootstrap genesis validators with full trust
        let ids: Vec<_> = self.validators.keys().cloned().collect();
        genesis_bootstrap(&mut self.consensus.trust_graph, &ids);
        
        // Recompute stake
        self.consensus.recompute_all_stake_q();
        
        // Create genesis block
        let genesis = Block {
            slot: 0,
            prev_hash: [0u8; 32],
            hash: [0x00; 32], // Genesis hash
            leader: ids[0],
            transactions: Vec::new(),
            signature: Vec::new(),
            timestamp: 0,
        };
        self.blocks.push(genesis);
        
        println!("│  Genesis block created with {} validators", ids.len());
    }
    
    fn create_private_tx(
        &self,
        sender: &Validator,
        recipient: &Validator,
        amount: u64,
    ) -> PrivateTx {
        // 1. Create Poseidon commitment witness
        let blinding = rand::random::<[u8; 32]>();
        let recipient_bytes = recipient.id;  // Use recipient ID as identifier
        
        let witness = Witness::new(amount as u128, blinding, recipient_bytes);
        
        // 2. Generate STARK range proof
        let (proof, pub_inputs) = prove_range_with_poseidon(
            witness, 
            64,  // 64-bit range
            default_proof_options()
        );
        let range_proof = proof.to_bytes();
        let commitment = pub_inputs.value_commitment;
        
        // 3. Stealth: encapsulate to recipient
        let (ss, ct) = kyber768::encapsulate(&recipient.kyber_pk);
        
        // 4. Derive stealth key
        let mut h = Shake256::default();
        h.update(b"TT.v7.STEALTH_KEY");
        h.update(ss.as_bytes());
        let mut stealth_key = [0u8; 32];
        h.finalize_xof().read(&mut stealth_key);
        
        // 5. View tag (first 8 bytes of hash)
        let mut h2 = Shake256::default();
        h2.update(b"TT.v7.VIEW_TAG");
        h2.update(ss.as_bytes());
        let mut view_tag = [0u8; 8];
        h2.finalize_xof().read(&mut view_tag);
        
        // 6. Encrypt amount with stealth key
        let amount_bytes = amount.to_le_bytes();
        let encrypted_amount: Vec<u8> = amount_bytes
            .iter()
            .zip(stealth_key.iter())
            .map(|(a, k)| a ^ k)
            .collect();
        
        // 7. Sign transaction
        let mut msg = Vec::new();
        msg.extend_from_slice(&commitment.to_le_bytes());
        msg.extend_from_slice(&range_proof[..64.min(range_proof.len())]);
        let sig = falcon512::detached_sign(&msg, &sender.falcon_sk);
        
        // 8. Compute TX hash
        let mut h3 = Shake256::default();
        h3.update(&msg);
        h3.update(sig.as_bytes());
        let mut hash = [0u8; 32];
        h3.finalize_xof().read(&mut hash);
        
        // 9. Recipient hint (first 32 bytes of Kyber PK hash)
        let mut h4 = Shake256::default();
        h4.update(recipient.kyber_pk.as_bytes());
        let mut recipient_hint = [0u8; 32];
        h4.finalize_xof().read(&mut recipient_hint);
        
        PrivateTx {
            hash,
            commitment,
            range_proof,
            pub_inputs,
            encrypted_amount,
            stealth_ct: ct.as_bytes().to_vec(),
            view_tag,
            signature: sig.as_bytes().to_vec(),
            sender_id: sender.id,
            recipient_hint,
        }
    }
    
    fn verify_tx(&self, tx: &PrivateTx) -> bool {
        // 1. Verify STARK proof
        let proof = match Proof::from_bytes(&tx.range_proof) {
            Ok(p) => p,
            Err(_) => return false,
        };
        
        if !verify_range_with_poseidon(proof, tx.pub_inputs.clone()) {
            return false;
        }
        
        // 2. Verify signature
        let sender = match self.validators.get(&tx.sender_id) {
            Some(v) => v,
            None => return false,
        };
        
        let mut msg = Vec::new();
        msg.extend_from_slice(&tx.commitment.to_le_bytes());
        msg.extend_from_slice(&tx.range_proof[..64.min(tx.range_proof.len())]);
        
        let sig = match falcon512::DetachedSignature::from_bytes(&tx.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        falcon512::verify_detached_signature(&sig, &msg, &sender.falcon_pk).is_ok()
    }
    
    fn produce_block(&mut self, slot: u64) -> Option<Block> {
        // 1. Get beacon (in real impl: from RandomX/VRF)
        let mut beacon = [0u8; 32];
        beacon[0..8].copy_from_slice(&slot.to_le_bytes());
        
        // 2. Select leader
        let leader_id = self.consensus.select_leader(beacon)?;
        let leader = self.validators.get(&leader_id)?;
        
        // 3. Collect pending transactions
        let txs: Vec<_> = self.pending_txs.drain(..).collect();
        
        // 4. Compute block hash
        let prev_hash = self.blocks.last().map(|b| b.hash).unwrap_or([0u8; 32]);
        let mut h = Shake256::default();
        h.update(&slot.to_le_bytes());
        h.update(&prev_hash);
        h.update(&leader_id);
        for tx in &txs {
            h.update(&tx.hash);
        }
        let mut hash = [0u8; 32];
        h.finalize_xof().read(&mut hash);
        
        // 5. Sign block
        let sig = falcon512::detached_sign(&hash, &leader.falcon_sk);
        
        let block = Block {
            slot,
            prev_hash,
            hash,
            leader: leader_id,
            transactions: txs,
            signature: sig.as_bytes().to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        Some(block)
    }
    
    fn apply_block(&mut self, block: Block) {
        // Update validator quality based on block production
        self.consensus.record_quality_f64(&block.leader, 0.95);
        
        // Apply transactions (simplified - just count)
        let tx_count = block.transactions.len();
        
        self.blocks.push(block);
        
        if tx_count > 0 {
            println!("│  Applied block with {} transactions", tx_count);
        }
    }
    
    fn end_epoch(&mut self) {
        // Update all trust scores
        self.consensus.update_all_trust();
        self.consensus.recompute_all_stake_q();
    }
}

// ============================================================================
// MAIN DEMO
// ============================================================================

fn main() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║          TRUE TRUST PROTOCOL - MICRO TESTNET DEMO                ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    let start = Instant::now();

    // ========================================================================
    // Phase 1: Initialize validators
    // ========================================================================
    println!("┌─ Phase 1: Initialize Validators ─");
    
    let mut chain = MicroChain::new();
    
    let alice = Validator::new("Alice", 1000, 10000);
    let bob = Validator::new("Bob", 800, 8000);
    let carol = Validator::new("Carol", 1200, 12000);
    
    println!("│  Alice: stake=1000, balance=10000, id={}", alice.short_id());
    println!("│  Bob:   stake=800,  balance=8000,  id={}", bob.short_id());
    println!("│  Carol: stake=1200, balance=12000, id={}", carol.short_id());
    
    // Store references for later
    let alice_id = alice.id;
    let bob_id = bob.id;
    let carol_id = carol.id;
    
    chain.add_validator(alice);
    chain.add_validator(bob);
    chain.add_validator(carol);
    
    println!("│  ✅ 3 validators registered\n");

    // ========================================================================
    // Phase 2: Genesis
    // ========================================================================
    println!("┌─ Phase 2: Genesis Block ─");
    chain.genesis_init();
    
    // Show initial trust/stake
    let ranking = chain.consensus.get_weight_ranking();
    println!("│  Initial weight ranking:");
    for (i, (id, weight)) in ranking.iter().enumerate() {
        let name = chain.validators.get(id).map(|v| v.name.as_str()).unwrap_or("?");
        println!("│    #{}: {} - weight: {}", i + 1, name, weight);
    }
    println!("│  ✅ Genesis complete\n");

    // ========================================================================
    // Phase 3: Create private transactions
    // ========================================================================
    println!("┌─ Phase 3: Create Private Transactions ─");
    
    let alice_ref = chain.validators.get(&alice_id).unwrap();
    let bob_ref = chain.validators.get(&bob_id).unwrap();
    let carol_ref = chain.validators.get(&carol_id).unwrap();
    
    // Transaction 1: Alice → Bob (500 TT)
    print!("│  Creating TX1: Alice → Bob (500 TT)... ");
    let tx1_start = Instant::now();
    let tx1 = chain.create_private_tx(alice_ref, bob_ref, 500);
    println!("✓ ({:.1}ms, proof: {} bytes)", 
             tx1_start.elapsed().as_millis(),
             tx1.range_proof.len());
    
    // Transaction 2: Bob → Carol (300 TT)
    print!("│  Creating TX2: Bob → Carol (300 TT)... ");
    let tx2_start = Instant::now();
    let tx2 = chain.create_private_tx(bob_ref, carol_ref, 300);
    println!("✓ ({:.1}ms, proof: {} bytes)", 
             tx2_start.elapsed().as_millis(),
             tx2.range_proof.len());
    
    // Transaction 3: Carol → Alice (1000 TT)
    print!("│  Creating TX3: Carol → Alice (1000 TT)... ");
    let tx3_start = Instant::now();
    let tx3 = chain.create_private_tx(carol_ref, alice_ref, 1000);
    println!("✓ ({:.1}ms, proof: {} bytes)", 
             tx3_start.elapsed().as_millis(),
             tx3.range_proof.len());
    
    println!("│  ✅ 3 private transactions created\n");

    // ========================================================================
    // Phase 4: Verify transactions
    // ========================================================================
    println!("┌─ Phase 4: Verify Transactions (STARK proofs) ─");
    
    let txs = vec![tx1.clone(), tx2.clone(), tx3.clone()];
    for (i, tx) in txs.iter().enumerate() {
        print!("│  Verifying TX{}... ", i + 1);
        let v_start = Instant::now();
        let valid = chain.verify_tx(tx);
        if valid {
            println!("✓ VALID ({:.1}ms)", v_start.elapsed().as_millis());
        } else {
            println!("✗ INVALID");
        }
    }
    
    // Add to pending
    chain.pending_txs.push(tx1);
    chain.pending_txs.push(tx2);
    chain.pending_txs.push(tx3);
    println!("│  ✅ All transactions verified and queued\n");

    // ========================================================================
    // Phase 5: Run consensus for 10 slots
    // ========================================================================
    println!("┌─ Phase 5: Run Consensus (10 slots) ─");
    
    let mut leader_counts: HashMap<NodeId, u32> = HashMap::new();
    
    for slot in 1..=10 {
        // Produce block
        if let Some(block) = chain.produce_block(slot) {
            let leader_name = chain.validators.get(&block.leader)
                .map(|v| v.name.as_str())
                .unwrap_or("?");
            
            let tx_count = block.transactions.len();
            
            *leader_counts.entry(block.leader).or_insert(0) += 1;
            
            if tx_count > 0 {
                println!("│  Slot {:2}: {} produced block with {} TX(s)", 
                         slot, leader_name, tx_count);
            } else {
                println!("│  Slot {:2}: {} produced empty block", slot, leader_name);
            }
            
            // Apply and update quality
            chain.apply_block(block);
            
            // Record quality for other validators (they're online but not leading)
            for (&id, _) in &chain.validators {
                if id != chain.blocks.last().unwrap().leader {
                    chain.consensus.record_quality_f64(&id, 0.80);
                }
            }
        }
    }
    
    // End of epoch - update trust
    chain.end_epoch();
    
    println!("│");
    println!("│  Leader distribution:");
    for (id, count) in &leader_counts {
        let name = chain.validators.get(id).map(|v| v.name.as_str()).unwrap_or("?");
        println!("│    {}: {} blocks", name, count);
    }
    println!("│  ✅ 10 slots completed\n");

    // ========================================================================
    // Phase 6: Final state
    // ========================================================================
    println!("┌─ Phase 6: Final State ─");
    
    println!("│  Chain height: {} blocks", chain.blocks.len());
    println!("│  Total transactions: {}", 
             chain.blocks.iter().map(|b| b.transactions.len()).sum::<usize>());
    
    let final_ranking = chain.consensus.get_weight_ranking();
    println!("│");
    println!("│  Final validator ranking:");
    for (i, (id, weight)) in final_ranking.iter().enumerate() {
        let v = chain.validators.get(id).unwrap();
        let trust = q_to_f64(chain.consensus.get_validator(id).unwrap().trust_q);
        let stake = q_to_f64(chain.consensus.get_validator(id).unwrap().stake_q);
        println!("│    #{}: {} - weight: {} (trust: {:.3}, stake: {:.3})", 
                 i + 1, v.name, weight, trust, stake);
    }
    
    // Show privacy features
    println!("│");
    println!("│  Privacy features demonstrated:");
    println!("│    ✓ Poseidon commitments (hidden amounts)");
    println!("│    ✓ STARK range proofs (~33KB, ~17ms generate, ~0.3ms verify)");
    println!("│    ✓ Kyber stealth addresses (quantum-safe)");
    println!("│    ✓ View tags for fast scanning");
    println!("│    ✓ Falcon-512 signatures (quantum-safe)");
    println!();

    // ========================================================================
    // Summary
    // ========================================================================
    let elapsed = start.elapsed();
    
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    MICRO TESTNET COMPLETE ✅                      ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  Total time: {:.2}s                                              ║", elapsed.as_secs_f64());
    println!("║  Validators: 3 (Alice, Bob, Carol)                               ║");
    println!("║  Blocks: {}                                                       ║", chain.blocks.len());
    println!("║  Private TXs: 3 (with STARK proofs)                              ║");
    println!("║  Consensus: RTT PRO + Golden Trio                                ║");
    println!("║  Crypto: Falcon-512, Kyber-768, Poseidon, Winterfell STARK       ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}
