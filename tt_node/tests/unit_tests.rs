#![forbid(unsafe_code)]

//! Unit tests for TRUE_TRUST Node

#[cfg(test)]
mod tests {
    use tt_node::*;

    #[test]
    fn test_falcon_keypair_generation() {
        let (pk, sk) = falcon_sigs::falcon_keypair();

        // Test that keys have expected sizes
        use pqcrypto_traits::sign::{PublicKey, SecretKey};
        assert_eq!(pk.as_bytes().len(), 897);
        assert!(sk.as_bytes().len() > 1000);
    }

    #[test]
    fn test_falcon_sign_verify() {
        let (pk, sk) = falcon_sigs::falcon_keypair();
        let nullifier = [42u8; 32];

        // Sign
        let sig = falcon_sigs::falcon_sign_nullifier(&nullifier, &sk).unwrap();

        // Verify
        assert!(falcon_sigs::falcon_verify_nullifier(&nullifier, &sig, &pk).is_ok());

        // Verify with wrong nullifier should fail
        let wrong_nullifier = [43u8; 32];
        assert!(falcon_sigs::falcon_verify_nullifier(&wrong_nullifier, &sig, &pk).is_err());
    }

    #[test]
    fn test_kyber_kem() {
        let (pk, sk) = kyber_kem::kyber_keypair();

        // Encapsulate
        let (ss1, ct) = kyber_kem::kyber_encapsulate(&pk);

        // Decapsulate
        let ss2 = kyber_kem::kyber_decapsulate(&ct, &sk).unwrap();

        // Shared secrets should match
        use pqcrypto_traits::kem::SharedSecret;
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_kmac_derive_key() {
        use crypto::kmac;

        let key = [1u8; 32];
        let label = b"test-label";
        let context = b"test-context";

        let derived = kmac::kmac256_derive_key(&key, label, context);

        // Should produce deterministic output
        let derived2 = kmac::kmac256_derive_key(&key, label, context);
        assert_eq!(derived, derived2);

        // Different inputs should produce different outputs
        let derived3 = kmac::kmac256_derive_key(&key, b"other-label", context);
        assert_ne!(derived, derived3);
    }

    #[test]
    fn test_node_id_generation() {
        let (pk, _) = falcon_sigs::falcon_keypair();
        let node_id = node_id::node_id_from_falcon_pk(&pk);

        // Node ID should be 32 bytes
        assert_eq!(node_id.len(), 32);

        // Different keys should produce different node IDs
        let (pk2, _) = falcon_sigs::falcon_keypair();
        let node_id2 = node_id::node_id_from_falcon_pk(&pk2);
        assert_ne!(node_id, node_id2);
    }

    #[test]
    fn test_consensus_basic() {
        let mut consensus = consensus_pro::ConsensusPro::new_default();

        // Generate validators
        let (pk1, _) = falcon_sigs::falcon_keypair();
        let id1 = node_id::node_id_from_falcon_pk(&pk1);

        let (pk2, _) = falcon_sigs::falcon_keypair();
        let id2 = node_id::node_id_from_falcon_pk(&pk2);

        // Register validators
        consensus.register_validator(id1, 1000000);
        consensus.register_validator(id2, 2000000);

        // Set quality
        consensus.record_quality_f64(&id1, 0.9);
        consensus.record_quality_f64(&id2, 0.8);

        // Update trust
        consensus.update_all_trust();

        // Compute weights
        let w1 = consensus.compute_validator_weight(&id1).unwrap();
        let w2 = consensus.compute_validator_weight(&id2).unwrap();

        // Validator 2 should have higher weight (more stake)
        assert!(w2 > w1);

        // Leader selection should work
        let beacon = [0u8; 32];
        let leader = consensus.select_leader(beacon);
        assert!(leader.is_some());
    }

    #[test]
    fn test_chain_store() {
        let store = chain_store::ChainStore::new();

        // Should be empty initially
        assert_eq!(store.blocks.len(), 0);
        // Store is empty initially
    }

    #[test]
    fn test_snapshot_pro() {
        use consensus_pro::ConsensusPro;
        use snapshot_pro::EpochSnapshot;

        let mut consensus = ConsensusPro::new_default();

        // Add a validator
        let (pk, _) = falcon_sigs::falcon_keypair();
        let id = node_id::node_id_from_falcon_pk(&pk);
        consensus.register_validator(id, 1000000);
        consensus.update_all_trust();

        // Build snapshot
        let snapshot = EpochSnapshot::build(0, &consensus);

        // Verify snapshot
        assert_eq!(snapshot.epoch, 0);
        // TODO: Add more snapshot tests when API is finalized
    }

    #[test]
    fn test_stark_placeholder() {
        use stark_full::{STARKProver, STARKVerifier};

        // Generate proof
        let value = 1000u64;
        let commitment = [0u8; 32];
        let proof = STARKProver::prove_range_with_commitment(value, &commitment);

        // Verify proof
        assert!(STARKVerifier::verify_proof(&proof));
    }

    #[test]
    fn test_fixed_point_arithmetic() {
        use rtt_pro::{q_from_f64, q_to_f64, qmul, ONE_Q};

        // Test conversion
        let half = q_from_f64(0.5);
        assert_eq!(q_to_f64(half), 0.5);

        // Test multiplication
        let quarter = qmul(half, half);
        assert!((q_to_f64(quarter) - 0.25).abs() < 1e-9);

        // Test ONE
        assert_eq!(q_to_f64(ONE_Q), 1.0);
    }
}
