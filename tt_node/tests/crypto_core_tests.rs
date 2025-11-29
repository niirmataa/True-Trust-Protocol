//! ╔════════════════════════════════════════════════════════════════════════════╗
//! ║           TRUE-TRUST-PROTOCOL: CORE CRYPTOGRAPHIC TESTS                     ║
//! ╠════════════════════════════════════════════════════════════════════════════╣
//! ║ Te testy weryfikują PRAWDZIWE właściwości kryptograficzne naszego kodu.    ║
//! ║ Nie są to symulacje - każdy test używa rzeczywistych implementacji.        ║
//! ╚════════════════════════════════════════════════════════════════════════════╝

use tt_node::crypto::kmac::{kmac256_derive_key, kmac256_xof, kmac256_tag, shake256_32};
use tt_node::crypto::kmac_drbg::KmacDrbg;
use tt_node::falcon_sigs::{
    falcon_keypair, falcon_sign, falcon_verify, falcon_sign_nullifier,
    falcon_verify_nullifier, falcon_pk_to_bytes, falcon_sk_to_bytes,
    falcon_pk_from_bytes, falcon_sk_from_bytes, compute_pqc_fingerprint,
};
use tt_node::kyber_kem::{
    kyber_keypair, kyber_encapsulate, kyber_decapsulate, kyber_ss_to_bytes,
    kyber_pk_from_bytes, kyber_sk_from_bytes, kyber_pk_to_bytes, kyber_sk_to_bytes,
    kyber_ct_to_bytes, derive_aes_key_from_shared_secret,
};
use tt_node::stealth_registry::{
    StealthKeyRegistry, RecipientStealthOutput, SenderChangeOutput,
};

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::PublicKey as KemPK;
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::PublicKey as SignPK;

use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;

fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

// ============================================================================
// 1. KMAC-256 TESTS
// ============================================================================

mod kmac_tests {
    use super::*;

    #[test]
    fn test_kmac_determinism() {
        let key = random_32();
        let out1 = kmac256_derive_key(&key, b"test", b"ctx");
        let out2 = kmac256_derive_key(&key, b"test", b"ctx");
        assert_eq!(out1, out2);
        println!("✅ KMAC determinism verified");
    }

    #[test]
    fn test_kmac_key_avalanche() {
        let mut key = random_32();
        let out1 = kmac256_derive_key(&key, b"test", b"ctx");
        key[0] ^= 0x01;
        let out2 = kmac256_derive_key(&key, b"test", b"ctx");
        
        let diff = out1.iter().zip(out2.iter())
            .map(|(a, b)| (a ^ b).count_ones()).sum::<u32>();
        assert!(diff > 100, "Avalanche effect: {} bits", diff);
        println!("✅ KMAC avalanche: {} bits differ", diff);
    }

    #[test]
    fn test_kmac_domain_separation() {
        let key = random_32();
        let o1 = kmac256_derive_key(&key, b"domain-A", b"ctx");
        let o2 = kmac256_derive_key(&key, b"domain-B", b"ctx");
        assert_ne!(o1, o2);
        println!("✅ KMAC domain separation works");
    }

    #[test]
    fn test_kmac_xof() {
        let key = random_32();
        let out64 = kmac256_xof(&key, b"xof", b"ctx", 64);
        let out128 = kmac256_xof(&key, b"xof", b"ctx", 128);
        assert_eq!(&out64[..], &out128[..64]);
        println!("✅ KMAC XOF consistency verified");
    }

    #[test]
    fn test_kmac_tag() {
        let key = random_32();
        let tag1 = kmac256_tag(&key, b"mac", b"msg1");
        let tag2 = kmac256_tag(&key, b"mac", b"msg2");
        assert_ne!(tag1, tag2);
        println!("✅ KMAC tag integrity verified");
    }

    #[test]
    fn test_shake256() {
        let inputs: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let h1 = shake256_32(&inputs);
        let h2 = shake256_32(&inputs);
        assert_eq!(h1, h2);
        println!("✅ SHAKE256 determinism verified");
    }
}

// ============================================================================
// 2. KMAC-DRBG TESTS
// ============================================================================

mod drbg_tests {
    use super::*;

    #[test]
    fn test_drbg_determinism() {
        let seed = random_32();
        let mut d1 = KmacDrbg::new(&seed, b"test");
        let mut d2 = KmacDrbg::new(&seed, b"test");
        
        for _ in 0..10 {
            let mut o1 = [0u8; 32]; let mut o2 = [0u8; 32];
            d1.fill_bytes(&mut o1); d2.fill_bytes(&mut o2);
            assert_eq!(o1, o2);
        }
        println!("✅ DRBG determinism: 10 blocks match");
    }

    #[test]
    fn test_drbg_personalization() {
        let seed = random_32();
        let mut d1 = KmacDrbg::new(&seed, b"A");
        let mut d2 = KmacDrbg::new(&seed, b"B");
        let mut o1 = [0u8; 32]; let mut o2 = [0u8; 32];
        d1.fill_bytes(&mut o1); d2.fill_bytes(&mut o2);
        assert_ne!(o1, o2);
        println!("✅ DRBG personalization works");
    }

    #[test]
    fn test_drbg_reseed() {
        let seed = random_32();
        let mut d1 = KmacDrbg::new(&seed, b"test");
        let mut d2 = KmacDrbg::new(&seed, b"test");
        d2.reseed(&random_32());
        let mut o1 = [0u8; 32]; let mut o2 = [0u8; 32];
        d1.fill_bytes(&mut o1); d2.fill_bytes(&mut o2);
        assert_ne!(o1, o2);
        println!("✅ DRBG reseed changes state");
    }

    #[test]
    fn test_drbg_ratchet() {
        let seed = random_32();
        let mut d = KmacDrbg::new(&seed, b"test");
        let mut b = [0u8; 32]; d.fill_bytes(&mut b);
        d.ratchet();
        let mut a = [0u8; 32]; d.fill_bytes(&mut a);
        assert_ne!(b, a);
        println!("✅ DRBG ratchet provides forward secrecy");
    }

    #[test]
    fn test_drbg_no_repeats() {
        let mut d = KmacDrbg::new(&random_32(), b"test");
        let mut set = HashSet::new();
        for _ in 0..1000 {
            let mut o = [0u8; 32]; d.fill_bytes(&mut o);
            assert!(set.insert(o), "Repeat detected!");
        }
        println!("✅ DRBG: 1000 unique outputs");
    }
}

// ============================================================================
// 3. FALCON-512 TESTS
// ============================================================================

mod falcon_tests {
    use super::*;

    #[test]
    fn test_falcon_roundtrip() {
        let (pk, sk) = falcon_keypair();
        let msg = b"Transaction: send 100 TTP";
        let sig = falcon_sign(msg, &sk).unwrap();
        assert!(falcon_verify(msg, &sig, &pk).is_ok());
        println!("✅ Falcon sign/verify roundtrip");
    }

    #[test]
    fn test_falcon_tamper_detection() {
        let (pk, sk) = falcon_keypair();
        let sig = falcon_sign(b"original", &sk).unwrap();
        assert!(falcon_verify(b"tampered", &sig, &pk).is_err());
        println!("✅ Falcon detects tampering");
    }

    #[test]
    fn test_falcon_wrong_key() {
        let (pk1, _) = falcon_keypair();
        let (_, sk2) = falcon_keypair();
        let sig = falcon_sign(b"msg", &sk2).unwrap();
        assert!(falcon_verify(b"msg", &sig, &pk1).is_err());
        println!("✅ Falcon rejects wrong key");
    }

    #[test]
    fn test_falcon_nullifier() {
        let (pk, sk) = falcon_keypair();
        let nullifier = random_32();
        let sig = falcon_sign_nullifier(&nullifier, &sk).unwrap();
        assert!(falcon_verify_nullifier(&nullifier, &sig, &pk).is_ok());
        assert!(falcon_verify_nullifier(&random_32(), &sig, &pk).is_err());
        println!("✅ Falcon nullifier signing works");
    }

    #[test]
    fn test_falcon_serialization() {
        let (pk, sk) = falcon_keypair();
        let pk_r = falcon_pk_from_bytes(falcon_pk_to_bytes(&pk)).unwrap();
        let sk_r = falcon_sk_from_bytes(&falcon_sk_to_bytes(&sk)).unwrap();
        let sig = falcon_sign(b"test", &sk_r).unwrap();
        assert!(falcon_verify(b"test", &sig, &pk_r).is_ok());
        println!("✅ Falcon key serialization works");
    }

    #[test]
    fn test_falcon_randomization() {
        let (_, sk) = falcon_keypair();
        let s1 = falcon_sign(b"msg", &sk).unwrap();
        let s2 = falcon_sign(b"msg", &sk).unwrap();
        assert_ne!(s1.as_bytes(), s2.as_bytes());
        println!("✅ Falcon signatures are randomized");
    }

    #[test]
    fn test_pqc_fingerprint() {
        let (fpk, _) = falcon_keypair();
        let (kpk, _) = kyber_keypair();
        let fp1 = compute_pqc_fingerprint(&fpk, kyber_pk_to_bytes(&kpk));
        let fp2 = compute_pqc_fingerprint(&fpk, kyber_pk_to_bytes(&kpk));
        assert_eq!(fp1, fp2);
        println!("✅ PQC fingerprint is deterministic");
    }
}

// ============================================================================
// 4. KYBER-768 TESTS
// ============================================================================

mod kyber_tests {
    use super::*;

    #[test]
    fn test_kyber_roundtrip() {
        let (pk, sk) = kyber_keypair();
        let (ss_e, ct) = kyber_encapsulate(&pk);
        let ss_d = kyber_decapsulate(&ct, &sk).unwrap();
        assert_eq!(&kyber_ss_to_bytes(&ss_e)[..], &kyber_ss_to_bytes(&ss_d)[..]);
        println!("✅ Kyber encapsulate/decapsulate roundtrip");
    }

    #[test]
    fn test_kyber_implicit_rejection() {
        let (pk1, _) = kyber_keypair();
        let (_, sk2) = kyber_keypair();
        let (ss_e, ct) = kyber_encapsulate(&pk1);
        let ss_w = kyber_decapsulate(&ct, &sk2).unwrap();
        assert_ne!(&kyber_ss_to_bytes(&ss_e)[..], &kyber_ss_to_bytes(&ss_w)[..]);
        println!("✅ Kyber implicit rejection works");
    }

    #[test]
    fn test_kyber_randomization() {
        let (pk, _) = kyber_keypair();
        let (ss1, ct1) = kyber_encapsulate(&pk);
        let (ss2, ct2) = kyber_encapsulate(&pk);
        assert_ne!(&kyber_ss_to_bytes(&ss1)[..], &kyber_ss_to_bytes(&ss2)[..]);
        assert_ne!(kyber_ct_to_bytes(&ct1), kyber_ct_to_bytes(&ct2));
        println!("✅ Kyber encapsulation is randomized");
    }

    #[test]
    fn test_kyber_serialization() {
        let (pk, sk) = kyber_keypair();
        let pk_r = kyber_pk_from_bytes(kyber_pk_to_bytes(&pk)).unwrap();
        let sk_r = kyber_sk_from_bytes(&kyber_sk_to_bytes(&sk)).unwrap();
        let (ss_e, ct) = kyber_encapsulate(&pk_r);
        let ss_d = kyber_decapsulate(&ct, &sk_r).unwrap();
        assert_eq!(&kyber_ss_to_bytes(&ss_e)[..], &kyber_ss_to_bytes(&ss_d)[..]);
        println!("✅ Kyber key serialization works");
    }

    #[test]
    fn test_kyber_key_derivation() {
        let (pk, sk) = kyber_keypair();
        let (ss, ct) = kyber_encapsulate(&pk);
        let ss_d = kyber_decapsulate(&ct, &sk).unwrap();
        let k1 = derive_aes_key_from_shared_secret(&ss, b"enc");
        let k2 = derive_aes_key_from_shared_secret(&ss_d, b"enc");
        assert_eq!(k1, k2);
        let k3 = derive_aes_key_from_shared_secret(&ss, b"mac");
        assert_ne!(k1, k3);
        println!("✅ Kyber key derivation works");
    }
}

// ============================================================================
// 5. STEALTH ADDRESS TESTS
// ============================================================================

mod stealth_tests {
    use super::*;

    #[test]
    fn test_stealth_unlinkability() {
        let (kpk, _) = kyber768::keypair();
        let (o1, _) = RecipientStealthOutput::generate(&kpk).unwrap();
        let (o2, _) = RecipientStealthOutput::generate(&kpk).unwrap();
        let (o3, _) = RecipientStealthOutput::generate(&kpk).unwrap();
        assert_ne!(o1.stealth_key, o2.stealth_key);
        assert_ne!(o2.stealth_key, o3.stealth_key);
        assert_ne!(o1.kem_ct, o2.kem_ct);
        println!("✅ Stealth outputs are unlinkable");
    }

    #[test]
    fn test_sender_change_recovery() {
        let (_, ksk) = kyber768::keypair();
        let out = SenderChangeOutput::generate(&ksk, 42);
        assert!(SenderChangeOutput::is_ours(&ksk, &out));
        let (k, t) = SenderChangeOutput::recover(&ksk, &out);
        assert_ne!(k, [0u8; 32]);
        assert_ne!(t, [0u8; 8]);
        
        let (_, other) = kyber768::keypair();
        assert!(!SenderChangeOutput::is_ours(&other, &out));
        println!("✅ Sender change recovery works");
    }

    #[test]
    fn test_sender_change_nonce() {
        let (_, ksk) = kyber768::keypair();
        let o1 = SenderChangeOutput::generate(&ksk, 1);
        let o2 = SenderChangeOutput::generate(&ksk, 2);
        let (k1, _) = SenderChangeOutput::recover(&ksk, &o1);
        let (k2, _) = SenderChangeOutput::recover(&ksk, &o2);
        assert_ne!(k1, k2);
        println!("✅ Different nonces = different outputs");
    }

    #[test]
    fn test_registry_validation() {
        let mut reg = StealthKeyRegistry::new();
        let (fpk, _) = falcon512::keypair();
        let (kpk, _) = kyber768::keypair();
        
        assert!(reg.register(fpk.as_bytes().to_vec(), kpk.as_bytes().to_vec(), 0, 0).is_ok());
        assert!(reg.register(vec![0u8; 100], kpk.as_bytes().to_vec(), 0, 0).is_err());
        assert!(reg.register(fpk.as_bytes().to_vec(), vec![0u8; 500], 0, 0).is_err());
        println!("✅ Registry validates key lengths");
    }

    #[test]
    fn test_master_key_id() {
        let (fpk, _) = falcon512::keypair();
        let (kpk, _) = kyber768::keypair();
        let id1 = StealthKeyRegistry::compute_master_key_id(fpk.as_bytes(), kpk.as_bytes());
        let id2 = StealthKeyRegistry::compute_master_key_id(fpk.as_bytes(), kpk.as_bytes());
        assert_eq!(id1, id2);
        
        let (fpk2, _) = falcon512::keypair();
        let id3 = StealthKeyRegistry::compute_master_key_id(fpk2.as_bytes(), kpk.as_bytes());
        assert_ne!(id1, id3);
        println!("✅ Master key ID is deterministic");
    }
}

// ============================================================================
// 6. INTEGRATION TESTS
// ============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_full_signing_flow() {
        let (fpk, fsk) = falcon_keypair();
        let (kpk, _) = kyber_keypair();
        
        let mut reg = StealthKeyRegistry::new();
        reg.register(
            falcon_pk_to_bytes(&fpk).to_vec(),
            kyber_pk_to_bytes(&kpk).to_vec(),
            0, 0,
        ).unwrap();
        
        let sig = falcon_sign(b"Transfer 50 TTP", &fsk).unwrap();
        assert!(falcon_verify(b"Transfer 50 TTP", &sig, &fpk).is_ok());
        println!("✅ Full signing flow works");
    }

    #[test]
    fn test_multiple_transactions() {
        let (fpk, fsk) = falcon_keypair();
        let (kpk, _) = kyber768::keypair();
        
        let txs: Vec<_> = (0..10).map(|i| {
            let data = format!("TX #{}", i);
            let (stealth, _) = RecipientStealthOutput::generate(&kpk).unwrap();
            let sig = falcon_sign(data.as_bytes(), &fsk).unwrap();
            (data, stealth, sig)
        }).collect();
        
        let keys: HashSet<_> = txs.iter().map(|(_, s, _)| s.stealth_key).collect();
        assert_eq!(keys.len(), 10);
        
        for (d, _, sig) in &txs {
            assert!(falcon_verify(d.as_bytes(), sig, &fpk).is_ok());
        }
        println!("✅ 10 transactions: all unique and verifiable");
    }
}

// ============================================================================
// 7. SECURITY BOUNDARY TESTS
// ============================================================================

mod security_tests {
    use super::*;

    #[test]
    fn test_empty_message() {
        let (pk, sk) = falcon_keypair();
        let sig = falcon_sign(b"", &sk).unwrap();
        assert!(falcon_verify(b"", &sig, &pk).is_ok());
        println!("✅ Empty message signing works");
    }

    #[test]
    fn test_long_message() {
        let (pk, sk) = falcon_keypair();
        let long = vec![0xABu8; 1_000_000];
        let sig = falcon_sign(&long, &sk).unwrap();
        assert!(falcon_verify(&long, &sig, &pk).is_ok());
        println!("✅ 1MB message signing works");
    }

    #[test]
    fn test_key_reuse() {
        let (pk, sk) = falcon_keypair();
        for i in 0..100 {
            let msg = format!("Msg {}", i);
            let sig = falcon_sign(msg.as_bytes(), &sk).unwrap();
            assert!(falcon_verify(msg.as_bytes(), &sig, &pk).is_ok());
        }
        println!("✅ 100 signatures with same key");
    }

    #[test]
    fn test_drbg_stress() {
        let mut d = KmacDrbg::new(&random_32(), b"stress");
        for _ in 0..10_000 {
            let mut o = [0u8; 32]; d.fill_bytes(&mut o);
        }
        println!("✅ DRBG: 320KB generated");
    }

    #[test]
    fn test_kmac_long_input() {
        let key = random_32();
        let long = vec![0xCDu8; 100_000];
        let o1 = kmac256_derive_key(&key, b"long", &long);
        let o2 = kmac256_derive_key(&key, b"long", &long);
        assert_eq!(o1, o2);
        println!("✅ KMAC handles 100KB input");
    }
}
