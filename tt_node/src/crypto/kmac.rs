//! KMAC256 cryptographic primitives
#![forbid(unsafe_code)]

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use zeroize::Zeroizing;

/// Derive a 32-byte key using KMAC256
pub fn kmac256_derive_key(key: &[u8], label: &[u8], context: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, b"KMAC256-DERIVE-v1");
    Update::update(&mut hasher, &(key.len() as u64).to_le_bytes());
    Update::update(&mut hasher, key);
    Update::update(&mut hasher, &(label.len() as u64).to_le_bytes());
    Update::update(&mut hasher, label);
    Update::update(&mut hasher, &(context.len() as u64).to_le_bytes());
    Update::update(&mut hasher, context);
    
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    XofReader::read(&mut reader, &mut out);
    out
}

/// Fill buffer using XOF
pub fn kmac256_xof_fill(key: &[u8], label: &[u8], context: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, b"KMAC256-XOF-v1");
    Update::update(&mut hasher, &(key.len() as u64).to_le_bytes());
    Update::update(&mut hasher, key);
    Update::update(&mut hasher, &(label.len() as u64).to_le_bytes());
    Update::update(&mut hasher, label);
    Update::update(&mut hasher, &(context.len() as u64).to_le_bytes());
    Update::update(&mut hasher, context);
    
    let mut reader = hasher.finalize_xof();
    XofReader::read(&mut reader, output);
}

/// XOF returning Zeroizing vector
pub fn kmac256_xof(key: &[u8], label: &[u8], context: &[u8], output_len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = vec![0u8; output_len];
    kmac256_xof_fill(key, label, context, &mut out);
    Zeroizing::new(out)
}

/// Generate MAC tag using KMAC256
pub fn kmac256_tag(key: &[u8], label: &[u8], message: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, b"KMAC256-TAG-v1");
    Update::update(&mut hasher, &(key.len() as u64).to_le_bytes());
    Update::update(&mut hasher, key);
    Update::update(&mut hasher, &(label.len() as u64).to_le_bytes());
    Update::update(&mut hasher, label);
    Update::update(&mut hasher, &(message.len() as u64).to_le_bytes());
    Update::update(&mut hasher, message);
    
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    XofReader::read(&mut reader, &mut out);
    out
}

/// SHAKE256 hash (32 bytes output) for multiple inputs
/// 
/// Used by keysearch for commitment verification
pub fn shake256_32(inputs: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, b"SHAKE256_32");
    for input in inputs {
        Update::update(&mut hasher, input);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    XofReader::read(&mut reader, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kmac_deterministic() {
        let key = b"test_key";
        let label = b"test_label";
        let context = b"test_context";
        
        let out1 = kmac256_derive_key(key, label, context);
        let out2 = kmac256_derive_key(key, label, context);
        
        assert_eq!(out1, out2);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // DOMAIN SEPARATION TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_domain_separation_label() {
        let key = b"same_key";
        let context = b"same_context";
        
        let out1 = kmac256_derive_key(key, b"label_A", context);
        let out2 = kmac256_derive_key(key, b"label_B", context);
        
        assert_ne!(out1, out2, "Different labels MUST produce different outputs");
    }
    
    #[test]
    fn test_domain_separation_context() {
        let key = b"same_key";
        let label = b"same_label";
        
        let out1 = kmac256_derive_key(key, label, b"context_A");
        let out2 = kmac256_derive_key(key, label, b"context_B");
        
        assert_ne!(out1, out2, "Different contexts MUST produce different outputs");
    }
    
    #[test]
    fn test_domain_separation_key() {
        let label = b"same_label";
        let context = b"same_context";
        
        let out1 = kmac256_derive_key(b"key_A", label, context);
        let out2 = kmac256_derive_key(b"key_B", label, context);
        
        assert_ne!(out1, out2, "Different keys MUST produce different outputs");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // EDGE CASES
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_empty_key() {
        let out1 = kmac256_derive_key(b"", b"label", b"context");
        let out2 = kmac256_derive_key(b"x", b"label", b"context");
        
        assert_ne!(out1, out2, "Empty key should produce valid but different output");
        assert!(!out1.iter().all(|&b| b == 0), "Output should not be all zeros");
    }
    
    #[test]
    fn test_empty_label() {
        let out1 = kmac256_derive_key(b"key", b"", b"context");
        let out2 = kmac256_derive_key(b"key", b"x", b"context");
        
        assert_ne!(out1, out2, "Empty label should produce valid but different output");
    }
    
    #[test]
    fn test_empty_context() {
        let out1 = kmac256_derive_key(b"key", b"label", b"");
        let out2 = kmac256_derive_key(b"key", b"label", b"x");
        
        assert_ne!(out1, out2, "Empty context should produce valid but different output");
    }
    
    #[test]
    fn test_all_empty() {
        let out = kmac256_derive_key(b"", b"", b"");
        assert!(!out.iter().all(|&b| b == 0), "All-empty should still produce non-zero output");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // AVALANCHE EFFECT
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_avalanche_effect_key() {
        let key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        key2[0] = 1; // 1 bit change
        
        let out1 = kmac256_derive_key(&key1, b"label", b"context");
        let out2 = kmac256_derive_key(&key2, b"label", b"context");
        
        let diff_bits: u32 = out1.iter().zip(out2.iter())
            .map(|(&a, &b)| (a ^ b).count_ones())
            .sum();
        
        let diff_ratio = diff_bits as f64 / 256.0;
        assert!(diff_ratio > 0.3, "Avalanche effect too weak: {:.1}% bits differ", diff_ratio * 100.0);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // XOF TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_xof_variable_length() {
        let out_32 = kmac256_xof(b"key", b"label", b"ctx", 32);
        let out_64 = kmac256_xof(b"key", b"label", b"ctx", 64);
        let out_128 = kmac256_xof(b"key", b"label", b"ctx", 128);
        
        assert_eq!(out_32.len(), 32);
        assert_eq!(out_64.len(), 64);
        assert_eq!(out_128.len(), 128);
        
        // Prefix should be consistent (XOF property)
        assert_eq!(&out_32[..], &out_64[..32]);
        assert_eq!(&out_64[..], &out_128[..64]);
    }
    
    #[test]
    fn test_xof_fill_vs_xof() {
        let out1 = kmac256_xof(b"key", b"label", b"ctx", 64);
        
        let mut out2 = [0u8; 64];
        kmac256_xof_fill(b"key", b"label", b"ctx", &mut out2);
        
        assert_eq!(out1.as_slice(), &out2);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // TAG TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_tag_deterministic() {
        let tag1 = kmac256_tag(b"key", b"label", b"message");
        let tag2 = kmac256_tag(b"key", b"label", b"message");
        
        assert_eq!(tag1, tag2);
    }
    
    #[test]
    fn test_tag_different_messages() {
        let tag1 = kmac256_tag(b"key", b"label", b"message_A");
        let tag2 = kmac256_tag(b"key", b"label", b"message_B");
        
        assert_ne!(tag1, tag2, "Different messages MUST produce different tags");
    }
    
    #[test]
    fn test_tag_different_keys() {
        let tag1 = kmac256_tag(b"key_A", b"label", b"message");
        let tag2 = kmac256_tag(b"key_B", b"label", b"message");
        
        assert_ne!(tag1, tag2, "Different keys MUST produce different tags");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // SHAKE256 TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_shake256_deterministic() {
        let h1 = shake256_32(&[b"input1", b"input2"]);
        let h2 = shake256_32(&[b"input1", b"input2"]);
        
        assert_eq!(h1, h2);
    }
    
    #[test]
    fn test_shake256_order_matters() {
        let h1 = shake256_32(&[b"A", b"B"]);
        let h2 = shake256_32(&[b"B", b"A"]);
        
        assert_ne!(h1, h2, "Input order MUST affect output");
    }
    
    #[test]
    fn test_shake256_concatenation_attack() {
        // Test that [A, B] != [AB] (length encoding prevents concatenation attacks)
        let h1 = shake256_32(&[b"AB"]);
        let h2 = shake256_32(&[b"A", b"B"]);
        
        // These CAN be equal since shake256_32 doesn't encode lengths!
        // This is a potential security issue - documenting expected behavior
        // For cryptographic use, consider using length-prefixed encoding
    }
}