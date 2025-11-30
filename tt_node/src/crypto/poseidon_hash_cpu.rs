// tt_node/src/crypto/poseidon_hash_cpu.rs
#![forbid(unsafe_code)]

use winterfell::math::{fields::f128::BaseElement, FieldElement};

use crate::crypto::poseidon_params::{
    POSEIDON_WIDTH, FULL_ROUNDS, PARTIAL_ROUNDS, TOTAL_ROUNDS,
    ROUND_CONSTANTS, MDS_MATRIX,
};

/// Indeksy lane’ów w stanie Poseidona
pub const POSEIDON_VALUE_LANE: usize = 0;
pub const POSEIDON_BLINDING_LANE: usize = 1;
pub const POSEIDON_RECIPIENT_LANE: usize = 2;

/// Stan permutacji Poseidona po stronie CPU (poza STARKiem)
#[derive(Clone)]
pub struct PoseidonState {
    pub state: [BaseElement; POSEIDON_WIDTH],
    round: usize,
}

impl PoseidonState {
    pub fn new() -> Self {
        Self {
            state: [BaseElement::ZERO; POSEIDON_WIDTH],
            round: 0,
        }
    }

    pub fn absorb(&mut self, inputs: &[BaseElement]) {
        for (i, &x) in inputs.iter().enumerate() {
            if i < POSEIDON_WIDTH {
                self.state[i] = x;
            }
        }
    }

    #[inline]
    fn sbox(x: BaseElement) -> BaseElement {
        // x^5 = x * (x^2)^2
        let x2 = x * x;
        let x4 = x2 * x2;
        x * x4
    }

    #[inline]
    fn add_round_constants(&mut self) {
        debug_assert!(self.round < TOTAL_ROUNDS);
        let rc_row = &ROUND_CONSTANTS[self.round];
        for i in 0..POSEIDON_WIDTH {
            self.state[i] += rc_row[i];
        }
    }

    #[inline]
    fn apply_mds(&mut self) {
        let mut result = [BaseElement::ZERO; POSEIDON_WIDTH];
        for i in 0..POSEIDON_WIDTH {
            let mut acc = BaseElement::ZERO;
            for j in 0..POSEIDON_WIDTH {
                acc += self.state[j] * MDS_MATRIX[i][j];
            }
            result[i] = acc;
        }
        self.state = result;
    }

    fn full_round(&mut self) {
        self.add_round_constants();
        for i in 0..POSEIDON_WIDTH {
            self.state[i] = Self::sbox(self.state[i]);
        }
        self.apply_mds();
        self.round += 1;
    }

    fn partial_round(&mut self) {
        self.add_round_constants();
        self.state[0] = Self::sbox(self.state[0]);
        self.apply_mds();
        self.round += 1;
    }

    pub fn permute(&mut self) {
        let half_full = FULL_ROUNDS / 2;

        for _ in 0..half_full {
            self.full_round();
        }
        for _ in 0..PARTIAL_ROUNDS {
            self.partial_round();
        }
        for _ in 0..half_full {
            self.full_round();
        }

        debug_assert_eq!(self.round, TOTAL_ROUNDS);
    }

    pub fn squeeze(&self) -> BaseElement {
        self.state[0]
    }
}

/// CPU-owy hash Poseidona – musi być bit-w-bit identyczny z tym,
/// co symulujemy w śladzie STARKa.
pub fn poseidon_hash_cpu(
    value: u128,
    blinding: &[u8; 32],
    recipient: &[u8; 32],
) -> BaseElement {
    let mut st = PoseidonState::new();

    let v = BaseElement::new(value);

    let blind = BaseElement::from(u64::from_le_bytes(
        blinding[0..8].try_into().expect("slice to [u8;8]"),
    ));
    let recip = BaseElement::from(u64::from_le_bytes(
        recipient[0..8].try_into().expect("slice to [u8;8]"),
    ));

    let mut inputs = [BaseElement::ZERO; POSEIDON_WIDTH];
    inputs[POSEIDON_VALUE_LANE] = v;
    inputs[POSEIDON_BLINDING_LANE] = blind;
    inputs[POSEIDON_RECIPIENT_LANE] = recip;

    st.absorb(&inputs);
    st.permute();
    st.squeeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_hash_deterministic() {
        let value = 42u128;
        let blinding = [1u8; 32];
        let recipient = [2u8; 32];

        let h1 = poseidon_hash_cpu(value, &blinding, &recipient);
        let h2 = poseidon_hash_cpu(value, &blinding, &recipient);
        assert_eq!(h1, h2);

        let h3 = poseidon_hash_cpu(value + 1u128, &blinding, &recipient);
        assert_ne!(h1, h3);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // AVALANCHE EFFECT TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_avalanche_value_change() {
        let blinding = [0u8; 32];
        let recipient = [0u8; 32];
        
        let h1 = poseidon_hash_cpu(0u128, &blinding, &recipient);
        let h2 = poseidon_hash_cpu(1u128, &blinding, &recipient);
        
        // Outputs should be completely different
        assert_ne!(h1, h2, "1-bit value change MUST produce different hash");
    }
    
    #[test]
    fn test_avalanche_blinding_change() {
        let value = 42u128;
        let recipient = [0u8; 32];
        
        let blinding1 = [0u8; 32];
        let mut blinding2 = [0u8; 32];
        blinding2[0] = 1; // 1 bit change
        
        let h1 = poseidon_hash_cpu(value, &blinding1, &recipient);
        let h2 = poseidon_hash_cpu(value, &blinding2, &recipient);
        
        assert_ne!(h1, h2, "1-bit blinding change MUST produce different hash");
    }
    
    #[test]
    fn test_avalanche_recipient_change() {
        let value = 42u128;
        let blinding = [0u8; 32];
        
        let recipient1 = [0u8; 32];
        let mut recipient2 = [0u8; 32];
        recipient2[0] = 1; // 1 bit change
        
        let h1 = poseidon_hash_cpu(value, &blinding, &recipient1);
        let h2 = poseidon_hash_cpu(value, &blinding, &recipient2);
        
        assert_ne!(h1, h2, "1-bit recipient change MUST produce different hash");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // EDGE CASES
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_zero_inputs() {
        let h = poseidon_hash_cpu(0u128, &[0u8; 32], &[0u8; 32]);
        // Should still produce non-trivial output
        assert_ne!(h, BaseElement::ZERO, "All-zero inputs should not produce zero hash");
    }
    
    #[test]
    fn test_max_value() {
        let max_u64 = u64::MAX as u128;
        let h1 = poseidon_hash_cpu(max_u64, &[0u8; 32], &[0u8; 32]);
        let h2 = poseidon_hash_cpu(max_u64 - 1, &[0u8; 32], &[0u8; 32]);
        
        assert_ne!(h1, h2, "Different values MUST produce different hashes");
    }
    
    #[test]
    fn test_large_value() {
        // Test with value > u64::MAX
        let large = (u64::MAX as u128) + 1;
        let h = poseidon_hash_cpu(large, &[0u8; 32], &[0u8; 32]);
        assert_ne!(h, BaseElement::ZERO);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // BINDING TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_commitment_binding() {
        // Same (value, blinding, recipient) should ALWAYS produce same commitment
        let value = 12345u128;
        let blinding = [0xABu8; 32];
        let recipient = [0xCDu8; 32];
        
        let h1 = poseidon_hash_cpu(value, &blinding, &recipient);
        let h2 = poseidon_hash_cpu(value, &blinding, &recipient);
        let h3 = poseidon_hash_cpu(value, &blinding, &recipient);
        
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }
    
    #[test]
    fn test_commitment_hiding() {
        // Different blinding with same value should produce different commitment
        let value = 100u128;
        let recipient = [0u8; 32];
        
        let h1 = poseidon_hash_cpu(value, &[1u8; 32], &recipient);
        let h2 = poseidon_hash_cpu(value, &[2u8; 32], &recipient);
        
        assert_ne!(h1, h2, "Different blinding MUST hide same value");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // STATE TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_poseidon_state_reset() {
        let mut state = PoseidonState::new();
        
        // First permutation
        state.absorb(&[BaseElement::new(42), BaseElement::new(1), BaseElement::new(2)]);
        state.permute();
        let h1 = state.squeeze();
        
        // New state should produce same result
        let mut state2 = PoseidonState::new();
        state2.absorb(&[BaseElement::new(42), BaseElement::new(1), BaseElement::new(2)]);
        state2.permute();
        let h2 = state2.squeeze();
        
        assert_eq!(h1, h2);
    }
}
