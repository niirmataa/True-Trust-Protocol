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
    value: u64,
    blinding: &[u8; 32],
    recipient: &[u8; 32],
) -> BaseElement {
    let mut st = PoseidonState::new();

    let v = BaseElement::from(value);

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
        let value = 42u64;
        let blinding = [1u8; 32];
        let recipient = [2u8; 32];

        let h1 = poseidon_hash_cpu(value, &blinding, &recipient);
        let h2 = poseidon_hash_cpu(value, &blinding, &recipient);
        assert_eq!(h1, h2);

        let h3 = poseidon_hash_cpu(value + 1, &blinding, &recipient);
        assert_ne!(h1, h3);
    }
}
