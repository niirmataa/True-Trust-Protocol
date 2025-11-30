#![forbid(unsafe_code)]

use winterfell::{
    verify, AcceptableOptions, Air, AirContext, Assertion, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions,
    Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
};

use crate::crypto::poseidon_hash_cpu::{
    POSEIDON_VALUE_LANE, POSEIDON_BLINDING_LANE, POSEIDON_RECIPIENT_LANE,
};
use crate::crypto::poseidon_params::{
    POSEIDON_WIDTH, FULL_ROUNDS, PARTIAL_ROUNDS, TOTAL_ROUNDS, MDS_MATRIX, ROUND_CONSTANTS,
};

/// Public inputs STARK-a:
/// - value_commitment: integer reprezentujący element pola (BaseElement::as_int())
/// - recipient: 32 bajty, STARK używa tylko pierwszych 8,
/// - num_bits: długość przedziału.
#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub value_commitment: u128,
    pub recipient: [u8; 32],
    pub num_bits: u32,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut els = Vec::with_capacity(1 + 4 + 1);

        // commitment jako element pola
        els.push(BaseElement::new(self.value_commitment));

        // recipient jako cztery u64
        for chunk in self.recipient.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            els.push(BaseElement::from(u64::from_le_bytes(buf)));
        }

        els.push(BaseElement::from(self.num_bits as u64));
        els
    }
}

/// Witness: wartość, blinding, recipient.
#[derive(Clone, Debug)]
pub struct Witness {
    pub value: u128,
    pub blinding: [u8; 32],
    pub recipient: [u8; 32],
}

impl Witness {
    pub fn new(value: u128, blinding: [u8; 32], recipient: [u8; 32]) -> Self {
        Self { value, blinding, recipient }
    }
}

/// Kolumny śladu
const COL_SUM: usize = 0;
const COL_BIT: usize = 1;
const COL_POW2: usize = 2;

const COL_POSEIDON_STATE_START: usize = 3;
const COL_POSEIDON_STATE_END: usize = COL_POSEIDON_STATE_START + POSEIDON_WIDTH;

const COL_RC_START: usize = COL_POSEIDON_STATE_END;
const COL_RC_END: usize = COL_RC_START + POSEIDON_WIDTH;

const COL_SEL_POSEIDON: usize = COL_RC_END;
const COL_SEL_FULL: usize = COL_SEL_POSEIDON + 1;
const COL_SEL_LINK: usize = COL_SEL_FULL + 1;

const NUM_COLUMNS: usize = COL_SEL_LINK + 1;

/// AIR dla range + Poseidon
pub struct CompositeRangeAir {
    context: AirContext<BaseElement>,
    value_commitment: BaseElement,
    recipient_elem: BaseElement,
    num_bits: usize,
}

impl Air for CompositeRangeAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), NUM_COLUMNS);

        let num_bits = pub_inputs.num_bits as usize;
        let t = POSEIDON_WIDTH;

        let mut degrees = Vec::new();

        // range
        degrees.push(TransitionConstraintDegree::new(2)); // sum
        degrees.push(TransitionConstraintDegree::new(1)); // pow2
        degrees.push(TransitionConstraintDegree::new(2)); // bit

        // poseidon step: x^5 + selektory + MDS → stopień 7
        for _ in 0..t {
            degrees.push(TransitionConstraintDegree::new(7));
        }
        // poseidon const / no-op
        for _ in 0..t {
            degrees.push(TransitionConstraintDegree::new(2));
        }

        degrees.push(TransitionConstraintDegree::new(2)); // s_poseidon bool
        degrees.push(TransitionConstraintDegree::new(2)); // s_full bool
        degrees.push(TransitionConstraintDegree::new(2)); // s_link bool
        degrees.push(TransitionConstraintDegree::new(2)); // s_full <= s_poseidon
        degrees.push(TransitionConstraintDegree::new(2)); // link

        let num_assertions = 5;

        let value_commitment = BaseElement::new(pub_inputs.value_commitment);

        let mut rbytes = [0u8; 8];
        rbytes.copy_from_slice(&pub_inputs.recipient[..8]);
        let recipient_elem = BaseElement::from(u64::from_le_bytes(rbytes));

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            value_commitment,
            recipient_elem,
            num_bits,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // RANGE
        let sum = current[COL_SUM];
        let bit = current[COL_BIT];
        let pow2 = current[COL_POW2];

        let next_sum = next[COL_SUM];
        let next_pow2 = next[COL_POW2];

        result[0] = next_sum - (sum + bit * pow2);
        result[1] = next_pow2 - (pow2 + pow2);
        result[2] = bit * (bit - E::ONE);

        // POSEIDON
        let t = POSEIDON_WIDTH;
        let c_poseidon_step_start = 3;
        let c_poseidon_const_start = c_poseidon_step_start + t;
        let c_sel_poseidon = c_poseidon_const_start + t;
        let c_sel_full = c_sel_poseidon + 1;
        let c_sel_link = c_sel_full + 1;
        let c_full_le_poseidon = c_sel_link + 1;
        let c_link = c_full_le_poseidon + 1;

        let s_poseidon = current[COL_SEL_POSEIDON];
        let s_full = current[COL_SEL_FULL];
        let s_link = current[COL_SEL_LINK];
        let s_partial = s_poseidon - s_full;

        result[c_sel_poseidon] = s_poseidon * (s_poseidon - E::ONE);
        result[c_sel_full] = s_full * (s_full - E::ONE);
        result[c_sel_link] = s_link * (s_link - E::ONE);
        result[c_full_le_poseidon] = s_full * (E::ONE - s_poseidon);

        let mut state = [E::ZERO; POSEIDON_WIDTH];
        let mut next_state = [E::ZERO; POSEIDON_WIDTH];
        let mut rc = [E::ZERO; POSEIDON_WIDTH];

        for i in 0..t {
            state[i] = current[COL_POSEIDON_STATE_START + i];
            next_state[i] = next[COL_POSEIDON_STATE_START + i];
            rc[i] = current[COL_RC_START + i];
        }

        let mut x = [E::ZERO; POSEIDON_WIDTH];
        for i in 0..t {
            x[i] = state[i] + rc[i];
        }

        let mut sbox = [E::ZERO; POSEIDON_WIDTH];
        for i in 0..t {
            let xi = x[i];
            let xi2 = xi * xi;
            let xi4 = xi2 * xi2;
            sbox[i] = xi * xi4;
        }

        let mut y = [E::ZERO; POSEIDON_WIDTH];
        for i in 0..t {
            let partial_val = if i == 0 { sbox[i] } else { x[i] };
            y[i] = s_full * sbox[i] + s_partial * partial_val;
        }

        let mut expected_next = [E::ZERO; POSEIDON_WIDTH];
        for i in 0..t {
            let mut acc = E::ZERO;
            for j in 0..t {
                let m = E::from(MDS_MATRIX[i][j]);
                acc += y[j] * m;
            }
            expected_next[i] = acc;
        }

        for i in 0..t {
            result[c_poseidon_step_start + i] =
                s_poseidon * (next_state[i] - expected_next[i]);
            result[c_poseidon_const_start + i] =
                (E::ONE - s_poseidon) * (next_state[i] - state[i]);
        }

        let state_value_lane =
            current[COL_POSEIDON_STATE_START + POSEIDON_VALUE_LANE];
        result[c_link] = s_link * (state_value_lane - sum);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut res = Vec::new();

        res.push(Assertion::single(COL_SUM, 0, BaseElement::ZERO));
        res.push(Assertion::single(COL_POW2, 0, BaseElement::ONE));
        res.push(Assertion::single(COL_BIT, self.num_bits, BaseElement::ZERO));

        let poseidon_start_row = self.num_bits;
        res.push(Assertion::single(
            COL_POSEIDON_STATE_START + POSEIDON_RECIPIENT_LANE,
            poseidon_start_row,
            self.recipient_elem,
        ));

        let last_row = self.context.trace_len() - 1;
        res.push(Assertion::single(
            COL_POSEIDON_STATE_START + POSEIDON_VALUE_LANE,
            last_row,
            self.value_commitment,
        ));

        res
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

/// Prover
pub struct CompositeProver {
    options: ProofOptions,
    num_bits: usize,
}

impl CompositeProver {
    pub fn new(num_bits: usize, options: ProofOptions) -> Self {
        Self { options, num_bits }
    }

    pub fn build_trace(&self, witness: &Witness) -> TraceTable<BaseElement> {
        let range_rows = self.num_bits + 1;
        let base_rows = range_rows + TOTAL_ROUNDS + 1;
        let trace_rows = base_rows.next_power_of_two();

        let mut trace = vec![vec![BaseElement::ZERO; trace_rows]; NUM_COLUMNS];

        // RANGE
        trace[COL_SUM][0] = BaseElement::ZERO;
        trace[COL_POW2][0] = BaseElement::ONE;

        for i in 0..(trace_rows - 1) {
            let bit_u64 = if i < self.num_bits {
                ((witness.value >> i) & 1u128) as u64
            } else {
                0u64
            };
            let bit = BaseElement::from(bit_u64);
            trace[COL_BIT][i] = bit;

            let sum = trace[COL_SUM][i];
            let pow2 = trace[COL_POW2][i];

            trace[COL_SUM][i + 1] = sum + bit * pow2;
            trace[COL_POW2][i + 1] = pow2 + pow2;
        }

        let poseidon_start = self.num_bits;

        let value_fe = BaseElement::new(witness.value);

        let mut blind_bytes = [0u8; 8];
        blind_bytes.copy_from_slice(&witness.blinding[..8]);
        let blind_fe = BaseElement::from(u64::from_le_bytes(blind_bytes));

        let mut recip_bytes = [0u8; 8];
        recip_bytes.copy_from_slice(&witness.recipient[..8]);
        let recip_fe = BaseElement::from(u64::from_le_bytes(recip_bytes));

        let mut initial_state = [BaseElement::ZERO; POSEIDON_WIDTH];
        initial_state[POSEIDON_VALUE_LANE] = value_fe;
        initial_state[POSEIDON_BLINDING_LANE] = blind_fe;
        initial_state[POSEIDON_RECIPIENT_LANE] = recip_fe;

        // Stan Poseidona stały, dopóki s_poseidon = 0
        for i in 0..POSEIDON_WIDTH {
            trace[COL_POSEIDON_STATE_START + i][0] = initial_state[i];
        }
        for row in 1..=poseidon_start {
            for i in 0..POSEIDON_WIDTH {
                trace[COL_POSEIDON_STATE_START + i][row] =
                    trace[COL_POSEIDON_STATE_START + i][row - 1];
            }
        }

        // link w wierszu startu Poseidona: value lane == SUM
        trace[COL_SEL_LINK][poseidon_start] = BaseElement::ONE;

        // Poseidon rounds
        for r in 0..TOTAL_ROUNDS {
            let row = poseidon_start + r;
            if row + 1 >= trace_rows {
                panic!("internal error: poseidon row out of bounds");
            }

            trace[COL_SEL_POSEIDON][row] = BaseElement::ONE;

            let is_full =
                r < FULL_ROUNDS / 2 || r >= (FULL_ROUNDS / 2 + PARTIAL_ROUNDS);
            trace[COL_SEL_FULL][row] =
                if is_full { BaseElement::ONE } else { BaseElement::ZERO };

            for i in 0..POSEIDON_WIDTH {
                trace[COL_RC_START + i][row] = ROUND_CONSTANTS[r][i];
            }

            let mut cur_state = [BaseElement::ZERO; POSEIDON_WIDTH];
            for i in 0..POSEIDON_WIDTH {
                cur_state[i] = trace[COL_POSEIDON_STATE_START + i][row];
            }

            let mut x = [BaseElement::ZERO; POSEIDON_WIDTH];
            for i in 0..POSEIDON_WIDTH {
                x[i] = cur_state[i] + trace[COL_RC_START + i][row];
            }

            let mut sbox = [BaseElement::ZERO; POSEIDON_WIDTH];
            for i in 0..POSEIDON_WIDTH {
                let xi = x[i];
                let xi2 = xi * xi;
                let xi4 = xi2 * xi2;
                sbox[i] = xi * xi4;
            }

            let mut y = [BaseElement::ZERO; POSEIDON_WIDTH];
            if is_full {
                y.copy_from_slice(&sbox);
            } else {
                y[0] = sbox[0];
                for i in 1..POSEIDON_WIDTH {
                    y[i] = x[i];
                }
            }

            let mut next_state = [BaseElement::ZERO; POSEIDON_WIDTH];
            for i in 0..POSEIDON_WIDTH {
                let mut acc = BaseElement::ZERO;
                for j in 0..POSEIDON_WIDTH {
                    acc += y[j] * MDS_MATRIX[i][j];
                }
                next_state[i] = acc;
            }

            let row_next = row + 1;
            for i in 0..POSEIDON_WIDTH {
                trace[COL_POSEIDON_STATE_START + i][row_next] = next_state[i];
            }
        }

        let last_poseidon_row = poseidon_start + TOTAL_ROUNDS;
        assert!(last_poseidon_row < trace_rows);

        trace[COL_SEL_POSEIDON][last_poseidon_row] = BaseElement::ZERO;
        trace[COL_SEL_FULL][last_poseidon_row] = BaseElement::ZERO;

        // Padding
        for row in (last_poseidon_row + 1)..trace_rows {
            for i in 0..POSEIDON_WIDTH {
                trace[COL_POSEIDON_STATE_START + i][row] =
                    trace[COL_POSEIDON_STATE_START + i][row - 1];
                trace[COL_RC_START + i][row] = BaseElement::ZERO;
            }
            trace[COL_SEL_POSEIDON][row] = BaseElement::ZERO;
            trace[COL_SEL_FULL][row] = BaseElement::ZERO;
            trace[COL_SEL_LINK][row] = BaseElement::ZERO;
        }

        TraceTable::init(trace)
    }
}

impl Prover for CompositeProver {
    type BaseField = BaseElement;
    type Air = CompositeRangeAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last = trace.length() - 1;

        let commitment_elem =
            trace.get(COL_POSEIDON_STATE_START + POSEIDON_VALUE_LANE, last);
        let commitment_int = commitment_elem.as_int(); // u128

        let recip_elem =
            trace.get(COL_POSEIDON_STATE_START + POSEIDON_RECIPIENT_LANE, self.num_bits);
        let recip_u64 = recip_elem.as_int() as u64;
        let recip_bytes = recip_u64.to_le_bytes();

        let mut recipient = [0u8; 32];
        recipient[..8].copy_from_slice(&recip_bytes);

        PublicInputs {
            value_commitment: commitment_int,
            recipient,
            num_bits: self.num_bits as u32,
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<winterfell::AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// High-level API

pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub fn prove_range_with_poseidon(
    witness: Witness,
    num_bits: usize,
    options: ProofOptions,
) -> (Proof, PublicInputs) {
    let prover = CompositeProver::new(num_bits, options);
    let trace = prover.build_trace(&witness);
    let pub_inputs = prover.get_pub_inputs(&trace);
    let proof = prover.prove(trace).expect("proof generation failed");
    (proof, pub_inputs)
}

pub fn verify_range_with_poseidon(proof: Proof, pub_inputs: PublicInputs) -> bool {
    let acceptable = AcceptableOptions::MinConjecturedSecurity(95);
    verify::<
        CompositeRangeAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &acceptable)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::poseidon_hash_cpu::poseidon_hash_cpu;

    #[test]
    fn test_poseidon_cpu_vs_trace() {
        let witness = Witness::new(42u128, [7u8; 32], [3u8; 32]);
        let opts = default_proof_options();
        let prover = CompositeProver::new(64, opts);
        let trace = prover.build_trace(&witness);

        let cpu_h = poseidon_hash_cpu(
            witness.value,
            &witness.blinding,
            &witness.recipient,
        );

        let last = trace.length() - 1;
        let stark_h =
            trace.get(super::COL_POSEIDON_STATE_START + POSEIDON_VALUE_LANE, last);

        assert_eq!(cpu_h, stark_h);
    }

    #[tokio::test]
    async fn test_composite_proof_roundtrip() {
        let witness = Witness::new(42u128, [9u8; 32], [5u8; 32]);
        let opts = default_proof_options();

        let (proof, pub_inputs) = prove_range_with_poseidon(
            witness.clone(),
            64,
            opts,
        );

        assert!(verify_range_with_poseidon(proof, pub_inputs));
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // TAMPERED PROOF TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[tokio::test]
    async fn test_tampered_commitment_rejects() {
        let witness = Witness::new(100u128, [1u8; 32], [2u8; 32]);
        let opts = default_proof_options();
        
        let (proof, mut pub_inputs) = prove_range_with_poseidon(witness, 64, opts);
        
        // Attacker tries to change the commitment
        pub_inputs.value_commitment = pub_inputs.value_commitment.wrapping_add(1);
        
        assert!(!verify_range_with_poseidon(proof, pub_inputs), 
            "SECURITY: Tampered commitment MUST be rejected");
    }
    
    #[tokio::test]
    async fn test_tampered_recipient_rejects() {
        let witness = Witness::new(100u128, [1u8; 32], [2u8; 32]);
        let opts = default_proof_options();
        
        let (proof, mut pub_inputs) = prove_range_with_poseidon(witness, 64, opts);
        
        // Attacker tries to redirect to different recipient
        pub_inputs.recipient[0] ^= 0xFF;
        
        assert!(!verify_range_with_poseidon(proof, pub_inputs), 
            "SECURITY: Tampered recipient MUST be rejected");
    }
    
    #[tokio::test]
    async fn test_tampered_num_bits_rejects() {
        let witness = Witness::new(100u128, [1u8; 32], [2u8; 32]);
        let opts = default_proof_options();
        
        let (proof, mut pub_inputs) = prove_range_with_poseidon(witness, 64, opts);
        
        // Attacker tries to claim smaller range
        pub_inputs.num_bits = 32;
        
        assert!(!verify_range_with_poseidon(proof, pub_inputs), 
            "SECURITY: Tampered num_bits MUST be rejected");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // WITNESS INTEGRITY TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_different_witnesses_different_commitments() {
        let w1 = Witness::new(42u128, [1u8; 32], [3u8; 32]);
        let w2 = Witness::new(43u128, [1u8; 32], [3u8; 32]); // Different value
        let w3 = Witness::new(42u128, [2u8; 32], [3u8; 32]); // Different blinding
        
        let opts = default_proof_options();
        let prover = CompositeProver::new(64, opts.clone());
        
        let trace1 = prover.build_trace(&w1);
        let trace2 = prover.build_trace(&w2);
        let trace3 = prover.build_trace(&w3);
        
        let pub1 = prover.get_pub_inputs(&trace1);
        let pub2 = prover.get_pub_inputs(&trace2);
        let pub3 = prover.get_pub_inputs(&trace3);
        
        assert_ne!(pub1.value_commitment, pub2.value_commitment, 
            "Different values MUST produce different commitments");
        assert_ne!(pub1.value_commitment, pub3.value_commitment, 
            "Different blinding MUST produce different commitments");
    }
    
    #[test]
    fn test_commitment_determinism() {
        let witness = Witness::new(12345u128, [0xABu8; 32], [0xCDu8; 32]);
        let opts = default_proof_options();
        let prover = CompositeProver::new(64, opts);
        
        let trace1 = prover.build_trace(&witness);
        let trace2 = prover.build_trace(&witness);
        
        let pub1 = prover.get_pub_inputs(&trace1);
        let pub2 = prover.get_pub_inputs(&trace2);
        
        assert_eq!(pub1.value_commitment, pub2.value_commitment, 
            "Same witness MUST produce same commitment");
        assert_eq!(pub1.recipient, pub2.recipient);
        assert_eq!(pub1.num_bits, pub2.num_bits);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // RANGE CONSTRAINT TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    #[tokio::test]
    async fn test_value_within_range() {
        // Value 255 fits in 8 bits
        let witness = Witness::new(255u128, [1u8; 32], [2u8; 32]);
        let opts = default_proof_options();
        
        let (proof, pub_inputs) = prove_range_with_poseidon(witness, 64, opts);
        assert!(verify_range_with_poseidon(proof, pub_inputs));
    }
    
    #[tokio::test]
    async fn test_small_nonzero_value() {
        // Small nonzero value should work
        let witness = Witness::new(1u128, [1u8; 32], [2u8; 32]);
        let opts = default_proof_options();
        
        let (proof, pub_inputs) = prove_range_with_poseidon(witness, 64, opts);
        assert!(verify_range_with_poseidon(proof, pub_inputs));
    }
    
    #[tokio::test]
    async fn test_max_64bit_value() {
        let max_val = (1u128 << 63) - 1; // Large but fits
        let witness = Witness::new(max_val, [1u8; 32], [2u8; 32]);
        let opts = default_proof_options();
        
        let (proof, pub_inputs) = prove_range_with_poseidon(witness, 64, opts);
        assert!(verify_range_with_poseidon(proof, pub_inputs));
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // PUBLIC INPUT SERIALIZATION
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_public_inputs_to_elements() {
        let pub_inputs = PublicInputs {
            value_commitment: 12345u128,
            recipient: [0xAB; 32],
            num_bits: 64,
        };
        
        let elements = pub_inputs.to_elements();
        
        // Should have: 1 commitment + 4 recipient chunks + 1 num_bits = 6 elements
        assert_eq!(elements.len(), 6);
        assert_eq!(elements[0], BaseElement::new(12345u128));
        assert_eq!(elements[5], BaseElement::from(64u64));
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // PROOF REPLAY PREVENTION
    // ═══════════════════════════════════════════════════════════════════════
    
    #[tokio::test]
    async fn test_proof_cannot_be_reused_with_different_inputs() {
        let witness1 = Witness::new(100u128, [1u8; 32], [2u8; 32]);
        let witness2 = Witness::new(200u128, [3u8; 32], [4u8; 32]);
        let opts = default_proof_options();
        
        let (proof1, _pub1) = prove_range_with_poseidon(witness1, 64, opts.clone());
        let (_proof2, pub2) = prove_range_with_poseidon(witness2, 64, opts);
        
        // Try to use proof1 with pub_inputs2
        assert!(!verify_range_with_poseidon(proof1, pub2), 
            "SECURITY: Proof MUST NOT be reusable with different public inputs");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // EDGE CASES
    // ═══════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_witness_new_constructor() {
        let w = Witness::new(42u128, [1u8; 32], [2u8; 32]);
        assert_eq!(w.value, 42);
        assert_eq!(w.blinding, [1u8; 32]);
        assert_eq!(w.recipient, [2u8; 32]);
    }
    
    #[test]
    fn test_trace_table_dimensions() {
        let witness = Witness::new(42u128, [1u8; 32], [2u8; 32]);
        let opts = default_proof_options();
        let prover = CompositeProver::new(64, opts);
        let trace = prover.build_trace(&witness);
        
        assert_eq!(trace.width(), NUM_COLUMNS);
        // Trace length should be power of 2
        assert!(trace.length().is_power_of_two());
    }
}
