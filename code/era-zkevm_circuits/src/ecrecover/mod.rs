use super::*;
use crate::base_structures::log_query::*;
use crate::base_structures::memory_query::*;
use crate::base_structures::precompile_input_outputs::PrecompileFunctionOutputData;
use crate::demux_log_queue::StorageLogQueue;
use crate::ethereum_types::U256;
use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use crate::fsm_input_output::*;
use arrayvec::ArrayVec;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::crypto_bigint::{Zero, U1024};
use boojum::cs::gates::ConstantAllocatableCS;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::curves::sw_projective::SWProjectivePoint;
use boojum::gadgets::keccak256::keccak256;
use boojum::gadgets::non_native_field::implementations::*;
use boojum::gadgets::num::Num;
use boojum::gadgets::queue::CircuitQueueWitness;
use boojum::gadgets::queue::QueueState;
use boojum::gadgets::traits::allocatable::{CSAllocatableExt, CSPlaceholder};
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::u16::UInt16;
use boojum::gadgets::u160::UInt160;
use boojum::gadgets::u256::UInt256;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use cs_derive::*;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use zkevm_opcode_defs::system_params::PRECOMPILE_AUX_BYTE;

pub mod input;
pub use self::input::*;

mod secp256k1;

pub const MEMORY_QUERIES_PER_CALL: usize = 4;

#[derive(Derivative, CSSelectable)]
#[derivative(Clone, Debug)]
pub struct EcrecoverPrecompileCallParams<F: SmallField> {
    pub input_page: UInt32<F>,
    pub input_offset: UInt32<F>,
    pub output_page: UInt32<F>,
    pub output_offset: UInt32<F>,
}

impl<F: SmallField> EcrecoverPrecompileCallParams<F> {
    // pub fn empty() -> Self {
    //     Self {
    //         input_page: UInt32::<E>::zero(),
    //         input_offset: UInt32::<E>::zero(),
    //         output_page: UInt32::<E>::zero(),
    //         output_offset: UInt32::<E>::zero(),
    //     }
    // }

    pub fn from_encoding<CS: ConstraintSystem<F>>(_cs: &mut CS, encoding: UInt256<F>) -> Self {
        let input_offset = encoding.inner[0];
        let output_offset = encoding.inner[2];
        let input_page = encoding.inner[4];
        let output_page = encoding.inner[5];

        let new = Self {
            input_page,
            input_offset,
            output_page,
            output_offset,
        };

        new
    }
}

// characteristics of the base field for secp curve
use self::secp256k1::fq::Fq as Secp256Fq;
// order of group of points for secp curve
use self::secp256k1::fr::Fr as Secp256Fr;
// some affine point
use self::secp256k1::PointAffine as Secp256Affine;

const NUM_WORDS: usize = 17;
const SECP_B_COEF: u64 = 7;
const EXCEPTION_FLAGS_ARR_LEN: usize = 8;
const NUM_MEMORY_READS_PER_CYCLE: usize = 4;
const X_POWERS_ARR_LEN: usize = 256;
const VALID_Y_IN_EXTERNAL_FIELD: u64 = 4;
const VALID_X_CUBED_IN_EXTERNAL_FIELD: u64 = 9;

type Secp256BaseNNFieldParams = NonNativeFieldOverU16Params<Secp256Fq, 17>;
type Secp256ScalarNNFieldParams = NonNativeFieldOverU16Params<Secp256Fr, 17>;

type Secp256BaseNNField<F> = NonNativeFieldOverU16<F, Secp256Fq, 17>;
type Secp256ScalarNNField<F> = NonNativeFieldOverU16<F, Secp256Fr, 17>;

pub fn secp256k1_base_field_params() -> Secp256BaseNNFieldParams {
    NonNativeFieldOverU16Params::create()
}

pub fn secp256k1_scalar_field_params() -> Secp256ScalarNNFieldParams {
    NonNativeFieldOverU16Params::create()
}

// assume that constructed field element is not zero
// if this is not satisfied - set the result to be F::one
fn convert_uint256_to_field_element_masked<
    F: SmallField,
    CS: ConstraintSystem<F>,
    P: boojum::pairing::ff::PrimeField,
    const N: usize,
>(
    cs: &mut CS,
    elem: &UInt256<F>,
    params: &Arc<NonNativeFieldOverU16Params<P, N>>,
) -> (NonNativeFieldOverU16<F, P, N>, Boolean<F>)
where
    [(); N + 1]:,
{
    let is_zero = elem.is_zero(cs);
    let one_nn = NonNativeFieldOverU16::<F, P, N>::allocated_constant(cs, P::one(), params);
    // we still have to decompose it into u16 words
    let zero_var = cs.allocate_constant(F::ZERO);
    let mut limbs = [zero_var; N];
    assert!(N >= 16);
    for (dst, src) in limbs.array_chunks_mut::<2>().zip(elem.inner.iter()) {
        let [b0, b1, b2, b3] = src.to_le_bytes(cs);
        let low = UInt16::from_le_bytes(cs, [b0, b1]);
        let high = UInt16::from_le_bytes(cs, [b2, b3]);

        *dst = [low.get_variable(), high.get_variable()];
    }

    let mut max_value = U1024::from_word(1u64);
    max_value = max_value.shl_vartime(256);
    max_value = max_value.saturating_sub(&U1024::from_word(1u64));

    let (overflows, rem) = max_value.div_rem(&params.modulus_u1024);

    let mut max_moduluses = overflows.as_words()[0] as u32;
    if rem.is_zero().unwrap_u8() != 1 {
        max_moduluses += 1;
    }

    let element = NonNativeFieldOverU16 {
        limbs: limbs,
        non_zero_limbs: 16,
        tracker: OverflowTracker { max_moduluses },
        form: RepresentationForm::Normalized,
        params: params.clone(),
        _marker: std::marker::PhantomData,
    };

    let selected = Selectable::conditionally_select(cs, is_zero, &one_nn, &element);

    (selected, is_zero)
}

fn convert_uint256_to_field_element<
    F: SmallField,
    CS: ConstraintSystem<F>,
    P: boojum::pairing::ff::PrimeField,
    const N: usize,
>(
    cs: &mut CS,
    elem: &UInt256<F>,
    params: &Arc<NonNativeFieldOverU16Params<P, N>>,
) -> NonNativeFieldOverU16<F, P, N> {
    // we still have to decompose it into u16 words
    let zero_var = cs.allocate_constant(F::ZERO);
    let mut limbs = [zero_var; N];
    assert!(N >= 16);
    for (dst, src) in limbs.array_chunks_mut::<2>().zip(elem.inner.iter()) {
        let [b0, b1, b2, b3] = src.to_le_bytes(cs);
        let low = UInt16::from_le_bytes(cs, [b0, b1]);
        let high = UInt16::from_le_bytes(cs, [b2, b3]);

        *dst = [low.get_variable(), high.get_variable()];
    }

    let mut max_value = U1024::from_word(1u64);
    max_value = max_value.shl_vartime(256);
    max_value = max_value.saturating_sub(&U1024::from_word(1u64));

    let (overflows, rem) = max_value.div_rem(&params.modulus_u1024);
    let mut max_moduluses = overflows.as_words()[0] as u32;
    if rem.is_zero().unwrap_u8() != 1 {
        max_moduluses += 1;
    }

    let element = NonNativeFieldOverU16 {
        limbs: limbs,
        non_zero_limbs: 16,
        tracker: OverflowTracker { max_moduluses },
        form: RepresentationForm::Normalized,
        params: params.clone(),
        _marker: std::marker::PhantomData,
    };

    element
}

fn ecrecover_precompile_inner_routine<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    recid: &UInt8<F>,
    r: &UInt256<F>,
    s: &UInt256<F>,
    message_hash: &UInt256<F>,
    valid_x_in_external_field: Secp256BaseNNField<F>,
    valid_y_in_external_field: Secp256BaseNNField<F>,
    valid_t_in_external_field: Secp256BaseNNField<F>,
    base_field_params: &Arc<Secp256BaseNNFieldParams>,
    scalar_field_params: &Arc<Secp256ScalarNNFieldParams>,
) -> (Boolean<F>, UInt256<F>) {
    use boojum::pairing::ff::Field;
    let curve_b = Secp256Affine::b_coeff();

    let mut minus_one = Secp256Fq::one();
    minus_one.negate();

    let mut curve_b_nn =
        Secp256BaseNNField::<F>::allocated_constant(cs, curve_b, &base_field_params);
    let mut minus_one_nn =
        Secp256BaseNNField::<F>::allocated_constant(cs, minus_one, &base_field_params);

    let secp_n_u256 = U256([
        scalar_field_params.modulus_u1024.as_ref().as_words()[0],
        scalar_field_params.modulus_u1024.as_ref().as_words()[1],
        scalar_field_params.modulus_u1024.as_ref().as_words()[2],
        scalar_field_params.modulus_u1024.as_ref().as_words()[3],
    ]);
    let secp_n_u256 = UInt256::allocated_constant(cs, secp_n_u256);

    let secp_p_u256 = U256([
        base_field_params.modulus_u1024.as_ref().as_words()[0],
        base_field_params.modulus_u1024.as_ref().as_words()[1],
        base_field_params.modulus_u1024.as_ref().as_words()[2],
        base_field_params.modulus_u1024.as_ref().as_words()[3],
    ]);
    let secp_p_u256 = UInt256::allocated_constant(cs, secp_p_u256);

    let mut exception_flags = ArrayVec::<_, EXCEPTION_FLAGS_ARR_LEN>::new();

    // recid = (x_overflow ? 2 : 0) | (secp256k1_fe_is_odd(&r.y) ? 1 : 0)
    // The point X = (x, y) we are going to recover is not known at the start, but it is strongly related to r.
    // This is because x = r + kn for some integer k, where x is an element of the field F_q . In other words, x < q.
    // (here n is the order of group of points on elleptic curve)
    // For secp256k1 curve values of q and n are relatively close, that is,
    // the probability of a random element of Fq being greater than n is about 1/{2^128}.
    // This in turn means that the overwhelming majority of r determine a unique x, however some of them determine
    // two: x = r and x = r + n. If x_overflow flag is set than x = r + n

    let [y_is_odd, x_overflow, ..] =
        Num::<F>::from_variable(recid.get_variable()).spread_into_bits::<_, 8>(cs);

    let (r_plus_n, of) = r.overflowing_add(cs, &secp_n_u256);
    let mut x_as_u256 = UInt256::conditionally_select(cs, x_overflow, &r_plus_n, &r);
    let error = Boolean::multi_and(cs, &[x_overflow, of]);
    exception_flags.push(error);

    // we handle x separately as it is the only element of base field of a curve (not a scalar field element!)
    // check that x < q - order of base point on Secp256 curve
    // if it is not actually the case - mask x to be zero
    let (_res, is_in_range) = x_as_u256.overflowing_sub(cs, &secp_p_u256);
    x_as_u256 = x_as_u256.mask(cs, is_in_range);
    let x_is_not_in_range = is_in_range.negated(cs);
    exception_flags.push(x_is_not_in_range);

    let mut x_fe = convert_uint256_to_field_element(cs, &x_as_u256, &base_field_params);

    let (mut r_fe, r_is_zero) =
        convert_uint256_to_field_element_masked(cs, &r, &scalar_field_params);
    exception_flags.push(r_is_zero);
    let (mut s_fe, s_is_zero) =
        convert_uint256_to_field_element_masked(cs, &s, &scalar_field_params);
    exception_flags.push(s_is_zero);

    // NB: although it is not strictly an exception we also assume that hash is never zero as field element
    let (mut message_hash_fe, message_hash_is_zero) =
        convert_uint256_to_field_element_masked(cs, &message_hash, &scalar_field_params);
    exception_flags.push(message_hash_is_zero);

    // curve equation is y^2 = x^3 + b
    // we compute t = r^3 + b and check if t is a quadratic residue or not.
    // we do this by computing Legendre symbol (t, p) = t^[(p-1)/2] (mod p)
    //           p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    // n = (p-1)/2 = 2^255 - 2^31 - 2^8 - 2^7 - 2^6 - 2^5 - 2^3 - 1
    // we have to compute t^b = t^{2^255} / ( t^{2^31} * t^{2^8} * t^{2^7} * t^{2^6} * t^{2^5} * t^{2^3} * t)
    // if t is not a quadratic residue we return error and replace x by another value that will make
    // t = x^3 + b a quadratic residue

    let mut t = x_fe.square(cs);
    t = t.mul(cs, &mut x_fe);
    t = t.add(cs, &mut curve_b_nn);

    let t_is_zero = t.is_zero(cs);
    exception_flags.push(t_is_zero);

    // if t is zero then just mask
    let t = Selectable::conditionally_select(cs, t_is_zero, &valid_t_in_external_field, &t);

    // array of powers of t of the form t^{2^i} starting from i = 0 to 255
    let mut t_powers = Vec::with_capacity(X_POWERS_ARR_LEN);
    t_powers.push(t);

    for _ in 1..X_POWERS_ARR_LEN {
        let prev = t_powers.last_mut().unwrap();
        let next = prev.square(cs);
        t_powers.push(next);
    }

    let mut acc = t_powers[0].clone();
    for idx in [3, 5, 6, 7, 8, 31].into_iter() {
        let other = &mut t_powers[idx];
        acc = acc.mul(cs, other);
    }
    let mut legendre_symbol = t_powers[255].div_unchecked(cs, &mut acc);

    // we can also reuse the same values to compute square root in case of p = 3 mod 4
    //           p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    // n = (p+1)/4 = 2^254 - 2^30 - 2^7 - 2^6 - 2^5 - 2^4 - 2^2

    let mut acc_2 = t_powers[2].clone();
    for idx in [4, 5, 6, 7, 30].into_iter() {
        let other = &mut t_powers[idx];
        acc_2 = acc_2.mul(cs, other);
    }

    let mut may_be_recovered_y = t_powers[254].div_unchecked(cs, &mut acc_2);
    may_be_recovered_y.normalize(cs);
    let mut may_be_recovered_y_negated = may_be_recovered_y.negated(cs);
    may_be_recovered_y_negated.normalize(cs);

    let [lowest_bit, ..] =
        Num::<F>::from_variable(may_be_recovered_y.limbs[0]).spread_into_bits::<_, 16>(cs);

    // if lowest bit != parity bit, then we need conditionally select
    let should_swap = lowest_bit.xor(cs, y_is_odd);
    let may_be_recovered_y = Selectable::conditionally_select(
        cs,
        should_swap,
        &may_be_recovered_y_negated,
        &may_be_recovered_y,
    );

    let t_is_nonresidue =
        Secp256BaseNNField::<F>::equals(cs, &mut legendre_symbol, &mut minus_one_nn);
    exception_flags.push(t_is_nonresidue);
    // unfortunately, if t is found to be a quadratic nonresidue, we can't simply let x to be zero,
    // because then t_new = 7 is again a quadratic nonresidue. So, in this case we let x to be 9, then
    // t = 16 is a quadratic residue
    let x =
        Selectable::conditionally_select(cs, t_is_nonresidue, &valid_x_in_external_field, &x_fe);
    let y = Selectable::conditionally_select(
        cs,
        t_is_nonresidue,
        &valid_y_in_external_field,
        &may_be_recovered_y,
    );

    // we recovered (x, y) using curve equation, so it's on curve (or was masked)
    let mut r_fe_inversed = r_fe.inverse_unchecked(cs);
    let mut s_by_r_inv = s_fe.mul(cs, &mut r_fe_inversed);
    let mut message_hash_by_r_inv = message_hash_fe.mul(cs, &mut r_fe_inversed);

    s_by_r_inv.normalize(cs);
    message_hash_by_r_inv.normalize(cs);

    let mut gen_negated = Secp256Affine::one();
    gen_negated.negate();
    let (gen_negated_x, gen_negated_y) = gen_negated.into_xy_unchecked();
    let gen_negated_x =
        Secp256BaseNNField::allocated_constant(cs, gen_negated_x, base_field_params);
    let gen_negated_y =
        Secp256BaseNNField::allocated_constant(cs, gen_negated_y, base_field_params);

    let s_by_r_inv_normalized_lsb_bits: Vec<_> = s_by_r_inv
        .limbs
        .iter()
        .map(|el| Num::<F>::from_variable(*el).spread_into_bits::<_, 16>(cs))
        .flatten()
        .collect();
    let message_hash_by_r_inv_lsb_bits: Vec<_> = message_hash_by_r_inv
        .limbs
        .iter()
        .map(|el| Num::<F>::from_variable(*el).spread_into_bits::<_, 16>(cs))
        .flatten()
        .collect();

    // now we are going to compute the public key Q = (x, y) determined by the formula:
    // Q = (s * X - hash * G) / r which is equivalent to r * Q = s * X - hash * G
    // current implementation of point by scalar multiplications doesn't support multiplication by zero
    // so we check that all s, r, hash are not zero (as FieldElements):
    // if any of them is zero we reject the signature and in circuit itself replace all zero variables by ones

    let mut recovered_point = (x, y);
    let mut generator_point = (gen_negated_x, gen_negated_y);
    // now we do multiexponentiation
    let mut q_acc =
        SWProjectivePoint::<F, Secp256Affine, Secp256BaseNNField<F>>::zero(cs, base_field_params);

    // we should start from MSB, double the accumulator, then conditionally add
    for (cycle, (x_bit, hash_bit)) in s_by_r_inv_normalized_lsb_bits
        .into_iter()
        .rev()
        .zip(message_hash_by_r_inv_lsb_bits.into_iter().rev())
        .enumerate()
    {
        if cycle != 0 {
            q_acc = q_acc.double(cs);
        }
        let q_plus_x = q_acc.add_mixed(cs, &mut recovered_point);
        let mut q_0: SWProjectivePoint<F, Secp256Affine, NonNativeFieldOverU16<F, Secp256Fq, 17>> =
            Selectable::conditionally_select(cs, x_bit, &q_plus_x, &q_acc);

        let q_plux_gen = q_0.add_mixed(cs, &mut generator_point);
        let q_1 = Selectable::conditionally_select(cs, hash_bit, &q_plux_gen, &q_0);

        q_acc = q_1;
    }

    use boojum::pairing::GenericCurveAffine;
    let ((mut q_x, mut q_y), is_infinity) =
        q_acc.convert_to_affine_or_default(cs, Secp256Affine::one());
    exception_flags.push(is_infinity);
    let any_exception = Boolean::multi_or(cs, &exception_flags[..]);

    q_x.normalize(cs);
    q_y.normalize(cs);

    let zero_u8 = UInt8::zero(cs);

    let mut bytes_to_hash = [zero_u8; 64];
    let it = q_x.limbs[..16]
        .iter()
        .rev()
        .chain(q_y.limbs[..16].iter().rev());

    for (dst, src) in bytes_to_hash.array_chunks_mut::<2>().zip(it) {
        let limb = unsafe { UInt16::from_variable_unchecked(*src) };
        *dst = limb.to_be_bytes(cs);
    }

    let mut digest_bytes = keccak256(cs, &bytes_to_hash);
    // digest is 32 bytes, but we need only 20 to recover address
    digest_bytes[0..12].copy_from_slice(&[zero_u8; 12]); // empty out top bytes
    digest_bytes.reverse();
    let written_value_unmasked = UInt256::from_le_bytes(cs, digest_bytes);

    let written_value = written_value_unmasked.mask_negated(cs, any_exception);
    let all_ok = any_exception.negated(cs);

    (all_ok, written_value)
}

pub fn ecrecover_function_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    witness: EcrecoverCircuitInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    assert!(limit <= u32::MAX as usize);

    let EcrecoverCircuitInstanceWitness {
        closed_form_input,
        requests_queue_witness,
        memory_reads_witness,
    } = witness;

    let memory_reads_witness: VecDeque<_> = memory_reads_witness.into_iter().flatten().collect();

    let precompile_address = UInt160::allocated_constant(
        cs,
        *zkevm_opcode_defs::system_params::ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    );
    let aux_byte_for_precompile = UInt8::allocated_constant(cs, PRECOMPILE_AUX_BYTE);

    let scalar_params = Arc::new(secp256k1_scalar_field_params());
    let base_params = Arc::new(secp256k1_base_field_params());

    use boojum::pairing::ff::PrimeField;

    let valid_x_in_external_field = Secp256BaseNNField::allocated_constant(
        cs,
        Secp256Fq::from_str(&VALID_X_CUBED_IN_EXTERNAL_FIELD.to_string()).unwrap(),
        &base_params,
    );
    let valid_t_in_external_field = Secp256BaseNNField::allocated_constant(
        cs,
        Secp256Fq::from_str(&(VALID_X_CUBED_IN_EXTERNAL_FIELD + SECP_B_COEF).to_string()).unwrap(),
        &base_params,
    );
    let valid_y_in_external_field = Secp256BaseNNField::allocated_constant(
        cs,
        Secp256Fq::from_str(&VALID_Y_IN_EXTERNAL_FIELD.to_string()).unwrap(),
        &base_params,
    );

    let mut structured_input =
        EcrecoverCircuitInputOutput::alloc_ignoring_outputs(cs, closed_form_input.clone());
    let start_flag = structured_input.start_flag;

    let requests_queue_state_from_input = structured_input.observable_input.initial_log_queue_state;

    // it must be trivial
    requests_queue_state_from_input.enforce_trivial_head(cs);

    let requests_queue_state_from_fsm = structured_input.hidden_fsm_input.log_queue_state;

    let requests_queue_state = QueueState::conditionally_select(
        cs,
        start_flag,
        &requests_queue_state_from_input,
        &requests_queue_state_from_fsm,
    );

    let memory_queue_state_from_input =
        structured_input.observable_input.initial_memory_queue_state;

    // it must be trivial
    memory_queue_state_from_input.enforce_trivial_head(cs);

    let memory_queue_state_from_fsm = structured_input.hidden_fsm_input.memory_queue_state;

    let memory_queue_state = QueueState::conditionally_select(
        cs,
        start_flag,
        &memory_queue_state_from_input,
        &memory_queue_state_from_fsm,
    );

    let mut requests_queue = StorageLogQueue::<F, R>::from_state(cs, requests_queue_state);
    let queue_witness = CircuitQueueWitness::from_inner_witness(requests_queue_witness);
    requests_queue.witness = Arc::new(queue_witness);

    let mut memory_queue = MemoryQueue::<F, R>::from_state(cs, memory_queue_state);

    let one_u32 = UInt32::allocated_constant(cs, 1u32);
    let zero_u256 = UInt256::zero(cs);
    let boolean_false = Boolean::allocated_constant(cs, false);
    let boolean_true = Boolean::allocated_constant(cs, true);

    use crate::storage_application::ConditionalWitnessAllocator;
    let read_queries_allocator = ConditionalWitnessAllocator::<F, UInt256<F>> {
        witness_source: Arc::new(RwLock::new(memory_reads_witness)),
    };

    for _cycle in 0..limit {
        let is_empty = requests_queue.is_empty(cs);
        let should_process = is_empty.negated(cs);
        let (request, _) = requests_queue.pop_front(cs, should_process);

        let mut precompile_call_params =
            EcrecoverPrecompileCallParams::from_encoding(cs, request.key);

        let timestamp_to_use_for_read = request.timestamp;
        let timestamp_to_use_for_write = timestamp_to_use_for_read.add_no_overflow(cs, one_u32);

        Num::conditionally_enforce_equal(
            cs,
            should_process,
            &Num::from_variable(request.aux_byte.get_variable()),
            &Num::from_variable(aux_byte_for_precompile.get_variable()),
        );
        for (a, b) in request
            .address
            .inner
            .iter()
            .zip(precompile_address.inner.iter())
        {
            Num::conditionally_enforce_equal(
                cs,
                should_process,
                &Num::from_variable(a.get_variable()),
                &Num::from_variable(b.get_variable()),
            );
        }

        let mut read_values = [zero_u256; NUM_MEMORY_READS_PER_CYCLE];
        let mut bias_variable = should_process.get_variable();
        for dst in read_values.iter_mut() {
            let read_query_value: UInt256<F> = read_queries_allocator
                .conditionally_allocate_biased(cs, should_process, bias_variable);
            bias_variable = read_query_value.inner[0].get_variable();

            *dst = read_query_value;

            let read_query = MemoryQuery {
                timestamp: timestamp_to_use_for_read,
                memory_page: precompile_call_params.input_page,
                index: precompile_call_params.input_offset,
                rw_flag: boolean_false,
                is_ptr: boolean_false,
                value: read_query_value,
            };

            let _ = memory_queue.push(cs, read_query, should_process);

            precompile_call_params.input_offset = precompile_call_params
                .input_offset
                .add_no_overflow(cs, one_u32);
        }

        let [message_hash_as_u256, v_as_u256, r_as_u256, s_as_u256] = read_values;
        let rec_id = v_as_u256.inner[0].to_le_bytes(cs)[0];

        let (success, written_value) = ecrecover_precompile_inner_routine(
            cs,
            &rec_id,
            &r_as_u256,
            &s_as_u256,
            &message_hash_as_u256,
            valid_x_in_external_field.clone(),
            valid_y_in_external_field.clone(),
            valid_t_in_external_field.clone(),
            &base_params,
            &scalar_params,
        );

        let success_as_u32 = unsafe { UInt32::from_variable_unchecked(success.get_variable()) };
        let mut success_as_u256 = zero_u256;
        success_as_u256.inner[0] = success_as_u32;

        let success_query = MemoryQuery {
            timestamp: timestamp_to_use_for_write,
            memory_page: precompile_call_params.output_page,
            index: precompile_call_params.output_offset,
            rw_flag: boolean_true,
            value: success_as_u256,
            is_ptr: boolean_false,
        };

        precompile_call_params.output_offset = precompile_call_params
            .output_offset
            .add_no_overflow(cs, one_u32);

        let _ = memory_queue.push(cs, success_query, should_process);

        let value_query = MemoryQuery {
            timestamp: timestamp_to_use_for_write,
            memory_page: precompile_call_params.output_page,
            index: precompile_call_params.output_offset,
            rw_flag: boolean_true,
            value: written_value,
            is_ptr: boolean_false,
        };

        let _ = memory_queue.push(cs, value_query, should_process);
    }

    requests_queue.enforce_consistency(cs);

    // form the final state
    let done = requests_queue.is_empty(cs);
    structured_input.completion_flag = done;
    structured_input.observable_output = PrecompileFunctionOutputData::placeholder(cs);

    let final_memory_state = memory_queue.into_state();
    let final_requets_state = requests_queue.into_state();

    structured_input.observable_output.final_memory_state = QueueState::conditionally_select(
        cs,
        structured_input.completion_flag,
        &final_memory_state,
        &structured_input.observable_output.final_memory_state,
    );

    structured_input.hidden_fsm_output.log_queue_state = final_requets_state;
    structured_input.hidden_fsm_output.memory_queue_state = final_memory_state;

    // self-check
    structured_input.hook_compare_witness(cs, &closed_form_input);

    use boojum::cs::gates::PublicInputGate;

    let compact_form =
        ClosedFormInputCompactForm::from_full_form(cs, &structured_input, round_function);
    let input_commitment = commit_variable_length_encodable_item(cs, &compact_form, round_function);
    for el in input_commitment.iter() {
        let gate = PublicInputGate::new(el.get_variable());
        gate.add_to_cs(cs);
    }

    input_commitment
}

#[cfg(test)]
mod test {
    use boojum::field::goldilocks::GoldilocksField;
    use boojum::gadgets::traits::allocatable::CSAllocatable;
    use boojum::pairing::ff::{Field, PrimeField, SqrtField};
    use boojum::worker::Worker;

    use super::*;

    type F = GoldilocksField;
    type P = GoldilocksField;

    use boojum::config::DevCSConfig;

    use boojum::pairing::ff::PrimeFieldRepr;
    use boojum::pairing::{GenericCurveAffine, GenericCurveProjective};
    use rand::Rng;
    use rand::SeedableRng;
    use rand::XorShiftRng;

    pub fn deterministic_rng() -> XorShiftRng {
        XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654])
    }

    fn simulate_signature() -> (Secp256Fr, Secp256Fr, Secp256Affine, Secp256Fr) {
        let mut rng = deterministic_rng();
        let sk: Secp256Fr = rng.gen();

        simulate_signature_for_sk(sk)
    }

    fn transmute_representation<T: PrimeFieldRepr, U: PrimeFieldRepr>(repr: T) -> U {
        assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<U>());

        unsafe { std::mem::transmute_copy::<T, U>(&repr) }
    }

    fn simulate_signature_for_sk(
        sk: Secp256Fr,
    ) -> (Secp256Fr, Secp256Fr, Secp256Affine, Secp256Fr) {
        let mut rng = deterministic_rng();
        let pk = Secp256Affine::one().mul(sk.into_repr()).into_affine();
        let digest: Secp256Fr = rng.gen();
        let k: Secp256Fr = rng.gen();
        let r_point = Secp256Affine::one().mul(k.into_repr()).into_affine();

        let r_x = r_point.into_xy_unchecked().0;
        let r = transmute_representation::<_, <Secp256Fr as PrimeField>::Repr>(r_x.into_repr());
        let r = Secp256Fr::from_repr(r).unwrap();

        let k_inv = k.inverse().unwrap();
        let mut s = r;
        s.mul_assign(&sk);
        s.add_assign(&digest);
        s.mul_assign(&k_inv);

        {
            let mut mul_by_generator = digest;
            mul_by_generator.mul_assign(&r.inverse().unwrap());
            mul_by_generator.negate();

            let mut mul_by_r = s;
            mul_by_r.mul_assign(&r.inverse().unwrap());

            let res_1 = Secp256Affine::one().mul(mul_by_generator.into_repr());
            let res_2 = r_point.mul(mul_by_r.into_repr());

            let mut tmp = res_1;
            tmp.add_assign(&res_2);

            let tmp = tmp.into_affine();

            let x = tmp.into_xy_unchecked().0;
            assert_eq!(x, pk.into_xy_unchecked().0);
        }

        (r, s, pk, digest)
    }

    fn repr_into_u256<T: PrimeFieldRepr>(repr: T) -> U256 {
        let mut u256 = U256::zero();
        u256.0.copy_from_slice(&repr.as_ref()[..4]);

        u256
    }

    use boojum::cs::cs_builder::*;
    use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
    use boojum::cs::gates::*;
    use boojum::cs::traits::gate::GatePlacementStrategy;
    use boojum::cs::CSGeometry;
    use boojum::cs::*;
    use boojum::gadgets::tables::byte_split::ByteSplitTable;
    use boojum::gadgets::tables::*;

    #[test]
    fn test_signature_for_address_verification() {
        let geometry = CSGeometry {
            num_columns_under_copy_permutation: 100,
            num_witness_columns: 0,
            num_constant_columns: 8,
            max_allowed_constraint_degree: 4,
        };
        let max_variables = 1 << 26;
        let max_trace_len = 1 << 20;

        fn configure<
            F: SmallField,
            T: CsBuilderImpl<F, T>,
            GC: GateConfigurationHolder<F>,
            TB: StaticToolboxHolder,
        >(
            builder: CsBuilder<T, F, GC, TB>,
        ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
            let builder = builder.allow_lookup(
                LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
                    width: 3,
                    num_repetitions: 8,
                    share_table_id: true,
                },
            );
            let builder = ConstantsAllocatorGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = ReductionGate::<F, 4>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            // let owned_cs = ReductionGate::<F, 4>::configure_for_cs(owned_cs, GatePlacementStrategy::UseSpecializedColumns { num_repetitions: 8, share_constants: true });
            let builder = BooleanConstraintGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = UIntXAddGate::<32>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = UIntXAddGate::<16>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = SelectionGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = ZeroCheckGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
                false,
            );
            let builder = DotProductGate::<4>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            // let owned_cs = DotProductGate::<4>::configure_for_cs(owned_cs, GatePlacementStrategy::UseSpecializedColumns { num_repetitions: 1, share_constants: true });
            let builder = NopGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );

            builder
        }

        let builder_impl = CsReferenceImplementationBuilder::<F, P, DevCSConfig>::new(
            geometry,
            max_variables,
            max_trace_len,
        );
        let builder = new_builder::<_, F>(builder_impl);

        let builder = configure(builder);
        let mut owned_cs = builder.build(());

        // add tables
        let table = create_xor8_table();
        owned_cs.add_lookup_table::<Xor8Table, 3>(table);

        let table = create_and8_table();
        owned_cs.add_lookup_table::<And8Table, 3>(table);

        let table = create_byte_split_table::<F, 1>();
        owned_cs.add_lookup_table::<ByteSplitTable<1>, 3>(table);
        let table = create_byte_split_table::<F, 2>();
        owned_cs.add_lookup_table::<ByteSplitTable<2>, 3>(table);
        let table = create_byte_split_table::<F, 3>();
        owned_cs.add_lookup_table::<ByteSplitTable<3>, 3>(table);
        let table = create_byte_split_table::<F, 4>();
        owned_cs.add_lookup_table::<ByteSplitTable<4>, 3>(table);

        let cs = &mut owned_cs;

        let sk = crate::ff::from_hex::<Secp256Fr>(
            "b5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7",
        )
        .unwrap();
        let eth_address = hex::decode("12890d2cce102216644c59dae5baed380d84830c").unwrap();
        let (r, s, _pk, digest) = simulate_signature_for_sk(sk);

        let scalar_params = secp256k1_scalar_field_params();
        let base_params = secp256k1_base_field_params();

        let digest_u256 = repr_into_u256(digest.into_repr());
        let r_u256 = repr_into_u256(r.into_repr());
        let s_u256 = repr_into_u256(s.into_repr());

        let rec_id = UInt8::allocate_checked(cs, 0);
        let r = UInt256::allocate(cs, r_u256);
        let s = UInt256::allocate(cs, s_u256);
        let digest = UInt256::allocate(cs, digest_u256);

        let scalar_params = Arc::new(scalar_params);
        let base_params = Arc::new(base_params);

        let valid_x_in_external_field = Secp256BaseNNField::allocated_constant(
            cs,
            Secp256Fq::from_str("9").unwrap(),
            &base_params,
        );
        let valid_t_in_external_field = Secp256BaseNNField::allocated_constant(
            cs,
            Secp256Fq::from_str("16").unwrap(),
            &base_params,
        );
        let valid_y_in_external_field = Secp256BaseNNField::allocated_constant(
            cs,
            Secp256Fq::from_str("4").unwrap(),
            &base_params,
        );

        let (no_error, digest) = ecrecover_precompile_inner_routine(
            cs,
            &rec_id,
            &r,
            &s,
            &digest,
            valid_x_in_external_field.clone(),
            valid_y_in_external_field.clone(),
            valid_t_in_external_field.clone(),
            &base_params,
            &scalar_params,
        );

        assert!(no_error.witness_hook(&*cs)().unwrap() == true);
        let recovered_address = digest.to_be_bytes(cs);
        let recovered_address = recovered_address.witness_hook(cs)().unwrap();
        assert_eq!(&recovered_address[12..], &eth_address[..]);

        dbg!(cs.next_available_row());

        cs.pad_and_shrink();

        let mut cs = owned_cs.into_assembly();
        cs.print_gate_stats();
        let worker = Worker::new();
        assert!(cs.check_if_satisfied(&worker));
    }
}
