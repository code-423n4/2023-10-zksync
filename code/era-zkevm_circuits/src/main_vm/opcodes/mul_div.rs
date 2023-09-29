use self::ethereum_types::U256;
use super::*;

use crate::base_structures::register::VMRegister;
use crate::base_structures::vm_state::ArithmeticFlagsPort;
use arrayvec::ArrayVec;
use boojum::gadgets::u256::{decompose_u256_as_u32x8, UInt256};

fn allocate_u256_from_limbs<F: SmallField>(limbs: &[F]) -> U256 {
    debug_assert_eq!(limbs.len(), 8);

    let mut byte_array = [0u8; 32];
    for (dst, limb) in byte_array.array_chunks_mut::<4>().zip(limbs.iter()) {
        *dst = (limb.as_u64_reduced() as u32).to_le_bytes();
    }

    U256::from_little_endian(&byte_array)
}

pub fn allocate_mul_result_unchecked<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    a: &[UInt32<F>; 8],
    b: &[UInt32<F>; 8],
) -> ([UInt32<F>; 8], [UInt32<F>; 8]) {
    let limbs_low = cs.alloc_multiple_variables_without_values::<8>();
    let limbs_high = cs.alloc_multiple_variables_without_values::<8>();

    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        let value_fn = move |inputs: [F; 16]| {
            let a = allocate_u256_from_limbs(&inputs[0..8]);
            let b = allocate_u256_from_limbs(&inputs[8..16]);
            let mut c_bytes = [0u8; 64];
            a.full_mul(b).to_little_endian(&mut c_bytes[..]);

            let mut outputs = [F::ZERO; 16];
            let mut byte_array = [0u8; 4];
            for (in_chunk, out_elem) in c_bytes.chunks(4).zip(outputs.iter_mut()) {
                byte_array.copy_from_slice(in_chunk);
                let as_u32 = u32::from_le_bytes(byte_array);
                *out_elem = F::from_u64_unchecked(as_u32 as u64);
            }

            outputs
        };

        let dependencies = Place::from_variables([
            a[0].get_variable(),
            a[1].get_variable(),
            a[2].get_variable(),
            a[3].get_variable(),
            a[4].get_variable(),
            a[5].get_variable(),
            a[6].get_variable(),
            a[7].get_variable(),
            b[0].get_variable(),
            b[1].get_variable(),
            b[2].get_variable(),
            b[3].get_variable(),
            b[4].get_variable(),
            b[5].get_variable(),
            b[6].get_variable(),
            b[7].get_variable(),
        ]);
        let outputs = Place::from_variables([
            limbs_low[0],
            limbs_low[1],
            limbs_low[2],
            limbs_low[3],
            limbs_low[4],
            limbs_low[5],
            limbs_low[6],
            limbs_low[7],
            limbs_high[0],
            limbs_high[1],
            limbs_high[2],
            limbs_high[3],
            limbs_high[4],
            limbs_high[5],
            limbs_high[6],
            limbs_high[7],
        ]);
        cs.set_values_with_dependencies(&dependencies, &outputs, value_fn);
    }

    let limbs_low = limbs_low.map(|el| unsafe { UInt32::from_variable_unchecked(el) });
    let limbs_high = limbs_high.map(|el| unsafe { UInt32::from_variable_unchecked(el) });

    (limbs_low, limbs_high)
}

pub fn allocate_div_result_unchecked<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    a: &[UInt32<F>; 8],
    b: &[UInt32<F>; 8],
) -> ([UInt32<F>; 8], [UInt32<F>; 8]) {
    let quotient = cs.alloc_multiple_variables_without_values::<8>();
    let remainder = cs.alloc_multiple_variables_without_values::<8>();

    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        let value_fn = move |inputs: [F; 16]| {
            let a = allocate_u256_from_limbs(&inputs[0..8]);
            let b = allocate_u256_from_limbs(&inputs[8..16]);

            let (quotient, remainder) = if b.is_zero() {
                (U256::zero(), U256::zero())
            } else {
                a.div_mod(b)
            };

            let mut outputs = [F::ZERO; 16];
            for (dst, src) in outputs[..8]
                .iter_mut()
                .zip(decompose_u256_as_u32x8(quotient).into_iter())
            {
                *dst = F::from_u64_unchecked(src as u64);
            }
            for (dst, src) in outputs[8..]
                .iter_mut()
                .zip(decompose_u256_as_u32x8(remainder).into_iter())
            {
                *dst = F::from_u64_unchecked(src as u64);
            }

            outputs
        };

        let dependencies = Place::from_variables([
            a[0].get_variable(),
            a[1].get_variable(),
            a[2].get_variable(),
            a[3].get_variable(),
            a[4].get_variable(),
            a[5].get_variable(),
            a[6].get_variable(),
            a[7].get_variable(),
            b[0].get_variable(),
            b[1].get_variable(),
            b[2].get_variable(),
            b[3].get_variable(),
            b[4].get_variable(),
            b[5].get_variable(),
            b[6].get_variable(),
            b[7].get_variable(),
        ]);
        let outputs = Place::from_variables([
            quotient[0],
            quotient[1],
            quotient[2],
            quotient[3],
            quotient[4],
            quotient[5],
            quotient[6],
            quotient[7],
            remainder[0],
            remainder[1],
            remainder[2],
            remainder[3],
            remainder[4],
            remainder[5],
            remainder[6],
            remainder[7],
        ]);
        cs.set_values_with_dependencies(&dependencies, &outputs, value_fn);
    }

    let quotient = quotient.map(|el| unsafe { UInt32::from_variable_unchecked(el) });
    let remainder = remainder.map(|el| unsafe { UInt32::from_variable_unchecked(el) });

    (quotient, remainder)
}

pub fn all_limbs_are_zero<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    limbs: &[UInt32<F>; 8],
) -> Boolean<F> {
    let limb_is_zero = limbs.map(|el| el.is_zero(cs));
    let result_is_zero = Boolean::multi_and(cs, &limb_is_zero);

    result_is_zero
}

pub fn all_limbs_are_equal<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    lhs: &[UInt32<F>; 8],
    rhs: &[UInt32<F>; 8],
) -> Boolean<F> {
    let boolean_false = Boolean::allocated_constant(cs, false);
    let mut flags = [boolean_false; 8];
    for ((lhs_limb, rhs_limb), out) in lhs.iter().zip(rhs.iter()).zip(flags.iter_mut()) {
        *out = UInt32::equals(cs, lhs_limb, rhs_limb);
    }
    let result = Boolean::multi_and(cs, &flags);

    result
}

pub(crate) fn apply_mul_div<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    _draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    _opcode_carry_parts: &AfterDecodingCarryParts<F>,
    diffs_accumulator: &mut StateDiffsAccumulator<F>,
) {
    const MUL_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Mul(zkevm_opcode_defs::MulOpcode);
    const DIV_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Div(zkevm_opcode_defs::DivOpcode);

    let should_apply_mul = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(MUL_OPCODE);
    let should_apply_div = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(DIV_OPCODE);

    if crate::config::CIRCUIT_VERSOBE {
        if (should_apply_mul.witness_hook(&*cs))().unwrap_or(false) {
            println!("Applying MUL");
        }
        if (should_apply_div.witness_hook(&*cs))().unwrap_or(false) {
            println!("Applying DIV");
        }
    }

    let should_set_flags = common_opcode_state
        .decoded_opcode
        .properties_bits
        .flag_booleans[SET_FLAGS_FLAG_IDX];

    let src0_view = &common_opcode_state.src0_view.u32x8_view;
    let src1_view = &common_opcode_state.src1_view.u32x8_view;

    let (mul_low_unchecked, mul_high_unchecked) =
        allocate_mul_result_unchecked(cs, src0_view, src1_view);
    let (quotient_unchecked, remainder_unchecked) =
        allocate_div_result_unchecked(cs, src0_view, src1_view);

    // if crate::config::CIRCUIT_VERSOBE {
    //     if (should_apply_mul.witness_hook(&*cs))().unwrap_or(false) || (should_apply_div.witness_hook(&*cs))().unwrap_or(false) {
    //         dbg!(mul_low_unchecked.witness_hook(&*cs)().unwrap());
    //         dbg!(mul_high_unchecked.witness_hook(&*cs)().unwrap());
    //         dbg!(quotient_unchecked.witness_hook(&*cs)().unwrap());
    //         dbg!(remainder_unchecked.witness_hook(&*cs)().unwrap());
    //     }
    // }

    let to_enforce_0 = UInt32::parallel_select(
        cs,
        should_apply_mul,
        &mul_low_unchecked,
        &quotient_unchecked,
    );
    let result_0 = to_enforce_0.map(|el| UInt32::from_variable_checked(cs, el.get_variable()));
    let to_enforce_1 = UInt32::parallel_select(
        cs,
        should_apply_mul,
        &mul_high_unchecked,
        &remainder_unchecked,
    );
    let result_1 = to_enforce_1.map(|el| UInt32::from_variable_checked(cs, el.get_variable()));

    // if we mull: src0 * src1 = mul_low + (mul_high << 256) => rem = 0, a = src0, b = src1, mul_low = mul_low, mul_high = mul_high
    // if we divide: src0 = q * src1 + rem =>                   rem = rem, a = quotient, b = src1, mul_low = src0, mul_high = 0
    let uint256_zero = UInt256::zero(cs);

    let rem_to_enforce = UInt32::parallel_select(
        cs,
        should_apply_mul,
        &uint256_zero.inner,
        &remainder_unchecked,
    );
    let a_to_enforce =
        UInt32::parallel_select(cs, should_apply_mul, src0_view, &quotient_unchecked);
    let b_to_enforce = src1_view.clone();
    let mul_low_to_enforce =
        UInt32::parallel_select(cs, should_apply_mul, &mul_low_unchecked, &src0_view);
    let mul_high_to_enforce = UInt32::parallel_select(
        cs,
        should_apply_mul,
        &mul_high_unchecked,
        &uint256_zero.inner,
    );

    let mul_relation = MulDivRelation {
        a: a_to_enforce,
        b: b_to_enforce,
        rem: rem_to_enforce,
        mul_low: mul_low_to_enforce,
        mul_high: mul_high_to_enforce,
    };

    // flags which are set in case of executing mul
    let high_is_zero = all_limbs_are_zero(cs, &mul_high_unchecked);
    let low_is_zero = all_limbs_are_zero(cs, &mul_low_unchecked);
    let of_mul = high_is_zero.negated(cs);
    let eq_mul = low_is_zero;
    let gt_mul = {
        let x = of_mul.negated(cs);
        let y = eq_mul.negated(cs);
        Boolean::multi_and(cs, &[x, y])
    };

    // flags which are set in case of executing div
    let divisor_is_zero = all_limbs_are_zero(cs, src1_view);
    let divisor_is_non_zero = divisor_is_zero.negated(cs);
    // check if quotient and remainder are 0
    let quotient_is_zero = all_limbs_are_zero(cs, &quotient_unchecked);
    let remainder_is_zero = all_limbs_are_zero(cs, &remainder_unchecked);

    // check that remainder is smaller than divisor

    // do remainder - divisor
    let (subtraction_result_unchecked, remainder_is_less_than_divisor) =
        allocate_subtraction_result_unchecked(cs, &remainder_unchecked, src1_view);

    // relation is a + b == c + of * 2^N,
    // but we compute d - e + 2^N * borrow = f

    // so we need to shuffle
    let addition_relation = AddSubRelation {
        a: *src1_view,
        b: subtraction_result_unchecked,
        c: remainder_unchecked,
        of: remainder_is_less_than_divisor,
    };

    // unless divisor is 0 (that we handle separately),
    // we require that remainder is < divisor
    remainder_is_less_than_divisor.conditionally_enforce_true(cs, divisor_is_non_zero);

    // if divisor is 0, then we assume quotient and remainder to be 0

    quotient_is_zero.conditionally_enforce_true(cs, divisor_is_zero);
    remainder_is_zero.conditionally_enforce_true(cs, divisor_is_zero);

    let of_div = divisor_is_zero;
    let eq_div = {
        let x = divisor_is_zero.negated(cs);
        Boolean::multi_and(cs, &[x, quotient_is_zero])
    };
    let gt_div = {
        let y = divisor_is_zero.negated(cs);
        Boolean::multi_and(cs, &[y, remainder_is_zero])
    };

    let of = Boolean::conditionally_select(cs, should_apply_mul, &of_mul, &of_div);
    let eq = Boolean::conditionally_select(cs, should_apply_mul, &eq_mul, &eq_div);
    let gt = Boolean::conditionally_select(cs, should_apply_mul, &gt_mul, &gt_div);

    let candidate_flags = ArithmeticFlagsPort {
        overflow_or_less_than: of,
        equal: eq,
        greater_than: gt,
    };

    let apply_any = Boolean::multi_or(cs, &[should_apply_mul, should_apply_div]);
    let dst0 = VMRegister {
        is_pointer: Boolean::allocated_constant(cs, false),
        value: UInt256 { inner: result_0 },
    };
    let dst1 = VMRegister {
        is_pointer: Boolean::allocated_constant(cs, false),
        value: UInt256 { inner: result_1 },
    };

    // if crate::config::CIRCUIT_VERSOBE {
    //     if (should_apply_mul.witness_hook(&*cs))().unwrap_or(false) || (should_apply_div.witness_hook(&*cs))().unwrap_or(false) {
    //         dbg!(result_0.witness_hook(&*cs)().unwrap());
    //         dbg!(result_1.witness_hook(&*cs)().unwrap());
    //     }
    // }

    let can_write_into_memory = MUL_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION);
    debug_assert_eq!(
        can_write_into_memory,
        DIV_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION)
    );

    diffs_accumulator
        .dst_0_values
        .push((can_write_into_memory, apply_any, dst0));
    diffs_accumulator.dst_1_values.push((apply_any, dst1));
    let set_flags_and_execute = Boolean::multi_and(cs, &[apply_any, should_set_flags]);
    diffs_accumulator
        .flags
        .push((set_flags_and_execute, candidate_flags));

    let mut add_sub_relations = ArrayVec::new();
    add_sub_relations.push(addition_relation);
    diffs_accumulator
        .add_sub_relations
        .push((apply_any, add_sub_relations));

    let mut mul_div_relations = ArrayVec::new();
    mul_div_relations.push(mul_relation);
    diffs_accumulator
        .mul_div_relations
        .push((apply_any, mul_div_relations));
}
