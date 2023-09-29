use arrayvec::ArrayVec;

use crate::base_structures::{register::VMRegister, vm_state::ArithmeticFlagsPort};
use boojum::gadgets::{traits::castable::WitnessCastable, u256::UInt256};

use super::*;

pub(crate) fn apply_add_sub<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    _draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    _opcode_carry_parts: &AfterDecodingCarryParts<F>,
    diffs_accumulator: &mut StateDiffsAccumulator<F>,
) {
    // main point of merging add/sub is to enforce single add/sub relation, that doesn't leak into any
    // other opcodes

    let (addition_result_unchecked, of_unchecked) = allocate_addition_result_unchecked(
        cs,
        &common_opcode_state.src0_view.u32x8_view,
        &common_opcode_state.src1_view.u32x8_view,
    );

    let (subtraction_result_unchecked, uf_unchecked) = allocate_subtraction_result_unchecked(
        cs,
        &common_opcode_state.src0_view.u32x8_view,
        &common_opcode_state.src1_view.u32x8_view,
    );

    const ADD_OPCODE: zkevm_opcode_defs::Opcode = Opcode::Add(AddOpcode::Add);
    const SUB_OPCODE: zkevm_opcode_defs::Opcode = Opcode::Sub(SubOpcode::Sub);

    // now we need to properly select and enforce
    let apply_add = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(ADD_OPCODE);
    let apply_sub = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(SUB_OPCODE);

    if crate::config::CIRCUIT_VERSOBE {
        if (apply_add.witness_hook(&*cs))().unwrap_or(false) {
            println!("Applying ADD");
        }
        if (apply_sub.witness_hook(&*cs))().unwrap_or(false) {
            println!("Applying SUB");
        }
    }

    let to_enforce = UInt32::<F>::parallel_select(
        cs,
        apply_add,
        &addition_result_unchecked,
        &subtraction_result_unchecked,
    );
    let result = to_enforce.map(|el| UInt32::from_variable_checked(cs, el.get_variable()));

    // now we need to enforce relation
    // we enforce a + b = c + 2^N * of,
    // so if we subtract, then we need to swap some staff

    // relation is a + b == c + of * 2^N,
    // but we compute d - e + 2^N * borrow = f,
    // so e + f = d + of * 2^N

    // Naive options
    // let add_relation = AddSubRelation {
    //     a: common_opcode_state.src0_view.u32x8_view,
    //     b: common_opcode_state.src1_view.u32x8_view,
    //     c: addition_result_unchecked,
    //     of
    // };

    // let sub_relation = AddSubRelation {
    //     a: common_opcode_state.src1_view.u32x8_view,
    //     b: subtraction_result_unchecked,
    //     c: common_opcode_state.src0_view.u32x8_view,
    //     of: uf,
    // };

    // Instead we select non-common part, using the fact
    // that it's summetric over a/b

    let new_a = common_opcode_state.src1_view.u32x8_view;

    let new_b = UInt32::<F>::parallel_select(
        cs,
        apply_add,
        &common_opcode_state.src0_view.u32x8_view,
        &subtraction_result_unchecked,
    );

    let new_c = UInt32::<F>::parallel_select(
        cs,
        apply_add,
        &addition_result_unchecked,
        &common_opcode_state.src0_view.u32x8_view,
    );

    let new_of = Boolean::conditionally_select(cs, apply_add, &of_unchecked, &uf_unchecked);

    let relation = AddSubRelation {
        a: new_a,
        b: new_b,
        c: new_c,
        of: new_of,
    };

    // now we need to check for zero and output
    let limb_is_zero = result.map(|el| el.is_zero(cs));
    let result_is_zero = Boolean::multi_and(cs, &limb_is_zero);

    // gt = !of & !zero, so it's !(of || zero)
    let gt = Boolean::multi_or(cs, &[new_of, result_is_zero]).negated(cs);

    let update_flags = common_opcode_state
        .decoded_opcode
        .properties_bits
        .flag_booleans[SET_FLAGS_FLAG_IDX];

    let candidate_flags = ArithmeticFlagsPort {
        overflow_or_less_than: new_of,
        equal: result_is_zero,
        greater_than: gt,
    };

    // we only update flags and dst0

    let apply_any = Boolean::multi_or(cs, &[apply_add, apply_sub]);
    let boolean_false = Boolean::allocated_constant(cs, false);
    let dst0 = VMRegister {
        is_pointer: boolean_false,
        value: UInt256 { inner: result },
    };

    let can_write_into_memory = ADD_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION);
    debug_assert_eq!(
        can_write_into_memory,
        SUB_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION)
    );

    let update_flags = Boolean::multi_and(cs, &[apply_any, update_flags]);

    diffs_accumulator
        .dst_0_values
        .push((can_write_into_memory, apply_any, dst0));
    diffs_accumulator
        .flags
        .push((update_flags, candidate_flags));

    let mut add_sub_relations = ArrayVec::new();
    add_sub_relations.push(relation);
    diffs_accumulator
        .add_sub_relations
        .push((apply_any, add_sub_relations));
}

pub fn allocate_addition_result_unchecked<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    a: &[UInt32<F>; 8],
    b: &[UInt32<F>; 8],
) -> ([UInt32<F>; 8], Boolean<F>) {
    let limbs = cs.alloc_multiple_variables_without_values::<8>();
    let of = cs.alloc_variable_without_value();

    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        let value_fn = move |inputs: [F; 16]| {
            let mut of = false;
            let mut result = [F::ZERO; 9];
            for (idx, (a, b)) in inputs[..8].iter().zip(inputs[8..].iter()).enumerate() {
                let a = <u32 as WitnessCastable<F, F>>::cast_from_source(*a);
                let b = <u32 as WitnessCastable<F, F>>::cast_from_source(*b);
                let (c, new_of_0) = a.overflowing_add(b);
                let (c, new_of_1) = c.overflowing_add(of as u32);

                of = new_of_0 || new_of_1;

                result[idx] = F::from_u64_unchecked(c as u64);
            }

            result[8] = F::from_u64_unchecked(of as u64);

            result
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
            limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5], limbs[6], limbs[7], of,
        ]);
        cs.set_values_with_dependencies(&dependencies, &outputs, value_fn);
    }

    let limbs = limbs.map(|el| unsafe { UInt32::from_variable_unchecked(el) });
    let of = unsafe { Boolean::from_variable_unchecked(of) };

    (limbs, of)
}

pub fn allocate_subtraction_result_unchecked<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    a: &[UInt32<F>; 8],
    b: &[UInt32<F>; 8],
) -> ([UInt32<F>; 8], Boolean<F>) {
    let limbs = cs.alloc_multiple_variables_without_values::<8>();
    let of = cs.alloc_variable_without_value();

    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        let value_fn = move |inputs: [F; 16]| {
            let mut uf = false;
            let mut result = [F::ZERO; 9];
            for (idx, (a, b)) in inputs[..8].iter().zip(inputs[8..].iter()).enumerate() {
                let a = <u32 as WitnessCastable<F, F>>::cast_from_source(*a);
                let b = <u32 as WitnessCastable<F, F>>::cast_from_source(*b);
                let (c, new_uf_0) = (a).overflowing_sub(b);
                let (c, new_uf_1) = c.overflowing_sub(uf as u32);

                uf = new_uf_0 || new_uf_1;

                result[idx] = F::from_u64_unchecked(c as u64);
            }

            result[8] = F::from_u64_unchecked(uf as u64);

            result
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
            limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5], limbs[6], limbs[7], of,
        ]);
        cs.set_values_with_dependencies(&dependencies, &outputs, value_fn);
    }

    let limbs = limbs.map(|el| unsafe { UInt32::from_variable_unchecked(el) });
    let of = unsafe { Boolean::from_variable_unchecked(of) };

    (limbs, of)
}
