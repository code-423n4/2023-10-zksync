use reduction_by_powers_gate::ReductionByPowersGate;

use boojum::{
    cs::gates::{
        reduction_by_powers_gate, ConstantAllocatableCS, ReductionGate, ReductionGateParams,
    },
    gadgets::u256::UInt256,
};

use crate::base_structures::{register::VMRegister, vm_state::ArithmeticFlagsPort};

use super::*;

pub(crate) fn apply_binop<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    _draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    _opcode_carry_parts: &AfterDecodingCarryParts<F>,
    diffs_accumulator: &mut StateDiffsAccumulator<F>,
) {
    const AND_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Binop(zkevm_opcode_defs::definitions::binop::BinopOpcode::And);
    const OR_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Binop(zkevm_opcode_defs::definitions::binop::BinopOpcode::Or);
    const XOR_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Binop(zkevm_opcode_defs::definitions::binop::BinopOpcode::Xor);

    let should_apply = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(AND_OPCODE);

    let should_set_flags = common_opcode_state
        .decoded_opcode
        .properties_bits
        .flag_booleans[SET_FLAGS_FLAG_IDX];

    let is_and = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(AND_OPCODE);
    let is_or = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(OR_OPCODE);
    let _is_xor = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(XOR_OPCODE);
    // main point of merging add/sub is to enforce single add/sub relation, that doesn't leak into any
    // other opcodes

    if crate::config::CIRCUIT_VERSOBE {
        if should_apply.witness_hook(&*cs)().unwrap_or(false) {
            println!("Applying BINOP");
            if is_and.witness_hook(&*cs)().unwrap_or(false) {
                println!("BINOP AND");
            }
            if is_or.witness_hook(&*cs)().unwrap_or(false) {
                println!("BINOP OR");
            }
            if _is_xor.witness_hook(&*cs)().unwrap_or(false) {
                println!("BINOP XOR");
            }
        }
    }

    let (and_result, or_result, xor_result) = get_binop_subresults(
        cs,
        &common_opcode_state.src0_view.u8x32_view,
        &common_opcode_state.src1_view.u8x32_view,
    );

    // now we need to select, so we first reduce, and then select

    let mut and_chunks = common_opcode_state.src0_view.u32x8_view;
    let mut or_chunks = common_opcode_state.src0_view.u32x8_view;
    let mut xor_chunks = common_opcode_state.src0_view.u32x8_view;

    for (dst, src) in [&mut and_chunks, &mut or_chunks, &mut xor_chunks]
        .into_iter()
        .zip([and_result, or_result, xor_result].into_iter())
    {
        for (dst, src) in dst.iter_mut().zip(src.array_chunks::<4>()) {
            *dst = UInt32::from_le_bytes(cs, *src);
        }
    }

    // now select

    let mut result = UInt32::parallel_select(cs, is_and, &and_chunks, &xor_chunks);
    result = UInt32::parallel_select(cs, is_or, &or_chunks, &result);

    let limb_is_zero = result.map(|el| el.is_zero(cs));
    let result_is_zero = Boolean::multi_and(cs, &limb_is_zero);

    let constant_false = Boolean::allocated_constant(cs, false);

    let candidate_flags = ArithmeticFlagsPort {
        overflow_or_less_than: constant_false,
        equal: result_is_zero,
        greater_than: constant_false,
    };

    // we only update flags and dst0

    let dst0 = VMRegister {
        is_pointer: Boolean::allocated_constant(cs, false),
        value: UInt256 { inner: result },
    };
    let can_write_into_memory = AND_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION);
    diffs_accumulator
        .dst_0_values
        .push((can_write_into_memory, should_apply, dst0));

    let update_flags = Boolean::multi_and(cs, &[should_apply, should_set_flags]);

    diffs_accumulator
        .flags
        .push((update_flags, candidate_flags));
}

fn get_binop_subresults<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    a: &[UInt8<F>; 32],
    b: &[UInt8<F>; 32],
) -> ([UInt8<F>; 32], [UInt8<F>; 32], [UInt8<F>; 32]) {
    // we apply our composite table twice - one to get compound result, and another one as range checks
    // and add alreabraic relation
    use boojum::gadgets::tables::binop_table::BinopTable;

    let table_id = cs
        .get_table_id_for_marker::<BinopTable>()
        .expect("table must exist");

    let mut composite_result = [Variable::placeholder(); 32];
    for ((a, b), dst) in a.iter().zip(b.iter()).zip(composite_result.iter_mut()) {
        let [result] = cs.perform_lookup::<2, 1>(table_id, &[a.get_variable(), b.get_variable()]);
        *dst = result;
    }

    // now we need to pull out individual parts. For that we decompose a value
    // let value = (xor_result as u64) << 32 | (or_result as u64) << 16 | (and_result as u64);

    let all_results = cs.alloc_multiple_variables_without_values::<96>();

    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        let value_fn = move |inputs: [F; 32]| {
            let mut results = [F::ZERO; 96];

            const MASK: u64 = (1u64 << 8) - 1;

            for (src, dst) in inputs.iter().zip(results.array_chunks_mut::<3>()) {
                let mut src = src.as_u64_reduced();
                let and_result = src & MASK;
                src >>= 16;
                let or_result = src & MASK;
                src >>= 16;
                let xor_result = src & MASK;

                *dst = [
                    F::from_u64_unchecked(and_result),
                    F::from_u64_unchecked(or_result),
                    F::from_u64_unchecked(xor_result),
                ]
            }

            results
        };

        let dependencies = Place::from_variables(composite_result);
        let outputs = Place::from_variables(all_results);
        cs.set_values_with_dependencies(&dependencies, &outputs, value_fn);
    }

    // lookup more

    for source_set in all_results.array_chunks::<3>() {
        // value is irrelevant, it's just a range check
        let _: [Variable; 1] = cs.perform_lookup::<2, 1>(table_id, &[source_set[0], source_set[1]]);
    }

    let zero_var = cs.allocate_constant(F::ZERO);

    debug_assert!(F::CAPACITY_BITS >= 56);

    if <CS::Config as CSConfig>::SetupConfig::KEEP_SETUP {
        // enforce. Note that there are no new variables here
        for (src, decomposition) in composite_result.iter().zip(all_results.array_chunks::<3>()) {
            if cs.gate_is_allowed::<ReductionGate<F, 4>>() {
                let mut gate = ReductionGate::<F, 4>::empty();
                gate.params = ReductionGateParams {
                    reduction_constants: [F::SHIFTS[0], F::SHIFTS[16], F::SHIFTS[32], F::ZERO],
                };
                gate.reduction_result = *src;
                gate.terms = [
                    decomposition[0],
                    decomposition[1],
                    decomposition[2],
                    zero_var,
                ];

                gate.add_to_cs(cs);
            } else if cs.gate_is_allowed::<ReductionByPowersGate<F, 4>>() {
                let mut gate = ReductionByPowersGate::<F, 4>::empty();
                use crate::main_vm::opcodes::binop::reduction_by_powers_gate::ReductionByPowersGateParams;
                gate.params = ReductionByPowersGateParams {
                    reduction_constant: F::from_u64_unchecked(1u64 << 16),
                };
                gate.reduction_result = *src;
                gate.terms = [
                    decomposition[0],
                    decomposition[1],
                    decomposition[2],
                    zero_var,
                ];

                gate.add_to_cs(cs);
            } else {
                unimplemented!()
            }
        }
    }

    let mut and_results = [Variable::placeholder(); 32];
    let mut or_results = [Variable::placeholder(); 32];
    let mut xor_results = [Variable::placeholder(); 32];

    for (((and, or), xor), src) in and_results
        .iter_mut()
        .zip(or_results.iter_mut())
        .zip(xor_results.iter_mut())
        .zip(all_results.array_chunks::<3>())
    {
        *and = src[0];
        *or = src[1];
        *xor = src[2];
    }

    let and_results = and_results.map(|el| unsafe { UInt8::from_variable_unchecked(el) });
    let or_results = or_results.map(|el| unsafe { UInt8::from_variable_unchecked(el) });
    let xor_results = xor_results.map(|el| unsafe { UInt8::from_variable_unchecked(el) });

    (and_results, or_results, xor_results)
}
