use crate::base_structures::register::VMRegister;
use boojum::gadgets::u256::UInt256;

use super::*;

pub(crate) fn apply_ptr<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    _draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    _opcode_carry_parts: &AfterDecodingCarryParts<F>,
    diffs_accumulator: &mut StateDiffsAccumulator<F>,
) {
    const PTR_ADD_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Ptr(zkevm_opcode_defs::PtrOpcode::Add);
    const PTR_SUB_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Ptr(zkevm_opcode_defs::PtrOpcode::Sub);
    const PTR_PACK_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Ptr(zkevm_opcode_defs::PtrOpcode::Pack);
    const PTR_SHRINK_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Ptr(zkevm_opcode_defs::PtrOpcode::Shrink);

    let should_apply = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(PTR_ADD_OPCODE);

    if crate::config::CIRCUIT_VERSOBE {
        if (should_apply.witness_hook(&*cs))().unwrap_or(false) {
            println!("Applying PTR");
        }
    }

    let ptr_add_variant = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(PTR_ADD_OPCODE);
    let ptr_sub_variant = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(PTR_SUB_OPCODE);
    let ptr_pack_variant = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(PTR_PACK_OPCODE);
    let ptr_shrink_variant = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(PTR_SHRINK_OPCODE);

    let src_0 = &common_opcode_state.src0_view;
    let src_1 = &common_opcode_state.src1_view;

    let src1_is_integer = src_1.is_ptr.negated(cs);

    // pointer + non_pointer
    let args_have_valid_type = Boolean::multi_and(cs, &[src_0.is_ptr, src1_is_integer]);
    let args_types_are_invalid = args_have_valid_type.negated(cs);
    // we also want to check that src1 is "small" in case of ptr.add

    let limb_is_zero = common_opcode_state
        .src1_view
        .u32x8_view
        .map(|el| el.is_zero(cs));
    let src1_32_to_256_is_zero = Boolean::multi_and(cs, &limb_is_zero[1..]);
    let src1_0_to_128_is_zero = Boolean::multi_and(cs, &limb_is_zero[..4]);

    let src1_32_to_256_is_nonzero = src1_32_to_256_is_zero.negated(cs);

    // if we add we want upper part of src1 to be zero
    let ptr_arith_variant = Boolean::multi_or(cs, &[ptr_add_variant, ptr_sub_variant]);
    let too_large_offset = Boolean::multi_and(cs, &[src1_32_to_256_is_nonzero, ptr_arith_variant]);

    // if we pack we want lower part of src1 to be zero
    let src1_0_to_128_is_nonzero = src1_0_to_128_is_zero.negated(cs);
    let dirty_value_for_pack =
        Boolean::multi_and(cs, &[src1_0_to_128_is_nonzero, ptr_pack_variant]);

    // now check overflows/underflows
    let (result_for_ptr_add, of) = src_0.u32x8_view[0].overflowing_add(cs, src_1.u32x8_view[0]);
    let overflow_panic_if_add = Boolean::multi_and(cs, &[ptr_add_variant, of]);

    let (result_for_ptr_sub, uf) = src_0.u32x8_view[0].overflowing_sub(cs, src_1.u32x8_view[0]);
    let underflow_panic_if_sub = Boolean::multi_and(cs, &[ptr_sub_variant, uf]);

    let (result_for_ptr_shrink, uf) = src_0.u32x8_view[3].overflowing_sub(cs, src_1.u32x8_view[0]);
    let underflow_panic_if_shrink = Boolean::multi_and(cs, &[ptr_shrink_variant, uf]);

    let any_potential_panic = Boolean::multi_or(
        cs,
        &[
            args_types_are_invalid,
            too_large_offset,
            dirty_value_for_pack,
            overflow_panic_if_add,
            underflow_panic_if_sub,
            underflow_panic_if_shrink,
        ],
    );

    let should_panic = Boolean::multi_and(cs, &[should_apply, any_potential_panic]);
    let ok_to_execute = any_potential_panic.negated(cs);
    let should_update_register = Boolean::multi_and(cs, &[should_apply, ok_to_execute]);

    // now we just need to select the result

    // low 32 bits from addition or unchanged original values
    let low_u32_if_add_or_sub = UInt32::conditionally_select(
        cs,
        ptr_add_variant,
        &result_for_ptr_add,
        &src_0.u32x8_view[0],
    );

    // low 32 bits from subtraction
    let low_u32_if_add_or_sub = UInt32::conditionally_select(
        cs,
        ptr_sub_variant,
        &result_for_ptr_sub,
        &low_u32_if_add_or_sub,
    );

    // higher 32 bits if shrink
    let bits_96_to_128_if_shrink = UInt32::conditionally_select(
        cs,
        ptr_shrink_variant,
        &result_for_ptr_shrink,
        &src_0.u32x8_view[3], // otherwise keep src_0 bits 96..128
    );

    let highest_128 = UInt32::parallel_select(
        cs,
        ptr_pack_variant,
        &[
            src_1.u32x8_view[4],
            src_1.u32x8_view[5],
            src_1.u32x8_view[6],
            src_1.u32x8_view[7],
        ],
        &[
            src_0.u32x8_view[4],
            src_0.u32x8_view[5],
            src_0.u32x8_view[6],
            src_0.u32x8_view[7],
        ],
    );

    let lowest32 = UInt32::conditionally_select(
        cs,
        ptr_pack_variant,
        &src_0.u32x8_view[0],
        &low_u32_if_add_or_sub,
    );

    let bits_96_to_128 = UInt32::conditionally_select(
        cs,
        ptr_pack_variant,
        &src_0.u32x8_view[3],
        &bits_96_to_128_if_shrink,
    );

    let dst0 = VMRegister {
        is_pointer: src_0.is_ptr,
        value: UInt256 {
            inner: [
                lowest32,
                src_0.u32x8_view[1],
                src_0.u32x8_view[2],
                bits_96_to_128,
                highest_128[0],
                highest_128[1],
                highest_128[2],
                highest_128[3],
            ],
        },
    };

    // only update dst0 and set exception if necessary
    let can_write_into_memory = PTR_ADD_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION);
    diffs_accumulator
        .dst_0_values
        .push((can_write_into_memory, should_update_register, dst0));
    diffs_accumulator.pending_exceptions.push(should_panic);
}
