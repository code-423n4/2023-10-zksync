use boojum::gadgets::u256::UInt256;

use crate::base_structures::register::VMRegister;

use super::*;

pub(crate) fn apply_context<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    opcode_carry_parts: &AfterDecodingCarryParts<F>,
    diffs_accumulator: &mut StateDiffsAccumulator<F>,
) {
    const GET_THIS_ADDRESS_OPCODE: zkevm_opcode_defs::Opcode = zkevm_opcode_defs::Opcode::Context(
        zkevm_opcode_defs::definitions::context::ContextOpcode::This,
    );
    const GET_CALLER_ADDRESS_OPCODE: zkevm_opcode_defs::Opcode = zkevm_opcode_defs::Opcode::Context(
        zkevm_opcode_defs::definitions::context::ContextOpcode::Caller,
    );
    const GET_CODE_ADDRESS_OPCODE: zkevm_opcode_defs::Opcode = zkevm_opcode_defs::Opcode::Context(
        zkevm_opcode_defs::definitions::context::ContextOpcode::CodeAddress,
    );
    const GET_META_OPCODE: zkevm_opcode_defs::Opcode = zkevm_opcode_defs::Opcode::Context(
        zkevm_opcode_defs::definitions::context::ContextOpcode::Meta,
    );
    const GET_ERGS_LEFT_OPCODE: zkevm_opcode_defs::Opcode = zkevm_opcode_defs::Opcode::Context(
        zkevm_opcode_defs::definitions::context::ContextOpcode::ErgsLeft,
    );
    const GET_SP_OPCODE: zkevm_opcode_defs::Opcode = zkevm_opcode_defs::Opcode::Context(
        zkevm_opcode_defs::definitions::context::ContextOpcode::Sp,
    );
    const GET_CONTEXT_U128_OPCODE: zkevm_opcode_defs::Opcode = zkevm_opcode_defs::Opcode::Context(
        zkevm_opcode_defs::definitions::context::ContextOpcode::GetContextU128,
    );
    // attempt to execute in non-kernel mode for this opcode would be caught before
    const SET_CONTEXT_U128_OPCODE: zkevm_opcode_defs::Opcode = zkevm_opcode_defs::Opcode::Context(
        zkevm_opcode_defs::definitions::context::ContextOpcode::SetContextU128,
    );
    const SET_PUBDATA_ERGS_OPCODE: zkevm_opcode_defs::Opcode = zkevm_opcode_defs::Opcode::Context(
        zkevm_opcode_defs::definitions::context::ContextOpcode::SetErgsPerPubdataByte,
    );
    const INCREMENT_TX_NUMBER_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Context(
            zkevm_opcode_defs::definitions::context::ContextOpcode::IncrementTxNumber,
        );

    let should_apply = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_opcode(GET_THIS_ADDRESS_OPCODE)
    };

    let is_retrieve_this = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(GET_THIS_ADDRESS_OPCODE)
    };
    let is_retrieve_caller = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(GET_CALLER_ADDRESS_OPCODE)
    };
    let is_retrieve_code_address = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(GET_CODE_ADDRESS_OPCODE)
    };
    let is_retrieve_meta = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(GET_META_OPCODE)
    };
    let is_retrieve_ergs_left = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(GET_ERGS_LEFT_OPCODE)
    };
    let _is_retrieve_sp = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(GET_SP_OPCODE)
    };
    let is_get_context_u128 = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(GET_CONTEXT_U128_OPCODE)
    };
    let is_set_context_u128 = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(SET_CONTEXT_U128_OPCODE)
    };
    let is_set_pubdata_ergs = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(SET_PUBDATA_ERGS_OPCODE)
    };
    let is_inc_tx_num = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(INCREMENT_TX_NUMBER_OPCODE)
    };

    let write_to_context = Boolean::multi_and(cs, &[should_apply, is_set_context_u128]);
    let set_pubdata_ergs = Boolean::multi_and(cs, &[should_apply, is_set_pubdata_ergs]);
    let increment_tx_counter = Boolean::multi_and(cs, &[should_apply, is_inc_tx_num]);

    // write in regards of dst0 register
    let read_only = Boolean::multi_or(
        cs,
        &[is_set_context_u128, is_set_pubdata_ergs, is_inc_tx_num],
    );
    let write_like = read_only.negated(cs);

    let write_to_dst0 = Boolean::multi_and(cs, &[should_apply, write_like]);

    let potentially_new_ergs_for_pubdata = common_opcode_state.src0_view.u32x8_view[0];

    let one_u32 = UInt32::allocated_constant(cs, 1u32);
    let (incremented_tx_number, _of) = draft_vm_state
        .tx_number_in_block
        .overflowing_add(cs, one_u32);

    let context_composite_to_set = [
        common_opcode_state.src0_view.u32x8_view[0],
        common_opcode_state.src0_view.u32x8_view[1],
        common_opcode_state.src0_view.u32x8_view[2],
        common_opcode_state.src0_view.u32x8_view[3],
    ];

    let zero_u32 = UInt32::zero(cs);
    let zero_u8 = UInt8::zero(cs);

    let meta_highest_u32 = UInt32::from_le_bytes(
        cs,
        [
            draft_vm_state
                .callstack
                .current_context
                .saved_context
                .this_shard_id,
            draft_vm_state
                .callstack
                .current_context
                .saved_context
                .caller_shard_id,
            draft_vm_state
                .callstack
                .current_context
                .saved_context
                .code_shard_id,
            zero_u8,
        ],
    );

    let meta_as_register = UInt256 {
        inner: [
            draft_vm_state.ergs_per_pubdata_byte,
            zero_u32, // reserved
            draft_vm_state
                .callstack
                .current_context
                .saved_context
                .heap_upper_bound,
            draft_vm_state
                .callstack
                .current_context
                .saved_context
                .aux_heap_upper_bound,
            zero_u32, // reserved
            zero_u32, // reserved
            zero_u32, // reserved
            meta_highest_u32,
        ],
    };

    // now we will select in the growding width manner

    let low_u32_to_get_sp = unsafe {
        UInt32::from_variable_unchecked(
            draft_vm_state
                .callstack
                .current_context
                .saved_context
                .sp
                .get_variable(),
        )
    };

    let low_u32_ergs_left = opcode_carry_parts.preliminary_ergs_left;

    let low_u32 = UInt32::conditionally_select(
        cs,
        is_retrieve_ergs_left,
        &low_u32_ergs_left,
        &low_u32_to_get_sp,
    );

    // now we have context

    let mut result_128 = [low_u32, zero_u32, zero_u32, zero_u32];

    result_128 = UInt32::parallel_select(
        cs,
        is_get_context_u128,
        &draft_vm_state
            .callstack
            .current_context
            .saved_context
            .context_u128_value_composite,
        &result_128,
    );

    // then we have address-like values

    let mut result_160 = [
        result_128[0],
        result_128[1],
        result_128[2],
        result_128[3],
        zero_u32,
    ];

    result_160 = UInt32::parallel_select(
        cs,
        is_retrieve_this,
        &draft_vm_state
            .callstack
            .current_context
            .saved_context
            .this
            .inner,
        &result_160,
    );

    result_160 = UInt32::parallel_select(
        cs,
        is_retrieve_caller,
        &draft_vm_state
            .callstack
            .current_context
            .saved_context
            .caller
            .inner,
        &result_160,
    );

    result_160 = UInt32::parallel_select(
        cs,
        is_retrieve_code_address,
        &draft_vm_state
            .callstack
            .current_context
            .saved_context
            .code_address
            .inner,
        &result_160,
    );

    // and finally full register for meta

    let mut result_256 = [
        result_160[0],
        result_160[1],
        result_160[2],
        result_160[3],
        result_160[4],
        zero_u32,
        zero_u32,
        zero_u32,
    ];

    result_256 =
        UInt32::parallel_select(cs, is_retrieve_meta, &meta_as_register.inner, &result_256);

    let boolean_false = Boolean::allocated_constant(cs, false);

    let dst0 = VMRegister {
        is_pointer: boolean_false,
        value: UInt256 { inner: result_256 },
    };
    let can_write_into_memory =
        GET_THIS_ADDRESS_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION);
    diffs_accumulator
        .dst_0_values
        .push((can_write_into_memory, write_to_dst0, dst0));

    diffs_accumulator
        .context_u128_candidates
        .push((write_to_context, context_composite_to_set));
    debug_assert!(diffs_accumulator.new_tx_number.is_none());
    diffs_accumulator.new_tx_number = Some((increment_tx_counter, incremented_tx_number));
    debug_assert!(diffs_accumulator.new_ergs_per_pubdata.is_none());
    diffs_accumulator.new_ergs_per_pubdata =
        Some((set_pubdata_ergs, potentially_new_ergs_for_pubdata));
}
