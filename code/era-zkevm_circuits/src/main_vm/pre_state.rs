use cs_derive::*;

use super::witness_oracle::{SynchronizedWitnessOracle, WitnessOracle};
use super::*;

use crate::base_structures::register::VMRegister;
use crate::base_structures::vm_state::{ArithmeticFlagsPort, FULL_SPONGE_QUEUE_STATE_WIDTH};
use crate::main_vm::decoded_opcode::OpcodePropertiesDecoding;
use crate::main_vm::register_input_view::RegisterInputView;
use crate::main_vm::utils::*;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::num::Num;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::u16::UInt16;
use boojum::gadgets::u256::UInt256;
use boojum::gadgets::u32::UInt32;
use boojum::serde_utils::BigArraySerde;

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Debug)]
pub struct CommonOpcodeState<F: SmallField> {
    pub reseted_flags: ArithmeticFlagsPort<F>,
    pub current_flags: ArithmeticFlagsPort<F>,
    pub decoded_opcode: OpcodePropertiesDecoding<F>,
    pub src0: VMRegister<F>,
    pub src1: VMRegister<F>,
    pub src0_view: RegisterInputView<F>,
    pub src1_view: RegisterInputView<F>,
    pub timestamp_for_code_or_src_read: UInt32<F>,
    pub timestamp_for_first_decommit_or_precompile_read: UInt32<F>,
    pub timestamp_for_second_decommit_or_precompile_write: UInt32<F>,
    pub timestamp_for_dst_write: UInt32<F>,
}

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct MemoryLocation<F: SmallField> {
    pub page: UInt32<F>,
    pub index: UInt32<F>,
}

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Debug)]
pub struct AfterDecodingCarryParts<F: SmallField> {
    pub did_skip_cycle: Boolean<F>,
    pub heap_page: UInt32<F>,
    pub aux_heap_page: UInt32<F>,
    pub next_pc: UInt16<F>,
    pub preliminary_ergs_left: UInt32<F>,
    pub src0_read_sponge_data: PendingSponge<F>,
    pub dst0_memory_location: MemoryLocation<F>,
    pub dst0_performs_memory_access: Boolean<F>,
}

#[derive(Derivative, CSAllocatable, CSSelectable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct PendingSponge<F: SmallField> {
    pub initial_state: [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    pub final_state: [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    pub should_enforce: Boolean<F>,
}

use crate::base_structures::vm_state::VmLocalState;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;

// create a draft candidate for next VM state, as well as all the data required for
// opcodes to proceed
pub fn create_prestate<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    W: WitnessOracle<F>,
>(
    cs: &mut CS,
    current_state: VmLocalState<F>,
    witness_oracle: &SynchronizedWitnessOracle<F, W>,
    round_function: &R,
) -> (
    VmLocalState<F>,
    CommonOpcodeState<F>,
    AfterDecodingCarryParts<F>,
) {
    let mut current_state = current_state;

    let execution_has_ended = current_state.callstack.is_empty(cs);
    let should_skip_cycle = execution_has_ended;
    let pending_exception = current_state.pending_exception;
    let execute_cycle = should_skip_cycle.negated(cs);

    if crate::config::CIRCUIT_VERSOBE {
        dbg!(execution_has_ended.witness_hook(&*cs)().unwrap());
    }

    // we should even try to perform a read only if we have something to do this cycle
    let should_try_to_read_opcode = execute_cycle.mask_negated(cs, pending_exception);

    let execute_pending_exception_at_this_cycle = pending_exception;

    // take down the flag
    current_state.pending_exception = current_state
        .pending_exception
        .mask_negated(cs, execute_pending_exception_at_this_cycle);

    let current_pc = current_state.callstack.current_context.saved_context.pc;

    let one_u16 = UInt16::allocated_constant(cs, 1);

    let (pc_plus_one, _) = current_pc.overflowing_add(cs, &one_u16);

    let (super_pc, subpc_spread) = split_pc(cs, current_pc);
    let previous_super_pc = current_state.previous_super_pc;

    let should_read_for_new_pc = should_read_memory(
        cs,
        current_state.previous_code_page,
        current_state
            .callstack
            .current_context
            .saved_context
            .code_page,
        super_pc,
        previous_super_pc,
    );

    let should_read_opcode =
        Boolean::multi_and(cs, &[should_try_to_read_opcode, should_read_for_new_pc]);

    // and in addition if we did finish execution then we never care and cleanup

    let location = MemoryLocation {
        page: current_state
            .callstack
            .current_context
            .saved_context
            .code_page,
        index: unsafe { UInt32::from_variable_unchecked(super_pc.get_variable()) },
    };

    // precompute timestamps
    let timestamp_for_code_or_src_read = current_state.timestamp;
    let timestamp_for_first_decommit_or_precompile_read =
        unsafe { timestamp_for_code_or_src_read.increment_unchecked(cs) };
    let timestamp_for_second_decommit_or_precompile_write =
        unsafe { timestamp_for_first_decommit_or_precompile_read.increment_unchecked(cs) };
    let timestamp_for_dst_write =
        unsafe { timestamp_for_second_decommit_or_precompile_write.increment_unchecked(cs) };
    let next_cycle_timestamp = unsafe { timestamp_for_dst_write.increment_unchecked(cs) };
    let next_cycle_timestamp = UInt32::conditionally_select(
        cs,
        should_skip_cycle,
        &current_state.timestamp,
        &next_cycle_timestamp,
    );

    // we can hardly make a judgement of using or not this sponge
    // for optimization purposes, so we will assume that we always run it

    let (mut code_word, (new_memory_queue_state, new_memory_queue_length)) =
        may_be_read_memory_for_code(
            cs,
            should_read_opcode,
            timestamp_for_code_or_src_read,
            location,
            current_state.memory_queue_state,
            current_state.memory_queue_length,
            round_function,
            witness_oracle,
        );

    // update current state
    current_state.memory_queue_length = new_memory_queue_length;
    current_state.memory_queue_state = new_memory_queue_state;

    code_word = UInt256::conditionally_select(
        cs,
        should_read_opcode,
        &code_word,
        &current_state.previous_code_word,
    );

    // subpc is 2 bits, so it's a range from 0 to 3. 1..=3 are bitspread via the table
    let subpc_bitmask = subpc_spread.spread_into_bits::<_, 3>(cs);

    // default one is one corresponding to the "highest" bytes in 32 byte word in our BE machine
    let opcode = [code_word.inner[6], code_word.inner[7]];
    let opcode = <[UInt32<F>; 2]>::conditionally_select(
        cs,
        subpc_bitmask[0],
        &[code_word.inner[4], code_word.inner[5]],
        &opcode,
    );
    let opcode = <[UInt32<F>; 2]>::conditionally_select(
        cs,
        subpc_bitmask[1],
        &[code_word.inner[2], code_word.inner[3]],
        &opcode,
    );
    let opcode = <[UInt32<F>; 2]>::conditionally_select(
        cs,
        subpc_bitmask[2],
        &[code_word.inner[0], code_word.inner[1]],
        &opcode,
    );

    if crate::config::CIRCUIT_VERSOBE {
        if should_skip_cycle.witness_hook(&*cs)().unwrap() {
            println!("Skipping cycle");
        }
        if execute_pending_exception_at_this_cycle.witness_hook(&*cs)().unwrap() {
            println!("Executing pending exception");
        }
    }

    // mask if we would be ok with NOPing. This masks a full 8-byte opcode, and not properties bitspread
    // We mask if this cycle is just NOPing till the end of circuit
    let opcode = mask_into_nop(cs, should_skip_cycle, opcode);
    // if we are not pending, and we have an exception to run - run it
    let opcode = mask_into_panic(cs, execute_pending_exception_at_this_cycle, opcode);

    // update super_pc and code words if we did read
    current_state.previous_code_word = code_word;
    // always update code page
    current_state.previous_code_page = current_state
        .callstack
        .current_context
        .saved_context
        .code_page;
    current_state.callstack.current_context.saved_context.pc = UInt16::conditionally_select(
        cs,
        should_skip_cycle,
        &current_state.callstack.current_context.saved_context.pc,
        &pc_plus_one,
    );

    current_state.previous_super_pc = UInt16::conditionally_select(
        cs,
        should_skip_cycle,
        &current_state.previous_super_pc,
        &super_pc,
    ); // may be it can be unconditional

    // update timestamp
    current_state.timestamp = next_cycle_timestamp;

    let is_kernel_mode = current_state
        .callstack
        .current_context
        .saved_context
        .is_kernel_mode;
    let is_static_context = current_state
        .callstack
        .current_context
        .saved_context
        .is_static_execution;
    let callstack_is_full = current_state.callstack.is_full(cs);
    let ergs_left = current_state
        .callstack
        .current_context
        .saved_context
        .ergs_remaining;

    use crate::main_vm::decoded_opcode::encode_flags;

    let encoded_flags = encode_flags(cs, &current_state.flags);

    use crate::main_vm::decoded_opcode::perform_initial_decoding;

    let (decoded_opcode, dirty_ergs_left) = perform_initial_decoding(
        cs,
        opcode,
        encoded_flags,
        is_kernel_mode,
        is_static_context,
        callstack_is_full,
        ergs_left,
        should_skip_cycle,
    );

    // decoded opcode and current (yet dirty) ergs left should be passed into the opcode,
    // but by default we set it into context that is true for most of the opcodes
    current_state
        .callstack
        .current_context
        .saved_context
        .ergs_remaining = dirty_ergs_left;

    // we did all the masking and "INVALID" opcode must never happed
    let invalid_opcode_bit =
        decoded_opcode
            .properties_bits
            .boolean_for_opcode(zkevm_opcode_defs::Opcode::Invalid(
                zkevm_opcode_defs::InvalidOpcode,
            ));

    let boolean_false = Boolean::allocated_constant(cs, false);
    Boolean::enforce_equal(cs, &invalid_opcode_bit, &boolean_false);

    // now read source operands
    // select low part of the registers
    let mut draft_src0 = VMRegister::<F>::zero(cs);
    for (mask_bit, register) in decoded_opcode.src_regs_selectors[0]
        .iter()
        .zip(current_state.registers.iter())
    {
        draft_src0 = VMRegister::conditionally_select(cs, *mask_bit, &register, &draft_src0);
    }
    let src0_reg_lowest = draft_src0.value.inner[0].low_u16(cs);

    let mut src1_register = VMRegister::<F>::zero(cs);
    for (mask_bit, register) in decoded_opcode.src_regs_selectors[1]
        .iter()
        .zip(current_state.registers.iter())
    {
        src1_register = VMRegister::conditionally_select(cs, *mask_bit, &register, &src1_register);
    }

    let mut current_dst0_reg_low = UInt32::<F>::zero(cs);
    for (mask_bit, register) in decoded_opcode.dst_regs_selectors[0]
        .iter()
        .zip(current_state.registers.iter())
    {
        let reg_low = register.value.inner[0];
        current_dst0_reg_low =
            UInt32::conditionally_select(cs, *mask_bit, &reg_low, &current_dst0_reg_low);
    }
    let dst0_reg_lowest = current_dst0_reg_low.low_u16(cs);

    let current_sp = current_state.callstack.current_context.saved_context.sp;
    let code_page = current_state
        .callstack
        .current_context
        .saved_context
        .code_page;
    let base_page = current_state
        .callstack
        .current_context
        .saved_context
        .base_page;
    let stack_page = unsafe { base_page.increment_unchecked(cs) };
    let heap_page = unsafe { stack_page.increment_unchecked(cs) };
    let aux_heap_page = unsafe { heap_page.increment_unchecked(cs) };

    if crate::config::CIRCUIT_VERSOBE {
        dbg!(decoded_opcode.imm0.witness_hook(&*cs)().unwrap());
        dbg!(decoded_opcode.imm1.witness_hook(&*cs)().unwrap());
    }

    let (memory_location_for_src0, new_sp_after_src0, should_read_memory_for_src0) =
        resolve_memory_region_and_index_for_source(
            cs,
            code_page,
            stack_page,
            src0_reg_lowest,
            &decoded_opcode,
            current_sp,
        );

    let (memory_location_for_dst0, new_sp, should_write_memory_for_dst0) =
        resolve_memory_region_and_index_for_dest(
            cs,
            stack_page,
            dst0_reg_lowest,
            &decoded_opcode,
            new_sp_after_src0,
        );

    current_state.callstack.current_context.saved_context.sp = new_sp;

    // perform actual read

    let (
        src0_register_from_mem,
        (
            initial_state_src0_read_sponge,
            final_state_src0_read_sponge,
            new_memory_queue_length,
            should_use_src0_read_sponge,
        ),
    ) = may_be_read_memory_for_source_operand(
        cs,
        should_read_memory_for_src0,
        timestamp_for_code_or_src_read,
        memory_location_for_src0,
        current_state.memory_queue_state,
        current_state.memory_queue_length,
        round_function,
        witness_oracle,
    );

    // update current state
    current_state.memory_queue_length = new_memory_queue_length;
    current_state.memory_queue_state = final_state_src0_read_sponge;

    // select source0 and source1

    use zkevm_opcode_defs::ImmMemHandlerFlags;

    // select if it was reg
    let use_reg = decoded_opcode
        .properties_bits
        .boolean_for_src_mem_access(ImmMemHandlerFlags::UseRegOnly);
    let src0 = VMRegister::conditionally_select(cs, use_reg, &draft_src0, &src0_register_from_mem);

    // select if it was imm
    let imm_as_reg = VMRegister::from_imm(cs, decoded_opcode.imm0);
    let use_imm = decoded_opcode
        .properties_bits
        .boolean_for_src_mem_access(ImmMemHandlerFlags::UseImm16Only);
    let src0 = VMRegister::conditionally_select(cs, use_imm, &imm_as_reg, &src0);

    // form an intermediate state to process the opcodes over it
    let next_pc = pc_plus_one;

    // swap operands
    let swap_operands = {
        use zkevm_opcode_defs::*;

        let is_sub = decoded_opcode
            .properties_bits
            .boolean_for_opcode(Opcode::Sub(SubOpcode::Sub));
        let is_div = decoded_opcode
            .properties_bits
            .boolean_for_opcode(Opcode::Div(DivOpcode));
        let is_shift = decoded_opcode
            .properties_bits
            .boolean_for_opcode(Opcode::Shift(ShiftOpcode::Rol));

        let is_assymmetric = Boolean::multi_or(cs, &[is_sub, is_div, is_shift]);
        let swap_flag =
            decoded_opcode.properties_bits.flag_booleans[SWAP_OPERANDS_FLAG_IDX_FOR_ARITH_OPCODES];

        let t0 = Boolean::multi_and(cs, &[is_assymmetric, swap_flag]);

        let is_ptr = decoded_opcode
            .properties_bits
            .boolean_for_opcode(Opcode::Ptr(PtrOpcode::Add));
        let swap_flag =
            decoded_opcode.properties_bits.flag_booleans[SWAP_OPERANDS_FLAG_IDX_FOR_PTR_OPCODE];

        let t1 = Boolean::multi_and(cs, &[is_ptr, swap_flag]);

        Boolean::multi_or(cs, &[t0, t1])
    };

    let selected_src0 = src0;
    let selected_src1 = src1_register;

    let src0 = VMRegister::conditionally_select(cs, swap_operands, &selected_src1, &selected_src0);
    let src1 = VMRegister::conditionally_select(cs, swap_operands, &selected_src0, &selected_src1);

    let src0_view = RegisterInputView::from_input_value(cs, &src0);
    let src1_view = RegisterInputView::from_input_value(cs, &src1);

    let empty_flags = ArithmeticFlagsPort::reseted_flags(cs);

    let common_opcode_state = CommonOpcodeState {
        reseted_flags: empty_flags,
        current_flags: current_state.flags,
        decoded_opcode: decoded_opcode,
        src0,
        src1,
        src0_view,
        src1_view,
        timestamp_for_code_or_src_read,
        timestamp_for_first_decommit_or_precompile_read,
        timestamp_for_second_decommit_or_precompile_write,
        timestamp_for_dst_write,
    };

    let carry_parts = AfterDecodingCarryParts {
        did_skip_cycle: should_skip_cycle,
        next_pc,
        src0_read_sponge_data: PendingSponge {
            initial_state: initial_state_src0_read_sponge,
            final_state: final_state_src0_read_sponge,
            should_enforce: should_use_src0_read_sponge,
        },
        dst0_memory_location: memory_location_for_dst0,
        dst0_performs_memory_access: should_write_memory_for_dst0,
        preliminary_ergs_left: dirty_ergs_left,
        heap_page,
        aux_heap_page,
    };

    (current_state, common_opcode_state, carry_parts)
}
