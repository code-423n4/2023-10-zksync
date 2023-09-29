use boojum::cs::traits::cs::DstBuffer;
use boojum::gadgets::traits::castable::WitnessCastable;

use crate::base_structures::{
    log_query::LogQuery, vm_state::saved_context::ExecutionContextRecord,
};

use super::*;
use crate::base_structures::decommit_query::DecommitQuery;
use crate::base_structures::vm_state::GlobalContext;
use crate::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;
use crate::main_vm::opcodes::call_ret_impl::*;
use crate::main_vm::state_diffs::MAX_SPONGES_PER_CYCLE;
use crate::main_vm::witness_oracle::SynchronizedWitnessOracle;
use crate::main_vm::witness_oracle::WitnessOracle;
use arrayvec::ArrayVec;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::gadgets::traits::allocatable::CSAllocatableExt;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;

// call and ret are merged because their main part is manipulation over callstack,
// and we will keep those functions here

pub(crate) fn apply_calls_and_ret<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    W: WitnessOracle<F>,
>(
    cs: &mut CS,
    draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    opcode_carry_parts: &AfterDecodingCarryParts<F>,
    diffs_accumulator: &mut StateDiffsAccumulator<F>,
    witness_oracle: &SynchronizedWitnessOracle<F, W>,
    global_context: &GlobalContext<F>,
    round_function: &R,
) where
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    let (common_part, far_call_abi, call_ret_forwarding_mode) =
        compute_shared_abi_parts(cs, &common_opcode_state.src0_view);

    let near_call_data = callstack_candidate_for_near_call(
        cs,
        draft_vm_state,
        common_opcode_state,
        opcode_carry_parts,
        witness_oracle,
    );

    let far_call_data = callstack_candidate_for_far_call(
        cs,
        draft_vm_state,
        common_opcode_state,
        opcode_carry_parts,
        witness_oracle,
        global_context,
        &common_part,
        &far_call_abi,
        &call_ret_forwarding_mode,
        round_function,
    );

    let ret_data = callstack_candidate_for_ret(
        cs,
        draft_vm_state,
        common_opcode_state,
        opcode_carry_parts,
        witness_oracle,
        &common_part,
        &call_ret_forwarding_mode,
    );

    // select callstack that will become current

    let NearCallData {
        apply_near_call,
        old_context: old_context_for_near_call,
        new_context: new_context_for_near_call,
    } = near_call_data;

    let FarCallData {
        apply_far_call,
        old_context: old_context_for_far_call,
        new_context: new_context_for_far_call,
        new_decommittment_queue_tail,
        new_decommittment_queue_len,
        new_forward_queue_tail: new_forward_queue_state_for_far_call,
        new_forward_queue_len: new_forward_queue_len_for_far_call,

        pending_sponges: pending_sponges_for_far_call,

        specific_registers_updates: specific_registers_updates_for_far_call,
        specific_registers_zeroing: specific_registers_zeroing_for_far_call,
        remove_ptr_on_specific_registers: remove_ptr_on_specific_registers_for_far_call,

        new_memory_pages_counter,
        pending_exception: pending_exception_from_far_call,
    } = far_call_data;

    let RetData {
        apply_ret,
        is_panic: is_ret_panic,
        new_context: new_context_for_ret,
        originally_popped_context: originally_popped_context_for_ret,
        previous_callstack_state: previous_callstack_state_for_ret,
        new_forward_queue_tail: new_forward_queue_state_for_ret,
        new_forward_queue_len: new_forward_queue_len_for_ret,
        did_return_from_far_call,

        specific_registers_updates: specific_registers_updates_for_ret,
        specific_registers_zeroing: specific_registers_zeroing_for_ret,
        remove_ptr_on_specific_registers: remove_ptr_on_specific_registers_for_ret,
    } = ret_data;

    let is_call_like = Boolean::multi_or(cs, &[apply_near_call, apply_far_call]);
    let apply_any = Boolean::multi_or(cs, &[is_call_like, apply_ret]);
    let is_ret_panic_if_apply = Boolean::multi_and(cs, &[is_ret_panic, apply_ret]);
    let pending_exception_if_far_call =
        Boolean::multi_and(cs, &[pending_exception_from_far_call, apply_far_call]);

    let current_frame_is_local = draft_vm_state
        .callstack
        .current_context
        .saved_context
        .is_local_call;

    let _current_frame_is_global = current_frame_is_local.negated(cs);

    let is_far_return = Boolean::multi_and(cs, &[apply_ret, did_return_from_far_call]);
    let reset_context_value = Boolean::multi_or(cs, &[is_far_return, apply_far_call]);

    // we only need select between candidates, and later on we will select on higher level between current and candidate from (near_call/far_call/ret)

    let mut new_callstack_entry = ExecutionContextRecord::conditionally_select(
        cs,
        apply_far_call,
        &new_context_for_far_call,
        &new_context_for_near_call,
    );

    new_callstack_entry = ExecutionContextRecord::conditionally_select(
        cs,
        apply_ret,
        &new_context_for_ret,
        &new_callstack_entry,
    );

    // this one will be largely no-op
    let mut old_callstack_entry = ExecutionContextRecord::conditionally_select(
        cs,
        apply_far_call,
        &old_context_for_far_call,
        &old_context_for_near_call,
    );

    old_callstack_entry = ExecutionContextRecord::conditionally_select(
        cs,
        apply_ret,
        &originally_popped_context_for_ret,
        &old_callstack_entry,
    );

    // manual implementation of the stack: we either take a old entry and hash along with the saved context for call-like, or one popped in case of ret

    let initial_state_to_use_for_sponge = Num::parallel_select(
        cs,
        apply_ret,
        &previous_callstack_state_for_ret,
        &draft_vm_state.callstack.stack_sponge_state,
    );

    // now we simulate absorb. Note that we have already chosen an initial state,
    // so we just use initial state and absorb

    let mut current_state = initial_state_to_use_for_sponge.map(|el| el.get_variable());
    use boojum::gadgets::traits::encodable::CircuitEncodable;

    let encoded_execution_record = old_callstack_entry.encode(cs);

    use boojum::gadgets::round_function::simulate_round_function;

    // absorb by replacement
    let round_0_initial = [
        encoded_execution_record[0],
        encoded_execution_record[1],
        encoded_execution_record[2],
        encoded_execution_record[3],
        encoded_execution_record[4],
        encoded_execution_record[5],
        encoded_execution_record[6],
        encoded_execution_record[7],
        current_state[8],
        current_state[9],
        current_state[10],
        current_state[11],
    ];

    let round_0_final =
        simulate_round_function::<_, _, 8, 12, 4, R>(cs, round_0_initial, apply_any);

    current_state = round_0_final;

    let round_1_initial = [
        encoded_execution_record[8],
        encoded_execution_record[9],
        encoded_execution_record[10],
        encoded_execution_record[11],
        encoded_execution_record[12],
        encoded_execution_record[13],
        encoded_execution_record[14],
        encoded_execution_record[15],
        current_state[8],
        current_state[9],
        current_state[10],
        current_state[11],
    ];

    let round_1_final =
        simulate_round_function::<_, _, 8, 12, 4, R>(cs, round_1_initial, apply_any);

    current_state = round_1_final;

    let round_2_initial = [
        encoded_execution_record[16],
        encoded_execution_record[17],
        encoded_execution_record[18],
        encoded_execution_record[19],
        encoded_execution_record[20],
        encoded_execution_record[21],
        encoded_execution_record[22],
        encoded_execution_record[23],
        current_state[8],
        current_state[9],
        current_state[10],
        current_state[11],
    ];

    let round_2_final =
        simulate_round_function::<_, _, 8, 12, 4, R>(cs, round_2_initial, apply_any);

    current_state = round_2_final;

    let round_3_initial = [
        encoded_execution_record[24],
        encoded_execution_record[25],
        encoded_execution_record[26],
        encoded_execution_record[27],
        encoded_execution_record[28],
        encoded_execution_record[29],
        encoded_execution_record[30],
        encoded_execution_record[31],
        current_state[8],
        current_state[9],
        current_state[10],
        current_state[11],
    ];

    let round_3_final =
        simulate_round_function::<_, _, 8, 12, 4, R>(cs, round_3_initial, apply_any);

    current_state = round_3_final;

    let potential_final_state = current_state.map(|el| Num::from_variable(el));

    for (a, b) in potential_final_state
        .iter()
        .zip(draft_vm_state.callstack.stack_sponge_state.iter())
    {
        Num::conditionally_enforce_equal(cs, apply_ret, a, b);
    }

    let new_callstack_state = Num::parallel_select(
        cs,
        apply_ret,
        &previous_callstack_state_for_ret,
        &potential_final_state,
    );

    let depth_increased = unsafe {
        draft_vm_state
            .callstack
            .context_stack_depth
            .increment_unchecked(cs)
    };
    let one_u32 = UInt32::allocated_constant(cs, 1);
    let (depth_decreased, uf) = draft_vm_state
        .callstack
        .context_stack_depth
        .overflowing_sub(cs, one_u32);

    uf.conditionally_enforce_false(cs, apply_ret);

    let new_callstack_depth =
        UInt32::conditionally_select(cs, apply_ret, &depth_decreased, &depth_increased);

    // assemble a new callstack in full

    let new_log_queue_forward_tail = Num::parallel_select(
        cs,
        apply_ret,
        &new_forward_queue_state_for_ret,
        &new_forward_queue_state_for_far_call,
    );

    let new_log_queue_forward_len = UInt32::conditionally_select(
        cs,
        apply_ret,
        &new_forward_queue_len_for_ret,
        &new_forward_queue_len_for_far_call,
    );

    use crate::base_structures::vm_state::callstack::FullExecutionContext;

    let new_context = FullExecutionContext {
        saved_context: new_callstack_entry,
        log_queue_forward_tail: new_log_queue_forward_tail,
        log_queue_forward_part_length: new_log_queue_forward_len,
    };

    use crate::base_structures::vm_state::callstack::Callstack;

    let new_callstack = Callstack {
        current_context: new_context,
        context_stack_depth: new_callstack_depth,
        stack_sponge_state: new_callstack_state,
    };

    let mut common_relations_buffer = ArrayVec::<
        (
            Boolean<F>,
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
        ),
        MAX_SPONGES_PER_CYCLE,
    >::new();
    // first we push relations that are common, namely callstack sponge

    common_relations_buffer.push((
        apply_any,
        round_0_initial.map(|el| Num::from_variable(el)),
        round_0_final.map(|el| Num::from_variable(el)),
    ));

    common_relations_buffer.push((
        apply_any,
        round_1_initial.map(|el| Num::from_variable(el)),
        round_1_final.map(|el| Num::from_variable(el)),
    ));

    common_relations_buffer.push((
        apply_any,
        round_2_initial.map(|el| Num::from_variable(el)),
        round_2_final.map(|el| Num::from_variable(el)),
    ));

    common_relations_buffer.push((
        apply_any,
        round_3_initial.map(|el| Num::from_variable(el)),
        round_3_final.map(|el| Num::from_variable(el)),
    ));

    // and now we append relations for far call, that are responsible for storage read and decommittment
    common_relations_buffer.extend(pending_sponges_for_far_call);

    // now just append relations to select later on

    // all the opcodes reset flags in full
    let mut new_flags = common_opcode_state.reseted_flags;
    new_flags.overflow_or_less_than = is_ret_panic_if_apply;

    // report to witness oracle
    let oracle = witness_oracle.clone();
    // we should assemble all the dependencies here, and we will use AllocateExt here
    let mut dependencies = Vec::with_capacity(
        <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 3,
    );
    dependencies.push(apply_any.get_variable().into());
    dependencies.push(is_call_like.get_variable().into());
    dependencies.push(new_callstack_depth.get_variable().into());
    dependencies.extend(Place::from_variables(
        new_callstack_entry.flatten_as_variables(),
    ));

    cs.set_values_with_dependencies_vararg(
        &dependencies,
        &[],
        move |inputs: &[F], _buffer: &mut DstBuffer<'_, '_, F>| {
            let execute = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
            let is_call_like = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[1]);
            let new_depth = <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[2]);

            let mut query =
                [F::ZERO; <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN];
            query.copy_from_slice(&inputs[3..]);
            use crate::base_structures::vm_state::saved_context::ExecutionContextRecordWitness;
            let query: ExecutionContextRecordWitness<F> =
                CSAllocatableExt::witness_from_set_of_values(query);

            let mut guard = oracle.inner.write().expect("not poisoned");
            guard.report_new_callstack_frame(&query, new_depth, is_call_like, execute);
            drop(guard);
        },
    );

    // add everything to state diffs

    // we should check that opcode can not use src0/dst0 in memory
    const FAR_CALL_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::FarCall(zkevm_opcode_defs::FarCallOpcode::Normal);
    const NEAR_CALL_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::NearCall(zkevm_opcode_defs::NearCallOpcode);
    const RET_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Ret(zkevm_opcode_defs::RetOpcode::Ok);

    assert!(FAR_CALL_OPCODE.can_have_src0_from_mem(SUPPORTED_ISA_VERSION) == false);
    assert!(NEAR_CALL_OPCODE.can_have_src0_from_mem(SUPPORTED_ISA_VERSION) == false);
    assert!(RET_OPCODE.can_have_src0_from_mem(SUPPORTED_ISA_VERSION) == false);

    assert!(FAR_CALL_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION) == false);
    assert!(NEAR_CALL_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION) == false);
    assert!(RET_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION) == false);

    diffs_accumulator.sponge_candidates_to_run.push((
        false,
        false,
        apply_any,
        common_relations_buffer,
    ));
    diffs_accumulator.flags.push((apply_any, new_flags));

    // each opcode may have different register updates
    for (idx, el) in specific_registers_updates_for_far_call
        .into_iter()
        .enumerate()
    {
        if let Some(el) = el {
            diffs_accumulator.specific_registers_updates[idx].push(el);
        }
    }

    for (idx, el) in specific_registers_updates_for_ret.into_iter().enumerate() {
        if let Some(el) = el {
            diffs_accumulator.specific_registers_updates[idx].push(el);
        }
    }

    // same for zeroing out and removing ptr markers
    for (idx, el) in specific_registers_zeroing_for_far_call
        .into_iter()
        .enumerate()
    {
        if let Some(el) = el {
            diffs_accumulator.specific_registers_zeroing[idx].push(el);
        }
    }

    for (idx, el) in specific_registers_zeroing_for_ret.into_iter().enumerate() {
        if let Some(el) = el {
            diffs_accumulator.specific_registers_zeroing[idx].push(el);
        }
    }

    for (idx, el) in remove_ptr_on_specific_registers_for_far_call
        .into_iter()
        .enumerate()
    {
        if let Some(el) = el {
            diffs_accumulator.remove_ptr_on_specific_registers[idx].push(el);
        }
    }

    for (idx, el) in remove_ptr_on_specific_registers_for_ret
        .into_iter()
        .enumerate()
    {
        if let Some(el) = el {
            diffs_accumulator.remove_ptr_on_specific_registers[idx].push(el);
        }
    }

    // pending exception if any
    diffs_accumulator
        .pending_exceptions
        .push(pending_exception_if_far_call);

    // callstacks in full
    diffs_accumulator
        .callstacks
        .push((apply_any, new_callstack));

    // far call already chosen it
    debug_assert!(diffs_accumulator.memory_page_counters.is_none());
    diffs_accumulator.memory_page_counters = Some(new_memory_pages_counter);

    let zero_u32 = UInt32::zero(cs);
    let empty_context_value = [zero_u32; 4];

    diffs_accumulator
        .context_u128_candidates
        .push((reset_context_value, empty_context_value));

    debug_assert!(diffs_accumulator.decommitment_queue_candidates.is_none());
    diffs_accumulator.decommitment_queue_candidates = Some((
        apply_far_call,
        new_decommittment_queue_len,
        new_decommittment_queue_tail,
    ));
}
