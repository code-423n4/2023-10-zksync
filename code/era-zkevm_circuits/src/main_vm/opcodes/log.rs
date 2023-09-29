use boojum::gadgets::u256::UInt256;

use crate::base_structures::{
    log_query::{self, LogQuery, LOG_QUERY_PACKED_WIDTH, ROLLBACK_PACKING_FLAG_VARIABLE_IDX},
    register::VMRegister,
};

use super::*;
use crate::main_vm::opcodes::log::log_query::LogQueryWitness;
use crate::main_vm::witness_oracle::SynchronizedWitnessOracle;
use crate::main_vm::witness_oracle::WitnessOracle;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::gadgets::traits::allocatable::CSAllocatableExt;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;

pub(crate) fn apply_log<
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
    round_function: &R,
) where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    const STORAGE_READ_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Log(LogOpcode::StorageRead);
    const STORAGE_WRITE_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Log(LogOpcode::StorageWrite);
    const L1_MESSAGE_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Log(LogOpcode::ToL1Message);
    const EVENT_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Log(LogOpcode::Event);
    const PRECOMPILE_CALL_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Log(LogOpcode::PrecompileCall);

    let should_apply = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(STORAGE_READ_OPCODE);

    let is_storage_read = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(STORAGE_READ_OPCODE)
    };
    let is_storage_write = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(STORAGE_WRITE_OPCODE)
    };
    let is_event = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(EVENT_OPCODE)
    };
    let is_l1_message = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(L1_MESSAGE_OPCODE)
    };
    let is_precompile = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .boolean_for_variant(PRECOMPILE_CALL_OPCODE)
    };

    if crate::config::CIRCUIT_VERSOBE {
        if should_apply.witness_hook(&*cs)().unwrap_or(false) {
            println!("Applying LOG");
            if is_storage_read.witness_hook(&*cs)().unwrap_or(false) {
                println!("SLOAD");
            }
            if is_storage_write.witness_hook(&*cs)().unwrap_or(false) {
                println!("SSTORE");
            }
            if is_event.witness_hook(&*cs)().unwrap_or(false) {
                println!("EVENT");
            }
            if is_l1_message.witness_hook(&*cs)().unwrap_or(false) {
                println!("L2 to L1 message");
            }
            if is_precompile.witness_hook(&*cs)().unwrap_or(false) {
                println!("PRECOMPILECALL");
            }
        }
    }

    let address = draft_vm_state.callstack.current_context.saved_context.this;

    let mut key = UInt256 {
        inner: common_opcode_state.src0_view.u32x8_view,
    };
    let written_value = UInt256 {
        inner: common_opcode_state.src1_view.u32x8_view,
    };

    // modify the key by replacing parts for precompile call
    let precompile_memory_page_to_read = opcode_carry_parts.heap_page;
    let precompile_memory_page_to_write = opcode_carry_parts.heap_page;
    // replace bits 128..160 and 160..192
    key.inner[4] = UInt32::conditionally_select(
        cs,
        is_precompile,
        &precompile_memory_page_to_read,
        &key.inner[4],
    );
    key.inner[5] = UInt32::conditionally_select(
        cs,
        is_precompile,
        &precompile_memory_page_to_write,
        &key.inner[5],
    );

    use zkevm_opcode_defs::system_params::{
        INITIAL_STORAGE_WRITE_PUBDATA_BYTES, L1_MESSAGE_PUBDATA_BYTES,
    };

    let is_rollup = draft_vm_state
        .callstack
        .current_context
        .saved_context
        .this_shard_id
        .is_zero(cs);
    let write_to_rollup = Boolean::multi_and(cs, &[is_rollup, is_storage_write]);

    let emit_l1_message = is_l1_message;

    let l1_message_pubdata_bytes_constnt =
        UInt32::allocated_constant(cs, L1_MESSAGE_PUBDATA_BYTES as u32);
    let ergs_to_burn_for_l1_message = draft_vm_state
        .ergs_per_pubdata_byte
        .non_widening_mul(cs, &l1_message_pubdata_bytes_constnt);

    let ergs_to_burn_for_precompile_call = common_opcode_state.src1_view.u32x8_view[0];

    let is_storage_access = Boolean::multi_or(cs, &[is_storage_read, is_storage_write]);
    let is_nonrevertable = Boolean::multi_or(cs, &[is_storage_read, is_precompile]);
    let is_revertable = is_nonrevertable.negated(cs);

    let aux_byte_variable = Num::linear_combination(
        cs,
        &[
            (
                is_storage_access.get_variable(),
                F::from_u64_unchecked(zkevm_opcode_defs::system_params::STORAGE_AUX_BYTE as u64),
            ),
            (
                is_event.get_variable(),
                F::from_u64_unchecked(zkevm_opcode_defs::system_params::EVENT_AUX_BYTE as u64),
            ),
            (
                is_l1_message.get_variable(),
                F::from_u64_unchecked(zkevm_opcode_defs::system_params::L1_MESSAGE_AUX_BYTE as u64),
            ),
            (
                is_precompile.get_variable(),
                F::from_u64_unchecked(zkevm_opcode_defs::system_params::PRECOMPILE_AUX_BYTE as u64),
            ),
        ],
    )
    .get_variable();

    let aux_byte = unsafe { UInt8::from_variable_unchecked(aux_byte_variable) };
    let timestamp = common_opcode_state.timestamp_for_first_decommit_or_precompile_read;

    let shard_id = draft_vm_state
        .callstack
        .current_context
        .saved_context
        .this_shard_id;

    // NOTE: our opcodes encoding guarantees that there is no "storage read + is first"
    // variant encodable
    let is_event_init = {
        common_opcode_state
            .decoded_opcode
            .properties_bits
            .flag_booleans[FIRST_MESSAGE_FLAG_IDX]
    };

    let zero_u256 = UInt256::zero(cs);
    let boolean_false = Boolean::allocated_constant(cs, false);
    let tx_number = draft_vm_state.tx_number_in_block;

    let mut log = LogQuery {
        address,
        key,
        read_value: zero_u256,
        written_value,
        rw_flag: is_revertable,
        aux_byte,
        rollback: boolean_false,
        is_service: is_event_init,
        shard_id,
        tx_number_in_block: tx_number,
        timestamp,
    };

    let oracle = witness_oracle.clone();
    // we should assemble all the dependencies here, and we will use AllocateExt here
    let mut dependencies =
        Vec::with_capacity(<LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 2);
    dependencies.push(is_storage_write.get_variable().into());
    dependencies.push(should_apply.get_variable().into());
    dependencies.extend(Place::from_variables(log.flatten_as_variables()));

    let pubdata_refund = UInt32::allocate_from_closure_and_dependencies(
        cs,
        move |inputs: &[F]| {
            let is_write = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
            let execute = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[1]);
            let mut log_query =
                [F::ZERO; <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN];
            log_query.copy_from_slice(&inputs[2..]);
            let log_query: LogQueryWitness<F> =
                CSAllocatableExt::witness_from_set_of_values(log_query);

            let mut guard = oracle.inner.write().expect("not poisoned");
            let witness = guard.get_refunds(&log_query, is_write, execute);
            drop(guard);

            witness
        },
        &dependencies,
    );

    let initial_storage_write_pubdata_bytes =
        UInt32::allocated_constant(cs, INITIAL_STORAGE_WRITE_PUBDATA_BYTES as u32);
    let net_cost = initial_storage_write_pubdata_bytes.sub_no_overflow(cs, pubdata_refund);

    let ergs_to_burn_for_rollup_storage_write = draft_vm_state
        .ergs_per_pubdata_byte
        .non_widening_mul(cs, &net_cost);

    let zero_u32 = UInt32::allocated_constant(cs, 0);

    // now we know net cost
    let ergs_to_burn = UInt32::conditionally_select(
        cs,
        write_to_rollup,
        &ergs_to_burn_for_rollup_storage_write,
        &zero_u32,
    );
    let ergs_to_burn = UInt32::conditionally_select(
        cs,
        is_precompile,
        &ergs_to_burn_for_precompile_call,
        &ergs_to_burn,
    );
    let ergs_to_burn = UInt32::conditionally_select(
        cs,
        emit_l1_message,
        &ergs_to_burn_for_l1_message,
        &ergs_to_burn,
    );

    let (ergs_remaining, uf) = opcode_carry_parts
        .preliminary_ergs_left
        .overflowing_sub(cs, ergs_to_burn);
    let not_enough_ergs_for_op = uf;

    // if not enough then leave only 0
    let ergs_remaining = ergs_remaining.mask_negated(cs, not_enough_ergs_for_op);
    let have_enough_ergs = not_enough_ergs_for_op.negated(cs);

    let execute_either_in_practice = Boolean::multi_and(cs, &[should_apply, have_enough_ergs]);

    let oracle = witness_oracle.clone();
    // we should assemble all the dependencies here, and we will use AllocateExt here
    let mut dependencies =
        Vec::with_capacity(<LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 2);
    dependencies.push(is_storage_access.get_variable().into());
    dependencies.push(execute_either_in_practice.get_variable().into());
    dependencies.extend(Place::from_variables(log.flatten_as_variables()));

    // we always access witness, as even for writes we have to get a claimed read value!
    let read_value = UInt256::allocate_from_closure_and_dependencies(
        cs,
        move |inputs: &[F]| {
            let is_storage = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
            let execute = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[1]);
            let mut log_query =
                [F::ZERO; <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN];
            log_query.copy_from_slice(&inputs[2..]);
            let log_query: LogQueryWitness<F> =
                CSAllocatableExt::witness_from_set_of_values(log_query);

            let mut guard = oracle.inner.write().expect("not poisoned");
            let witness = guard.get_storage_read_witness(&log_query, is_storage, execute);
            drop(guard);

            witness
        },
        &dependencies,
    );

    let u256_zero = UInt256::zero(cs);

    let read_value = UInt256::conditionally_select(cs, is_storage_access, &read_value, &u256_zero);
    log.read_value = read_value.clone();
    // if we read then use the same value - convension!
    log.written_value =
        UInt256::conditionally_select(cs, log.rw_flag, &log.written_value, &log.read_value);

    use boojum::gadgets::traits::encodable::CircuitEncodable;
    let packed_log_forward = log.encode(cs);

    let mut packed_log_rollback = packed_log_forward;
    LogQuery::update_packing_for_rollback(cs, &mut packed_log_rollback);

    let execute_rollback = Boolean::multi_and(cs, &[execute_either_in_practice, is_revertable]);

    let current_forward_tail = draft_vm_state
        .callstack
        .current_context
        .log_queue_forward_tail;
    let current_rollback_head = draft_vm_state
        .callstack
        .current_context
        .saved_context
        .reverted_queue_head;

    let oracle = witness_oracle.clone();
    let mut dependencies =
        Vec::with_capacity(<LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1);
    dependencies.push(execute_rollback.get_variable().into());
    dependencies.extend(Place::from_variables(log.flatten_as_variables()));

    let prev_revert_head_witness = Num::allocate_multiple_from_closure_and_dependencies(
        cs,
        move |inputs: &[F]| {
            let execute_rollback = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
            let mut log_query =
                [F::ZERO; <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN];
            log_query.copy_from_slice(&inputs[1..]);
            let log_query: LogQueryWitness<F> =
                CSAllocatableExt::witness_from_set_of_values(log_query);

            let mut guard = oracle.inner.write().expect("not poisoned");
            let witness = guard.get_rollback_queue_witness(&log_query, execute_rollback);
            drop(guard);

            witness
        },
        &dependencies,
    );

    let (new_forward_queue_tail, new_rollback_queue_head, relations) =
        construct_hash_relations_for_log_and_new_queue_states(
            cs,
            &packed_log_forward,
            &packed_log_rollback,
            &current_forward_tail,
            &prev_revert_head_witness,
            &current_rollback_head,
            &execute_either_in_practice,
            &execute_rollback,
            round_function,
        );

    // add actual update of register in case of write
    let register_value_if_storage_read = read_value;

    let mut precompile_call_result = u256_zero;
    precompile_call_result.inner[0] =
        unsafe { UInt32::from_variable_unchecked(have_enough_ergs.get_variable()) };

    let register_value = UInt256::conditionally_select(
        cs,
        is_storage_read,
        &register_value_if_storage_read,
        &precompile_call_result,
    );

    let dst0 = VMRegister {
        value: register_value,
        is_pointer: boolean_false,
    };

    let old_forward_queue_length = draft_vm_state
        .callstack
        .current_context
        .log_queue_forward_part_length;

    let new_forward_queue_length_candidate =
        unsafe { old_forward_queue_length.increment_unchecked(cs) };
    let new_forward_queue_length = UInt32::conditionally_select(
        cs,
        execute_either_in_practice,
        &new_forward_queue_length_candidate,
        &old_forward_queue_length,
    );

    let old_revert_queue_length = draft_vm_state
        .callstack
        .current_context
        .saved_context
        .reverted_queue_segment_len;

    let new_revert_queue_length_candidate =
        unsafe { old_revert_queue_length.increment_unchecked(cs) };
    let new_revert_queue_length = UInt32::conditionally_select(
        cs,
        execute_rollback,
        &new_revert_queue_length_candidate,
        &old_revert_queue_length,
    );

    let can_update_dst0 = Boolean::multi_or(cs, &[is_storage_read, is_precompile]);
    let should_update_dst0 = Boolean::multi_and(cs, &[can_update_dst0, should_apply]);

    if crate::config::CIRCUIT_VERSOBE {
        if should_apply.witness_hook(&*cs)().unwrap() {
            dbg!(should_update_dst0.witness_hook(&*cs)().unwrap());
            dbg!(dst0.witness_hook(&*cs)().unwrap());
        }
    }

    let can_write_into_memory =
        STORAGE_READ_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION);
    diffs_accumulator
        .dst_0_values
        .push((can_write_into_memory, should_update_dst0, dst0));

    diffs_accumulator.log_queue_forward_candidates.push((
        should_apply,
        new_forward_queue_length,
        new_forward_queue_tail,
    ));

    diffs_accumulator.log_queue_rollback_candidates.push((
        should_apply,
        new_revert_queue_length,
        new_rollback_queue_head,
    ));

    diffs_accumulator
        .new_ergs_left_candidates
        .push((should_apply, ergs_remaining));

    assert!(STORAGE_READ_OPCODE.can_have_src0_from_mem(SUPPORTED_ISA_VERSION) == false);
    assert!(STORAGE_READ_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION) == false);

    diffs_accumulator
        .sponge_candidates_to_run
        .push((false, false, should_apply, relations));
}

use crate::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;
use crate::main_vm::state_diffs::MAX_SPONGES_PER_CYCLE;
use arrayvec::ArrayVec;

fn construct_hash_relations_for_log_and_new_queue_states<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    forward_packed_log: &[Variable; LOG_QUERY_PACKED_WIDTH],
    forward_rollback_log: &[Variable; LOG_QUERY_PACKED_WIDTH],
    forward_queue_tail: &[Num<F>; 4],
    claimed_rollback_head: &[Num<F>; 4],
    current_rollback_head: &[Num<F>; 4],
    should_execute_either: &Boolean<F>,
    should_execute_rollback: &Boolean<F>,
    _round_function: &R,
) -> (
    [Num<F>; 4],
    [Num<F>; 4],
    ArrayVec<
        (
            Boolean<F>,
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
        ),
        MAX_SPONGES_PER_CYCLE,
    >,
) {
    // we should be clever and simultaneously produce 2 relations:
    // - 2 common sponges for forward/rollback that only touch the encodings
    // - 1 unique sponge for forward
    // - 1 unique sponge for rollback

    // check that we only differ at the very end
    for (a, b) in forward_packed_log[..ROLLBACK_PACKING_FLAG_VARIABLE_IDX]
        .iter()
        .zip(forward_rollback_log[..ROLLBACK_PACKING_FLAG_VARIABLE_IDX].iter())
    {
        debug_assert_eq!(a, b);
    }

    // we absort with replacement

    let mut current_state = R::create_empty_state(cs);
    // TODO: may be decide on length specialization

    // absorb by replacement
    let round_0_initial = [
        forward_packed_log[0],
        forward_packed_log[1],
        forward_packed_log[2],
        forward_packed_log[3],
        forward_packed_log[4],
        forward_packed_log[5],
        forward_packed_log[6],
        forward_packed_log[7],
        current_state[8],
        current_state[9],
        current_state[10],
        current_state[11],
    ];

    use boojum::gadgets::round_function::simulate_round_function;

    let round_0_final =
        simulate_round_function::<_, _, 8, 12, 4, R>(cs, round_0_initial, *should_execute_either);

    current_state = round_0_final;

    // absorb by replacement
    let round_1_initial = [
        forward_packed_log[8],
        forward_packed_log[9],
        forward_packed_log[10],
        forward_packed_log[11],
        forward_packed_log[12],
        forward_packed_log[13],
        forward_packed_log[14],
        forward_packed_log[15],
        current_state[8],
        current_state[9],
        current_state[10],
        current_state[11],
    ];

    let round_1_final =
        simulate_round_function::<_, _, 8, 12, 4, R>(cs, round_1_initial, *should_execute_either);

    current_state = round_1_final;

    // absorb by replacement
    let round_2_initial_forward = [
        forward_packed_log[16],
        forward_packed_log[17],
        forward_packed_log[18],
        forward_packed_log[19],
        forward_queue_tail[0].get_variable(),
        forward_queue_tail[1].get_variable(),
        forward_queue_tail[2].get_variable(),
        forward_queue_tail[3].get_variable(),
        current_state[8],
        current_state[9],
        current_state[10],
        current_state[11],
    ];

    let forward_round_2_final = simulate_round_function::<_, _, 8, 12, 4, R>(
        cs,
        round_2_initial_forward,
        *should_execute_either,
    );

    // absorb by replacement
    let round_2_initial_rollback = [
        forward_rollback_log[16],
        forward_rollback_log[17],
        forward_rollback_log[18],
        forward_rollback_log[19],
        claimed_rollback_head[0].get_variable(),
        claimed_rollback_head[1].get_variable(),
        claimed_rollback_head[2].get_variable(),
        claimed_rollback_head[3].get_variable(),
        current_state[8],
        current_state[9],
        current_state[10],
        current_state[11],
    ];

    let rollback_round_2_final = simulate_round_function::<_, _, 8, 12, 4, R>(
        cs,
        round_2_initial_rollback,
        *should_execute_either,
    ); // at the moment we do not mark which sponges are actually used and which are not
       // in the opcode, so we properly simulate all of them

    let new_forward_tail_candidate = [
        forward_round_2_final[0],
        forward_round_2_final[1],
        forward_round_2_final[2],
        forward_round_2_final[3],
    ];

    let new_forward_tail_candidate = new_forward_tail_candidate.map(|el| Num::from_variable(el));

    let simulated_rollback_head = [
        rollback_round_2_final[0],
        rollback_round_2_final[1],
        rollback_round_2_final[2],
        rollback_round_2_final[3],
    ];

    let simulated_rollback_head = simulated_rollback_head.map(|el| Num::from_variable(el));

    // select forward

    let new_forward_queue_tail = Num::parallel_select(
        cs,
        *should_execute_either,
        &new_forward_tail_candidate,
        &forward_queue_tail,
    );

    // select rollback

    let new_rollback_queue_head = Num::parallel_select(
        cs,
        *should_execute_rollback,
        &claimed_rollback_head,
        &current_rollback_head,
    );

    for (a, b) in simulated_rollback_head
        .iter()
        .zip(current_rollback_head.iter())
    {
        Num::conditionally_enforce_equal(cs, *should_execute_rollback, a, b);
    }

    let mut relations = ArrayVec::new();
    relations.push((
        *should_execute_either,
        round_0_initial.map(|el| Num::from_variable(el)),
        round_0_final.map(|el| Num::from_variable(el)),
    ));

    relations.push((
        *should_execute_either,
        round_1_initial.map(|el| Num::from_variable(el)),
        round_1_final.map(|el| Num::from_variable(el)),
    ));

    relations.push((
        *should_execute_either,
        round_2_initial_forward.map(|el| Num::from_variable(el)),
        forward_round_2_final.map(|el| Num::from_variable(el)),
    ));

    relations.push((
        *should_execute_rollback,
        round_2_initial_rollback.map(|el| Num::from_variable(el)),
        rollback_round_2_final.map(|el| Num::from_variable(el)),
    ));

    (new_forward_queue_tail, new_rollback_queue_head, relations)
}
