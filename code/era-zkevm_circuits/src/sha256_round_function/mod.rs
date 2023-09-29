use super::*;

use boojum::field::SmallField;

use boojum::gadgets::traits::witnessable::WitnessHookable;

use boojum::cs::traits::cs::ConstraintSystem;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::u256::UInt256;
use boojum::gadgets::u32::UInt32;
use cs_derive::*;

use crate::ethereum_types::U256;
use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use boojum::gadgets::num::Num;
use zkevm_opcode_defs::system_params::PRECOMPILE_AUX_BYTE;

use crate::base_structures::log_query::*;
use crate::base_structures::memory_query::*;
use crate::base_structures::precompile_input_outputs::PrecompileFunctionOutputData;
use crate::demux_log_queue::StorageLogQueue;
use crate::fsm_input_output::*;
use crate::storage_application::ConditionalWitnessAllocator;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::Variable;
use boojum::gadgets::queue::CircuitQueueWitness;
use boojum::gadgets::queue::QueueState;
use boojum::gadgets::sha256::{self};
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::allocatable::{CSAllocatableExt, CSPlaceholder};
use boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::u160::UInt160;
use boojum::gadgets::u8::UInt8;
use std::sync::{Arc, RwLock};

pub mod input;
use self::input::*;

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
// #[DerivePrettyComparison("true")]
pub struct Sha256PrecompileCallParams<F: SmallField> {
    pub input_page: UInt32<F>,
    pub input_offset: UInt32<F>,
    pub output_page: UInt32<F>,
    pub output_offset: UInt32<F>,
    pub num_rounds: UInt32<F>,
}

impl<F: SmallField> CSPlaceholder<F> for Sha256PrecompileCallParams<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_u32 = UInt32::zero(cs);
        Self {
            input_page: zero_u32,
            input_offset: zero_u32,
            output_page: zero_u32,
            output_offset: zero_u32,
            num_rounds: zero_u32,
        }
    }
}

impl<F: SmallField> Sha256PrecompileCallParams<F> {
    pub fn from_encoding<CS: ConstraintSystem<F>>(_cs: &mut CS, encoding: UInt256<F>) -> Self {
        let input_offset = encoding.inner[0];
        let output_offset = encoding.inner[2];
        let input_page = encoding.inner[4];
        let output_page = encoding.inner[5];

        let num_rounds = encoding.inner[6];

        let new = Self {
            input_page,
            input_offset,
            output_page,
            output_offset,
            num_rounds,
        };

        new
    }
}

pub const MEMORY_READ_QUERIES_PER_CYCLE: usize = 2;

pub fn sha256_precompile_inner<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    memory_queue: &mut MemoryQueue<F, R>,
    precompile_calls_queue: &mut StorageLogQueue<F, R>,
    memory_read_witness: ConditionalWitnessAllocator<F, UInt256<F>>,
    mut state: Sha256RoundFunctionFSM<F>,
    _round_function: &R,
    limit: usize,
) -> Sha256RoundFunctionFSM<F>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    assert!(limit <= u32::MAX as usize);

    let precompile_address = UInt160::allocated_constant(
        cs,
        *zkevm_opcode_defs::system_params::SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    );
    let aux_byte_for_precompile = UInt8::allocated_constant(cs, PRECOMPILE_AUX_BYTE);

    let boolean_false = Boolean::allocated_constant(cs, false);
    let boolean_true = Boolean::allocated_constant(cs, true);
    let zero_u32 = UInt32::zero(cs);
    let zero_u256 = UInt256::zero(cs);

    // we can have a degenerate case when queue is empty, but it's a first circuit in the queue,
    // so we taken default FSM state that has state.read_precompile_call = true;
    let input_queue_is_empty = precompile_calls_queue.is_empty(cs);
    // we can only skip the full circuit if we are not in any form of progress
    let can_finish_immediatelly =
        Boolean::multi_and(cs, &[state.read_precompile_call, input_queue_is_empty]);

    if crate::config::CIRCUIT_VERSOBE {
        dbg!(can_finish_immediatelly.witness_hook(cs)());
        dbg!(state.witness_hook(cs)());
    }

    state.read_precompile_call = state
        .read_precompile_call
        .mask_negated(cs, can_finish_immediatelly);
    state.read_words_for_round = state
        .read_words_for_round
        .mask_negated(cs, can_finish_immediatelly);
    state.completed = Boolean::multi_or(cs, &[state.completed, can_finish_immediatelly]);

    if crate::config::CIRCUIT_VERSOBE {
        dbg!(state.witness_hook(cs)());
        dbg!(precompile_calls_queue.into_state().witness_hook(cs)());
        memory_read_witness.print_debug_info();
    }
    // main work cycle
    for _cycle in 0..limit {
        if crate::config::CIRCUIT_VERSOBE {
            dbg!(_cycle);
            dbg!(state.witness_hook(cs)());
            dbg!(precompile_calls_queue.into_state().witness_hook(cs)());
        }
        // if we are in a proper state then get the ABI from the queue
        let (precompile_call, _) = precompile_calls_queue.pop_front(cs, state.read_precompile_call);

        Num::conditionally_enforce_equal(
            cs,
            state.read_precompile_call,
            &Num::from_variable(precompile_call.aux_byte.get_variable()),
            &Num::from_variable(aux_byte_for_precompile.get_variable()),
        );
        for (a, b) in precompile_call
            .address
            .inner
            .iter()
            .zip(precompile_address.inner.iter())
        {
            Num::conditionally_enforce_equal(
                cs,
                state.read_precompile_call,
                &Num::from_variable(a.get_variable()),
                &Num::from_variable(b.get_variable()),
            );
        }

        // now compute some parameters that describe the call itself

        let params_encoding = precompile_call.key;
        let call_params = Sha256PrecompileCallParams::from_encoding(cs, params_encoding);

        state.precompile_call_params = Sha256PrecompileCallParams::conditionally_select(
            cs,
            state.read_precompile_call,
            &call_params,
            &state.precompile_call_params,
        );
        // also set timestamps
        state.timestamp_to_use_for_read = UInt32::conditionally_select(
            cs,
            state.read_precompile_call,
            &precompile_call.timestamp,
            &state.timestamp_to_use_for_read,
        );

        // timestamps have large space, so this can be expected
        let timestamp_to_use_for_write =
            unsafe { state.timestamp_to_use_for_read.increment_unchecked(cs) };
        state.timestamp_to_use_for_write = UInt32::conditionally_select(
            cs,
            state.read_precompile_call,
            &timestamp_to_use_for_write,
            &state.timestamp_to_use_for_write,
        );

        let reset_buffer = Boolean::multi_or(cs, &[state.read_precompile_call, state.completed]);
        state.read_words_for_round = Boolean::multi_or(
            cs,
            &[state.read_precompile_call, state.read_words_for_round],
        );
        state.read_precompile_call = boolean_false;

        // ---------------------------------
        // Now perform few memory queries to read content

        let zero_rounds_left = state.precompile_call_params.num_rounds.is_zero(cs);

        let mut memory_queries_as_u32_words = [zero_u32; 8 * MEMORY_READ_QUERIES_PER_CYCLE];
        let should_read = zero_rounds_left.negated(cs);
        let mut bias_variable = should_read.get_variable();
        for dst in memory_queries_as_u32_words.array_chunks_mut::<8>() {
            let read_query_value =
                memory_read_witness.conditionally_allocate_biased(cs, should_read, bias_variable);
            bias_variable = read_query_value.inner[0].get_variable();

            let read_query = MemoryQuery {
                timestamp: state.timestamp_to_use_for_read,
                memory_page: state.precompile_call_params.input_page,
                index: state.precompile_call_params.input_offset,
                rw_flag: boolean_false,
                is_ptr: boolean_false,
                value: read_query_value,
            };

            let may_be_new_offset = unsafe {
                state
                    .precompile_call_params
                    .input_offset
                    .increment_unchecked(cs)
            };
            state.precompile_call_params.input_offset = UInt32::conditionally_select(
                cs,
                state.read_words_for_round,
                &may_be_new_offset,
                &state.precompile_call_params.input_offset,
            );

            // perform read
            memory_queue.push(cs, read_query, should_read);

            // we need to change endianess. Memory is BE, and each of 4 byte chunks should be interpreted as BE u32 for sha256
            let be_bytes = read_query_value.to_be_bytes(cs);
            for (dst, src) in dst.iter_mut().zip(be_bytes.array_chunks::<4>()) {
                let as_u32 = UInt32::from_be_bytes(cs, *src);
                *dst = as_u32;
            }
        }

        let may_be_new_num_rounds = unsafe {
            state
                .precompile_call_params
                .num_rounds
                .decrement_unchecked(cs)
        };
        state.precompile_call_params.num_rounds = UInt32::conditionally_select(
            cs,
            state.read_words_for_round,
            &may_be_new_num_rounds,
            &state.precompile_call_params.num_rounds,
        );

        // absorb
        let sha256_empty_internal_state = sha256::ivs_as_uint32(cs);

        let mut current_sha256_state = <[UInt32<F>; 8]>::conditionally_select(
            cs,
            reset_buffer,
            &sha256_empty_internal_state,
            &state.sha256_inner_state,
        );

        let sha256_output = sha256::round_function::round_function_over_uint32(
            cs,
            &mut current_sha256_state,
            &memory_queries_as_u32_words,
        );
        state.sha256_inner_state = current_sha256_state;

        let no_rounds_left = state.precompile_call_params.num_rounds.is_zero(cs);
        let write_result = Boolean::multi_and(cs, &[state.read_words_for_round, no_rounds_left]);

        let mut write_word = zero_u256;
        // some endianess magic
        for (dst, src) in write_word
            .inner
            .iter_mut()
            .rev()
            .zip(sha256_output.array_chunks::<4>())
        {
            *dst = UInt32::from_le_bytes(cs, *src);
        }

        let write_query = MemoryQuery {
            timestamp: state.timestamp_to_use_for_write,
            memory_page: state.precompile_call_params.output_page,
            index: state.precompile_call_params.output_offset,
            rw_flag: boolean_true,
            is_ptr: boolean_false,
            value: write_word,
        };

        // perform write
        memory_queue.push(cs, write_query, write_result);

        // ---------------------------------

        // update state
        let input_is_empty = precompile_calls_queue.is_empty(cs);
        let input_is_not_empty = input_is_empty.negated(cs);
        let nothing_left = Boolean::multi_and(cs, &[write_result, input_is_empty]);
        let process_next = Boolean::multi_and(cs, &[write_result, input_is_not_empty]);

        state.read_precompile_call = process_next;
        state.completed = Boolean::multi_or(cs, &[nothing_left, state.completed]);
        let t = Boolean::multi_or(cs, &[state.read_precompile_call, state.completed]);
        state.read_words_for_round = t.negated(cs);

        if crate::config::CIRCUIT_VERSOBE {
            dbg!(state.witness_hook(cs)());
            dbg!(precompile_calls_queue.into_state().witness_hook(cs)());
        }
    }

    if crate::config::CIRCUIT_VERSOBE {
        dbg!(state.witness_hook(cs)());
        dbg!(precompile_calls_queue.into_state().witness_hook(cs)());
    }

    precompile_calls_queue.enforce_consistency(cs);

    state
}

#[track_caller]
pub fn sha256_round_function_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    witness: Sha256RoundFunctionCircuitInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    let Sha256RoundFunctionCircuitInstanceWitness {
        closed_form_input,
        requests_queue_witness,
        memory_reads_witness,
    } = witness;

    let mut structured_input = Sha256RoundFunctionCircuitInputOutput::alloc_ignoring_outputs(
        cs,
        closed_form_input.clone(),
    );

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

    let read_queries_allocator = ConditionalWitnessAllocator::<F, UInt256<F>> {
        witness_source: Arc::new(RwLock::new(memory_reads_witness)),
    };

    let mut starting_fsm_state = Sha256RoundFunctionFSM::placeholder(cs);
    starting_fsm_state.read_precompile_call = Boolean::allocated_constant(cs, true);

    let initial_state = Sha256RoundFunctionFSM::conditionally_select(
        cs,
        start_flag,
        &starting_fsm_state,
        &structured_input.hidden_fsm_input.internal_fsm,
    );

    let final_state = sha256_precompile_inner::<F, CS, R>(
        cs,
        &mut memory_queue,
        &mut requests_queue,
        read_queries_allocator,
        initial_state,
        round_function,
        limit,
    );

    let final_memory_state = memory_queue.into_state();
    let final_requets_state = requests_queue.into_state();

    // form the final state
    let done = final_state.completed;
    structured_input.completion_flag = done;
    structured_input.observable_output = PrecompileFunctionOutputData::placeholder(cs);

    structured_input.observable_output.final_memory_state = QueueState::conditionally_select(
        cs,
        structured_input.completion_flag,
        &final_memory_state,
        &structured_input.observable_output.final_memory_state,
    );

    structured_input.hidden_fsm_output.internal_fsm = final_state;
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
