use super::*;

use boojum::field::SmallField;

use boojum::cs::traits::cs::ConstraintSystem;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::u16::UInt16;
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
use boojum::gadgets::keccak256::{self};
use boojum::gadgets::queue::CircuitQueueWitness;
use boojum::gadgets::queue::QueueState;
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
pub struct Keccak256PrecompileCallParams<F: SmallField> {
    pub input_page: UInt32<F>,
    pub input_offset: UInt32<F>,
    pub output_page: UInt32<F>,
    pub output_offset: UInt32<F>,
    pub num_rounds: UInt32<F>,
}

impl<F: SmallField> CSPlaceholder<F> for Keccak256PrecompileCallParams<F> {
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

impl<F: SmallField> Keccak256PrecompileCallParams<F> {
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

pub const KECCAK256_RATE_IN_U64_WORDS: usize = 17;
pub const MEMORY_EQURIES_PER_CYCLE: usize = 5; // we need to read as much as possible to use a round function every cycle
pub const NUM_U64_WORDS_PER_CYCLE: usize = 4 * MEMORY_EQURIES_PER_CYCLE;
pub const NEW_BYTES_PER_CYCLE: usize = 8 * NUM_U64_WORDS_PER_CYCLE;
// we absorb 136 elements per cycle, and add 160 elements per cycle, so we need to skip memory reads
// sometimes and do absorbs instead
pub const BUFFER_SIZE_IN_U64_WORDS: usize =
    MEMORY_EQURIES_PER_CYCLE * 4 + KECCAK256_RATE_IN_U64_WORDS - 1;
pub const BYTES_BUFFER_SIZE: usize = BUFFER_SIZE_IN_U64_WORDS * 8;

pub fn keccak256_precompile_inner<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    memory_queue: &mut MemoryQueue<F, R>,
    precompile_calls_queue: &mut StorageLogQueue<F, R>,
    memory_read_witness: ConditionalWitnessAllocator<F, UInt256<F>>,
    mut state: Keccak256RoundFunctionFSM<F>,
    _round_function: &R,
    limit: usize,
) -> Keccak256RoundFunctionFSM<F>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    assert!(limit <= u32::MAX as usize);

    let precompile_address = UInt160::allocated_constant(
        cs,
        *zkevm_opcode_defs::system_params::KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    );
    let aux_byte_for_precompile = UInt8::allocated_constant(cs, PRECOMPILE_AUX_BYTE);

    let boolean_false = Boolean::allocated_constant(cs, false);
    let boolean_true = Boolean::allocated_constant(cs, true);
    let zero_u8 = UInt8::zero(cs);
    let buffer_len_bound = UInt16::allocated_constant(
        cs,
        (BUFFER_SIZE_IN_U64_WORDS - NUM_U64_WORDS_PER_CYCLE + 1) as u16,
    );

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
    state.read_unaligned_words_for_round = state
        .read_unaligned_words_for_round
        .mask_negated(cs, can_finish_immediatelly);
    state.completed = Boolean::multi_or(cs, &[state.completed, can_finish_immediatelly]);

    // main work cycle
    for _cycle in 0..limit {
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
        let call_params = Keccak256PrecompileCallParams::from_encoding(cs, params_encoding);

        state.precompile_call_params = Keccak256PrecompileCallParams::conditionally_select(
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

        // and do some work! keccak256 is expensive
        let reset_buffer = Boolean::multi_or(cs, &[state.read_precompile_call, state.completed]);
        state.read_unaligned_words_for_round = Boolean::multi_or(
            cs,
            &[
                state.read_precompile_call,
                state.read_unaligned_words_for_round,
            ],
        );
        state.read_precompile_call = boolean_false;

        // ---------------------------------
        // Now perform few memory queries to read content

        for el in state.u64_words_buffer_markers.iter_mut() {
            *el = Boolean::conditionally_select(cs, reset_buffer, &boolean_false, el);
        }

        // even though it's not important, we cleanup the buffer too
        for el in state.u8_words_buffer.iter_mut() {
            *el = UInt8::conditionally_select(cs, reset_buffer, &zero_u8, el);
        }

        let initial_buffer_len = {
            let lc: Vec<_> = state
                .u64_words_buffer_markers
                .iter()
                .map(|el| (el.get_variable(), F::ONE))
                .collect();
            let lc = Num::linear_combination(cs, &lc);

            unsafe { UInt16::from_variable_unchecked(lc.get_variable()) }
        };

        // we can fill the buffer as soon as it's length <= MAX - NEW_WORDS_PER_CYCLE
        let (_, of) = initial_buffer_len.overflowing_sub(cs, &buffer_len_bound);
        let can_fill = of;
        let can_not_fill = can_fill.negated(cs);
        let zero_rounds_left = state.precompile_call_params.num_rounds.is_zero(cs);
        // if we can not fill then we should (sanity check) be in a state of reading new words
        // and have >0 rounds left

        state
            .read_unaligned_words_for_round
            .conditionally_enforce_true(cs, can_not_fill);
        zero_rounds_left.conditionally_enforce_false(cs, can_not_fill);
        let non_zero_rounds_left = zero_rounds_left.negated(cs);

        let should_read = Boolean::multi_and(
            cs,
            &[
                non_zero_rounds_left,
                state.read_unaligned_words_for_round,
                can_fill,
            ],
        );

        let mut new_bytes_to_read = [zero_u8; NEW_BYTES_PER_CYCLE];
        let mut bias_variable = should_read.get_variable();
        for dst in new_bytes_to_read.array_chunks_mut::<32>() {
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
                should_read,
                &may_be_new_offset,
                &state.precompile_call_params.input_offset,
            );

            // perform read
            memory_queue.push(cs, read_query, should_read);

            // we need to change endianess. Memory is BE, and each of 4 byte chunks should be interpreted as BE u32 for sha256
            let be_bytes = read_query_value.to_be_bytes(cs);
            *dst = be_bytes;
        }

        // our buffer len fits at least to push new elements and get enough for round function
        // this is quadratic complexity, but we it's easier to handle and cheap compared to round function
        let should_push = should_read;

        for src in new_bytes_to_read.array_chunks::<8>() {
            let mut should_push = should_push;
            for (is_busy, dst) in state
                .u64_words_buffer_markers
                .iter_mut()
                .zip(state.u8_words_buffer.array_chunks_mut::<8>())
            {
                let is_free = is_busy.negated(cs);
                let update = Boolean::multi_and(cs, &[is_free, should_push]);
                let should_not_update = update.negated(cs);
                *dst = UInt8::parallel_select(cs, update, src, dst);
                *is_busy = Boolean::multi_or(cs, &[update, *is_busy]);
                should_push = Boolean::multi_and(cs, &[should_push, should_not_update]);
            }

            Boolean::enforce_equal(cs, &should_push, &boolean_false);
        }

        let may_be_new_num_rounds = unsafe {
            state
                .precompile_call_params
                .num_rounds
                .decrement_unchecked(cs)
        };
        state.precompile_call_params.num_rounds = UInt32::conditionally_select(
            cs,
            state.read_unaligned_words_for_round,
            &may_be_new_num_rounds,
            &state.precompile_call_params.num_rounds,
        );

        // absorb

        // compute shifted buffer that removes first RATE elements and padds with something

        // take some work
        let mut input = [zero_u8; keccak256::KECCAK_RATE_BYTES];
        input.copy_from_slice(&state.u8_words_buffer[..keccak256::KECCAK_RATE_BYTES]);

        // keep the rest
        let mut tmp_buffer = [zero_u8; BYTES_BUFFER_SIZE];
        tmp_buffer[..(BYTES_BUFFER_SIZE - keccak256::KECCAK_RATE_BYTES)]
            .copy_from_slice(&state.u8_words_buffer[keccak256::KECCAK_RATE_BYTES..]);

        // also reset markers
        let mut tmp_buffer_markers = [boolean_false; BUFFER_SIZE_IN_U64_WORDS];
        tmp_buffer_markers[..(BUFFER_SIZE_IN_U64_WORDS - KECCAK256_RATE_IN_U64_WORDS)]
            .copy_from_slice(&state.u64_words_buffer_markers[KECCAK256_RATE_IN_U64_WORDS..]);

        // update buffers
        state.u8_words_buffer = tmp_buffer;
        state.u64_words_buffer_markers = tmp_buffer_markers;

        // conditionally reset state. Keccak256 empty state is just all 0s

        for dst in state.keccak_internal_state.iter_mut() {
            for dst in dst.iter_mut() {
                for dst in dst.iter_mut() {
                    *dst = dst.mask_negated(cs, reset_buffer);
                }
            }
        }

        // manually absorb and run round function
        let squeezed =
            keccak256_absorb_and_run_permutation(cs, &mut state.keccak_internal_state, &input);

        let no_rounds_left = state.precompile_call_params.num_rounds.is_zero(cs);
        let write_result =
            Boolean::multi_and(cs, &[state.read_unaligned_words_for_round, no_rounds_left]);

        let result = UInt256::from_be_bytes(cs, squeezed);

        let write_query = MemoryQuery {
            timestamp: state.timestamp_to_use_for_write,
            memory_page: state.precompile_call_params.output_page,
            index: state.precompile_call_params.output_offset,
            rw_flag: boolean_true,
            is_ptr: boolean_false,
            value: result,
        };

        // perform write
        memory_queue.push(cs, write_query, write_result);

        // ---------------------------------

        // update call props
        let input_is_empty = precompile_calls_queue.is_empty(cs);
        let input_is_not_empty = input_is_empty.negated(cs);
        let nothing_left = Boolean::multi_and(cs, &[write_result, input_is_empty]);
        let process_next = Boolean::multi_and(cs, &[write_result, input_is_not_empty]);

        state.read_precompile_call = process_next;
        state.completed = Boolean::multi_or(cs, &[nothing_left, state.completed]);
        let t = Boolean::multi_or(cs, &[state.read_precompile_call, state.completed]);
        state.read_unaligned_words_for_round = t.negated(cs);
    }

    precompile_calls_queue.enforce_consistency(cs);

    state
}

#[track_caller]
pub fn keccak256_round_function_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    witness: Keccak256RoundFunctionCircuitInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    let Keccak256RoundFunctionCircuitInstanceWitness {
        closed_form_input,
        requests_queue_witness,
        memory_reads_witness,
    } = witness;

    let mut structured_input = Keccak256RoundFunctionCircuitInputOutput::alloc_ignoring_outputs(
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

    let mut starting_fsm_state = Keccak256RoundFunctionFSM::placeholder(cs);
    starting_fsm_state.read_precompile_call = Boolean::allocated_constant(cs, true);

    let initial_state = Keccak256RoundFunctionFSM::conditionally_select(
        cs,
        start_flag,
        &starting_fsm_state,
        &structured_input.hidden_fsm_input.internal_fsm,
    );

    let final_state = keccak256_precompile_inner::<F, CS, R>(
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

pub(crate) fn keccak256_absorb_and_run_permutation<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    state: &mut [[[UInt8<F>; keccak256::BYTES_PER_WORD]; keccak256::LANE_WIDTH];
             keccak256::LANE_WIDTH],
    block: &[UInt8<F>; keccak256::KECCAK_RATE_BYTES],
) -> [UInt8<F>; keccak256::KECCAK256_DIGEST_SIZE] {
    let mut state_as_variables = state.map(|el| el.map(|el| el.map(|el| el.get_variable())));
    for i in 0..keccak256::LANE_WIDTH {
        for j in 0..keccak256::LANE_WIDTH {
            if i + keccak256::LANE_WIDTH * j
                < (keccak256::KECCAK_RATE_BYTES / keccak256::BYTES_PER_WORD)
            {
                let tmp = block
                    .array_chunks::<{ keccak256::BYTES_PER_WORD }>()
                    .skip(i + keccak256::LANE_WIDTH * j)
                    .next()
                    .unwrap();
                use boojum::gadgets::blake2s::mixing_function::xor_many;
                let tmp = tmp.map(|el| el.get_variable());
                state_as_variables[i][j] = xor_many(cs, &state_as_variables[i][j], &tmp);
            }
        }
    }
    use boojum::gadgets::keccak256::round_function::keccak_256_round_function;
    keccak_256_round_function(cs, &mut state_as_variables);

    let new_state = unsafe {
        state_as_variables.map(|el| el.map(|el| el.map(|el| UInt8::from_variable_unchecked(el))))
    };

    *state = new_state;

    // copy back
    let mut result =
        [std::mem::MaybeUninit::<UInt8<F>>::uninit(); keccak256::KECCAK256_DIGEST_SIZE];
    for (i, dst) in result.array_chunks_mut::<8>().enumerate() {
        for (dst, src) in dst.iter_mut().zip(state[i][0].iter()) {
            dst.write(*src);
        }
    }

    unsafe { result.map(|el| el.assume_init()) }
}
