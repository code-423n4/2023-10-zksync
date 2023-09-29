use std::collections::VecDeque;
use std::mem::MaybeUninit;

use crate::base_structures::log_query::LogQuery;
use crate::base_structures::state_diff_record::StateDiffRecord;
use crate::demux_log_queue::StorageLogQueue;
use crate::ethereum_types::U256;
use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::config::*;
use boojum::cs::traits::cs::{ConstraintSystem, DstBuffer};
use boojum::cs::{Place, Variable};
use boojum::field::SmallField;
use boojum::gadgets::blake2s::blake2s;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::keccak256;
use boojum::gadgets::num::Num;
use boojum::gadgets::queue::CircuitQueueWitness;
use boojum::gadgets::queue::QueueState;
use boojum::gadgets::traits::allocatable::{CSAllocatable, CSAllocatableExt, CSPlaceholder};
use boojum::gadgets::traits::castable::WitnessCastable;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::u256::UInt256;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use std::sync::{Arc, RwLock};
use zkevm_opcode_defs::system_params::STORAGE_AUX_BYTE;

use super::*;

pub mod input;
use self::input::*;

fn u64_as_u32x2_conditionally_increment<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    input: &[UInt32<F>; 2],
    should_increment: &Boolean<F>,
) -> [UInt32<F>; 2] {
    let one_u32 = UInt32::allocated_constant(cs, 1u32);
    let (incremented_low, carry) = input[0].overflowing_add(cs, one_u32);
    let carry_as_u32 = unsafe { UInt32::from_variable_unchecked(carry.get_variable()) };
    let incremented_high = input[1].add_no_overflow(cs, carry_as_u32);

    let selected = Selectable::conditionally_select(
        cs,
        *should_increment,
        &[incremented_low, incremented_high],
        input,
    );

    selected
}

pub(crate) fn keccak256_conditionally_absorb_and_run_permutation<
    F: SmallField,
    CS: ConstraintSystem<F>,
>(
    cs: &mut CS,
    condition: Boolean<F>,
    state: &mut [[[Variable; keccak256::BYTES_PER_WORD]; keccak256::LANE_WIDTH];
             keccak256::LANE_WIDTH],
    block: &[Variable; keccak256::KECCAK_RATE_BYTES],
) {
    let mut new_state = *state;
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
                new_state[i][j] = xor_many(cs, &new_state[i][j], tmp);
            }
        }
    }
    use boojum::gadgets::keccak256::round_function::keccak_256_round_function;
    keccak_256_round_function(cs, &mut new_state);

    // if we do not write then discard
    for (a, b) in state.iter_mut().zip(new_state.iter()) {
        for (a, b) in a.iter_mut().zip(b.iter()) {
            let new = b.map(|el| Num::from_variable(el));
            let old = a.map(|el| Num::from_variable(el));
            let selected = Num::parallel_select(cs, condition, &new, &old);
            *a = selected.map(|el| el.get_variable());
        }
    }
}

pub struct ConditionalWitnessAllocator<F: SmallField, EL: CSAllocatableExt<F>> {
    pub witness_source: Arc<RwLock<VecDeque<EL::Witness>>>,
}

impl<F: SmallField, EL: CSAllocatableExt<F>> ConditionalWitnessAllocator<F, EL>
where
    [(); EL::INTERNAL_STRUCT_LEN]:,
    [(); EL::INTERNAL_STRUCT_LEN + 1]:,
{
    pub fn print_debug_info(&self) {
        if let Ok(read_lock) = self.witness_source.read() {
            let inner = &*read_lock;
            dbg!(inner.len());
        }
    }

    pub fn conditionally_allocate_with_default<
        CS: ConstraintSystem<F>,
        DEF: FnOnce() -> EL::Witness + 'static + Send + Sync,
    >(
        &self,
        cs: &mut CS,
        should_allocate: Boolean<F>,
        default_values_closure: DEF,
    ) -> EL {
        let el = EL::allocate_without_value(cs);

        if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
            let dependencies = [should_allocate.get_variable().into()];
            let witness = self.witness_source.clone();
            let value_fn = move |inputs: [F; 1]| {
                let should_allocate = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);

                let witness = if should_allocate == true {
                    let mut guard = witness.write().expect("not poisoned");
                    let witness_element = guard.pop_front().expect("not empty witness");
                    drop(guard);

                    witness_element
                } else {
                    let witness_element = (default_values_closure)();

                    witness_element
                };

                let mut result = [F::ZERO; EL::INTERNAL_STRUCT_LEN];
                let mut dst = DstBuffer::MutSlice(&mut result, 0);
                EL::set_internal_variables_values(witness, &mut dst);
                drop(dst);

                result
            };

            let outputs = Place::from_variables(el.flatten_as_variables());

            cs.set_values_with_dependencies(&dependencies, &outputs, value_fn);
        }

        el
    }

    pub fn conditionally_allocate_with_default_biased<
        CS: ConstraintSystem<F>,
        DEF: FnOnce() -> EL::Witness + 'static + Send + Sync,
    >(
        &self,
        cs: &mut CS,
        should_allocate: Boolean<F>,
        bias: Variable, // any variable that has to be resolved BEFORE executing witness query
        default_values_closure: DEF,
    ) -> EL {
        let el = EL::allocate_without_value(cs);

        if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
            let dependencies = [should_allocate.get_variable().into(), bias.into()];
            let witness = self.witness_source.clone();
            let value_fn = move |inputs: [F; 2]| {
                let should_allocate = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);

                let witness = if should_allocate == true {
                    let mut guard = witness.write().expect("not poisoned");
                    let witness_element = guard.pop_front().expect("not empty witness");
                    drop(guard);

                    witness_element
                } else {
                    let witness_element = (default_values_closure)();

                    witness_element
                };

                let mut result = [F::ZERO; EL::INTERNAL_STRUCT_LEN];
                let mut dst = DstBuffer::MutSlice(&mut result, 0);
                EL::set_internal_variables_values(witness, &mut dst);
                drop(dst);

                result
            };

            let outputs = Place::from_variables(el.flatten_as_variables());

            cs.set_values_with_dependencies(&dependencies, &outputs, value_fn);
        }

        el
    }

    pub fn conditionally_allocate<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        should_allocate: Boolean<F>,
    ) -> EL
    where
        EL::Witness: Default,
    {
        self.conditionally_allocate_with_default(cs, should_allocate, || {
            std::default::Default::default()
        })
    }

    pub fn conditionally_allocate_biased<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        should_allocate: Boolean<F>,
        bias: Variable, // any variable that has to be resolved BEFORE executing witness query
    ) -> EL
    where
        EL::Witness: Default,
    {
        self.conditionally_allocate_with_default_biased(cs, should_allocate, bias, || {
            std::default::Default::default()
        })
    }
}

fn allocate_enumeration_index_from_witness<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    should_allocate: Boolean<F>,
    witness_source: Arc<RwLock<VecDeque<(u32, u32)>>>,
) -> [UInt32<F>; 2] {
    let flattened: [_; 2] = std::array::from_fn(|_| UInt32::allocate_without_value(cs));

    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        let dependencies = [should_allocate.get_variable().into()];
        let witness = witness_source.clone();
        let value_fn = move |inputs: [F; 1]| {
            let should_allocate = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);

            let (low, high) = if should_allocate == true {
                let mut guard = witness.write().expect("not poisoned");
                let witness_element = guard.pop_front().expect("not empty witness");
                drop(guard);

                witness_element
            } else {
                (0, 0)
            };

            [
                F::from_u64_with_reduction(low as u64),
                F::from_u64_with_reduction(high as u64),
            ]
        };

        let outputs = Place::from_variables(flattened.map(|el| el.get_variable()));

        cs.set_values_with_dependencies(&dependencies, &outputs, value_fn);
    }

    flattened
}

pub fn storage_applicator_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    witness: StorageApplicationCircuitInstanceWitness<F>,
    round_function: &R,
    params: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    let limit = params;

    assert!(limit <= u32::MAX as usize);

    let StorageApplicationCircuitInstanceWitness {
        closed_form_input,
        storage_queue_witness,
        merkle_paths,
        leaf_indexes_for_reads,
    } = witness;

    let leaf_indexes_for_reads: VecDeque<_> = leaf_indexes_for_reads
        .into_iter()
        .map(|el| (el as u32, (el >> 32) as u32))
        .collect();

    let merkle_paths: VecDeque<U256> = merkle_paths
        .into_iter()
        .flatten()
        .map(|el| U256::from_little_endian(&el))
        .collect();

    let mut structured_input =
        StorageApplicationInputOutput::alloc_ignoring_outputs(cs, closed_form_input.clone());
    let start_flag = structured_input.start_flag;

    let mut current_root_hash = UInt8::<F>::parallel_select(
        cs,
        start_flag,
        &structured_input.observable_input.initial_root_hash,
        &structured_input.hidden_fsm_input.current_root_hash,
    );
    let shard = structured_input.observable_input.shard;

    let mut current_next_enumeration_index = <[UInt32<F>; 2]>::conditionally_select(
        cs,
        start_flag,
        &structured_input
            .observable_input
            .initial_next_enumeration_counter,
        &structured_input.hidden_fsm_input.next_enumeration_counter,
    );

    let storage_queue_state_from_input = structured_input
        .observable_input
        .storage_application_log_state;

    // it must be trivial
    storage_queue_state_from_input.enforce_trivial_head(cs);

    let storage_queue_state_from_fsm = structured_input
        .hidden_fsm_input
        .current_storage_application_log_state;

    let storage_accesses_queue_state = QueueState::conditionally_select(
        cs,
        start_flag,
        &storage_queue_state_from_input,
        &storage_queue_state_from_fsm,
    );

    let mut storage_accesses_queue =
        StorageLogQueue::<F, R>::from_state(cs, storage_accesses_queue_state);
    let storage_queue_witness = CircuitQueueWitness::from_inner_witness(storage_queue_witness);
    storage_accesses_queue.witness = Arc::new(storage_queue_witness);

    let zero_u8: UInt8<F> = UInt8::zero(cs);

    let mut diffs_keccak_accumulator_state =
        [[[zero_u8; keccak256::BYTES_PER_WORD]; keccak256::LANE_WIDTH]; keccak256::LANE_WIDTH];
    let keccak_sponge_state_from_fsm = structured_input
        .hidden_fsm_input
        .current_diffs_keccak_accumulator_state;

    for (a, b) in diffs_keccak_accumulator_state
        .iter_mut()
        .zip(keccak_sponge_state_from_fsm.iter())
    {
        for (a, b) in a.iter_mut().zip(b.iter()) {
            *a = UInt8::parallel_select(cs, start_flag, &*a, b);
        }
    }

    let mut diffs_keccak_accumulator_state =
        diffs_keccak_accumulator_state.map(|el| el.map(|el| el.map(|el| el.get_variable())));

    let boolean_false = Boolean::allocated_constant(cs, false);
    let boolean_true = Boolean::allocated_constant(cs, true);
    let zero_u32 = UInt32::allocated_constant(cs, 0u32);

    let storage_aux_byte = UInt8::allocated_constant(cs, STORAGE_AUX_BYTE);
    let mut write_stage_in_progress = boolean_false;
    let mut path_key = [zero_u8; 32];
    let mut completed = storage_accesses_queue.is_empty(cs);
    let mut merkle_path_witness = Box::new([[zero_u8; 32]; STORAGE_DEPTH]);
    let mut current_in_progress_enumeration_index = [zero_u32; 2];
    let mut saved_written_value = [zero_u8; 32];

    let mut state_diff_data = StateDiffRecord {
        address: [zero_u8; 20],
        key: [zero_u8; 32],
        derived_key: [zero_u8; 32],
        enumeration_index: [zero_u8; 8],
        initial_value: [zero_u8; 32],
        final_value: [zero_u8; 32],
    };

    let read_index_witness_allocator = Arc::new(RwLock::new(leaf_indexes_for_reads));
    let merkle_path_witness_allocator = ConditionalWitnessAllocator::<F, UInt256<F>> {
        witness_source: Arc::new(RwLock::new(merkle_paths)),
    };

    for cycle in 0..limit {
        let is_first = cycle == 0;
        let is_last = cycle == limit - 1;

        // if this is the last executing cycle - we do not start the parsing of the new element:
        // instead we either complete the second iter of processing of the last element or simply do nothing
        let (should_compare_roots, parse_next_queue_elem) = if is_last == false {
            let should_compare_roots = completed.negated(cs);
            let read_stage_in_progress = write_stage_in_progress.negated(cs);
            let parse_next_queue_elem = should_compare_roots.and(cs, read_stage_in_progress);

            (should_compare_roots, parse_next_queue_elem)
        } else {
            // last iteration can never pop, and is never "read"

            (boolean_false, boolean_false)
        };

        let (storage_log, _) = storage_accesses_queue.pop_front(cs, parse_next_queue_elem);

        let LogQuery {
            address,
            key,
            read_value,
            written_value,
            rw_flag,
            shard_id,
            ..
        } = storage_log;

        let shard_is_valid = UInt8::equals(cs, &shard_id, &shard);
        let aux_byte_is_valid = UInt8::equals(cs, &storage_log.aux_byte, &storage_aux_byte);
        let is_valid = Boolean::multi_and(cs, &[shard_is_valid, aux_byte_is_valid]);
        is_valid.conditionally_enforce_true(cs, parse_next_queue_elem);

        // we can decompose everythin right away
        let address_bytes = address.to_be_bytes(cs);
        let key_bytes = key.to_be_bytes(cs);

        let mut bytes_for_key_derivation = [zero_u8; 64];
        bytes_for_key_derivation[12..32].copy_from_slice(&address_bytes);
        bytes_for_key_derivation[32..64].copy_from_slice(&key_bytes);

        let derived_key = blake2s(cs, &bytes_for_key_derivation);

        // update current key
        path_key = UInt8::parallel_select(cs, parse_next_queue_elem, &derived_key, &path_key);
        let mut path_selectors = [boolean_false; STORAGE_DEPTH];
        // get path bits
        for (dst, src) in path_selectors.array_chunks_mut::<8>().zip(path_key.iter()) {
            let bits: [_; 8] = Num::from_variable(src.get_variable()).spread_into_bits(cs);
            *dst = bits;
        }

        // determine whether we need to increment enumeration index
        let read_index = allocate_enumeration_index_from_witness(
            cs,
            parse_next_queue_elem,
            read_index_witness_allocator.clone(),
        );
        // update index over which we work
        current_in_progress_enumeration_index = <[UInt32<F>; 2]>::conditionally_select(
            cs,
            parse_next_queue_elem,
            &read_index,
            &current_in_progress_enumeration_index,
        );

        let idx_parts_are_zeroes = current_in_progress_enumeration_index.map(|el| el.is_zero(cs));
        let current_idx_is_zero = Boolean::multi_and(cs, &idx_parts_are_zeroes);
        let should_assign_fresh_idx =
            Boolean::multi_and(cs, &[write_stage_in_progress, current_idx_is_zero]);

        // use next enumeration index
        current_in_progress_enumeration_index = <[UInt32<F>; 2]>::conditionally_select(
            cs,
            should_assign_fresh_idx,
            &current_next_enumeration_index,
            &current_in_progress_enumeration_index,
        );
        current_next_enumeration_index = u64_as_u32x2_conditionally_increment(
            cs,
            &current_next_enumeration_index,
            &should_assign_fresh_idx,
        );

        // index is done, now we need merkle path
        let mut new_merkle_path_witness = Vec::with_capacity(STORAGE_DEPTH);
        let mut bias_variable = parse_next_queue_elem.get_variable();
        for _ in 0..STORAGE_DEPTH {
            let wit = merkle_path_witness_allocator.conditionally_allocate_biased(
                cs,
                parse_next_queue_elem,
                bias_variable,
            );
            bias_variable = wit.inner[0].get_variable();
            new_merkle_path_witness.push(wit);
        }

        // if we read then we save and use it for write too
        for (dst, src) in merkle_path_witness
            .iter_mut()
            .zip(new_merkle_path_witness.iter())
        {
            let src_bytes = src.to_le_bytes(cs); // NOP
            *dst = UInt8::parallel_select(cs, parse_next_queue_elem, &src_bytes, &*dst);
        }

        let read_value_bytes = read_value.to_be_bytes(cs);
        let written_value_bytes = written_value.to_be_bytes(cs);

        let mut leaf_value_for_this_stage = read_value_bytes;
        // if we just processed a value from the queue then save it
        saved_written_value = UInt8::parallel_select(
            cs,
            parse_next_queue_elem,
            &written_value_bytes,
            &saved_written_value,
        );
        // if we have write stage in progress then use saved value as the one we will use for path
        leaf_value_for_this_stage = UInt8::parallel_select(
            cs,
            write_stage_in_progress,
            &saved_written_value,
            &leaf_value_for_this_stage,
        );

        // we need to serialize leaf index as 8 bytes

        let leaf_index_low_be = current_in_progress_enumeration_index[0].to_be_bytes(cs);
        let leaf_index_high_be = current_in_progress_enumeration_index[1].to_be_bytes(cs);

        let mut leaf_index_bytes = [zero_u8; 8];
        leaf_index_bytes[0..4].copy_from_slice(&leaf_index_high_be);
        leaf_index_bytes[4..8].copy_from_slice(&leaf_index_low_be);

        // now we have everything to update state diff data
        {
            state_diff_data.address = UInt8::parallel_select(
                cs,
                parse_next_queue_elem,
                &address_bytes,
                &state_diff_data.address,
            );
            state_diff_data.key =
                UInt8::parallel_select(cs, parse_next_queue_elem, &key_bytes, &state_diff_data.key);
            state_diff_data.derived_key = UInt8::parallel_select(
                cs,
                parse_next_queue_elem,
                &derived_key,
                &state_diff_data.derived_key,
            );
            // NOTE: we need READ index, before updating
            state_diff_data.enumeration_index = UInt8::parallel_select(
                cs,
                parse_next_queue_elem,
                &leaf_index_bytes,
                &state_diff_data.enumeration_index,
            );
            state_diff_data.initial_value = UInt8::parallel_select(
                cs,
                parse_next_queue_elem,
                &read_value_bytes,
                &state_diff_data.initial_value,
            );
            state_diff_data.final_value = UInt8::parallel_select(
                cs,
                parse_next_queue_elem,
                &written_value_bytes,
                &state_diff_data.final_value,
            );
        }

        let mut leaf_bytes = [zero_u8; 32 + 8];
        leaf_bytes[0..8].copy_from_slice(&leaf_index_bytes);
        leaf_bytes[8..40].copy_from_slice(&leaf_value_for_this_stage);

        let mut current_hash = blake2s(cs, &leaf_bytes);

        for (path_bit, path_witness) in path_selectors
            .into_iter()
            .zip(merkle_path_witness.into_iter())
        {
            let left = UInt8::parallel_select(cs, path_bit, &path_witness, &current_hash);
            let right = UInt8::parallel_select(cs, path_bit, &current_hash, &path_witness);
            let mut input = [zero_u8; 64];
            input[0..32].copy_from_slice(&left);
            input[32..64].copy_from_slice(&right);

            current_hash = blake2s(cs, &input);
        }

        // in case of read: merkle_root == computed_merkle_root == new_merkle_root
        // new_merkle_root = select(if is_write: then new_merkle_root else computed_merkle_root);
        // so we first compute merkle_root - either the old one or the selected one and then enforce equality

        // update if we write
        current_root_hash = UInt8::parallel_select(
            cs,
            write_stage_in_progress,
            &current_hash,
            &current_root_hash,
        );
        // otherwise enforce equality
        for (a, b) in current_root_hash.iter().zip(current_hash.iter()) {
            Num::conditionally_enforce_equal(
                cs,
                should_compare_roots,
                &Num::from_variable(a.get_variable()),
                &Num::from_variable(b.get_variable()),
            );
        }

        // update our accumulator

        // we use keccak256 here because it's same table structure
        use crate::base_structures::state_diff_record::NUM_KECCAK256_ROUNDS_PER_RECORD_ACCUMULATION;
        let mut extended_state_diff_encoding =
            [zero_u8; keccak256::KECCAK_RATE_BYTES * NUM_KECCAK256_ROUNDS_PER_RECORD_ACCUMULATION];
        let packed_encoding = state_diff_data.encode(cs);
        extended_state_diff_encoding[0..packed_encoding.len()].copy_from_slice(&packed_encoding);
        let extended_state_diff_encoding = extended_state_diff_encoding.map(|el| el.get_variable());
        // absorb and run permutation

        // we do not write here anyway
        if is_first == false {
            for block in
                extended_state_diff_encoding.array_chunks::<{ keccak256::KECCAK_RATE_BYTES }>()
            {
                keccak256_conditionally_absorb_and_run_permutation(
                    cs,
                    write_stage_in_progress,
                    &mut diffs_keccak_accumulator_state,
                    block,
                );
            }
        }

        // toggle control flags
        let input_queue_is_empty = storage_accesses_queue.is_empty(cs);
        // cur elem is processed only in the case second iter in progress or rw_flag is false;
        let current_element_is_read = rw_flag.negated(cs);
        let cur_elem_was_processed =
            Boolean::multi_or(cs, &[write_stage_in_progress, current_element_is_read]);
        let completed_now = Boolean::multi_and(cs, &[input_queue_is_empty, cur_elem_was_processed]);
        completed = Boolean::multi_or(cs, &[completed, completed_now]);

        write_stage_in_progress = Boolean::multi_and(cs, &[parse_next_queue_elem, rw_flag]);
    }

    storage_accesses_queue.enforce_consistency(cs);

    structured_input.completion_flag = completed.clone();
    let storage_queue_state = storage_accesses_queue.into_state();

    let current_diffs_keccak_accumulator_state_for_fsm = unsafe {
        diffs_keccak_accumulator_state
            .map(|el| el.map(|el| el.map(|el| UInt8::from_variable_unchecked(el))))
    };

    let fsm_output = StorageApplicationFSMInputOutput {
        current_root_hash: current_root_hash,
        next_enumeration_counter: current_next_enumeration_index,
        current_storage_application_log_state: storage_queue_state.clone(),
        current_diffs_keccak_accumulator_state: current_diffs_keccak_accumulator_state_for_fsm,
    };
    structured_input.hidden_fsm_output = fsm_output;

    // we need to run padding and one more permutation for final output
    let zero_var = zero_u8.get_variable();
    let mut padding_block = [zero_var; keccak256::KECCAK_RATE_BYTES];
    use boojum::cs::gates::ConstantAllocatableCS;
    padding_block[0] = cs.allocate_constant(F::from_u64_unchecked(0x01 as u64));
    padding_block[135] = cs.allocate_constant(F::from_u64_unchecked(0x80 as u64));
    keccak256_conditionally_absorb_and_run_permutation(
        cs,
        boolean_true,
        &mut diffs_keccak_accumulator_state,
        &padding_block,
    );

    // squeeze
    let mut result = [MaybeUninit::<UInt8<F>>::uninit(); keccak256::KECCAK256_DIGEST_SIZE];
    for (i, dst) in result.array_chunks_mut::<8>().enumerate() {
        for (dst, src) in dst
            .iter_mut()
            .zip(diffs_keccak_accumulator_state[i][0].iter())
        {
            let tmp = unsafe { UInt8::from_variable_unchecked(*src) };
            dst.write(tmp);
        }
    }

    let state_diffs_keccak256_hash = unsafe { result.map(|el| el.assume_init()) };

    let observable_output = StorageApplicationOutputData {
        new_root_hash: current_root_hash,
        new_next_enumeration_counter: current_next_enumeration_index,
        state_diffs_keccak256_hash: state_diffs_keccak256_hash,
    };

    let empty_observable_output = StorageApplicationOutputData::placeholder(cs);
    let observable_output = StorageApplicationOutputData::conditionally_select(
        cs,
        structured_input.completion_flag,
        &observable_output,
        &empty_observable_output,
    );
    structured_input.observable_output = observable_output;

    // self-check
    structured_input.hook_compare_witness(cs, &closed_form_input);

    use crate::fsm_input_output::commit_variable_length_encodable_item;
    use crate::fsm_input_output::ClosedFormInputCompactForm;
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
