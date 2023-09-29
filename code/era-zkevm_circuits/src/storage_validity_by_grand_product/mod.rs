use super::*;

pub mod input;
#[cfg(test)]
mod test_input;

use crate::base_structures::log_query::log_query_witness_from_values;
use crate::fsm_input_output::ClosedFormInputCompactForm;

use crate::base_structures::{
    log_query::{LogQuery, LOG_QUERY_PACKED_WIDTH},
    vm_state::*,
};
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::traits::cs::DstBuffer;
use boojum::cs::{gates::*, traits::cs::ConstraintSystem, Variable};
use boojum::field::SmallField;
use boojum::gadgets::traits::castable::WitnessCastable;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::{
    boolean::Boolean,
    num::Num,
    queue::*,
    traits::{
        allocatable::*,
        encodable::{CircuitEncodable, CircuitEncodableExt},
        selectable::Selectable,
        witnessable::*,
    },
    u160::*,
    u256::*,
    u32::UInt32,
    u8::UInt8,
};

use crate::{
    demux_log_queue::StorageLogQueue,
    fsm_input_output::{circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH, *},
    storage_validity_by_grand_product::input::*,
};

// we make a generation aware memory that store all the old and new values
// for a current storage cell. There are largely 3 possible sequences that we must be aware of
// - write_0, .. .... without rollback of the current write
// - write_0, ..., rollback_0, read_0, ... - in this case we must issue and explicit read, even though it's not the first one
// - read_0, ..., - same as above

// We use extra structure with timestamping. Even though we DO have
// timestamp field in LogQuery, such timestamp is the SAME
// for "forward" and "rollback" items, while we do need to have them
// on different timestamps

const TIMESTAMPED_STORAGE_LOG_ENCODING_LEN: usize = 20;

use cs_derive::*;

use std::sync::Arc;

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Clone, Debug)]
pub struct TimestampedStorageLogRecord<F: SmallField> {
    pub record: LogQuery<F>,
    pub timestamp: UInt32<F>,
}

pub const EXTENDED_TIMESTAMP_ENCODING_ELEMENT: usize = 19;
pub const EXTENDED_TIMESTAMP_ENCODING_OFFSET: usize = 8;

impl<F: SmallField> TimestampedStorageLogRecord<F> {
    pub fn append_timestamp_to_raw_query_encoding<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        original_encoding: &[Variable; TIMESTAMPED_STORAGE_LOG_ENCODING_LEN],
        timestamp: &UInt32<F>,
    ) -> [Variable; TIMESTAMPED_STORAGE_LOG_ENCODING_LEN] {
        debug_assert!(F::CAPACITY_BITS >= 40);
        // LogQuery encoding leaves last variable as < 8 bits value
        let encoding = Num::linear_combination(
            cs,
            &[
                (
                    // Original encoding at index 19 is only 8 bits
                    original_encoding[EXTENDED_TIMESTAMP_ENCODING_ELEMENT],
                    F::ONE,
                ),
                (timestamp.get_variable(), F::from_u64_unchecked(1u64 << 8)),
            ],
        )
        .get_variable();

        let mut result = *original_encoding;
        result[EXTENDED_TIMESTAMP_ENCODING_ELEMENT] = encoding;
        result
    }
}

impl<F: SmallField> CircuitEncodable<F, TIMESTAMPED_STORAGE_LOG_ENCODING_LEN>
    for TimestampedStorageLogRecord<F>
{
    fn encode<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> [Variable; TIMESTAMPED_STORAGE_LOG_ENCODING_LEN] {
        let original_encoding = self.record.encode(cs);

        Self::append_timestamp_to_raw_query_encoding(cs, &original_encoding, &self.timestamp)
    }
}

impl<F: SmallField> CSAllocatableExt<F> for TimestampedStorageLogRecord<F> {
    const INTERNAL_STRUCT_LEN: usize = 37;

    fn witness_from_set_of_values(values: [F; Self::INTERNAL_STRUCT_LEN]) -> Self::Witness {
        // NOTE(shamatar) Using CSAllocatableExt causes cyclic dependency here, so we use workaround
        let mut record_values =
            [F::ZERO; crate::base_structures::log_query::FLATTENED_VARIABLE_LENGTH];
        record_values.copy_from_slice(
            &values[..crate::base_structures::log_query::FLATTENED_VARIABLE_LENGTH],
        );
        let record = log_query_witness_from_values(record_values);
        let other_timestamp: u32 = WitnessCastable::cast_from_source(values[36]);

        Self::Witness {
            record,
            timestamp: other_timestamp,
        }
    }

    // we should be able to allocate without knowing values yet
    fn create_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            record: LogQuery::<F>::allocate_without_value(cs),
            timestamp: UInt32::allocate_without_value(cs),
        }
    }

    fn flatten_as_variables(&self) -> [Variable; 37]
    where
        [(); Self::INTERNAL_STRUCT_LEN]:,
    {
        let mut result = [Variable::placeholder(); 37];
        let record_variables = self.record.flatten_as_variables_impl();
        result[..crate::base_structures::log_query::FLATTENED_VARIABLE_LENGTH]
            .copy_from_slice(&record_variables);
        result[crate::base_structures::log_query::FLATTENED_VARIABLE_LENGTH] =
            self.timestamp.get_variable();
        assert_no_placeholder_variables(&result);

        result
    }

    fn set_internal_variables_values(witness: Self::Witness, dst: &mut DstBuffer<'_, '_, F>) {
        LogQuery::set_internal_variables_values(witness.record, dst);
        UInt32::set_internal_variables_values(witness.timestamp, dst);
    }
}

impl<F: SmallField> CircuitEncodableExt<F, TIMESTAMPED_STORAGE_LOG_ENCODING_LEN>
    for TimestampedStorageLogRecord<F>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
}

pub fn sort_and_deduplicate_storage_access_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    closed_form_input: StorageDeduplicatorInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    let structured_input_witness = closed_form_input.closed_form_input;
    let unsorted_queue_witness = closed_form_input.unsorted_queue_witness;
    let intermediate_sorted_queue_witness = closed_form_input.intermediate_sorted_queue_witness;

    let mut structured_input = StorageDeduplicatorInputOutput::alloc_ignoring_outputs(
        cs,
        structured_input_witness.clone(),
    );

    let unsorted_queue_from_passthrough_state = QueueState {
        head: structured_input
            .observable_input
            .unsorted_log_queue_state
            .head,
        tail: structured_input
            .observable_input
            .unsorted_log_queue_state
            .tail,
    };

    let unsorted_queue_from_fsm_input_state = QueueState {
        head: structured_input
            .hidden_fsm_input
            .current_unsorted_queue_state
            .head,
        tail: structured_input
            .hidden_fsm_input
            .current_unsorted_queue_state
            .tail,
    };

    // passthrought must be trivial
    unsorted_queue_from_passthrough_state.enforce_trivial_head(cs);

    let state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &unsorted_queue_from_passthrough_state,
        &unsorted_queue_from_fsm_input_state,
    );
    let mut unsorted_queue = StorageLogQueue::<F, R>::from_state(cs, state);

    unsorted_queue.witness = Arc::new(CircuitQueueWitness::from_inner_witness(
        unsorted_queue_witness,
    ));

    // same logic from sorted
    let intermediate_sorted_queue_from_passthrough = CircuitQueue::<
        F,
        TimestampedStorageLogRecord<F>,
        8,
        12,
        4,
        QUEUE_STATE_WIDTH,
        TIMESTAMPED_STORAGE_LOG_ENCODING_LEN,
        R,
    >::from_raw_parts(
        cs,
        structured_input
            .observable_input
            .intermediate_sorted_queue_state
            .head,
        structured_input
            .observable_input
            .intermediate_sorted_queue_state
            .tail
            .tail,
        structured_input
            .observable_input
            .intermediate_sorted_queue_state
            .tail
            .length,
    );

    let intermediate_sorted_queue_from_fsm_input = CircuitQueue::<
        F,
        TimestampedStorageLogRecord<F>,
        8,
        12,
        4,
        QUEUE_STATE_WIDTH,
        TIMESTAMPED_STORAGE_LOG_ENCODING_LEN,
        R,
    >::from_raw_parts(
        cs,
        structured_input
            .hidden_fsm_input
            .current_intermediate_sorted_queue_state
            .head,
        structured_input
            .hidden_fsm_input
            .current_intermediate_sorted_queue_state
            .tail
            .tail,
        structured_input
            .hidden_fsm_input
            .current_intermediate_sorted_queue_state
            .tail
            .length,
    );

    // passthrought must be trivial
    intermediate_sorted_queue_from_passthrough.enforce_trivial_head(cs);

    let state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &intermediate_sorted_queue_from_passthrough.into_state(),
        &intermediate_sorted_queue_from_fsm_input.into_state(),
    );
    let mut intermediate_sorted_queue = CircuitQueue::<
        F,
        TimestampedStorageLogRecord<F>,
        8,
        12,
        4,
        QUEUE_STATE_WIDTH,
        TIMESTAMPED_STORAGE_LOG_ENCODING_LEN,
        R,
    >::from_state(cs, state);

    intermediate_sorted_queue.witness = Arc::new(CircuitQueueWitness::from_inner_witness(
        intermediate_sorted_queue_witness,
    ));

    // for final sorted queue it's easier

    let empty_final_sorted_queue = StorageLogQueue::<F, R>::empty(cs);
    let final_sorted_queue_from_fsm_input = StorageLogQueue::<F, R>::from_raw_parts(
        cs,
        structured_input
            .hidden_fsm_input
            .current_final_sorted_queue_state
            .head,
        structured_input
            .hidden_fsm_input
            .current_final_sorted_queue_state
            .tail
            .tail,
        structured_input
            .hidden_fsm_input
            .current_final_sorted_queue_state
            .tail
            .length,
    );

    let state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &empty_final_sorted_queue.into_state(),
        &final_sorted_queue_from_fsm_input.into_state(),
    );
    let mut final_sorted_queue = StorageLogQueue::<F, R>::from_state(cs, state);

    // get challenges for permutation argument
    let challenges = crate::utils::produce_fs_challenges::<
        F,
        CS,
        R,
        QUEUE_STATE_WIDTH,
        { TIMESTAMPED_STORAGE_LOG_ENCODING_LEN + 1 },
        DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS,
    >(
        cs,
        structured_input
            .observable_input
            .unsorted_log_queue_state
            .tail,
        structured_input
            .observable_input
            .intermediate_sorted_queue_state
            .tail,
        round_function,
    );

    let one = Num::allocated_constant(cs, F::ONE);
    let initial_lhs =
        <[Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS]>::conditionally_select(
            cs,
            structured_input.start_flag,
            &[one; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
            &structured_input.hidden_fsm_input.lhs_accumulator,
        );

    let initial_rhs =
        <[Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS]>::conditionally_select(
            cs,
            structured_input.start_flag,
            &[one; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
            &structured_input.hidden_fsm_input.rhs_accumulator,
        );

    let zero_u32: UInt32<F> = UInt32::zero(cs);

    // there is no code at address 0 in our case, so we can formally use it for all the purposes
    let previous_packed_key = <[UInt32<F>; PACKED_KEY_LENGTH]>::conditionally_select(
        cs,
        structured_input.start_flag,
        &[zero_u32; PACKED_KEY_LENGTH],
        &structured_input.hidden_fsm_input.previous_packed_key,
    );

    let cycle_idx = UInt32::conditionally_select(
        cs,
        structured_input.start_flag,
        &zero_u32,
        &structured_input.hidden_fsm_input.cycle_idx,
    );

    let shard_id = structured_input.observable_input.shard_id_to_process;

    let (
        new_lhs,
        new_rhs,
        cycle_idx,
        previous_packed_key,
        previous_key,
        previous_address,
        previous_timestamp,
        this_cell_has_explicit_read_and_rollback_depth_zero,
        this_cell_base_value,
        this_cell_current_value,
        this_cell_current_depth,
    ) = sort_and_deduplicate_storage_access_inner(
        cs,
        initial_lhs,
        initial_rhs,
        &mut unsorted_queue,
        &mut intermediate_sorted_queue,
        &mut final_sorted_queue,
        structured_input.start_flag,
        cycle_idx,
        challenges,
        previous_packed_key,
        structured_input.hidden_fsm_input.previous_key,
        structured_input.hidden_fsm_input.previous_address,
        structured_input.hidden_fsm_input.previous_timestamp,
        structured_input
            .hidden_fsm_input
            .this_cell_has_explicit_read_and_rollback_depth_zero,
        structured_input.hidden_fsm_input.this_cell_base_value,
        structured_input.hidden_fsm_input.this_cell_current_value,
        structured_input.hidden_fsm_input.this_cell_current_depth,
        shard_id,
        limit,
    );

    unsorted_queue.enforce_consistency(cs);
    intermediate_sorted_queue.enforce_consistency(cs);

    let unsorted_is_empty = unsorted_queue.is_empty(cs);
    let sorted_is_empty = intermediate_sorted_queue.is_empty(cs);

    Boolean::enforce_equal(cs, &unsorted_is_empty, &sorted_is_empty);

    let completed = unsorted_is_empty.and(cs, sorted_is_empty);
    new_lhs.iter().zip(new_rhs).for_each(|(l, r)| {
        Num::conditionally_enforce_equal(cs, completed, &l, &r);
    });

    // form the input/output

    structured_input.hidden_fsm_output.cycle_idx = cycle_idx;
    structured_input.hidden_fsm_output.previous_packed_key = previous_packed_key;
    structured_input.hidden_fsm_output.previous_key = previous_key;
    structured_input.hidden_fsm_output.previous_address = previous_address;
    structured_input.hidden_fsm_output.previous_timestamp = previous_timestamp;
    structured_input
        .hidden_fsm_output
        .this_cell_has_explicit_read_and_rollback_depth_zero =
        this_cell_has_explicit_read_and_rollback_depth_zero;
    structured_input.hidden_fsm_output.this_cell_base_value = this_cell_base_value;
    structured_input.hidden_fsm_output.this_cell_current_value = this_cell_current_value;
    structured_input.hidden_fsm_output.this_cell_current_depth = this_cell_current_depth;

    structured_input.hidden_fsm_output.lhs_accumulator = new_lhs;
    structured_input.hidden_fsm_output.rhs_accumulator = new_rhs;

    structured_input
        .hidden_fsm_output
        .current_unsorted_queue_state = unsorted_queue.into_state();
    structured_input
        .hidden_fsm_output
        .current_intermediate_sorted_queue_state = intermediate_sorted_queue.into_state();

    structured_input.completion_flag = completed;

    let empty_queue_state = QueueState::empty(cs);
    let state = QueueState::conditionally_select(
        cs,
        completed,
        &final_sorted_queue.into_state(),
        &empty_queue_state,
    );
    let final_queue_for_observable_output = CircuitQueue::<
        F,
        LogQuery<F>,
        8,
        12,
        4,
        QUEUE_STATE_WIDTH,
        LOG_QUERY_PACKED_WIDTH,
        R,
    >::from_state(cs, state);

    structured_input.observable_output.final_sorted_queue_state =
        final_queue_for_observable_output.into_state();

    structured_input
        .hidden_fsm_output
        .current_final_sorted_queue_state = final_sorted_queue.into_state();

    structured_input.hook_compare_witness(cs, &structured_input_witness);

    let compact_form =
        ClosedFormInputCompactForm::from_full_form(cs, &structured_input, round_function);

    // dbg!(compact_form.create_witness());
    let input_committment =
        commit_variable_length_encodable_item(cs, &compact_form, round_function);
    for el in input_committment.iter() {
        let gate = PublicInputGate::new(el.get_variable());
        gate.add_to_cs(cs);
    }

    input_committment
}

pub const NUM_PERMUTATION_ARG_CHALLENGES: usize = TIMESTAMPED_STORAGE_LOG_ENCODING_LEN + 1;

pub fn sort_and_deduplicate_storage_access_inner<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    mut lhs: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    mut rhs: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    original_queue: &mut StorageLogQueue<F, R>,
    intermediate_sorted_queue: &mut CircuitQueue<
        F,
        TimestampedStorageLogRecord<F>,
        8,
        12,
        4,
        QUEUE_STATE_WIDTH,
        TIMESTAMPED_STORAGE_LOG_ENCODING_LEN,
        R,
    >,
    sorted_queue: &mut StorageLogQueue<F, R>,
    is_start: Boolean<F>,
    mut cycle_idx: UInt32<F>,
    fs_challenges: [[Num<F>; TIMESTAMPED_STORAGE_LOG_ENCODING_LEN + 1];
        DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    mut previous_packed_key: [UInt32<F>; PACKED_KEY_LENGTH],
    mut previous_key: UInt256<F>,
    mut previous_address: UInt160<F>,
    mut previous_timestamp: UInt32<F>,
    mut this_cell_has_explicit_read_and_rollback_depth_zero: Boolean<F>,
    mut this_cell_base_value: UInt256<F>,
    mut this_cell_current_value: UInt256<F>,
    mut this_cell_current_depth: UInt32<F>,
    shard_id_to_process: UInt8<F>,
    limit: usize,
) -> (
    [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    UInt32<F>,
    [UInt32<F>; PACKED_KEY_LENGTH],
    UInt256<F>,
    UInt160<F>,
    UInt32<F>,
    Boolean<F>,
    UInt256<F>,
    UInt256<F>,
    UInt32<F>,
)
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    assert!(limit <= u32::MAX as usize);

    let unsorted_queue_length = Num::from_variable(original_queue.length.get_variable());
    let intermediate_sorted_queue_length =
        Num::from_variable(intermediate_sorted_queue.length.get_variable());

    Num::enforce_equal(
        cs,
        &unsorted_queue_length,
        &intermediate_sorted_queue_length,
    );

    // we can recreate it here, there are two cases:
    // - we are 100% empty, but it's the only circuit in this case
    // - otherwise we continue, and then it's not trivial
    let no_work = original_queue.is_empty(cs);
    let mut previous_item_is_trivial = no_work.or(cs, is_start);

    let additive_parts = fs_challenges.map(|el| el.last().copied().expect("additive part"));

    // we simultaneously pop, accumulate partial product,
    // and decide whether or not we should move to the next cell

    // to ensure uniqueness we place timestamps in a addition to the

    let mut lhs_lc = Vec::with_capacity(TIMESTAMPED_STORAGE_LOG_ENCODING_LEN + 1);
    let mut rhs_lc = Vec::with_capacity(TIMESTAMPED_STORAGE_LOG_ENCODING_LEN + 1);

    for _cycle in 0..limit {
        let original_timestamp = cycle_idx;
        // increment it immediatelly
        unsafe {
            let new_cycle_idx = cycle_idx.increment_unchecked(cs);
            cycle_idx = new_cycle_idx;
        }

        let original_is_empty = original_queue.is_empty(cs);
        let sorted_is_empty = intermediate_sorted_queue.is_empty(cs);
        Boolean::enforce_equal(cs, &original_is_empty, &sorted_is_empty);

        let original_is_not_empty = original_is_empty.negated(cs);
        let sorted_is_not_empty = sorted_is_empty.negated(cs);

        let should_pop = Boolean::multi_and(cs, &[original_is_not_empty, sorted_is_not_empty]);
        let item_is_trivial = original_is_empty;

        // NOTE: we do not need to check shard_id of unsorted item because we can just check it on sorted item
        let (_, original_encoding) = original_queue.pop_front(cs, should_pop);
        let (sorted_item, sorted_encoding) = intermediate_sorted_queue.pop_front(cs, should_pop);
        let extended_original_encoding =
            TimestampedStorageLogRecord::append_timestamp_to_raw_query_encoding(
                cs,
                &original_encoding,
                &original_timestamp,
            );

        let shard_id_is_valid =
            UInt8::equals(cs, &shard_id_to_process, &sorted_item.record.shard_id);
        shard_id_is_valid.conditionally_enforce_true(cs, should_pop);

        assert_eq!(extended_original_encoding.len(), sorted_encoding.len());
        for challenges in fs_challenges {
            assert_eq!(extended_original_encoding.len(), challenges.len() - 1);
        }

        // accumulate into product
        let extended_original_encoding = extended_original_encoding
            .iter()
            .map(|v| Num::from_variable(*v))
            .collect::<Vec<Num<F>>>();
        let sorted_encoding = sorted_encoding
            .iter()
            .map(|v| Num::from_variable(*v))
            .collect::<Vec<Num<F>>>();

        for (((lhs_dst, rhs_dst), challenges), additive_part) in lhs
            .iter_mut()
            .zip(rhs.iter_mut())
            .zip(fs_challenges.iter())
            .zip(additive_parts.iter())
        {
            lhs_lc.clear();
            rhs_lc.clear();

            for ((original_el, sorted_el), challenge) in extended_original_encoding
                .iter()
                .zip(sorted_encoding.iter())
                .zip(challenges.iter())
            {
                let lhs_contribution = original_el.mul(cs, &challenge);
                let rhs_contribution = sorted_el.mul(cs, &challenge);

                lhs_lc.push((lhs_contribution.get_variable(), F::ONE));
                rhs_lc.push((rhs_contribution.get_variable(), F::ONE));
            }

            lhs_lc.push((additive_part.get_variable(), F::ONE));
            rhs_lc.push((additive_part.get_variable(), F::ONE));

            let lhs_lc = Num::linear_combination(cs, &lhs_lc);
            let rhs_lc = Num::linear_combination(cs, &rhs_lc);

            let lhs_candidate = lhs_dst.mul(cs, &lhs_lc);
            let rhs_candidate = rhs_dst.mul(cs, &rhs_lc);

            *lhs_dst = Num::conditionally_select(cs, should_pop, &lhs_candidate, &*lhs_dst);
            *rhs_dst = Num::conditionally_select(cs, should_pop, &rhs_candidate, &*rhs_dst);
        }

        let TimestampedStorageLogRecord { record, timestamp } = sorted_item;

        // now resolve a logic about sorting itself
        let packed_key = concatenate_key(cs, (record.address.clone(), record.key));

        // ensure sorting. Check that previous key < this key
        let (keys_are_equal, previous_key_is_greater) =
            unpacked_long_comparison(cs, &previous_packed_key, &packed_key);

        let not_item_is_trivial = item_is_trivial.negated(cs);
        previous_key_is_greater.conditionally_enforce_false(cs, not_item_is_trivial);

        // if keys are the same then timestamps are sorted
        let (_, previous_timestamp_is_less) = previous_timestamp.overflowing_sub(cs, timestamp);
        // enforce if keys are the same and not trivial
        let must_enforce = keys_are_equal.and(cs, not_item_is_trivial);
        previous_timestamp_is_less.conditionally_enforce_true(cs, must_enforce);

        // we follow the procedure:
        // if keys are different then we finish with a previous one and update parameters
        // else we just update parameters

        // if new cell
        {
            let not_keys_are_equal = keys_are_equal.negated(cs);
            if _cycle == 0 {
                // it must always be true if we start
                not_keys_are_equal.conditionally_enforce_true(cs, is_start);
            }
            // finish with the old one
            // if somewhere along the way we did encounter a read at rollback depth zero (not important if there were such),
            // and if current rollback depth is 0 then we MUST issue a read

            let value_is_unchanged =
                UInt256::equals(cs, &this_cell_current_value, &this_cell_base_value);
            // there may be a situation when as a result of sequence of writes
            // storage slot is CLAIMED to be unchanged. There are two options:
            // - unchanged because we had write - ... - rollback AND we do not have read at depth 0.
            //   In this case we used a temporary value, and the fact that the last action is rollback
            //   all the way to the start (to depth 0), we are not interested in what was an initial value
            // - unchanged because a -> write b -> ... -> write a AND we do or do not have read at depth 0.
            //   In this case we would not need to write IF prover is honest and provides a true witness to "read value"
            //   field at the first write. But we can not rely on this and have to check this fact!
            let current_depth_is_zero = this_cell_current_depth.is_zero(cs);
            let not_current_depth_is_zero = current_depth_is_zero.negated(cs);
            let unchanged_but_not_by_rollback =
                value_is_unchanged.and(cs, not_current_depth_is_zero);
            let issue_protective_read = this_cell_has_explicit_read_and_rollback_depth_zero
                .or(cs, unchanged_but_not_by_rollback);
            let should_write = value_is_unchanged.negated(cs);

            let query = LogQuery {
                address: previous_address,
                key: previous_key,
                read_value: this_cell_base_value,
                written_value: this_cell_current_value,
                rw_flag: should_write,
                aux_byte: UInt8::zero(cs),
                rollback: Boolean::allocated_constant(cs, false),
                is_service: Boolean::allocated_constant(cs, false),
                shard_id: shard_id_to_process,
                tx_number_in_block: UInt32::zero(cs),
                timestamp: UInt32::zero(cs),
            };

            // if we did only writes and rollbacks then we don't need to update
            let should_update = issue_protective_read.or(cs, should_write);
            let not_keys_are_equal_and_should_update = not_keys_are_equal.and(cs, should_update);
            let should_push = previous_item_is_trivial
                .negated(cs)
                .and(cs, not_keys_are_equal_and_should_update);

            sorted_queue.push(cs, query, should_push);

            let new_non_trivial_cell = item_is_trivial.negated(cs).and(cs, not_keys_are_equal);

            // and update as we switch to the new cell with extra logic
            let meaningful_value = UInt256::conditionally_select(
                cs,
                record.rw_flag,
                &record.written_value,
                &record.read_value,
            );

            // re-update
            this_cell_base_value = UInt256::conditionally_select(
                cs,
                new_non_trivial_cell,
                &record.read_value,
                &this_cell_base_value,
            );

            this_cell_current_value = UInt256::conditionally_select(
                cs,
                new_non_trivial_cell,
                &meaningful_value,
                &this_cell_current_value,
            );

            let one = UInt32::allocated_constant(cs, 1);
            let zero = UInt32::zero(cs);
            let rollback_depth_for_new_cell =
                UInt32::conditionally_select(cs, record.rw_flag, &one, &zero);

            this_cell_current_depth = UInt32::conditionally_select(
                cs,
                new_non_trivial_cell,
                &rollback_depth_for_new_cell,
                &this_cell_current_depth,
            );

            // we have new non-trivial
            // and if it's read then it's definatelly at depth 0
            let not_rw_flag = record.rw_flag.negated(cs);
            this_cell_has_explicit_read_and_rollback_depth_zero = Boolean::conditionally_select(
                cs,
                new_non_trivial_cell,
                &not_rw_flag,
                &this_cell_has_explicit_read_and_rollback_depth_zero,
            );
        }

        // if same cell - update
        {
            let not_rw_flag = record.rw_flag.negated(cs);
            let non_trivial_and_same_cell = item_is_trivial.negated(cs).and(cs, keys_are_equal);
            let non_trivial_read_of_same_cell = non_trivial_and_same_cell.and(cs, not_rw_flag);
            let non_trivial_write_of_same_cell = non_trivial_and_same_cell.and(cs, record.rw_flag);
            let not_rollback = record.rollback.negated(cs);
            let write_no_rollback = non_trivial_write_of_same_cell.and(cs, not_rollback);
            let write_rollback = non_trivial_write_of_same_cell.and(cs, record.rollback);

            // update rollback depth the is a result of this action
            unsafe {
                let incremented_depth = this_cell_current_depth.increment_unchecked(cs);
                this_cell_current_depth = UInt32::conditionally_select(
                    cs,
                    write_no_rollback,
                    &incremented_depth,
                    &this_cell_current_depth,
                );
                let decremented_depth = this_cell_current_depth.decrement_unchecked(cs);
                this_cell_current_depth = UInt32::conditionally_select(
                    cs,
                    write_rollback,
                    &decremented_depth,
                    &this_cell_current_depth,
                );
            }

            // check consistency
            let read_is_equal_to_current =
                UInt256::equals(cs, &this_cell_current_value, &record.read_value);
            // we ALWAYS ensure read consistency on write (but not rollback) and on plain read
            let check_read_consistency =
                Boolean::multi_or(cs, &[non_trivial_read_of_same_cell, write_no_rollback]);
            read_is_equal_to_current.conditionally_enforce_true(cs, check_read_consistency);

            // decide to update
            this_cell_current_value = UInt256::conditionally_select(
                cs,
                write_no_rollback,
                &record.written_value,
                &this_cell_current_value,
            );

            this_cell_current_value = UInt256::conditionally_select(
                cs,
                write_rollback,
                &record.read_value,
                &this_cell_current_value,
            );

            let current_rollback_depth_is_zero = this_cell_current_depth.is_zero(cs);
            let read_at_rollback_depth_zero_of_same_cell =
                current_rollback_depth_is_zero.and(cs, non_trivial_read_of_same_cell);

            this_cell_base_value = UInt256::conditionally_select(
                cs,
                read_at_rollback_depth_zero_of_same_cell,
                &record.read_value,
                &this_cell_base_value,
            );

            // we definately read non-trivial, and that is on depth 0, so set to true
            let constant_true = Boolean::allocated_constant(cs, true);
            this_cell_has_explicit_read_and_rollback_depth_zero = Boolean::conditionally_select(
                cs,
                read_at_rollback_depth_zero_of_same_cell,
                &constant_true,
                &this_cell_has_explicit_read_and_rollback_depth_zero,
            );
        }

        // always update counters
        previous_address = record.address;
        previous_key = record.key;
        previous_item_is_trivial = item_is_trivial;
        previous_timestamp = timestamp;
        previous_packed_key = packed_key;
    }

    // finalization step - out of cycle, and only if we are done just yet
    {
        let queues_exhausted = original_queue.is_empty(cs);

        // cell state is final
        let value_is_unchanged =
            UInt256::equals(cs, &this_cell_current_value, &this_cell_base_value);
        let current_depth_is_zero = this_cell_current_depth.is_zero(cs);
        let not_current_depth_is_zero = current_depth_is_zero.negated(cs);
        let unchanged_but_not_by_rollback = value_is_unchanged.and(cs, not_current_depth_is_zero);
        let issue_protective_read = this_cell_has_explicit_read_and_rollback_depth_zero
            .or(cs, unchanged_but_not_by_rollback);
        let should_write = value_is_unchanged.negated(cs);

        let query = LogQuery {
            address: previous_address,
            key: previous_key,
            read_value: this_cell_base_value,
            written_value: this_cell_current_value,
            rw_flag: should_write,
            aux_byte: UInt8::zero(cs),
            rollback: Boolean::allocated_constant(cs, false),
            is_service: Boolean::allocated_constant(cs, false),
            shard_id: shard_id_to_process,
            tx_number_in_block: UInt32::zero(cs),
            timestamp: UInt32::zero(cs),
        };

        // if we did only writes and rollbacks then we don't need to update
        let should_update = issue_protective_read.or(cs, should_write);
        let should_update_and_queues_exhausted = should_update.and(cs, queues_exhausted);
        let should_push = previous_item_is_trivial
            .negated(cs)
            .and(cs, should_update_and_queues_exhausted);

        sorted_queue.push(cs, query, should_push);

        // reset flag to match simple witness generation convensions
        let constant_false = Boolean::allocated_constant(cs, false);
        this_cell_has_explicit_read_and_rollback_depth_zero = Boolean::conditionally_select(
            cs,
            queues_exhausted,
            &constant_false,
            &this_cell_has_explicit_read_and_rollback_depth_zero,
        );
    }

    // output our FSM values

    (
        lhs,
        rhs,
        cycle_idx,
        previous_packed_key,
        previous_key,
        previous_address,
        previous_timestamp,
        this_cell_has_explicit_read_and_rollback_depth_zero,
        this_cell_base_value,
        this_cell_current_value,
        this_cell_current_depth,
    )
}

fn concatenate_key<F: SmallField, CS: ConstraintSystem<F>>(
    _cs: &mut CS,
    key_tuple: (UInt160<F>, UInt256<F>),
) -> [UInt32<F>; PACKED_KEY_LENGTH] {
    // LE packing so comparison is subtraction
    let (address, key) = key_tuple;
    [
        key.inner[0],
        key.inner[1],
        key.inner[2],
        key.inner[3],
        key.inner[4],
        key.inner[5],
        key.inner[6],
        key.inner[7],
        address.inner[0],
        address.inner[1],
        address.inner[2],
        address.inner[3],
        address.inner[4],
    ]
}

/// Check that a == b and a > b by performing a long subtraction b - a with borrow.
/// Both a and b are considered as least significant word first
#[track_caller]
pub fn unpacked_long_comparison<F: SmallField, CS: ConstraintSystem<F>, const N: usize>(
    cs: &mut CS,
    a: &[UInt32<F>; N],
    b: &[UInt32<F>; N],
) -> (Boolean<F>, Boolean<F>) {
    let boolean_false = Boolean::allocated_constant(cs, false);
    let mut equals = [boolean_false; N];
    let mut borrow = boolean_false;

    for i in 0..N {
        let (diff, new_borrow) = b[i].overflowing_sub_with_borrow_in(cs, a[i], borrow);
        borrow = new_borrow;
        equals[i] = diff.is_zero(cs);
    }

    let equal = Boolean::multi_and(cs, &equals);
    let a_is_greater = borrow;

    (equal, a_is_greater)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boojum::algebraic_props::poseidon2_parameters::Poseidon2GoldilocksExternalMatrix;
    use boojum::cs::implementations::reference_cs::{
        CSDevelopmentAssembly, CSReferenceImplementation,
    };
    use boojum::cs::traits::gate::GatePlacementStrategy;
    use boojum::cs::CSGeometry;
    // use boojum::cs::EmptyToolbox;
    use boojum::cs::*;
    use boojum::field::goldilocks::GoldilocksField;
    use boojum::gadgets::tables::*;
    use boojum::implementations::poseidon2::Poseidon2Goldilocks;
    use boojum::worker::Worker;
    use ethereum_types::{Address, U256};

    type F = GoldilocksField;
    type P = GoldilocksField;

    use boojum::config::*;
    use boojum::cs::cs_builder::*;

    fn configure<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        let owned_cs = builder;
        let owned_cs = owned_cs.allow_lookup(
            LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
                width: 3,
                num_repetitions: 8,
                share_table_id: true,
            },
        );
        let owned_cs = ConstantsAllocatorGate::configure_builder(
            owned_cs,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let owned_cs = FmaGateInBaseFieldWithoutConstant::configure_builder(
            owned_cs,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let owned_cs = ReductionGate::<F, 4>::configure_builder(
            owned_cs,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let owned_cs = BooleanConstraintGate::configure_builder(
            owned_cs,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let owned_cs = UIntXAddGate::<32>::configure_builder(
            owned_cs,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let owned_cs = UIntXAddGate::<16>::configure_builder(
            owned_cs,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let owned_cs = SelectionGate::configure_builder(
            owned_cs,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let owned_cs = ZeroCheckGate::configure_builder(
            owned_cs,
            GatePlacementStrategy::UseGeneralPurposeColumns,
            false,
        );
        let owned_cs = DotProductGate::<4>::configure_builder(
            owned_cs,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let owned_cs =
            MatrixMultiplicationGate::<F, 12, Poseidon2GoldilocksExternalMatrix>::configure_builder(
                owned_cs,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
        let owned_cs =
            NopGate::configure_builder(owned_cs, GatePlacementStrategy::UseGeneralPurposeColumns);

        owned_cs
    }

    #[test]
    fn test_storage_validity_circuit() {
        let geometry = CSGeometry {
            num_columns_under_copy_permutation: 100,
            num_witness_columns: 0,
            num_constant_columns: 8,
            max_allowed_constraint_degree: 4,
        };

        use boojum::config::DevCSConfig;
        use boojum::cs::cs_builder_reference::*;

        let builder_impl =
            CsReferenceImplementationBuilder::<F, P, DevCSConfig>::new(geometry, 1 << 26, 1 << 20);
        use boojum::cs::cs_builder::new_builder;
        let builder = new_builder::<_, F>(builder_impl);

        let builder = configure(builder);
        let mut owned_cs = builder.build(());

        // add tables
        let table = create_xor8_table();
        owned_cs.add_lookup_table::<Xor8Table, 3>(table);

        let cs = &mut owned_cs;

        let lhs = [Num::allocated_constant(cs, F::from_nonreduced_u64(1));
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
        let rhs = [Num::allocated_constant(cs, F::from_nonreduced_u64(1));
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];

        let execute = Boolean::allocated_constant(cs, true);
        let mut original_queue = StorageLogQueue::<F, Poseidon2Goldilocks>::empty(cs);
        let unsorted_input = test_input::generate_test_input_unsorted(cs);
        for el in unsorted_input {
            original_queue.push(cs, el, execute);
        }

        let mut intermediate_sorted_queue = CircuitQueue::empty(cs);
        let sorted_input = test_input::generate_test_input_sorted(cs);
        for el in sorted_input {
            intermediate_sorted_queue.push(cs, el, execute);
        }

        let mut sorted_queue = StorageLogQueue::empty(cs);

        let is_start = Boolean::allocated_constant(cs, true);
        let cycle_idx = UInt32::allocated_constant(cs, 0);
        let round_function = Poseidon2Goldilocks;
        let fs_challenges = crate::utils::produce_fs_challenges::<
            F,
            _,
            Poseidon2Goldilocks,
            QUEUE_STATE_WIDTH,
            { TIMESTAMPED_STORAGE_LOG_ENCODING_LEN + 1 },
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS,
        >(
            cs,
            original_queue.into_state().tail,
            intermediate_sorted_queue.into_state().tail,
            &round_function,
        );
        let previous_packed_key = [UInt32::allocated_constant(cs, 0); PACKED_KEY_LENGTH];
        let previous_key = UInt256::allocated_constant(cs, U256::default());
        let previous_address = UInt160::allocated_constant(cs, Address::default());
        let previous_timestamp = UInt32::allocated_constant(cs, 0);
        let this_cell_has_explicit_read_and_rollback_depth_zero =
            Boolean::allocated_constant(cs, false);
        let this_cell_base_value = UInt256::allocated_constant(cs, U256::default());
        let this_cell_current_value = UInt256::allocated_constant(cs, U256::default());
        let this_cell_current_depth = UInt32::allocated_constant(cs, 0);
        let shard_id_to_process = UInt8::allocated_constant(cs, 0);
        let limit = 16;

        sort_and_deduplicate_storage_access_inner(
            cs,
            lhs,
            rhs,
            &mut original_queue,
            &mut intermediate_sorted_queue,
            &mut sorted_queue,
            is_start,
            cycle_idx,
            fs_challenges,
            previous_packed_key,
            previous_key,
            previous_address,
            previous_timestamp,
            this_cell_has_explicit_read_and_rollback_depth_zero,
            this_cell_base_value,
            this_cell_current_value,
            this_cell_current_depth,
            shard_id_to_process,
            limit,
        );

        cs.pad_and_shrink();
        let worker = Worker::new();
        let mut owned_cs = owned_cs.into_assembly();
        owned_cs.print_gate_stats();
        assert!(owned_cs.check_if_satisfied(&worker));
    }
}
