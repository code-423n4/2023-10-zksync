pub mod input;

use super::*;
use crate::base_structures::log_query::{LogQuery, LOG_QUERY_PACKED_WIDTH};
use crate::base_structures::vm_state::*;
use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use crate::fsm_input_output::{commit_variable_length_encodable_item, ClosedFormInputCompactForm};
use crate::storage_validity_by_grand_product::unpacked_long_comparison;
use boojum::cs::{gates::*, traits::cs::ConstraintSystem};
use boojum::field::SmallField;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::{
    boolean::Boolean,
    num::Num,
    queue::*,
    traits::{allocatable::CSAllocatableExt, selectable::Selectable},
    u256::UInt256,
    u32::UInt32,
    u8::UInt8,
};

use crate::demux_log_queue::StorageLogQueue;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
// This is a sorter of logs that are kind-of "pure", e.g. event emission or L2 -> L1 messages.
// Those logs do not affect a global state and may either be rolled back in full or not.
// We identify equality of logs using "timestamp" field that is a monotonic unique counter
// across the block

pub const NUM_PERMUTATION_ARG_CHALLENGES: usize = LOG_QUERY_PACKED_WIDTH + 1;

use crate::log_sorter::input::*;

pub fn sort_and_deduplicate_events_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    witness: EventsDeduplicatorInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    //use table
    let EventsDeduplicatorInstanceWitness {
        closed_form_input,
        initial_queue_witness,
        intermediate_sorted_queue_witness,
    } = witness;

    let mut structured_input =
        EventsDeduplicatorInputOutput::alloc_ignoring_outputs(cs, closed_form_input.clone());

    let unsorted_queue_from_passthrough_state =
        structured_input.observable_input.initial_log_queue_state;

    // passthrough must be trivial
    unsorted_queue_from_passthrough_state.enforce_trivial_head(cs);

    let unsorted_queue_from_fsm_input_state = structured_input
        .hidden_fsm_input
        .initial_unsorted_queue_state;

    let state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &unsorted_queue_from_passthrough_state,
        &unsorted_queue_from_fsm_input_state,
    );

    let mut unsorted_queue = StorageLogQueue::<F, R>::from_state(cs, state);

    use std::sync::Arc;
    let initial_queue_witness = CircuitQueueWitness::from_inner_witness(initial_queue_witness);
    unsorted_queue.witness = Arc::new(initial_queue_witness);

    let intermediate_sorted_queue_from_passthrough_state = structured_input
        .observable_input
        .intermediate_sorted_queue_state;

    // passthrough must be trivial
    intermediate_sorted_queue_from_passthrough_state.enforce_trivial_head(cs);

    let intermediate_sorted_queue_from_fsm_state = structured_input
        .hidden_fsm_input
        .intermediate_sorted_queue_state;

    let state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &intermediate_sorted_queue_from_passthrough_state,
        &intermediate_sorted_queue_from_fsm_state,
    );
    let mut intermediate_sorted_queue = StorageLogQueue::<F, R>::from_state(cs, state);
    let intermediate_sorted_queue_witness =
        CircuitQueueWitness::from_inner_witness(intermediate_sorted_queue_witness);
    intermediate_sorted_queue.witness = Arc::new(intermediate_sorted_queue_witness);

    let final_sorted_queue_from_fsm = structured_input.hidden_fsm_input.final_result_queue_state;
    let empty_state = QueueState::empty(cs);

    let final_sorted_state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &empty_state,
        &final_sorted_queue_from_fsm,
    );
    let mut final_sorted_queue = StorageLogQueue::<F, R>::from_state(cs, final_sorted_state);

    // get challenges for permutation argument
    let challenges = crate::utils::produce_fs_challenges::<
        F,
        CS,
        R,
        QUEUE_STATE_WIDTH,
        { MEMORY_QUERY_PACKED_WIDTH + 1 },
        DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS,
    >(
        cs,
        structured_input
            .observable_input
            .initial_log_queue_state
            .tail,
        structured_input
            .observable_input
            .intermediate_sorted_queue_state
            .tail,
        round_function,
    );

    let one = Num::allocated_constant(cs, F::ONE);
    let initial_lhs = Num::parallel_select(
        cs,
        structured_input.start_flag,
        &[one; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
        &structured_input.hidden_fsm_input.lhs_accumulator,
    );

    let initial_rhs = Num::parallel_select(
        cs,
        structured_input.start_flag,
        &[one; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
        &structured_input.hidden_fsm_input.rhs_accumulator,
    );

    // there is no code at address 0 in our case, so we can formally use it for all the purposes
    let zero_u32 = UInt32::zero(cs);
    let previous_key = UInt32::conditionally_select(
        cs,
        structured_input.start_flag,
        &zero_u32,
        &structured_input.hidden_fsm_input.previous_key,
    );

    // there is no code at address 0 in our case, so we can formally use it for all the purposes
    use boojum::gadgets::traits::allocatable::CSPlaceholder;
    let empty_storage = LogQuery::placeholder(cs);
    let previous_item = LogQuery::conditionally_select(
        cs,
        structured_input.start_flag,
        &empty_storage,
        &structured_input.hidden_fsm_input.previous_item,
    );

    let (new_lhs, new_rhs, previous_key, previous_item) =
        repack_and_prove_events_rollbacks_inner::<_, _, R>(
            cs,
            initial_lhs,
            initial_rhs,
            &mut unsorted_queue,
            &mut intermediate_sorted_queue,
            &mut final_sorted_queue,
            structured_input.start_flag,
            challenges,
            previous_key,
            previous_item,
            limit,
        );

    let unsorted_is_empty = unsorted_queue.is_empty(cs);
    let sorted_is_empty = intermediate_sorted_queue.is_empty(cs);

    Boolean::enforce_equal(cs, &unsorted_is_empty, &sorted_is_empty);

    let completed = unsorted_queue.length.is_zero(cs);
    for (lhs, rhs) in new_lhs.iter().zip(new_rhs.iter()) {
        Num::conditionally_enforce_equal(cs, completed, lhs, rhs);
    }
    // form the final state
    structured_input.hidden_fsm_output.previous_key = previous_key;
    structured_input.hidden_fsm_output.previous_item = previous_item;
    structured_input.hidden_fsm_output.lhs_accumulator = new_lhs;
    structured_input.hidden_fsm_output.rhs_accumulator = new_rhs;

    structured_input
        .hidden_fsm_output
        .initial_unsorted_queue_state = unsorted_queue.into_state();
    structured_input
        .hidden_fsm_output
        .intermediate_sorted_queue_state = intermediate_sorted_queue.into_state();

    structured_input.completion_flag = completed;

    let empty_state = QueueState::empty(cs);
    let final_queue_for_observable_output = QueueState::conditionally_select(
        cs,
        completed,
        &final_sorted_queue.into_state(),
        &empty_state,
    );

    structured_input.observable_output.final_queue_state = final_queue_for_observable_output;

    structured_input.hidden_fsm_output.final_result_queue_state = final_sorted_queue.into_state();

    let compact_form =
        ClosedFormInputCompactForm::from_full_form(cs, &structured_input, round_function);

    // dbg!(compact_form.create_witness());
    let input_commitment = commit_variable_length_encodable_item(cs, &compact_form, round_function);
    for el in input_commitment.iter() {
        let gate = PublicInputGate::new(el.get_variable());
        gate.add_to_cs(cs);
    }

    input_commitment
}
use crate::base_structures::memory_query::MEMORY_QUERY_PACKED_WIDTH;
pub fn repack_and_prove_events_rollbacks_inner<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    mut lhs: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    mut rhs: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    unsorted_queue: &mut StorageLogQueue<F, R>,
    intermediate_sorted_queue: &mut StorageLogQueue<F, R>,
    result_queue: &mut StorageLogQueue<F, R>,
    is_start: Boolean<F>,
    fs_challenges: [[Num<F>; MEMORY_QUERY_PACKED_WIDTH + 1];
        DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    mut previous_key: UInt32<F>,
    mut previous_item: LogQuery<F>,
    limit: usize,
) -> (
    [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    UInt32<F>,
    LogQuery<F>,
)
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    assert!(limit <= u32::MAX as usize);

    // we can recreate it here, there are two cases:
    // - we are 100% empty, but it's the only circuit in this case
    // - otherwise we continue, and then it's not trivial
    let no_work = unsorted_queue.is_empty(cs);
    let mut previous_is_trivial = Boolean::multi_or(cs, &[no_work, is_start]);

    let unsorted_queue_lenght = Num::from_variable(unsorted_queue.length.get_variable());
    let intermediate_sorted_queue_lenght =
        Num::from_variable(intermediate_sorted_queue.length.get_variable());

    Num::enforce_equal(
        cs,
        &unsorted_queue_lenght,
        &intermediate_sorted_queue_lenght,
    );

    // reallocate and simultaneously collapse rollbacks

    for _cycle in 0..limit {
        let original_is_empty = unsorted_queue.is_empty(cs);
        let sorted_is_empty = intermediate_sorted_queue.is_empty(cs);
        Boolean::enforce_equal(cs, &original_is_empty, &sorted_is_empty);

        let should_pop = original_is_empty.negated(cs);
        let is_trivial = original_is_empty;

        let (_, original_encoding) = unsorted_queue.pop_front(cs, should_pop);
        let (sorted_item, sorted_encoding) = intermediate_sorted_queue.pop_front(cs, should_pop);

        // we also ensure that items are "write" unless it's a padding
        sorted_item
            .rw_flag
            .conditionally_enforce_true(cs, should_pop);

        assert_eq!(original_encoding.len(), sorted_encoding.len());
        assert_eq!(lhs.len(), rhs.len());
        for ((challenges, lhs), rhs) in fs_challenges.iter().zip(lhs.iter_mut()).zip(rhs.iter_mut())
        {
            // additive parts
            let mut lhs_contribution = challenges[MEMORY_QUERY_PACKED_WIDTH];
            let mut rhs_contribution = challenges[MEMORY_QUERY_PACKED_WIDTH];

            for ((original_el, sorted_el), challenge) in original_encoding
                .iter()
                .zip(sorted_encoding.iter())
                .zip(challenges.iter())
            {
                lhs_contribution = Num::fma(
                    cs,
                    &Num::from_variable(*original_el),
                    challenge,
                    &F::ONE,
                    &lhs_contribution,
                    &F::ONE,
                );

                rhs_contribution = Num::fma(
                    cs,
                    &Num::from_variable(*sorted_el),
                    challenge,
                    &F::ONE,
                    &rhs_contribution,
                    &F::ONE,
                );
            }

            let new_lhs = lhs.mul(cs, &lhs_contribution);
            let new_rhs = rhs.mul(cs, &rhs_contribution);

            *lhs = Num::conditionally_select(cs, should_pop, &new_lhs, &lhs);
            *rhs = Num::conditionally_select(cs, should_pop, &new_rhs, &rhs);
        }
        // now ensure sorting
        {
            // sanity check - all such logs are "write into the sky"
            sorted_item
                .rw_flag
                .conditionally_enforce_true(cs, should_pop);

            // check if keys are equal and check a value

            // We compare timestamps, and then resolve logic over rollbacks, so the only way when
            // keys are equal can be when we do rollback
            let sorting_key = sorted_item.timestamp;

            // ensure sorting for uniqueness timestamp and rollback flag
            // We know that timestamps are unique accross logs, and are also the same between write and rollback
            let (keys_are_equal, new_key_is_smaller) =
                unpacked_long_comparison(cs, &[previous_key], &[sorting_key]);

            // keys are always ordered no matter what, and are never equal unless it's padding
            new_key_is_smaller.conditionally_enforce_false(cs, should_pop);

            // there are only two cases when keys are equal:
            // - it's a padding element
            // - it's a rollback

            // it's enough to compare timestamps as VM circuit guarantees uniqueness of the if it's not a padding
            let previous_is_not_rollback = previous_item.rollback.negated(cs);
            let enforce_sequential_rollback = Boolean::multi_and(
                cs,
                &[previous_is_not_rollback, sorted_item.rollback, should_pop],
            );
            keys_are_equal.conditionally_enforce_true(cs, enforce_sequential_rollback);

            let same_log = UInt32::equals(cs, &sorted_item.timestamp, &previous_item.timestamp);

            let values_are_equal =
                UInt256::equals(cs, &sorted_item.written_value, &previous_item.written_value);

            let negate_previous_is_trivial = previous_is_trivial.negated(cs);
            let should_enforce = Boolean::multi_and(cs, &[same_log, negate_previous_is_trivial]);

            values_are_equal.conditionally_enforce_true(cs, should_enforce);

            let this_item_is_non_trivial_rollback =
                Boolean::multi_and(cs, &[sorted_item.rollback, should_pop]);
            let negate_previous_item_rollback = previous_item.rollback.negated(cs);
            let prevous_item_is_non_trivial_write = Boolean::multi_and(
                cs,
                &[negate_previous_item_rollback, negate_previous_is_trivial],
            );
            let is_sequential_rollback = Boolean::multi_and(
                cs,
                &[
                    this_item_is_non_trivial_rollback,
                    prevous_item_is_non_trivial_write,
                ],
            );
            same_log.conditionally_enforce_true(cs, is_sequential_rollback);

            // decide if we should add the PREVIOUS into the queue
            // We add only if previous one is not trivial,
            // and it had a different key, and it wasn't rolled back
            let negate_same_log = same_log.and(cs, should_pop).negated(cs);
            let add_to_the_queue = Boolean::multi_and(
                cs,
                &[
                    negate_previous_is_trivial,
                    negate_same_log,
                    negate_previous_item_rollback,
                ],
            );
            let boolean_false = Boolean::allocated_constant(cs, false);
            // cleanup some fields that are not useful
            let query_to_add = LogQuery {
                address: previous_item.address,
                key: previous_item.key,
                read_value: UInt256::zero(cs),
                written_value: previous_item.written_value,
                rw_flag: boolean_false,
                aux_byte: UInt8::zero(cs),
                rollback: boolean_false,
                is_service: previous_item.is_service,
                shard_id: previous_item.shard_id,
                tx_number_in_block: previous_item.tx_number_in_block,
                timestamp: UInt32::zero(cs),
            };

            result_queue.push(cs, query_to_add, add_to_the_queue);

            previous_is_trivial = is_trivial;
            previous_item = sorted_item;
            previous_key = sorting_key;
        }
    }

    // finalization step - same way, check if last item is not a rollback
    {
        let now_empty = unsorted_queue.is_empty(cs);

        let negate_previous_is_trivial = previous_is_trivial.negated(cs);
        let negate_previous_item_rollback = previous_item.rollback.negated(cs);
        let add_to_the_queue = Boolean::multi_and(
            cs,
            &[
                negate_previous_is_trivial,
                negate_previous_item_rollback,
                now_empty,
            ],
        );
        let boolean_false = Boolean::allocated_constant(cs, false);
        let query_to_add = LogQuery {
            address: previous_item.address,
            key: previous_item.key,
            read_value: UInt256::zero(cs),
            written_value: previous_item.written_value,
            rw_flag: boolean_false,
            aux_byte: UInt8::zero(cs),
            rollback: boolean_false,
            is_service: previous_item.is_service,
            shard_id: previous_item.shard_id,
            tx_number_in_block: previous_item.tx_number_in_block,
            timestamp: UInt32::zero(cs),
        };

        result_queue.push(cs, query_to_add, add_to_the_queue);
    }

    unsorted_queue.enforce_consistency(cs);
    intermediate_sorted_queue.enforce_consistency(cs);

    (lhs, rhs, previous_key, previous_item)
}

/// Check that a == b and a > b by performing a long subtraction b - a with borrow.
/// Both a and b are considered as least significant word first
#[track_caller]
pub fn prepacked_long_comparison<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    a: &[Num<F>],
    b: &[Num<F>],
    width_data: &[usize],
) -> (Boolean<F>, Boolean<F>) {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), width_data.len());

    let mut previous_borrow = Boolean::allocated_constant(cs, false);
    let mut limbs_are_equal = vec![];
    for (a, b) in a.iter().zip(b.iter()) {
        let a_uint32 = unsafe { UInt32::from_variable_unchecked(a.get_variable()) };
        let b_uint32 = unsafe { UInt32::from_variable_unchecked(b.get_variable()) };
        let (diff, borrow) = a_uint32.overflowing_sub_with_borrow_in(cs, b_uint32, previous_borrow);
        let equal = diff.is_zero(cs);
        limbs_are_equal.push(equal);
        previous_borrow = borrow;
    }
    let final_borrow = previous_borrow;
    let eq = Boolean::multi_and(cs, &limbs_are_equal);

    (eq, final_borrow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boojum::algebraic_props::poseidon2_parameters::Poseidon2GoldilocksExternalMatrix;
    use boojum::cs::implementations::reference_cs::CSDevelopmentAssembly;
    use boojum::cs::traits::gate::GatePlacementStrategy;
    use boojum::cs::CSGeometry;
    use boojum::cs::*;
    use boojum::field::goldilocks::GoldilocksField;
    use boojum::gadgets::tables::*;
    use boojum::gadgets::traits::allocatable::CSPlaceholder;
    use boojum::gadgets::u160::UInt160;
    use boojum::gadgets::u256::UInt256;
    use boojum::gadgets::u8::UInt8;
    use boojum::implementations::poseidon2::Poseidon2Goldilocks;
    use boojum::worker::Worker;
    use ethereum_types::{Address, U256};
    type F = GoldilocksField;
    type P = GoldilocksField;

    #[test]
    fn test_repack_and_prove_events_rollbacks_inner() {
        let geometry = CSGeometry {
            num_columns_under_copy_permutation: 100,
            num_witness_columns: 0,
            num_constant_columns: 8,
            max_allowed_constraint_degree: 4,
        };

        use boojum::cs::cs_builder::*;

        fn configure<
            T: CsBuilderImpl<F, T>,
            GC: GateConfigurationHolder<F>,
            TB: StaticToolboxHolder,
        >(
            builder: CsBuilder<T, F, GC, TB>,
        ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
            let builder = builder.allow_lookup(
                LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
                    width: 3,
                    num_repetitions: 8,
                    share_table_id: true,
                },
            );
            let builder = ConstantsAllocatorGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = ReductionGate::<F, 4>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = BooleanConstraintGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = UIntXAddGate::<32>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = UIntXAddGate::<16>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = SelectionGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = ZeroCheckGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
                false,
            );
            let builder = DotProductGate::<4>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = MatrixMultiplicationGate::<F, 12, Poseidon2GoldilocksExternalMatrix>::configure_builder(builder,GatePlacementStrategy::UseGeneralPurposeColumns);
            let builder = NopGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );

            builder
        }

        use boojum::config::DevCSConfig;
        use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

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

        let execute = Boolean::allocated_constant(cs, true);
        let mut original_queue = StorageLogQueue::<F, Poseidon2Goldilocks>::empty(cs);
        let unsorted_input = witness_input_unsorted(cs);
        for el in unsorted_input {
            original_queue.push(cs, el, execute);
        }
        let mut sorted_queue = StorageLogQueue::<F, Poseidon2Goldilocks>::empty(cs);
        let sorted_input = witness_input_sorted(cs);
        for el in sorted_input {
            sorted_queue.push(cs, el, execute);
        }

        let mut result_queue = StorageLogQueue::empty(cs);

        let lhs = [Num::allocated_constant(cs, F::from_nonreduced_u64(1));
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
        let rhs = [Num::allocated_constant(cs, F::from_nonreduced_u64(1));
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
        let is_start = Boolean::allocated_constant(cs, true);
        let round_function = Poseidon2Goldilocks;
        let fs_challenges = crate::utils::produce_fs_challenges::<
            F,
            _,
            Poseidon2Goldilocks,
            QUEUE_STATE_WIDTH,
            { MEMORY_QUERY_PACKED_WIDTH + 1 },
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS,
        >(
            cs,
            original_queue.into_state().tail,
            sorted_queue.into_state().tail,
            &round_function,
        );
        let limit = 16;
        let previous_key = UInt32::allocated_constant(cs, 0);
        let previous_item = LogQuery::placeholder(cs);
        repack_and_prove_events_rollbacks_inner(
            cs,
            lhs,
            rhs,
            &mut original_queue,
            &mut sorted_queue,
            &mut result_queue,
            is_start,
            fs_challenges,
            previous_key,
            previous_item,
            limit,
        );

        cs.pad_and_shrink();
        let worker = Worker::new();
        let mut owned_cs = owned_cs.into_assembly();
        owned_cs.print_gate_stats();
        assert!(owned_cs.check_if_satisfied(&worker));
    }

    fn witness_input_unsorted<CS: ConstraintSystem<F>>(cs: &mut CS) -> Vec<LogQuery<F>> {
        let mut unsorted_querie = vec![];
        let bool_false = Boolean::allocated_constant(cs, false);
        let bool_true = Boolean::allocated_constant(cs, true);
        let zero_8 = UInt8::allocated_constant(cs, 0);
        let one_8 = UInt8::allocated_constant(cs, 1);
        let zero_32 = UInt32::allocated_constant(cs, 0);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32781)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("962072674308").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("32776").unwrap()),
            rw_flag: bool_true,
            aux_byte: one_8,
            rollback: bool_false,
            is_service: bool_true,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 9441),
        };

        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32781)),
            key: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "26331131646299181274004581916076390273434308111684230560370784413089286382145",
                )
                .unwrap(),
            ),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("32769").unwrap()),
            rw_flag: bool_true,
            aux_byte: one_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 9597),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32781)),
            key: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "39698723498166066574330386068075452510013183019908537087846976369872031173837",
                )
                .unwrap(),
            ),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("32").unwrap()),
            rw_flag: bool_true,
            aux_byte: one_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 9677),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32781)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("154").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "34572686050049115524117736286529744084162467349680365734578449291092091566196",
                )
                .unwrap(),
            ),
            rw_flag: bool_true,
            aux_byte: one_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 9725),
        };
        unsorted_querie.push(q);

        unsorted_querie
    }
    fn witness_input_sorted<CS: ConstraintSystem<F>>(cs: &mut CS) -> Vec<LogQuery<F>> {
        let mut sorted_querie = vec![];
        let bool_false = Boolean::allocated_constant(cs, false);
        let bool_true = Boolean::allocated_constant(cs, true);
        let zero_8 = UInt8::allocated_constant(cs, 0);
        let one_8 = UInt8::allocated_constant(cs, 1);
        let zero_32 = UInt32::allocated_constant(cs, 0);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32781)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("962072674308").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("32776").unwrap()),
            rw_flag: bool_true,
            aux_byte: one_8,
            rollback: bool_false,
            is_service: bool_true,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 9441),
        };

        sorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32781)),
            key: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "26331131646299181274004581916076390273434308111684230560370784413089286382145",
                )
                .unwrap(),
            ),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("32769").unwrap()),
            rw_flag: bool_true,
            aux_byte: one_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 9597),
        };
        sorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32781)),
            key: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "39698723498166066574330386068075452510013183019908537087846976369872031173837",
                )
                .unwrap(),
            ),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("32").unwrap()),
            rw_flag: bool_true,
            aux_byte: one_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 9677),
        };
        sorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32781)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("154").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "34572686050049115524117736286529744084162467349680365734578449291092091566196",
                )
                .unwrap(),
            ),
            rw_flag: bool_true,
            aux_byte: one_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 9725),
        };
        sorted_querie.push(q);

        sorted_querie
    }
}
