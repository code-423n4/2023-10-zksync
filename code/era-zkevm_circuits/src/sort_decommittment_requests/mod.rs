use super::*;

use crate::base_structures::log_query::LOG_QUERY_PACKED_WIDTH;
use crate::fsm_input_output::ClosedFormInputCompactForm;

use boojum::cs::{gates::*, traits::cs::ConstraintSystem};
use boojum::field::SmallField;
use boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueWitness;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::{
    boolean::Boolean,
    num::Num,
    queue::*,
    traits::{allocatable::CSAllocatableExt, selectable::Selectable},
    u32::UInt32,
};

use crate::base_structures::decommit_query::{DecommitQueue, DECOMMIT_QUERY_PACKED_WIDTH};
use crate::base_structures::vm_state::*;
use crate::base_structures::{
    decommit_query::DecommitQuery, memory_query::MEMORY_QUERY_PACKED_WIDTH,
};
use crate::fsm_input_output::{circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH, *};
use crate::sort_decommittment_requests::input::*;
use crate::storage_validity_by_grand_product::unpacked_long_comparison;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::gadgets::traits::allocatable::CSPlaceholder;
use boojum::gadgets::u256::UInt256;

pub mod input;

// This is a sorter of logs that are kind-of "pure", F.g. event emission or L2 -> L1 messages.
// Those logs do not affect a global state and may either be rolled back in full or not.
// We identify equality of logs using "timestamp" field that is a monotonic unique counter
// across the block
pub const NUM_PERMUTATION_ARG_CHALLENGES: usize = LOG_QUERY_PACKED_WIDTH + 1;

pub fn sort_and_deduplicate_code_decommittments_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    witness: CodeDecommittmentsDeduplicatorInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    // as usual we assume that a caller of this fuunction has already split input queue,
    // so it can be comsumed in full

    //use table
    let CodeDecommittmentsDeduplicatorInstanceWitness {
        closed_form_input,
        initial_queue_witness,
        sorted_queue_witness,
    } = witness;

    let mut structured_input = CodeDecommittmentsDeduplicatorInputOutput::alloc_ignoring_outputs(
        cs,
        closed_form_input.clone(),
    );

    let initial_queue_from_passthrough_state =
        structured_input.observable_input.initial_queue_state;
    let initial_log_queue_state_from_fsm_state =
        structured_input.hidden_fsm_input.initial_queue_state;

    let state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &initial_queue_from_passthrough_state,
        &initial_log_queue_state_from_fsm_state,
    );
    let mut initial_queue = DecommitQueue::<F, R>::from_state(cs, state);

    // passthrough must be trivial
    initial_queue_from_passthrough_state.enforce_trivial_head(cs);

    use std::sync::Arc;
    let initial_queue_witness =
        FullStateCircuitQueueWitness::from_inner_witness(initial_queue_witness);
    initial_queue.witness = Arc::new(initial_queue_witness);

    let intermediate_sorted_queue_from_passthrough_state =
        structured_input.observable_input.sorted_queue_initial_state;
    let intermediate_sorted_queue_from_fsm_input_state =
        structured_input.hidden_fsm_input.sorted_queue_state;

    // it must be trivial
    intermediate_sorted_queue_from_passthrough_state.enforce_trivial_head(cs);

    let state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &intermediate_sorted_queue_from_passthrough_state,
        &intermediate_sorted_queue_from_fsm_input_state,
    );
    let mut intermediate_sorted_queue = DecommitQueue::<F, R>::from_state(cs, state);

    let sorted_queue_witness =
        FullStateCircuitQueueWitness::from_inner_witness(sorted_queue_witness);
    intermediate_sorted_queue.witness = Arc::new(sorted_queue_witness);

    let empty_state = QueueState::empty(cs);

    let final_sorted_queue_from_fsm_state = structured_input.hidden_fsm_input.final_queue_state;

    let state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &empty_state,
        &final_sorted_queue_from_fsm_state,
    );
    let mut final_sorted_queue = DecommitQueue::<F, R>::from_state(cs, state);

    let challenges = crate::utils::produce_fs_challenges::<
        F,
        CS,
        R,
        FULL_SPONGE_QUEUE_STATE_WIDTH,
        { DECOMMIT_QUERY_PACKED_WIDTH + 1 },
        DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS,
    >(
        cs,
        structured_input.observable_input.initial_queue_state.tail,
        structured_input
            .observable_input
            .sorted_queue_initial_state
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

    let trivial_record = DecommitQuery::placeholder(cs);
    let mut previous_record = DecommitQuery::conditionally_select(
        cs,
        structured_input.start_flag,
        &trivial_record,
        &structured_input.hidden_fsm_input.previous_record,
    );

    let zero_u32 = UInt32::zero(cs);
    let mut previous_packed_key = <[UInt32<F>; PACKED_KEY_LENGTH]>::conditionally_select(
        cs,
        structured_input.start_flag,
        &[zero_u32; PACKED_KEY_LENGTH],
        &structured_input.hidden_fsm_input.previous_packed_key,
    );

    let mut first_encountered_timestamp = UInt32::conditionally_select(
        cs,
        structured_input.start_flag,
        &zero_u32,
        &structured_input
            .hidden_fsm_input
            .first_encountered_timestamp,
    );

    let (completed, new_lhs, new_rhs) = sort_and_deduplicate_code_decommittments_inner(
        cs,
        &mut initial_queue,
        &mut intermediate_sorted_queue,
        &mut final_sorted_queue,
        initial_lhs,
        initial_rhs,
        challenges,
        &mut previous_packed_key,
        &mut first_encountered_timestamp,
        &mut previous_record,
        structured_input.start_flag,
        limit,
    );

    for (lhs, rhs) in new_lhs.iter().zip(new_rhs.iter()) {
        Num::conditionally_enforce_equal(cs, completed, lhs, rhs);
    }
    // form the final state
    structured_input.observable_output = CodeDecommittmentsDeduplicatorOutputData::placeholder(cs);

    structured_input.hidden_fsm_output =
        CodeDecommittmentsDeduplicatorFSMInputOutput::placeholder(cs);
    structured_input.hidden_fsm_output.initial_queue_state = initial_queue.into_state();
    structured_input.hidden_fsm_output.sorted_queue_state = intermediate_sorted_queue.into_state();
    structured_input.hidden_fsm_output.final_queue_state = final_sorted_queue.into_state();
    structured_input.hidden_fsm_output.lhs_accumulator = new_lhs;
    structured_input.hidden_fsm_output.rhs_accumulator = new_rhs;
    structured_input.hidden_fsm_output.previous_packed_key = previous_packed_key;
    structured_input.hidden_fsm_output.previous_record = previous_record;
    structured_input
        .hidden_fsm_output
        .first_encountered_timestamp = first_encountered_timestamp;

    structured_input.observable_output.final_queue_state = QueueState::conditionally_select(
        cs,
        completed,
        &structured_input.hidden_fsm_output.final_queue_state,
        &structured_input.observable_output.final_queue_state,
    );

    structured_input.completion_flag = completed;

    // self-check
    structured_input.hook_compare_witness(cs, &closed_form_input);

    let compact_form =
        ClosedFormInputCompactForm::from_full_form(cs, &structured_input, round_function);
    let input_commitment = commit_variable_length_encodable_item(cs, &compact_form, round_function);
    for el in input_commitment.iter() {
        let gate = PublicInputGate::new(el.get_variable());
        gate.add_to_cs(cs);
    }

    input_commitment
}

pub fn sort_and_deduplicate_code_decommittments_inner<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    original_queue: &mut DecommitQueue<F, R>,
    sorted_queue: &mut DecommitQueue<F, R>,
    result_queue: &mut DecommitQueue<F, R>,
    mut lhs: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    mut rhs: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    fs_challenges: [[Num<F>; DECOMMIT_QUERY_PACKED_WIDTH + 1];
        DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    previous_packed_key: &mut [UInt32<F>; PACKED_KEY_LENGTH],
    first_encountered_timestamp: &mut UInt32<F>,
    previous_record: &mut DecommitQuery<F>,
    start_flag: Boolean<F>,
    limit: usize,
) -> (
    Boolean<F>,
    [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
)
where
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    assert!(limit <= u32::MAX as usize);
    let unsorted_queue_length = Num::from_variable(original_queue.length.get_variable());
    let intermediate_sorted_queue_length = Num::from_variable(sorted_queue.length.get_variable());

    Num::enforce_equal(
        cs,
        &unsorted_queue_length,
        &intermediate_sorted_queue_length,
    );

    let no_work = original_queue.is_empty(cs);

    let mut previous_item_is_trivial = no_work.or(cs, start_flag);

    // Simultaneously pop, prove sorting and resolve logic

    for _cycle in 0..limit {
        let original_is_empty = original_queue.is_empty(cs);
        let sorted_is_empty = sorted_queue.is_empty(cs);
        Boolean::enforce_equal(cs, &original_is_empty, &sorted_is_empty);

        let should_pop = original_is_empty.negated(cs);
        let is_trivial = original_is_empty;

        let (_, original_encoding) = original_queue.pop_front(cs, should_pop);
        let (sorted_item, sorted_encoding) = sorted_queue.pop_front(cs, should_pop);

        // we make encoding that is the same as defined for timestamped item
        assert_eq!(original_encoding.len(), sorted_encoding.len());
        assert_eq!(lhs.len(), rhs.len());

        for ((challenges, lhs), rhs) in fs_challenges.iter().zip(lhs.iter_mut()).zip(rhs.iter_mut())
        {
            let mut lhs_contribution = challenges[DECOMMIT_QUERY_PACKED_WIDTH];
            let mut rhs_contribution = challenges[DECOMMIT_QUERY_PACKED_WIDTH];

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

        // check if keys are equal and check a value
        let packed_key = concatenate_key(cs, (sorted_item.timestamp, sorted_item.code_hash));

        // ensure sorting for uniqueness timestamp and rollback flag
        // We know that timestamps are unique accross logs, and are also the same between write and rollback
        let (_keys_are_equal, new_key_is_greater) =
            unpacked_long_comparison(cs, &packed_key, &*previous_packed_key);
        // always ascedning
        new_key_is_greater.conditionally_enforce_true(cs, should_pop);

        let same_hash = UInt256::equals(cs, &previous_record.code_hash, &sorted_item.code_hash);

        // if we get new hash then it my have a "first" marker
        let different_hash = same_hash.negated(cs);
        let enforce_must_be_first = Boolean::multi_and(cs, &[different_hash, should_pop]);
        sorted_item
            .is_first
            .conditionally_enforce_true(cs, enforce_must_be_first);

        // otherwise it should have the same memory page
        let previous_is_non_trivial = previous_item_is_trivial.negated(cs);
        let enforce_same_memory_page =
            Boolean::multi_and(cs, &[same_hash, previous_is_non_trivial]);

        Num::conditionally_enforce_equal(
            cs,
            enforce_same_memory_page,
            &sorted_item.page.into_num(),
            &previous_record.page.into_num(),
        );

        // decide if we should add the PREVIOUS into the queue
        let add_to_the_queue = Boolean::multi_and(cs, &[previous_is_non_trivial, different_hash]);

        let mut record_to_add = *previous_record;
        record_to_add.is_first = Boolean::allocated_constant(cs, true); // we use convension to be easier consistent with out of circuit part
        record_to_add.timestamp = *first_encountered_timestamp;
        result_queue.push(cs, record_to_add, add_to_the_queue);

        previous_item_is_trivial = is_trivial;
        // may be update the timestamp
        *first_encountered_timestamp = UInt32::conditionally_select(
            cs,
            same_hash,
            &first_encountered_timestamp,
            &sorted_item.timestamp,
        );
        *previous_record = sorted_item;
        *previous_packed_key = packed_key;
    }

    // if this circuit is the last one the queues must be empty and grand products must be equal
    let completed = original_queue.is_empty(cs);
    let sorted_queue_is_empty = sorted_queue.is_empty(cs);
    Boolean::enforce_equal(cs, &completed, &sorted_queue_is_empty);

    // finalization step - push the last one if necessary
    {
        let previous_is_non_trivial = previous_item_is_trivial.negated(cs);
        let add_to_the_queue = Boolean::multi_and(cs, &[previous_is_non_trivial, completed]);

        let mut record_to_add = *previous_record;
        record_to_add.is_first = Boolean::allocated_constant(cs, true); // we use convension to be easier consistent with out of circuit part
        record_to_add.timestamp = *first_encountered_timestamp;

        result_queue.push(cs, record_to_add, add_to_the_queue);
    }

    original_queue.enforce_consistency(cs);
    sorted_queue.enforce_consistency(cs);

    (completed, lhs, rhs)
}

fn concatenate_key<F: SmallField, CS: ConstraintSystem<F>>(
    _cs: &mut CS,
    key_tuple: (UInt32<F>, UInt256<F>),
) -> [UInt32<F>; PACKED_KEY_LENGTH] {
    // LE packing so comparison is subtraction
    let (timestamp, key) = key_tuple;
    [
        timestamp,
        key.inner[0],
        key.inner[1],
        key.inner[2],
        key.inner[3],
        key.inner[4],
        key.inner[5],
        key.inner[6],
        key.inner[7],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_types::U256;
    use boojum::algebraic_props::poseidon2_parameters::Poseidon2GoldilocksExternalMatrix;
    use boojum::cs::implementations::reference_cs::CSDevelopmentAssembly;
    use boojum::cs::traits::gate::GatePlacementStrategy;
    use boojum::cs::CSGeometry;
    use boojum::cs::*;
    use boojum::field::goldilocks::GoldilocksField;
    use boojum::gadgets::tables::*;
    use boojum::gadgets::traits::allocatable::CSPlaceholder;
    use boojum::gadgets::u256::UInt256;
    use boojum::implementations::poseidon2::Poseidon2Goldilocks;
    use boojum::worker::Worker;
    type F = GoldilocksField;
    type P = GoldilocksField;

    #[test]
    fn test_sort_and_deduplicate_code_decommittments_inner() {
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
        let mut original_queue = DecommitQueue::<F, Poseidon2Goldilocks>::empty(cs);
        let unsorted_input = witness_input_unsorted(cs);
        for el in unsorted_input {
            original_queue.push(cs, el, execute);
        }
        let mut sorted_queue = DecommitQueue::<F, Poseidon2Goldilocks>::empty(cs);
        let sorted_input = witness_input_sorted(cs);
        for el in sorted_input {
            sorted_queue.push(cs, el, execute);
        }

        let mut result_queue = DecommitQueue::empty(cs);

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
            FULL_SPONGE_QUEUE_STATE_WIDTH,
            { MEMORY_QUERY_PACKED_WIDTH + 1 },
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS,
        >(
            cs,
            original_queue.into_state().tail,
            sorted_queue.into_state().tail,
            &round_function,
        );
        let limit = 16;
        let mut previous_packed_key = [UInt32::allocated_constant(cs, 0); PACKED_KEY_LENGTH];
        let mut first_encountered_timestamp = UInt32::allocated_constant(cs, 0);
        let mut previous_record = DecommitQuery::placeholder(cs);
        sort_and_deduplicate_code_decommittments_inner(
            cs,
            &mut original_queue,
            &mut sorted_queue,
            &mut result_queue,
            lhs,
            rhs,
            fs_challenges,
            &mut previous_packed_key,
            &mut first_encountered_timestamp,
            &mut previous_record,
            is_start,
            limit,
        );

        cs.pad_and_shrink();
        let worker = Worker::new();
        let mut owned_cs = owned_cs.into_assembly();
        owned_cs.print_gate_stats();
        assert!(owned_cs.check_if_satisfied(&worker));
    }
    fn witness_input_unsorted<CS: ConstraintSystem<F>>(cs: &mut CS) -> Vec<DecommitQuery<F>> {
        let mut unsorted_querie = vec![];
        let bool_false = Boolean::allocated_constant(cs, false);
        let bool_true = Boolean::allocated_constant(cs, true);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452334469539131717490596781220410444809589670111004622364436613658071035425",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 8),
            is_first: bool_true,
            timestamp: UInt32::allocated_constant(cs, 1),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2048),
            is_first: bool_true,
            timestamp: UInt32::allocated_constant(cs, 1205),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2048),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 1609),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2048),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 1969),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2048),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 2429),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2048),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 2901),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2048),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 3265),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2048),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 3597),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2048),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 4001),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2048),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 4389),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2048),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 4889),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_true,
            timestamp: UInt32::allocated_constant(cs, 5413),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314303070458905393772003110276921984481582690891142221610001680774704050",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2136),
            is_first: bool_true,
            timestamp: UInt32::allocated_constant(cs, 6181),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452315323292561252187007358802027294616051526905825659974295089200090160077",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2144),
            is_first: bool_true,
            timestamp: UInt32::allocated_constant(cs, 7689),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 8333),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314563023454543640061243127807783650961769624362936951212864970460788229",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2160),
            is_first: bool_true,
            timestamp: UInt32::allocated_constant(cs, 9281),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 10337),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314303070458905393772003110276921984481582690891142221610001680774704050",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2136),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 11169),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452315323292561252187007358802027294616051526905825659974295089200090160077",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2144),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 13521),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 14197),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314563023454543640061243127807783650961769624362936951212864970460788229",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2160),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 15209),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 16321),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314303070458905393772003110276921984481582690891142221610001680774704050",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2136),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 17217),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452315323292561252187007358802027294616051526905825659974295089200090160077",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2144),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 19561),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 20269),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314563023454543640061243127807783650961769624362936951212864970460788229",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2160),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 21345),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 22457),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314303070458905393772003110276921984481582690891142221610001680774704050",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2136),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 23417),
        };
        unsorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452315323292561252187007358802027294616051526905825659974295089200090160077",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2144),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 26209),
        };
        unsorted_querie.push(q);

        unsorted_querie
    }
    fn witness_input_sorted<CS: ConstraintSystem<F>>(cs: &mut CS) -> Vec<DecommitQuery<F>> {
        let mut sorted_querie = vec![];
        let bool_false = Boolean::allocated_constant(cs, false);
        let bool_true = Boolean::allocated_constant(cs, true);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452313746998214869734508634865817576060841700842481516984674100922521850987",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2368),
            is_first: bool_true,
            timestamp: UInt32::allocated_constant(cs, 40973),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452313746998214869734508634865817576060841700842481516984674100922521850987",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2368),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 41617),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452313746998214869734508634865817576060841700842481516984674100922521850987",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2368),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 42369),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314299079945159748026115793412643474177571247148724523427478208200944620",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2680),
            is_first: bool_true,
            timestamp: UInt32::allocated_constant(cs, 60885),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_true,
            timestamp: UInt32::allocated_constant(cs, 5413),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 8333),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 10337),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 14197),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 16321),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 20269),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 22457),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 26949),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 31393),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 38757),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 53341),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 53865),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 54737),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 56061),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 57493),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314302625333346664221779405237214670769280401891479637776384083169086090",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2128),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 59957),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314303070458905393772003110276921984481582690891142221610001680774704050",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2136),
            is_first: bool_true,
            timestamp: UInt32::allocated_constant(cs, 6181),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314303070458905393772003110276921984481582690891142221610001680774704050",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2136),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 11169),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314303070458905393772003110276921984481582690891142221610001680774704050",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2136),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 17217),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314303070458905393772003110276921984481582690891142221610001680774704050",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2136),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 23417),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314303070458905393772003110276921984481582690891142221610001680774704050",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2136),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 37357),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314563023454543640061243127807783650961769624362936951212864970460788229",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2160),
            is_first: bool_true,
            timestamp: UInt32::allocated_constant(cs, 9281),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314563023454543640061243127807783650961769624362936951212864970460788229",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2160),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 15209),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314563023454543640061243127807783650961769624362936951212864970460788229",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2160),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 21345),
        };
        sorted_querie.push(q);

        let q = DecommitQuery::<F> {
            code_hash: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452314563023454543640061243127807783650961769624362936951212864970460788229",
                )
                .unwrap(),
            ),
            page: UInt32::allocated_constant(cs, 2160),
            is_first: bool_false,
            timestamp: UInt32::allocated_constant(cs, 28089),
        };
        sorted_querie.push(q);

        sorted_querie
    }
}
