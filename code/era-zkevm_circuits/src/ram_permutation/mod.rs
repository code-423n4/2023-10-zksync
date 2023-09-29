use super::*;

use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::num::Num;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::u256::UInt256;
use boojum::gadgets::u32::UInt32;
use std::sync::Arc;

use crate::base_structures::memory_query::MemoryQuery;
use crate::base_structures::memory_query::MEMORY_QUERY_PACKED_WIDTH;
use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use crate::fsm_input_output::commit_variable_length_encodable_item;
use crate::fsm_input_output::ClosedFormInputCompactForm;
use crate::storage_validity_by_grand_product::unpacked_long_comparison;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::gates::PublicInputGate;
use boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueWitness;
use boojum::gadgets::queue::QueueState;
use boojum::gadgets::traits::allocatable::CSAllocatableExt;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;

use zkevm_opcode_defs::BOOTLOADER_HEAP_PAGE;

pub mod input;
use input::*;

pub fn ram_permutation_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    closed_form_input_witness: RamPermutationCircuitInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    let RamPermutationCircuitInstanceWitness {
        closed_form_input,
        unsorted_queue_witness,
        sorted_queue_witness,
    } = closed_form_input_witness;

    let mut structured_input =
        RamPermutationCycleInputOutput::alloc_ignoring_outputs(cs, closed_form_input.clone());

    let start_flag = structured_input.start_flag;
    let observable_input = structured_input.observable_input.clone();
    let hidden_fsm_input = structured_input.hidden_fsm_input.clone();

    // passthrought must be trivial
    observable_input
        .unsorted_queue_initial_state
        .enforce_trivial_head(cs);

    let unsorted_queue_state = QueueState::conditionally_select(
        cs,
        start_flag,
        &observable_input.unsorted_queue_initial_state,
        &hidden_fsm_input.current_unsorted_queue_state,
    );

    use crate::boojum::gadgets::queue::full_state_queue::FullStateCircuitQueue;
    let mut unsorted_queue: FullStateCircuitQueue<
        F,
        MemoryQuery<F>,
        8,
        12,
        4,
        MEMORY_QUERY_PACKED_WIDTH,
        R,
    > = MemoryQueriesQueue::from_state(cs, unsorted_queue_state);

    unsorted_queue.witness = Arc::new(FullStateCircuitQueueWitness::from_inner_witness(
        unsorted_queue_witness,
    ));

    // passthrought must be trivial
    observable_input
        .sorted_queue_initial_state
        .enforce_trivial_head(cs);

    let sorted_queue_state = QueueState::conditionally_select(
        cs,
        start_flag,
        &observable_input.sorted_queue_initial_state,
        &hidden_fsm_input.current_sorted_queue_state,
    );

    let mut sorted_queue: FullStateCircuitQueue<
        F,
        MemoryQuery<F>,
        8,
        12,
        4,
        MEMORY_QUERY_PACKED_WIDTH,
        R,
    > = MemoryQueriesQueue::from_state(cs, sorted_queue_state);

    sorted_queue.witness = Arc::new(FullStateCircuitQueueWitness::from_inner_witness(
        sorted_queue_witness,
    ));

    // get challenges for permutation argument
    let fs_challenges = crate::utils::produce_fs_challenges(
        cs,
        observable_input.unsorted_queue_initial_state.tail,
        observable_input.sorted_queue_initial_state.tail,
        round_function,
    );

    let num_one = Num::allocated_constant(cs, F::ONE);
    let mut lhs = <[Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS]>::conditionally_select(
        cs,
        start_flag,
        &[num_one; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
        &hidden_fsm_input.lhs_accumulator,
    );
    let mut rhs = <[Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS]>::conditionally_select(
        cs,
        start_flag,
        &[num_one; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
        &hidden_fsm_input.rhs_accumulator,
    );

    let uint32_zero = UInt32::zero(cs);
    let mut num_nondeterministic_writes = UInt32::conditionally_select(
        cs,
        start_flag,
        &uint32_zero,
        &hidden_fsm_input.num_nondeterministic_writes,
    );

    let mut previous_sorting_key = hidden_fsm_input.previous_sorting_key;
    let mut previous_full_key = hidden_fsm_input.previous_full_key;
    let mut previous_value = hidden_fsm_input.previous_value;
    let mut previous_is_ptr = hidden_fsm_input.previous_is_ptr;

    partial_accumulate_inner::<F, CS, R>(
        cs,
        &mut unsorted_queue,
        &mut sorted_queue,
        &fs_challenges,
        start_flag,
        &mut lhs,
        &mut rhs,
        &mut previous_sorting_key,
        &mut previous_full_key,
        &mut previous_value,
        &mut previous_is_ptr,
        &mut num_nondeterministic_writes,
        limit,
    );

    unsorted_queue.enforce_consistency(cs);
    sorted_queue.enforce_consistency(cs);

    let completed = unsorted_queue.length.is_zero(cs);

    for (lhs, rhs) in lhs.iter().zip(rhs.iter()) {
        Num::conditionally_enforce_equal(cs, completed, lhs, rhs);
    }

    let num_nondeterministic_writes_equal = UInt32::equals(
        cs,
        &num_nondeterministic_writes,
        &observable_input.non_deterministic_bootloader_memory_snapshot_length,
    );
    num_nondeterministic_writes_equal.conditionally_enforce_true(cs, completed);

    // form the final state
    structured_input
        .hidden_fsm_output
        .num_nondeterministic_writes = num_nondeterministic_writes;
    structured_input
        .hidden_fsm_output
        .current_unsorted_queue_state = unsorted_queue.into_state();
    structured_input
        .hidden_fsm_output
        .current_sorted_queue_state = sorted_queue.into_state();

    structured_input.hidden_fsm_output.lhs_accumulator = lhs;
    structured_input.hidden_fsm_output.rhs_accumulator = rhs;

    structured_input.hidden_fsm_output.previous_sorting_key = previous_sorting_key;
    structured_input.hidden_fsm_output.previous_full_key = previous_full_key;
    structured_input.hidden_fsm_output.previous_value = previous_value;
    structured_input.hidden_fsm_output.previous_is_ptr = previous_is_ptr;

    structured_input.completion_flag = completed;

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

pub fn partial_accumulate_inner<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    unsorted_queue: &mut MemoryQueriesQueue<F, R>,
    sorted_queue: &mut MemoryQueriesQueue<F, R>,
    fs_challenges: &[[Num<F>; MEMORY_QUERY_PACKED_WIDTH + 1];
         DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    is_start: Boolean<F>,
    lhs: &mut [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    rhs: &mut [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    previous_sorting_key: &mut [UInt32<F>; RAM_SORTING_KEY_LENGTH],
    previous_comparison_key: &mut [UInt32<F>; RAM_FULL_KEY_LENGTH],
    previous_element_value: &mut UInt256<F>,
    previous_is_ptr: &mut Boolean<F>,
    num_nondeterministic_writes: &mut UInt32<F>,
    limit: usize,
) where
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    let not_start = is_start.negated(cs);
    Num::enforce_equal(
        cs,
        &unsorted_queue.length.into_num(),
        &sorted_queue.length.into_num(),
    );

    let bootloader_heap_page = UInt32::allocated_constant(cs, BOOTLOADER_HEAP_PAGE);
    let uint256_zero = UInt256::zero(cs);

    for _cycle in 0..limit {
        let unsorted_is_empty = unsorted_queue.is_empty(cs);
        let sorted_is_empty = sorted_queue.is_empty(cs);

        // this is an exotic way so synchronize popping from both queues
        // in asynchronous resolution
        Boolean::enforce_equal(cs, &unsorted_is_empty, &sorted_is_empty);
        let can_pop = unsorted_is_empty.negated(cs);

        // we do not need any information about unsorted element other than it's encoding
        let (_, unsorted_item_encoding) = unsorted_queue.pop_front(cs, can_pop);
        let (sorted_item, sorted_item_encoding) = sorted_queue.pop_front(cs, can_pop);

        // check non-deterministic writes
        {
            let ts_is_zero = sorted_item.timestamp.is_zero(cs);

            let page_is_bootloader_heap =
                UInt32::equals(cs, &sorted_item.memory_page, &bootloader_heap_page);

            let is_write = sorted_item.rw_flag;
            let is_ptr = sorted_item.is_ptr;
            let not_ptr = is_ptr.negated(cs);

            let is_nondeterministic_write = Boolean::multi_and(
                cs,
                &[
                    can_pop,
                    ts_is_zero,
                    page_is_bootloader_heap,
                    is_write,
                    not_ptr,
                ],
            );

            let num_nondeterministic_writes_incremented =
                unsafe { UInt32::increment_unchecked(&num_nondeterministic_writes, cs) };

            *num_nondeterministic_writes = UInt32::conditionally_select(
                cs,
                is_nondeterministic_write,
                &num_nondeterministic_writes_incremented,
                &num_nondeterministic_writes,
            );
        }

        // check RAM ordering
        {
            // either continue the argument or do nothing

            let sorting_key = [
                sorted_item.timestamp,
                sorted_item.index,
                sorted_item.memory_page,
            ];
            let comparison_key = [sorted_item.index, sorted_item.memory_page];

            // ensure sorting
            let (_keys_are_equal, previous_key_is_smaller) =
                unpacked_long_comparison(cs, &sorting_key, previous_sorting_key);

            // we can not have previous sorting key even to be >= than our current key

            let keys_are_in_ascending_order = previous_key_is_smaller;

            if _cycle != 0 {
                keys_are_in_ascending_order.conditionally_enforce_true(cs, can_pop);
            } else {
                let should_enforce = can_pop.and(cs, not_start);
                keys_are_in_ascending_order.conditionally_enforce_true(cs, should_enforce);
            }

            let same_memory_cell = long_equals(cs, &comparison_key, previous_comparison_key);
            let value_equal = UInt256::equals(cs, &sorted_item.value, &previous_element_value);

            let not_same_cell = same_memory_cell.negated(cs);
            let rw_flag = sorted_item.rw_flag;
            let not_rw_flag = rw_flag.negated(cs);

            // check uninit read
            let value_is_zero = UInt256::equals(cs, &sorted_item.value, &uint256_zero);
            let is_ptr = sorted_item.is_ptr;
            let not_ptr = is_ptr.negated(cs);
            let is_zero = value_is_zero.and(cs, not_ptr);
            let ptr_equality = Num::equals(cs, &previous_is_ptr.into_num(), &is_ptr.into_num());
            let value_and_ptr_equal = value_equal.and(cs, ptr_equality);

            // we only have a difference in these flags at the first step
            if _cycle != 0 {
                let read_uninitialized = not_same_cell.and(cs, not_rw_flag);
                is_zero.conditionally_enforce_true(cs, read_uninitialized);

                // check standard RW validity
                let check_equality = same_memory_cell.and(cs, not_rw_flag);
                value_and_ptr_equal.conditionally_enforce_true(cs, check_equality);
            } else {
                // see if we continue the argument then all our checks should be valid,
                // otherwise only read uninit should be enforced

                // if we start a fresh argument then our comparison
                let read_uninitialized_if_continue =
                    Boolean::multi_and(cs, &[not_start, not_same_cell, not_rw_flag]);
                let read_uninit_if_at_the_start = is_start.and(cs, not_rw_flag);
                let should_enforce =
                    read_uninitialized_if_continue.or(cs, read_uninit_if_at_the_start);
                is_zero.conditionally_enforce_true(cs, should_enforce);

                // check standard RW validity, but it can break if we are at the very start
                let check_equality =
                    Boolean::multi_and(cs, &[same_memory_cell, not_rw_flag, not_start]);
                value_and_ptr_equal.conditionally_enforce_true(cs, check_equality);
            }

            *previous_sorting_key = sorting_key;
            *previous_comparison_key = comparison_key;
            *previous_element_value = sorted_item.value;
            *previous_is_ptr = sorted_item.is_ptr;
        }

        // if we did pop then accumulate to grand product
        for ((challenges, lhs), rhs) in fs_challenges.iter().zip(lhs.iter_mut()).zip(rhs.iter_mut())
        {
            // additive parts
            let mut lhs_contribution = challenges[MEMORY_QUERY_PACKED_WIDTH];
            let mut rhs_contribution = challenges[MEMORY_QUERY_PACKED_WIDTH];

            debug_assert_eq!(unsorted_item_encoding.len(), sorted_item_encoding.len());
            debug_assert_eq!(
                unsorted_item_encoding.len(),
                challenges[..MEMORY_QUERY_PACKED_WIDTH].len()
            );

            for ((unsorted_contribution, sorted_contribution), challenge) in unsorted_item_encoding
                .iter()
                .zip(sorted_item_encoding.iter())
                .zip(challenges[..MEMORY_QUERY_PACKED_WIDTH].iter())
            {
                let new_lhs = Num::fma(
                    cs,
                    &Num::from_variable(*unsorted_contribution),
                    challenge,
                    &F::ONE,
                    &lhs_contribution,
                    &F::ONE,
                );
                lhs_contribution = new_lhs;

                let new_rhs = Num::fma(
                    cs,
                    &Num::from_variable(*sorted_contribution),
                    challenge,
                    &F::ONE,
                    &rhs_contribution,
                    &F::ONE,
                );
                rhs_contribution = new_rhs;
            }

            let new_lhs = lhs.mul(cs, &lhs_contribution);
            let new_rhs = rhs.mul(cs, &rhs_contribution);

            *lhs = Num::conditionally_select(cs, can_pop, &new_lhs, &lhs);
            *rhs = Num::conditionally_select(cs, can_pop, &new_rhs, &rhs);
        }
    }
}

pub(crate) fn long_equals<F: SmallField, CS: ConstraintSystem<F>, const N: usize>(
    cs: &mut CS,
    a: &[UInt32<F>; N],
    b: &[UInt32<F>; N],
) -> Boolean<F> {
    let equals: [_; N] = std::array::from_fn(|i| UInt32::equals(cs, &a[i], &b[i]));

    Boolean::multi_and(cs, &equals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boojum::algebraic_props::poseidon2_parameters::Poseidon2GoldilocksExternalMatrix;
    use boojum::cs::gates::*;
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
    fn test_ram_permutation_inner() {
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
        let mut original_queue = MemoryQueriesQueue::<F, Poseidon2Goldilocks>::empty(cs);
        let unsorted_input = witness_input_unsorted(cs);
        for el in unsorted_input {
            original_queue.push(cs, el, execute);
        }
        let mut sorted_queue = MemoryQueriesQueue::<F, Poseidon2Goldilocks>::empty(cs);
        let sorted_input = witness_input_sorted(cs);
        for el in sorted_input {
            sorted_queue.push(cs, el, execute);
        }

        let mut lhs = [Num::allocated_constant(cs, F::from_nonreduced_u64(1));
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
        let mut rhs = [Num::allocated_constant(cs, F::from_nonreduced_u64(1));
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
        let is_start = Boolean::allocated_constant(cs, true);
        let round_function = Poseidon2Goldilocks;
        let fs_challenges = crate::utils::produce_fs_challenges(
            cs,
            original_queue.into_state().tail,
            sorted_queue.into_state().tail,
            &round_function,
        );
        let limit = 16;
        let mut previous_sorting_key = [UInt32::allocated_constant(cs, 0); RAM_SORTING_KEY_LENGTH];
        let mut previous_comparison_key = [UInt32::allocated_constant(cs, 0); RAM_FULL_KEY_LENGTH];
        let mut previous_element_value =
            UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap());
        let mut previous_is_ptr = Boolean::allocated_constant(cs, false);
        let mut num_nondeterministic_writes = UInt32::allocated_constant(cs, 1);
        partial_accumulate_inner(
            cs,
            &mut original_queue,
            &mut sorted_queue,
            &fs_challenges,
            is_start,
            &mut lhs,
            &mut rhs,
            &mut previous_sorting_key,
            &mut previous_comparison_key,
            &mut previous_element_value,
            &mut previous_is_ptr,
            &mut num_nondeterministic_writes,
            limit,
        );

        cs.pad_and_shrink();
        let worker = Worker::new();
        let mut owned_cs = owned_cs.into_assembly();
        owned_cs.print_gate_stats();
        assert!(owned_cs.check_if_satisfied(&worker));
    }

    fn witness_input_unsorted<CS: ConstraintSystem<F>>(cs: &mut CS) -> Vec<MemoryQuery<F>> {
        let mut unsorted_querie = vec![];
        let bool_false = Boolean::allocated_constant(cs, false);
        let bool_true = Boolean::allocated_constant(cs, true);

        let q = MemoryQuery::<F> {
            timestamp: UInt32::allocated_constant(cs, 1025),
            memory_page: UInt32::allocated_constant(cs, 30),
            index: UInt32::allocated_constant(cs, 0),
            rw_flag: bool_false,
            is_ptr: bool_false,
            value: UInt256::allocated_constant(cs, U256::from_dec_str("1125899906842626").unwrap()),
        };
        unsorted_querie.push(q);

        let q = MemoryQuery::<F> {
            timestamp: UInt32::allocated_constant(cs, 1024),
            memory_page: UInt32::allocated_constant(cs, 30),
            index: UInt32::allocated_constant(cs, 0),
            rw_flag: bool_true,
            is_ptr: bool_false,
            value: UInt256::allocated_constant(cs, U256::from_dec_str("1125899906842626").unwrap()),
        };

        unsorted_querie.push(q);

        let q = MemoryQuery::<F> {
            timestamp: UInt32::allocated_constant(cs, 0),
            memory_page: UInt32::allocated_constant(cs, BOOTLOADER_HEAP_PAGE),
            index: UInt32::allocated_constant(cs, 695),
            rw_flag: bool_true,
            is_ptr: bool_false,
            value: UInt256::allocated_constant(cs, U256::from_dec_str("12345678").unwrap()),
        };
        unsorted_querie.push(q);

        unsorted_querie
    }

    fn witness_input_sorted<CS: ConstraintSystem<F>>(cs: &mut CS) -> Vec<MemoryQuery<F>> {
        let mut sorted_querie = vec![];
        let bool_false = Boolean::allocated_constant(cs, false);
        let bool_true = Boolean::allocated_constant(cs, true);

        let q = MemoryQuery::<F> {
            timestamp: UInt32::allocated_constant(cs, 0),
            memory_page: UInt32::allocated_constant(cs, BOOTLOADER_HEAP_PAGE),
            index: UInt32::allocated_constant(cs, 695),
            rw_flag: bool_true,
            is_ptr: bool_false,
            value: UInt256::allocated_constant(cs, U256::from_dec_str("12345678").unwrap()),
        };
        sorted_querie.push(q);

        let q = MemoryQuery::<F> {
            timestamp: UInt32::allocated_constant(cs, 1024),
            memory_page: UInt32::allocated_constant(cs, 30),
            index: UInt32::allocated_constant(cs, 0),
            rw_flag: bool_true,
            is_ptr: bool_false,
            value: UInt256::allocated_constant(cs, U256::from_dec_str("1125899906842626").unwrap()),
        };
        sorted_querie.push(q);

        let q = MemoryQuery::<F> {
            timestamp: UInt32::allocated_constant(cs, 1025),
            memory_page: UInt32::allocated_constant(cs, 30),
            index: UInt32::allocated_constant(cs, 0),
            rw_flag: bool_false,
            is_ptr: bool_false,
            value: UInt256::allocated_constant(cs, U256::from_dec_str("1125899906842626").unwrap()),
        };
        sorted_querie.push(q);

        sorted_querie
    }
}
