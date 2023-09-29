pub mod input;

use input::*;

use crate::ethereum_types::U256;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use crate::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;
use crate::base_structures::{decommit_query::*, memory_query::*};
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::{gates::*, traits::cs::ConstraintSystem};
use boojum::field::SmallField;
use boojum::gadgets::sha256::round_function::round_function_over_uint32;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::{
    boolean::Boolean,
    num::Num,
    queue::*,
    traits::{
        allocatable::{CSAllocatable, CSAllocatableExt},
        selectable::Selectable,
    },
    u16::UInt16,
    u256::UInt256,
    u32::UInt32,
};

use crate::fsm_input_output::{circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH, *};

use crate::storage_application::ConditionalWitnessAllocator;

pub fn unpack_code_into_memory_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    witness: CodeDecommitterCircuitInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); UInt256::<F>::INTERNAL_STRUCT_LEN]:,
    [(); UInt256::<F>::INTERNAL_STRUCT_LEN + 1]:,
{
    let CodeDecommitterCircuitInstanceWitness {
        closed_form_input,
        sorted_requests_queue_witness,
        code_words,
    } = witness;

    let code_words: VecDeque<U256> = code_words.into_iter().flatten().collect();

    let mut structured_input =
        CodeDecommitterCycleInputOutput::alloc_ignoring_outputs(cs, closed_form_input.clone());

    let requests_queue_state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &structured_input
            .observable_input
            .sorted_requests_queue_initial_state,
        &structured_input
            .hidden_fsm_input
            .decommittment_requests_queue_state,
    );

    let mut requests_queue = DecommitQueue::<F, R>::from_state(cs, requests_queue_state);

    use crate::code_unpacker_sha256::full_state_queue::FullStateCircuitQueueWitness;
    requests_queue.witness = Arc::new(FullStateCircuitQueueWitness::from_inner_witness(
        sorted_requests_queue_witness,
    ));

    let memory_queue_state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &structured_input.observable_input.memory_queue_initial_state,
        &structured_input.hidden_fsm_input.memory_queue_state,
    );

    let mut memory_queue = MemoryQueryQueue::<F, 8, 12, 4, R>::from_state(cs, memory_queue_state);

    use boojum::gadgets::traits::allocatable::CSPlaceholder;
    let mut starting_fsm_state = CodeDecommittmentFSM::placeholder(cs);
    starting_fsm_state.state_get_from_queue = Boolean::allocated_constant(cs, true);

    let initial_state = CodeDecommittmentFSM::conditionally_select(
        cs,
        structured_input.start_flag,
        &starting_fsm_state,
        &structured_input.hidden_fsm_input.internal_fsm,
    );

    let code_words_allocator = ConditionalWitnessAllocator::<F, UInt256<F>> {
        witness_source: Arc::new(RwLock::new(code_words)),
    };

    let final_state = unpack_code_into_memory_inner(
        cs,
        &mut memory_queue,
        &mut requests_queue,
        initial_state,
        code_words_allocator,
        round_function,
        limit,
    );

    let final_memory_state = memory_queue.into_state();
    let final_requets_state = requests_queue.into_state();
    // form the final state
    let done = final_state.finished;
    structured_input.completion_flag = done;
    structured_input.observable_output = CodeDecommitterOutputData::placeholder(cs);

    structured_input.observable_output.memory_queue_final_state = QueueState::conditionally_select(
        cs,
        structured_input.completion_flag,
        &final_memory_state,
        &structured_input.observable_output.memory_queue_final_state,
    );

    structured_input.hidden_fsm_output.internal_fsm = final_state;
    structured_input
        .hidden_fsm_output
        .decommittment_requests_queue_state = final_requets_state;
    structured_input.hidden_fsm_output.memory_queue_state = final_memory_state;

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

// we take a request to decommit hash H into memory page X. Following our internal conventions
// we decommit individual elements starting from the index 1 in the page, and later on set a full length
// into index 0. All elements are 32 bytes
pub fn unpack_code_into_memory_inner<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    memory_queue: &mut MemoryQueue<F, R>,
    unpack_requests_queue: &mut DecommitQueue<F, R>,
    initial_state: CodeDecommittmentFSM<F>,
    code_word_witness: ConditionalWitnessAllocator<F, UInt256<F>>,
    _round_function: &R,
    limit: usize,
) -> CodeDecommittmentFSM<F>
where
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); UInt256::<F>::INTERNAL_STRUCT_LEN]:,
    [(); UInt256::<F>::INTERNAL_STRUCT_LEN + 1]:,
{
    assert!(limit <= u32::MAX as usize);

    // const POP_QUEUE_OR_WRITE_ID: u64 = 0;
    // const FINALIZE_SHA256: u64 = 1;

    let mut state = initial_state;

    let mut half = F::ONE;
    half.double();
    half = half.inverse().unwrap();
    let half_num = Num::allocated_constant(cs, half);

    let words_to_bits = UInt32::allocated_constant(cs, 32 * 8);

    let initial_state_uint32 = boojum::gadgets::sha256::ivs_as_uint32(cs);

    let boolean_false = Boolean::allocated_constant(cs, false);
    let boolean_true = Boolean::allocated_constant(cs, true);

    let zero_u32 = UInt32::zero(cs);

    use zkevm_opcode_defs::VersionedHashDef;
    let versioned_hash_top_16_bits =
        (zkevm_opcode_defs::versioned_hash::ContractCodeSha256::VERSION_BYTE as u16) << 8;
    let versioned_hash_top_16_bits = UInt16::allocated_constant(cs, versioned_hash_top_16_bits);

    for _cycle in 0..limit {
        // we need exactly 3 sponges per cycle:
        // - two memory reads when we work on the existing decommittment
        // - and may be queue pop before it
        let (may_be_new_request, _) =
            unpack_requests_queue.pop_front(cs, state.state_get_from_queue);

        let hash = may_be_new_request.code_hash;

        let chunks = decompose_uint32_to_uint16s(cs, &hash.inner[7]);

        let version_hash_matches = UInt16::equals(cs, &chunks[1], &versioned_hash_top_16_bits);

        state
            .state_get_from_queue
            .conditionally_enforce_true(cs, version_hash_matches);

        let uint_16_one = UInt16::allocated_constant(cs, 1);
        let length_in_words = chunks[0];
        let length_in_words = UInt16::conditionally_select(
            cs,
            state.state_get_from_queue,
            &length_in_words,
            &uint_16_one,
        );

        let length_in_rounds = unsafe { length_in_words.increment_unchecked(cs) };

        let length_in_rounds = length_in_rounds.into_num().mul(cs, &half_num);
        // length is always a multiple of 2 since we decided so

        let length_in_rounds = UInt16::from_variable_checked(cs, length_in_rounds.get_variable());

        let length_in_bits_may_be = unsafe {
            UInt32::from_variable_unchecked(length_in_words.get_variable())
                .non_widening_mul(cs, &words_to_bits)
        };

        // turn over the endianess
        // we IGNORE the highest 4 bytes
        let uint32_zero = UInt32::allocated_constant(cs, 0);
        let mut cutted_hash = hash;
        cutted_hash.inner[7] = uint32_zero;

        state.num_rounds_left = UInt16::conditionally_select(
            cs,
            state.state_get_from_queue,
            &length_in_rounds,
            &state.num_rounds_left,
        );
        state.length_in_bits = UInt32::conditionally_select(
            cs,
            state.state_get_from_queue,
            &length_in_bits_may_be,
            &state.length_in_bits,
        );
        state.timestamp = UInt32::conditionally_select(
            cs,
            state.state_get_from_queue,
            &may_be_new_request.timestamp,
            &state.timestamp,
        );
        state.current_page = UInt32::conditionally_select(
            cs,
            state.state_get_from_queue,
            &may_be_new_request.page,
            &state.current_page,
        );
        state.hash_to_compare_against = UInt256::conditionally_select(
            cs,
            state.state_get_from_queue,
            &cutted_hash,
            &state.hash_to_compare_against,
        );
        state.current_index = UInt32::conditionally_select(
            cs,
            state.state_get_from_queue,
            &uint32_zero,
            &state.current_index,
        );
        state.sha256_inner_state = <[UInt32<F>; 8]>::conditionally_select(
            cs,
            state.state_get_from_queue,
            &initial_state_uint32,
            &state.sha256_inner_state,
        );

        // we decommit if we either decommit or just got a new request
        state.state_decommit = state.state_decommit.or(cs, state.state_get_from_queue);
        state.state_get_from_queue = boolean_false;

        // even though it's not that useful, we will do it in a checked way for ease of witness
        let may_be_num_rounds_left = unsafe { state.num_rounds_left.decrement_unchecked(cs) };
        state.num_rounds_left = UInt16::conditionally_select(
            cs,
            state.state_decommit,
            &may_be_num_rounds_left,
            &state.num_rounds_left,
        );

        let last_round = state.num_rounds_left.is_zero(cs);
        let finalize = last_round.and(cs, state.state_decommit);
        let not_last_round = last_round.negated(cs);
        let process_second_word = not_last_round.and(cs, state.state_decommit);

        // we either pop from the queue, or absorb-decommit, or finalize hash
        let code_word_0 = code_word_witness.conditionally_allocate(cs, state.state_decommit);
        let code_word_0_be_bytes = code_word_0.to_be_bytes(cs);

        // NOTE: we have to enforce a sequence of access to witness, so we always wait for code_word_0 to be resolved
        let code_word_1 = code_word_witness.conditionally_allocate_biased(
            cs,
            process_second_word,
            code_word_0.inner[0].get_variable(),
        );
        let code_word_1_be_bytes = code_word_1.to_be_bytes(cs);

        // perform two writes. It's never a "pointer" type
        let mem_query_0 = MemoryQuery {
            timestamp: state.timestamp,
            memory_page: state.current_page,
            index: state.current_index,
            rw_flag: boolean_true,
            value: code_word_0,
            is_ptr: boolean_false,
        };

        let state_index_incremented = unsafe { state.current_index.increment_unchecked(cs) };

        state.current_index = UInt32::conditionally_select(
            cs,
            state.state_decommit,
            &state_index_incremented,
            &state.current_index,
        );

        let mem_query_1 = MemoryQuery {
            timestamp: state.timestamp,
            memory_page: state.current_page,
            index: state.current_index,
            rw_flag: boolean_true,
            value: code_word_1,
            is_ptr: boolean_false,
        };

        // even if we do not write in practice then we will never use next value too

        let state_index_incremented = unsafe { state.current_index.increment_unchecked(cs) };

        state.current_index = UInt32::conditionally_select(
            cs,
            process_second_word,
            &state_index_incremented,
            &state.current_index,
        );

        memory_queue.push(cs, mem_query_0, state.state_decommit);
        memory_queue.push(cs, mem_query_1, process_second_word);

        // mind endianess!
        let mut sha256_input = [zero_u32; 16];
        for (dst, src) in sha256_input.iter_mut().zip(
            code_word_0_be_bytes
                .array_chunks::<4>()
                .chain(code_word_1_be_bytes.array_chunks::<4>()),
        ) {
            *dst = UInt32::from_be_bytes(cs, *src);
        }

        // then conditionally form the second half of the block

        let mut sha256_padding = [zero_u32; 8];

        // padding of single byte of 1<<7 and some zeroes after, and interpret it as BE integer
        sha256_padding[0] = UInt32::allocated_constant(cs, 1 << 31);
        // last word is just number of bits
        sha256_padding[7] = state.length_in_bits;

        assert_eq!(sha256_input.len(), 16);

        for (dst, src) in sha256_input[8..].iter_mut().zip(sha256_padding.iter()) {
            *dst = UInt32::conditionally_select(cs, finalize, src, dst);
        }

        let sha256_input: [_; 16] = sha256_input.try_into().unwrap();

        let mut new_internal_state = state.sha256_inner_state;
        round_function_over_uint32(cs, &mut new_internal_state, &sha256_input);

        state.sha256_inner_state = <[UInt32<F>; 8]>::conditionally_select(
            cs,
            state.state_decommit,
            &new_internal_state,
            &state.sha256_inner_state,
        );

        // make it into uint256, and do not forget to ignore highest four bytes
        let hash = UInt256 {
            inner: [
                new_internal_state[7],
                new_internal_state[6],
                new_internal_state[5],
                new_internal_state[4],
                new_internal_state[3],
                new_internal_state[2],
                new_internal_state[1],
                UInt32::allocated_constant(cs, 0),
            ],
        };

        for (part_of_first, part_of_second) in hash
            .inner
            .iter()
            .zip(state.hash_to_compare_against.inner.iter())
        {
            Num::conditionally_enforce_equal(
                cs,
                finalize,
                &part_of_first.into_num(),
                &part_of_second.into_num(),
            );
        }

        // finish
        let is_empty = unpack_requests_queue.is_empty(cs);
        let not_empty = is_empty.negated(cs);
        let done = is_empty.and(cs, finalize);
        state.finished = state.finished.or(cs, done);
        let proceed_next = not_empty.and(cs, finalize);
        state.state_get_from_queue = proceed_next;
        let continue_decommit = process_second_word;
        state.state_decommit = continue_decommit;
    }

    unpack_requests_queue.enforce_consistency(cs);

    state
}

fn decompose_uint32_to_uint16s<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    value: &UInt32<F>,
) -> [UInt16<F>; 2] {
    let [byte_0, byte_1, byte_2, byte_3] = value.decompose_into_bytes(cs);

    [
        UInt16::from_le_bytes(cs, [byte_0, byte_1]),
        UInt16::from_le_bytes(cs, [byte_2, byte_3]),
    ]
}

#[cfg(test)]
mod tests {
    use crate::base_structures::decommit_query;

    use super::*;
    use crate::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;
    use crate::ethereum_types::{Address, U256};
    use boojum::algebraic_props::poseidon2_parameters::Poseidon2GoldilocksExternalMatrix;
    use boojum::cs::implementations::reference_cs::CSDevelopmentAssembly;
    use boojum::cs::traits::gate::GatePlacementStrategy;
    use boojum::cs::CSGeometry;
    use boojum::cs::*;
    use boojum::field::goldilocks::GoldilocksField;
    use boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueWitness;
    use boojum::gadgets::tables::*;
    use boojum::gadgets::traits::allocatable::{CSAllocatable, CSPlaceholder};
    use boojum::gadgets::u160::UInt160;
    use boojum::gadgets::u256::UInt256;
    use boojum::gadgets::u8::UInt8;
    use boojum::implementations::poseidon2::Poseidon2Goldilocks;
    use boojum::worker::Worker;

    type F = GoldilocksField;
    type P = GoldilocksField;

    #[test]
    fn test_code_unpacker_inner() {
        // Create a constraint system with proper configuration
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
                    width: 4,
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

        let table = create_maj4_table();
        owned_cs.add_lookup_table::<Maj4Table, 4>(table);

        let table = create_tri_xor_table();
        owned_cs.add_lookup_table::<TriXor4Table, 4>(table);

        let table = create_ch4_table();
        owned_cs.add_lookup_table::<Ch4Table, 4>(table);

        let table = create_4bit_chunk_split_table::<F, 1>();
        owned_cs.add_lookup_table::<chunk4bits::Split4BitChunkTable<1>, 4>(table);
        let table = create_4bit_chunk_split_table::<F, 2>();
        owned_cs.add_lookup_table::<chunk4bits::Split4BitChunkTable<2>, 4>(table);

        let cs = &mut owned_cs;

        // Create inputs for the inner function
        let execute = Boolean::allocated_constant(cs, true);
        let mut memory_queue = MemoryQueryQueue::<F, 8, 12, 4, Poseidon2Goldilocks>::empty(cs);
        let mut decommit_queue = DecommitQueue::<F, Poseidon2Goldilocks>::empty(cs);

        let decommit_queue_witness = create_request_queue_witness(cs);
        for el in decommit_queue_witness {
            decommit_queue.push(cs, el, execute);
        }

        let round_function = Poseidon2Goldilocks;
        let limit = 40;

        let mut starting_fsm_state = CodeDecommittmentFSM::placeholder(cs);
        starting_fsm_state.state_get_from_queue = Boolean::allocated_constant(cs, true);

        let word_witness = create_witness_allocator(cs);

        // Run the inner function
        let _final_state = unpack_code_into_memory_inner(
            cs,
            &mut memory_queue,
            &mut decommit_queue,
            starting_fsm_state,
            word_witness,
            &round_function,
            limit,
        );

        // Check the corectness
        let boolean_true = Boolean::allocated_constant(cs, true);
        let no_decommits_left = decommit_queue.is_empty(cs);
        no_decommits_left.conditionally_enforce_true(cs, boolean_true);

        let final_memory_queue_state = compute_memory_queue_state(cs);
        for (lhs, rhs) in final_memory_queue_state
            .tail
            .tail
            .iter()
            .zip(memory_queue.tail.iter())
        {
            Num::enforce_equal(cs, lhs, rhs);
        }

        cs.pad_and_shrink();
        let worker = Worker::new();
        let mut owned_cs = owned_cs.into_assembly();
        owned_cs.print_gate_stats();
        assert!(owned_cs.check_if_satisfied(&worker));
    }

    fn create_witness_allocator<CS: ConstraintSystem<F>>(
        _cs: &mut CS,
    ) -> ConditionalWitnessAllocator<F, UInt256<F>> {
        let code_words_witness = get_byte_code_witness();

        let code_words_allocator = ConditionalWitnessAllocator::<F, UInt256<F>> {
            witness_source: Arc::new(RwLock::new(code_words_witness.into())),
        };

        code_words_allocator
    }

    fn create_request_queue_witness<CS: ConstraintSystem<F>>(cs: &mut CS) -> Vec<DecommitQuery<F>> {
        let code_hash = get_code_hash_witness();

        let witness = DecommitQueryWitness::<F> {
            code_hash,
            page: 2368,
            is_first: true,
            timestamp: 40973,
        };

        let result = DecommitQuery::allocate(cs, witness);

        vec![result]
    }

    fn compute_memory_queue_state<CS: ConstraintSystem<F>>(
        cs: &mut CS,
    ) -> QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH> {
        let boolean_true = Boolean::allocate(cs, true);
        let mut memory_queue = MemoryQueryQueue::<F, 8, 12, 4, Poseidon2Goldilocks>::empty(cs);

        for (index, byte_code) in get_byte_code_witness().into_iter().enumerate() {
            let code_word = byte_code;

            let witness = MemoryQueryWitness::<F> {
                timestamp: 40973,
                memory_page: 2368,
                index: index as u32,
                rw_flag: true,
                value: code_word,
                is_ptr: false,
            };

            let mem_query = MemoryQuery::allocate(cs, witness);
            memory_queue.push(cs, mem_query, boolean_true);
        }

        memory_queue.into_state()
    }

    fn get_code_hash_witness() -> U256 {
        U256::from_dec_str(
            "452313746998214869734508634865817576060841700842481516984674100922521850987",
        )
        .unwrap()
    }

    fn get_byte_code_witness() -> [U256; 33] {
        [
            "1766847064778396883786768274127037193463854637992579046408942445291110457",
            "20164191265753785488708351879363656296986696452890681959140868413",
            "230371115084700836133063546338735802439952161310848373590933373335",
            "315943403191476362254281516594763167672429992099855389200211772263",
            "2588391838226565201098400008033996167521966238460106068954150751699824",
            "211454133716954493758258064291659686758464834211097193222448873537",
            "755661767828730679150831008859380024863962510235974769491784599863434",
            "792722291272121268575835624931127487546448993321488813145330852157",
            "422901469332729376614825971396751231447294514335432723148645467189",
            "1725759105948670702159993994396013188152302135650842820951922845941817",
            "14404925315129564325488546414599286071787685034596420832328728893",
            "105318844962770555588522034545405007512793608572268457634281029689",
            "809009025005867921013546649078805150441502566947026555373812841472317",
            "105319039552922728847306638821735002815060289446290876141406257209",
            "211036116403988059590520874377734556453268914677076498415914844236",
            "1860236630555339893722514217592548129137355495764522944782381539722297",
            "7764675265080516174154537029624996607702824353047648753753695920848961",
            "166085834804801355241996194532094100761080533058945135475412415734372892697",
            "210624740264657758079982132082095218827023230710668103574628597825",
            "6588778667853837091013175373259869215603100833946083743887393845",
            "970663392666895392257512002784069674802928967218673951998329152864412",
            "107163641223087021704532235449659860614865516518490400358586646684",
            "212475932891644255176568460416224004946153631397142661140395918382",
            "2588266777670668978723371609412889835982022923910173388865216276661294",
            "2588155298151653810924065765928146445685410508309586403046357418901504",
            "53919893334301279589334030174039261347274288845081144962207220498432",
            "1461501637330902918203684832716283019655932542975",
            "432420386565659656852420866394968145599",
            "432420386565659656852420866394968145600",
            "35408467139433450592217433187231851964531694900788300625387963629091585785856",
            "79228162514264337610723819524",
            "4294967295",
            "0",
        ]
        .map(|el| U256::from_dec_str(el).unwrap())
    }
}
