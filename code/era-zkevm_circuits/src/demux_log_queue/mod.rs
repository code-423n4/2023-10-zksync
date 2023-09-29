use super::*;

pub mod input;

use crate::base_structures::{
    log_query::{LogQuery, LOG_QUERY_PACKED_WIDTH},
    vm_state::*,
};
use crate::fsm_input_output::ClosedFormInputCompactForm;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::{gates::*, traits::cs::ConstraintSystem};
use boojum::field::SmallField;
use boojum::gadgets::queue::queue_optimizer::SpongeOptimizer;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use boojum::gadgets::{
    boolean::Boolean,
    num::Num,
    queue::*,
    traits::{
        allocatable::CSAllocatableExt, encodable::CircuitEncodableExt, selectable::Selectable,
    },
    u160::*,
};

use zkevm_opcode_defs::system_params::*;

use crate::{
    demux_log_queue::input::*,
    fsm_input_output::{circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH, *},
};

pub type StorageLogQueue<F, R> = CircuitQueue<F, LogQuery<F>, 8, 12, 4, 4, 20, R>;
pub type StorageLogQueueWitness<F> =
    CircuitQueueWitness<F, LogQuery<F>, QUEUE_STATE_WIDTH, LOG_QUERY_PACKED_WIDTH>;

pub fn demultiplex_storage_logs_enty_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    witness: LogDemuxerCircuitInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    let LogDemuxerCircuitInstanceWitness {
        closed_form_input,
        initial_queue_witness,
    } = witness;

    let mut structured_input =
        LogDemuxerInputOutput::alloc_ignoring_outputs(cs, closed_form_input.clone());

    // passthrough must be trivial
    structured_input
        .observable_input
        .initial_log_queue_state
        .enforce_trivial_head(cs);

    let state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        &structured_input.observable_input.initial_log_queue_state,
        &structured_input.hidden_fsm_input.initial_log_queue_state,
    );
    let mut initial_queue = StorageLogQueue::<F, R>::from_state(cs, state);
    use std::sync::Arc;
    let initial_queue_witness = CircuitQueueWitness::from_inner_witness(initial_queue_witness);
    initial_queue.witness = Arc::new(initial_queue_witness);

    // for the rest it's just select between empty or from FSM
    let queue_states_from_fsm = [
        &structured_input.hidden_fsm_input.storage_access_queue_state,
        &structured_input.hidden_fsm_input.events_access_queue_state,
        &structured_input
            .hidden_fsm_input
            .l1messages_access_queue_state,
        &structured_input
            .hidden_fsm_input
            .keccak256_access_queue_state,
        &structured_input.hidden_fsm_input.sha256_access_queue_state,
        &structured_input
            .hidden_fsm_input
            .ecrecover_access_queue_state,
    ];

    let empty_state = QueueState::empty(cs);
    let [mut storage_access_queue, mut events_access_queue, mut l1messages_access_queue, mut keccak256_access_queue, mut sha256_access_queue, mut ecrecover_access_queue] =
        queue_states_from_fsm.map(|el| {
            let state = QueueState::conditionally_select(
                cs,
                structured_input.start_flag,
                &empty_state,
                &el,
            );
            StorageLogQueue::<F, R>::from_state(cs, state)
        });

    let input_queues = [
        &mut storage_access_queue,
        &mut events_access_queue,
        &mut l1messages_access_queue,
        &mut keccak256_access_queue,
        &mut sha256_access_queue,
        &mut ecrecover_access_queue,
    ];

    demultiplex_storage_logs_inner(cs, &mut initial_queue, input_queues, limit);

    use boojum::gadgets::traits::allocatable::CSPlaceholder;
    // form the final state
    structured_input.observable_output = LogDemuxerOutputData::placeholder(cs);

    let completed = initial_queue.is_empty(cs);
    structured_input.completion_flag = completed;

    structured_input.hidden_fsm_output.initial_log_queue_state = initial_queue.into_state();

    structured_input
        .hidden_fsm_output
        .storage_access_queue_state = storage_access_queue.into_state();

    structured_input.hidden_fsm_output.events_access_queue_state = events_access_queue.into_state();

    structured_input
        .hidden_fsm_output
        .l1messages_access_queue_state = l1messages_access_queue.into_state();

    structured_input
        .hidden_fsm_output
        .keccak256_access_queue_state = keccak256_access_queue.into_state();

    structured_input.hidden_fsm_output.sha256_access_queue_state = sha256_access_queue.into_state();

    structured_input
        .hidden_fsm_output
        .ecrecover_access_queue_state = ecrecover_access_queue.into_state();

    // copy into observable output
    structured_input
        .observable_output
        .storage_access_queue_state = QueueState::conditionally_select(
        cs,
        completed,
        &structured_input
            .hidden_fsm_output
            .storage_access_queue_state,
        &structured_input
            .observable_output
            .storage_access_queue_state,
    );
    structured_input.observable_output.events_access_queue_state = QueueState::conditionally_select(
        cs,
        completed,
        &structured_input.hidden_fsm_output.events_access_queue_state,
        &structured_input.observable_output.events_access_queue_state,
    );
    structured_input
        .observable_output
        .l1messages_access_queue_state = QueueState::conditionally_select(
        cs,
        completed,
        &structured_input
            .hidden_fsm_output
            .l1messages_access_queue_state,
        &structured_input
            .observable_output
            .l1messages_access_queue_state,
    );
    structured_input
        .observable_output
        .keccak256_access_queue_state = QueueState::conditionally_select(
        cs,
        completed,
        &structured_input
            .hidden_fsm_output
            .keccak256_access_queue_state,
        &structured_input
            .observable_output
            .keccak256_access_queue_state,
    );
    structured_input.observable_output.sha256_access_queue_state = QueueState::conditionally_select(
        cs,
        completed,
        &structured_input.hidden_fsm_output.sha256_access_queue_state,
        &structured_input.observable_output.sha256_access_queue_state,
    );
    structured_input
        .observable_output
        .ecrecover_access_queue_state = QueueState::conditionally_select(
        cs,
        completed,
        &structured_input
            .hidden_fsm_output
            .ecrecover_access_queue_state,
        &structured_input
            .observable_output
            .ecrecover_access_queue_state,
    );

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

pub const NUM_SEPARATE_QUEUES: usize = 6;

#[repr(u64)]
pub enum LogType {
    RollupStorage = 0,
    Events = 1,
    L1Messages = 2,
    KeccakCalls = 3,
    Sha256Calls = 4,
    ECRecoverCalls = 5,
    PorterStorage = 1024, // force unreachable
}

pub fn demultiplex_storage_logs_inner<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    storage_log_queue: &mut StorageLogQueue<F, R>,
    output_queues: [&mut StorageLogQueue<F, R>; NUM_SEPARATE_QUEUES],
    limit: usize,
) where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    assert!(limit <= u32::MAX as usize);

    let [rollup_storage_queue, events_queue, l1_messages_queue, keccak_calls_queue, sha256_calls_queue, ecdsa_calls_queue] =
        output_queues;

    let keccak_precompile_address = UInt160::allocated_constant(
        cs,
        *zkevm_opcode_defs::system_params::KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    );
    let sha256_precompile_address = UInt160::allocated_constant(
        cs,
        *zkevm_opcode_defs::system_params::SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    );
    let ecrecover_precompile_address = UInt160::allocated_constant(
        cs,
        *zkevm_opcode_defs::system_params::ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    );

    // we have 6 queues to demux into, and up to 3 sponges per any push
    // use crate::base_structures::log_query::LOG_QUERY_ABSORBTION_ROUNDS;
    // let mut optimizer = SpongeOptimizer::<F, R, 8, 12, 4, 6>::new(LOG_QUERY_ABSORBTION_ROUNDS * limit);

    for _ in 0..limit {
        // debug_assert!(optimizer.is_fresh());

        let queue_is_empty = storage_log_queue.is_empty(cs);
        let execute = queue_is_empty.negated(cs);
        let popped = storage_log_queue.pop_front(cs, execute);

        let [aux_byte_for_storage, aux_byte_for_event, aux_byte_for_l1_message, aux_byte_for_precompile_call] =
            [
                STORAGE_AUX_BYTE,
                EVENT_AUX_BYTE,
                L1_MESSAGE_AUX_BYTE,
                PRECOMPILE_AUX_BYTE,
            ]
            .map(|byte| UInt8::allocated_constant(cs, byte));

        let is_storage_aux_byte = UInt8::equals(cs, &aux_byte_for_storage, &popped.0.aux_byte);
        let is_event_aux_byte = UInt8::equals(cs, &aux_byte_for_event, &popped.0.aux_byte);
        let is_l1_message_aux_byte =
            UInt8::equals(cs, &aux_byte_for_l1_message, &popped.0.aux_byte);
        let is_precompile_aux_byte =
            UInt8::equals(cs, &aux_byte_for_precompile_call, &popped.0.aux_byte);

        let is_keccak_address = UInt160::equals(cs, &keccak_precompile_address, &popped.0.address);
        let is_sha256_address = UInt160::equals(cs, &sha256_precompile_address, &popped.0.address);
        let is_ecrecover_address =
            UInt160::equals(cs, &ecrecover_precompile_address, &popped.0.address);

        let is_rollup_shard = popped.0.shard_id.is_zero(cs);
        let execute_rollup_storage =
            Boolean::multi_and(cs, &[is_storage_aux_byte, is_rollup_shard, execute]);
        let is_porter_shard = is_rollup_shard.negated(cs);
        let execute_porter_storage =
            Boolean::multi_and(cs, &[is_storage_aux_byte, is_porter_shard, execute]);

        let boolean_false = Boolean::allocated_constant(cs, false);
        Boolean::enforce_equal(cs, &execute_porter_storage, &boolean_false);

        let execute_event = Boolean::multi_and(cs, &[is_event_aux_byte, execute]);
        let execute_l1_message = Boolean::multi_and(cs, &[is_l1_message_aux_byte, execute]);
        let execute_keccak_call =
            Boolean::multi_and(cs, &[is_precompile_aux_byte, is_keccak_address, execute]);
        let execute_sha256_call =
            Boolean::multi_and(cs, &[is_precompile_aux_byte, is_sha256_address, execute]);
        let execute_ecrecover_call =
            Boolean::multi_and(cs, &[is_precompile_aux_byte, is_ecrecover_address, execute]);

        // rollup_storage_queue.push_encoding_with_optimizer_without_changing_witness(
        //     cs,
        //     popped.1,
        //     execute_rollup_storage,
        //     LogType::RollupStorage as usize,
        //     &mut optimizer
        // );
        // events_queue.push_encoding_with_optimizer_without_changing_witness(
        //     cs,
        //     popped.1,
        //     execute_event,
        //     LogType::Events as usize,
        //     &mut optimizer
        // );
        // l1_messages_queue.push_encoding_with_optimizer_without_changing_witness(
        //     cs,
        //     popped.1,
        //     execute_l1_message,
        //     LogType::L1Messages as usize,
        //     &mut optimizer
        // );
        // keccak_calls_queue.push_encoding_with_optimizer_without_changing_witness(
        //     cs,
        //     popped.1,
        //     execute_keccak_call,
        //     LogType::KeccakCalls as usize,
        //     &mut optimizer
        // );
        // sha256_calls_queue.push_encoding_with_optimizer_without_changing_witness(
        //     cs,
        //     popped.1,
        //     execute_sha256_call,
        //     LogType::Sha256Calls as usize,
        //     &mut optimizer
        // );
        // ecdsa_calls_queue.push_encoding_with_optimizer_without_changing_witness(
        //     cs,
        //     popped.1,
        //     execute_ecrecover_call,
        //     LogType::ECRecoverCalls as usize,
        //     &mut optimizer
        // );

        let bitmask = [
            execute_rollup_storage,
            execute_event,
            execute_l1_message,
            execute_keccak_call,
            execute_sha256_call,
            execute_ecrecover_call,
        ];

        push_with_optimize(
            cs,
            [
                rollup_storage_queue,
                events_queue,
                l1_messages_queue,
                keccak_calls_queue,
                sha256_calls_queue,
                ecdsa_calls_queue,
            ],
            bitmask,
            popped.0,
        );

        let expected_bitmask_bits = [
            is_storage_aux_byte,
            is_event_aux_byte,
            is_l1_message_aux_byte,
            is_precompile_aux_byte,
        ];

        let is_bitmask = check_if_bitmask_and_if_empty(cs, expected_bitmask_bits);
        is_bitmask.conditionally_enforce_true(cs, execute);

        // // we enforce optimizer in this round, and it clears it up
        // optimizer.enforce(cs);
    }

    storage_log_queue.enforce_consistency(cs);

    // checks in "Drop" interact badly with some tools, so we check it during testing instead
    // debug_assert!(optimizer.is_fresh());
}

pub fn push_with_optimize<
    F: SmallField,
    CS: ConstraintSystem<F>,
    EL: CircuitEncodableExt<F, N>,
    const AW: usize,
    const SW: usize,
    const CW: usize,
    const T: usize,
    const N: usize,
    R: CircuitRoundFunction<F, AW, SW, CW>,
    const NUM_QUEUE: usize,
>(
    cs: &mut CS,
    mut queues: [&mut CircuitQueue<F, EL, AW, SW, CW, T, N, R>; NUM_QUEUE],
    bitmask: [Boolean<F>; NUM_QUEUE],
    value_encoding: EL,
) where
    [(); <EL as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    let mut states = queues.iter().map(|x| x.into_state());
    let mut state = states.next().unwrap();

    for (bit, next_state) in bitmask.iter().skip(1).zip(states) {
        state = QueueState::conditionally_select(cs, *bit, &next_state, &state);
    }

    let mut exec_queue = CircuitQueue::<F, EL, AW, SW, CW, T, N, R>::from_raw_parts(
        cs,
        state.head,
        state.tail.tail,
        state.tail.length,
    );

    let boolean_true = Boolean::allocated_constant(cs, true);

    exec_queue.push(cs, value_encoding, boolean_true);

    for (bit, queue) in bitmask.into_iter().zip(queues.iter_mut()) {
        // We don't need to update head
        // queue.head = <[Num<F>; T]>::conditionally_select(cs, bit, &exec_queue.head, &queue.head);
        queue.tail = <[Num<F>; T]>::conditionally_select(cs, bit, &exec_queue.tail, &queue.tail);
        queue.length = UInt32::conditionally_select(cs, bit, &exec_queue.length, &queue.length);
    }
}

pub fn check_if_bitmask_and_if_empty<F: SmallField, CS: ConstraintSystem<F>, const N: usize>(
    cs: &mut CS,
    mask: [Boolean<F>; N],
) -> Boolean<F> {
    let lc: [_; N] = mask.map(|el| (el.get_variable(), F::ONE));

    let lc = Num::linear_combination(cs, &lc);

    let one = Num::from_variable(cs.allocate_constant(F::ONE));
    let is_boolean = Num::equals(cs, &lc, &one);

    is_boolean
}

#[cfg(test)]
mod tests {
    use super::*;
    use boojum::algebraic_props::poseidon2_parameters::Poseidon2GoldilocksExternalMatrix;
    use boojum::cs::traits::gate::GatePlacementStrategy;
    use boojum::cs::CSGeometry;
    use boojum::cs::*;
    use boojum::field::goldilocks::GoldilocksField;
    use boojum::gadgets::tables::*;
    use boojum::gadgets::u160::UInt160;
    use boojum::gadgets::u256::UInt256;
    use boojum::gadgets::u32::UInt32;
    use boojum::gadgets::u8::UInt8;
    use boojum::implementations::poseidon2::Poseidon2Goldilocks;
    use boojum::worker::Worker;
    use ethereum_types::{Address, U256};
    type F = GoldilocksField;
    type P = GoldilocksField;

    #[test]
    fn test_demultiplex_storage_logs_inner() {
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

        // start test
        let execute = Boolean::allocated_constant(cs, true);

        let mut storage_log_queue = StorageLogQueue::<F, Poseidon2Goldilocks>::empty(cs);
        let unsorted_input = witness_input_unsorted(cs);
        for el in unsorted_input {
            storage_log_queue.push(cs, el, execute);
        }
        let mut output_queue = StorageLogQueue::empty(cs);
        let mut output_queue1 = StorageLogQueue::empty(cs);
        let mut output_queue2 = StorageLogQueue::empty(cs);
        let mut output_queue3 = StorageLogQueue::empty(cs);
        let mut output_queue4 = StorageLogQueue::empty(cs);
        let mut output_queue5 = StorageLogQueue::empty(cs);

        let output = [
            &mut output_queue,
            &mut output_queue1,
            &mut output_queue2,
            &mut output_queue3,
            &mut output_queue4,
            &mut output_queue5,
        ];
        let limit = 16;
        demultiplex_storage_logs_inner(cs, &mut storage_log_queue, output, limit);

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
        let zero_32 = UInt32::allocated_constant(cs, 0);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
            read_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            written_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 1205),
        };

        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("1").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 1425),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
            read_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            written_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 1609),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("7").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 1777),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
            read_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            written_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 1969),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("5").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 2253),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("10").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 2357),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
            read_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            written_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 2429),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("4").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 2681),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("9").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 2797),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("9").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 2829),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
            read_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            written_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 2901),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("3").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 3089),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("8").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 3193),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
            read_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            written_value: UInt256::allocated_constant(
                cs,
                U256::from_dec_str(
                    "452319300877325313852488925888724764263521004047156906617735320131041551860",
                )
                .unwrap(),
            ),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 3265),
        };
        unsorted_querie.push(q);

        let q = LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("2").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 3421),
        };
        unsorted_querie.push(q);

        unsorted_querie
    }
}
