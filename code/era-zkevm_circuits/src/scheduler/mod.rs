use super::*;

pub mod block_header;
use self::block_header::*;

pub mod input;
use self::input::*;

pub mod auxiliary;
pub use auxiliary as aux;

use boojum::cs::implementations::proof::Proof;

use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;

use boojum::gadgets::recursion::allocated_proof::AllocatedProof;
use boojum::gadgets::recursion::allocated_vk::AllocatedVerificationKey;

use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use boojum::gadgets::{
    boolean::Boolean,
    queue::*,
    traits::{allocatable::*, selectable::Selectable},
};

use crate::base_structures::decommit_query::DecommitQuery;
use crate::base_structures::decommit_query::DecommitQueue;
use crate::base_structures::memory_query::MemoryQuery;
use crate::base_structures::memory_query::MemoryQueue;

use crate::base_structures::recursion_query::*;
use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use crate::linear_hasher::input::LinearHasherOutputData;
use crate::recursion::VK_COMMITMENT_LENGTH;
use crate::scheduler::auxiliary::NUM_CIRCUIT_TYPES_TO_SCHEDULE;
use boojum::gadgets::num::Num;
use boojum::gadgets::recursion::recursive_tree_hasher::RecursiveTreeHasher;

use crate::base_structures::precompile_input_outputs::*;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::implementations::prover::ProofConfig;
use boojum::cs::implementations::verifier::VerificationKeyCircuitGeometry;
use boojum::cs::oracle::TreeHasher;
use boojum::cs::traits::circuit::*;
use boojum::field::FieldExtension;
use boojum::gadgets::keccak256;
use boojum::gadgets::recursion::circuit_pow::RecursivePoWRunner;
use boojum::gadgets::recursion::recursive_transcript::*;
use boojum::gadgets::recursion::recursive_tree_hasher::*;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use std::collections::HashMap;

use crate::base_structures::vm_state::*;
use crate::code_unpacker_sha256::input::*;
use crate::demux_log_queue::input::*;
use crate::fsm_input_output::circuit_inputs::main_vm::*;
use crate::fsm_input_output::*;
use crate::log_sorter::input::*;
use crate::ram_permutation::input::*;
use crate::recursion::leaf_layer::input::*;
use crate::recursion::node_layer::input::*;
use crate::scheduler::auxiliary::*;
use crate::sort_decommittment_requests::input::*;
use crate::storage_application::input::*;
use crate::storage_validity_by_grand_product::input::*;

pub const SCHEDULER_TIMESTAMP: u32 = 1;
pub const NUM_SCHEDULER_PUBLIC_INPUTS: usize = 4;
pub const LEAF_LAYER_PARAMETERS_COMMITMENT_LENGTH: usize = 4;
pub const QUEUE_FINAL_STATE_COMMITMENT_LENGTH: usize = 4;

pub const SEQUENCE_OF_CIRCUIT_TYPES: [BaseLayerCircuitType; NUM_CIRCUIT_TYPES_TO_SCHEDULE] = [
    BaseLayerCircuitType::VM,
    BaseLayerCircuitType::DecommitmentsFilter,
    BaseLayerCircuitType::Decommiter,
    BaseLayerCircuitType::LogDemultiplexer,
    BaseLayerCircuitType::KeccakPrecompile,
    BaseLayerCircuitType::Sha256Precompile,
    BaseLayerCircuitType::EcrecoverPrecompile,
    BaseLayerCircuitType::RamValidation,
    BaseLayerCircuitType::StorageFilter,
    BaseLayerCircuitType::StorageApplicator,
    BaseLayerCircuitType::EventsRevertsFilter,
    BaseLayerCircuitType::L1MessagesRevertsFilter,
    BaseLayerCircuitType::L1MessagesHasher,
];

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug)]
#[serde(bound = "H::Output: serde::Serialize + serde::de::DeserializeOwned")]
pub struct SchedulerConfig<F: SmallField, H: TreeHasher<F>, EXT: FieldExtension<2, BaseField = F>> {
    pub proof_config: ProofConfig,
    pub vk_fixed_parameters: VerificationKeyCircuitGeometry,
    pub capacity: usize,
    pub _marker: std::marker::PhantomData<(F, H, EXT)>,
}

pub fn scheduler_function<
    F: SmallField,
    CS: ConstraintSystem<F> + 'static,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    H: RecursiveTreeHasher<F, Num<F>>,
    EXT: FieldExtension<2, BaseField = F>,
    TR: RecursiveTranscript<
        F,
        CompatibleCap = <H::NonCircuitSimulator as TreeHasher<F>>::Output,
        CircuitReflection = CTR,
    >,
    CTR: CircuitTranscript<
        F,
        CircuitCompatibleCap = <H as CircuitTreeHasher<F, Num<F>>>::CircuitOutput,
        TransciptParameters = TR::TransciptParameters,
    >,
    POW: RecursivePoWRunner<F>,
>(
    cs: &mut CS,
    mut witness: SchedulerCircuitInstanceWitness<F, H, EXT>,
    round_function: &R,
    config: SchedulerConfig<F, H::NonCircuitSimulator, EXT>,
    verifier_builder: Box<dyn ErasedBuilderForRecursiveVerifier<F, EXT, CS>>,
    transcript_params: TR::TransciptParameters,
) where
    [(); <RecursionQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    let prev_block_data = BlockPassthroughData::allocate(cs, witness.prev_block_data.clone());
    let block_meta_parameters =
        BlockMetaParameters::allocate(cs, witness.block_meta_parameters.clone());

    let boolean_false = Boolean::allocated_constant(cs, false);
    let boolean_true = Boolean::allocated_constant(cs, true);

    Boolean::enforce_equal(
        cs,
        &block_meta_parameters.zkporter_is_available,
        &boolean_false,
    );

    // create initial queues
    let bootloader_heap_memory_state =
        QueueTailState::allocate(cs, witness.bootloader_heap_memory_state.clone());

    let mut initial_memory_queue_state = MemoryQueue::<F, R>::empty(cs);
    initial_memory_queue_state.tail = bootloader_heap_memory_state.tail;
    initial_memory_queue_state.length = bootloader_heap_memory_state.length;

    let mut decommittments_queue = DecommitQueue::<F, R>::empty(cs);
    let bootloader_code_hash = block_meta_parameters.bootloader_code_hash;
    let bootloader_code_page =
        UInt32::allocated_constant(cs, zkevm_opcode_defs::BOOTLOADER_CODE_PAGE);
    let scheduler_timestamp = UInt32::allocated_constant(cs, SCHEDULER_TIMESTAMP);
    let bootloader_decommittment_query = crate::base_structures::decommit_query::DecommitQuery {
        code_hash: bootloader_code_hash,
        page: bootloader_code_page,
        is_first: boolean_true,
        timestamp: scheduler_timestamp,
    };

    let _ = decommittments_queue.push(cs, bootloader_decommittment_query, boolean_true);

    // create all the intermediate output data in uncommitted form to later check for equality

    let vm_end_of_execution_observable_output =
        VmOutputData::allocate(cs, witness.vm_end_of_execution_observable_output.clone());

    let decommits_sorter_observable_output = CodeDecommittmentsDeduplicatorOutputData::allocate(
        cs,
        witness.decommits_sorter_observable_output.clone(),
    );

    let code_decommitter_observable_output =
        CodeDecommitterOutputData::allocate(cs, witness.code_decommitter_observable_output.clone());

    let log_demuxer_observable_output =
        LogDemuxerOutputData::allocate(cs, witness.log_demuxer_observable_output.clone());

    let keccak256_observable_output =
        PrecompileFunctionOutputData::allocate(cs, witness.keccak256_observable_output.clone());

    let sha256_observable_output =
        PrecompileFunctionOutputData::allocate(cs, witness.sha256_observable_output.clone());

    let ecrecover_observable_output =
        PrecompileFunctionOutputData::allocate(cs, witness.ecrecover_observable_output.clone());

    let storage_sorter_observable_output = StorageDeduplicatorOutputData::allocate(
        cs,
        witness.storage_sorter_observable_output.clone(),
    );

    let storage_application_observable_output = StorageApplicationOutputData::allocate(
        cs,
        witness.storage_application_observable_output.clone(),
    );

    let events_sorter_observable_output =
        EventsDeduplicatorOutputData::allocate(cs, witness.events_sorter_observable_output.clone());

    let l1messages_sorter_observable_output = EventsDeduplicatorOutputData::allocate(
        cs,
        witness.l1messages_sorter_observable_output.clone(),
    );

    let l1messages_linear_hasher_observable_output =
        LinearHasherOutputData::allocate(cs, witness.l1messages_linear_hasher_observable_output);

    // auxilary intermediate states
    let rollup_storage_sorter_intermediate_queue_state = QueueTailState::allocate(
        cs,
        witness
            .rollup_storage_sorter_intermediate_queue_state
            .clone(),
    );

    let events_sorter_intermediate_queue_state =
        QueueTailState::allocate(cs, witness.events_sorter_intermediate_queue_state.clone());

    let l1messages_sorter_intermediate_queue_state = QueueTailState::allocate(
        cs,
        witness.l1messages_sorter_intermediate_queue_state.clone(),
    );

    // final VM storage log state for our construction
    let storage_log_tail = <[Num<F>; QUEUE_STATE_WIDTH]>::allocate(cs, witness.storage_log_tail);

    // form the VM input
    let default_aa_code_hash = block_meta_parameters.default_aa_code_hash;

    let global_context = GlobalContext {
        zkporter_is_available: block_meta_parameters.zkporter_is_available,
        default_aa_code_hash,
    };

    // we can form all the observable inputs already as those are just functions of observable outputs

    let vm_observable_input = VmInputData {
        rollback_queue_tail_for_block: storage_log_tail,
        memory_queue_initial_state: initial_memory_queue_state.into_state().tail,
        decommitment_queue_initial_state: decommittments_queue.into_state().tail,
        per_block_context: global_context,
    };
    let vm_observable_input_commitment =
        commit_variable_length_encodable_item(cs, &vm_observable_input, round_function);
    let vm_observable_output_commitment = commit_variable_length_encodable_item(
        cs,
        &vm_end_of_execution_observable_output,
        round_function,
    );

    let mut decommittments_sorted_queue_state = QueueState::empty(cs);
    decommittments_sorted_queue_state.tail = QueueTailState::allocate(
        cs,
        witness.decommits_sorter_intermediate_queue_state.clone(),
    );

    let decommittments_sorter_circuit_input = CodeDecommittmentsDeduplicatorInputData {
        initial_queue_state: vm_end_of_execution_observable_output.decommitment_queue_final_state,
        sorted_queue_initial_state: decommittments_sorted_queue_state,
    };
    let decommittments_sorter_circuit_input_commitment = commit_variable_length_encodable_item(
        cs,
        &decommittments_sorter_circuit_input,
        round_function,
    );
    let decommittments_sorter_observable_output_commitment = commit_variable_length_encodable_item(
        cs,
        &decommits_sorter_observable_output,
        round_function,
    );

    // code decommiments:
    let code_decommitter_circuit_input = CodeDecommitterInputData {
        memory_queue_initial_state: vm_end_of_execution_observable_output.memory_queue_final_state,
        sorted_requests_queue_initial_state: decommits_sorter_observable_output.final_queue_state,
    };
    let code_decommitter_circuit_input_commitment =
        commit_variable_length_encodable_item(cs, &code_decommitter_circuit_input, round_function);
    let code_decommitter_observable_output_commitment = commit_variable_length_encodable_item(
        cs,
        &code_decommitter_observable_output,
        round_function,
    );

    // log demultiplexer
    let log_demux_circuit_input = LogDemuxerInputData {
        initial_log_queue_state: vm_end_of_execution_observable_output.log_queue_final_state,
    };
    let log_demux_circuit_input_commitment =
        commit_variable_length_encodable_item(cs, &log_demux_circuit_input, round_function);
    let log_demuxer_observable_output_commitment =
        commit_variable_length_encodable_item(cs, &log_demuxer_observable_output, round_function);

    // all intermediate queues for sorters

    // precompiles: keccak, sha256 and ecrecover
    let (keccak_circuit_observable_input_commitment, keccak_circuit_observable_output_commitment) =
        compute_precompile_commitment(
            cs,
            &log_demuxer_observable_output.keccak256_access_queue_state,
            &code_decommitter_observable_output.memory_queue_final_state,
            &keccak256_observable_output.final_memory_state,
            round_function,
        );
    let (sha256_circuit_observable_input_commitment, sha256_circuit_observable_output_commitment) =
        compute_precompile_commitment(
            cs,
            &log_demuxer_observable_output.sha256_access_queue_state,
            &keccak256_observable_output.final_memory_state,
            &sha256_observable_output.final_memory_state,
            round_function,
        );
    let (
        ecrecover_circuit_observable_input_commitment,
        ecrecover_circuit_observable_output_commitment,
    ) = compute_precompile_commitment(
        cs,
        &log_demuxer_observable_output.ecrecover_access_queue_state,
        &sha256_observable_output.final_memory_state,
        &ecrecover_observable_output.final_memory_state,
        round_function,
    );

    // ram permutation and validation
    // NBL this circuit is terminal - it has no actual output

    let mut ram_sorted_queue_state = QueueState::empty(cs);
    ram_sorted_queue_state.tail =
        QueueTailState::allocate(cs, witness.ram_sorted_queue_state.clone());

    let ram_validation_circuit_input = RamPermutationInputData {
        unsorted_queue_initial_state: ecrecover_observable_output.final_memory_state,
        sorted_queue_initial_state: ram_sorted_queue_state,
        non_deterministic_bootloader_memory_snapshot_length: bootloader_heap_memory_state.length,
    };
    let ram_validation_circuit_input_commitment =
        commit_variable_length_encodable_item(cs, &ram_validation_circuit_input, round_function);

    // events reverts filter and merkelization
    let (events_filter_input_com, events_filter_output_com) = compute_filter_circuit_commitment(
        cs,
        &log_demuxer_observable_output.events_access_queue_state,
        &events_sorter_intermediate_queue_state,
        &events_sorter_observable_output.final_queue_state,
        round_function,
    );

    // let (events_merkelizer_input_com, events_merkelizer_output_com) = compute_merkelization_circuit_commitment(
    //     cs,
    //     &filtered_events_queue_state,
    //     &events_linear_hash_as_bytes32,
    //     &events_root_as_bytes32,
    //     round_function
    // );

    // l1 messages reverts filter and merkelization
    let (l1_messages_filter_input_com, l1_messages_filter_output_com) =
        compute_filter_circuit_commitment(
            cs,
            &log_demuxer_observable_output.l1messages_access_queue_state,
            &l1messages_sorter_intermediate_queue_state,
            &l1messages_sorter_observable_output.final_queue_state,
            round_function,
        );

    let (l1_messages_hasher_input_com, l1_messages_hasher_output_com) =
        compute_hasher_circuit_commitment(
            cs,
            &l1messages_sorter_observable_output.final_queue_state,
            &l1messages_linear_hasher_observable_output.keccak256_hash,
            round_function,
        );

    const NUM_PROCESSABLE_SHARDS: usize = 1;

    let zero_num = Num::zero(cs);
    let empty_input_output_commitment = [zero_num; CLOSED_FORM_COMMITTMENT_LENGTH];

    let mut storage_filter_input_commitments =
        [empty_input_output_commitment; NUM_PROCESSABLE_SHARDS];
    let mut storage_filter_output_commitments =
        [empty_input_output_commitment; NUM_PROCESSABLE_SHARDS];
    let mut storage_applicator_input_commitments =
        [empty_input_output_commitment; NUM_PROCESSABLE_SHARDS];
    let mut storage_applicator_output_commitments =
        [empty_input_output_commitment; NUM_PROCESSABLE_SHARDS];

    let storage_queues_state = [log_demuxer_observable_output.storage_access_queue_state];

    let filtered_storage_queues_state = [storage_sorter_observable_output.final_sorted_queue_state];

    let initial_enumeration_counters = [prev_block_data.per_shard_states[0].enumeration_counter];

    let initial_state_roots = [prev_block_data.per_shard_states[0].state_root];

    let final_enumeration_counters =
        [storage_application_observable_output.new_next_enumeration_counter];

    let final_state_roots = [storage_application_observable_output.new_root_hash];

    let storage_intermediate_sorted_queue_state = [rollup_storage_sorter_intermediate_queue_state];

    let storage_diffs_for_compression =
        [storage_application_observable_output.state_diffs_keccak256_hash];

    assert_eq!(NUM_PROCESSABLE_SHARDS, 1); // no support of porter as of yet

    for shard_id in 0..NUM_PROCESSABLE_SHARDS {
        assert!(shard_id <= u8::MAX as usize);

        let shard_id_uint8 = UInt8::allocated_constant(cs, shard_id as u8);
        // storage acesses filter
        let (storage_filter_input_com, storage_filter_output_com) =
            compute_storage_sorter_circuit_commitment(
                cs,
                shard_id_uint8,
                &storage_queues_state[shard_id],
                &storage_intermediate_sorted_queue_state[shard_id],
                &filtered_storage_queues_state[shard_id],
                round_function,
            );
        storage_filter_input_commitments[shard_id] = storage_filter_input_com;
        storage_filter_output_commitments[shard_id] = storage_filter_output_com;

        // storage applicator for rollup subtree (porter subtree is shut down globally currently)
        let (storage_applicator_input_com, storage_applicator_output_com) =
            compute_storage_applicator_circuit_commitment(
                cs,
                &filtered_storage_queues_state[shard_id],
                &initial_state_roots[shard_id],
                &initial_enumeration_counters[shard_id],
                &final_state_roots[shard_id],
                &final_enumeration_counters[shard_id],
                &storage_diffs_for_compression[shard_id],
                shard_id as u8,
                round_function,
            );
        storage_applicator_input_commitments[shard_id] = storage_applicator_input_com;
        storage_applicator_output_commitments[shard_id] = storage_applicator_output_com;
    }

    // now we can run all the cirucits in sequence

    // now let's map it for convenience, and later on walk over it

    let input_commitments_as_map =
        HashMap::<BaseLayerCircuitType, [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH]>::from_iter(
            [
                (BaseLayerCircuitType::VM, vm_observable_input_commitment),
                (
                    BaseLayerCircuitType::DecommitmentsFilter,
                    decommittments_sorter_circuit_input_commitment,
                ),
                (
                    BaseLayerCircuitType::Decommiter,
                    code_decommitter_circuit_input_commitment,
                ),
                (
                    BaseLayerCircuitType::LogDemultiplexer,
                    log_demux_circuit_input_commitment,
                ),
                (
                    BaseLayerCircuitType::KeccakPrecompile,
                    keccak_circuit_observable_input_commitment,
                ),
                (
                    BaseLayerCircuitType::Sha256Precompile,
                    sha256_circuit_observable_input_commitment,
                ),
                (
                    BaseLayerCircuitType::EcrecoverPrecompile,
                    ecrecover_circuit_observable_input_commitment,
                ),
                (
                    BaseLayerCircuitType::RamValidation,
                    ram_validation_circuit_input_commitment,
                ),
                (
                    BaseLayerCircuitType::EventsRevertsFilter,
                    events_filter_input_com,
                ),
                (
                    BaseLayerCircuitType::L1MessagesRevertsFilter,
                    l1_messages_filter_input_com,
                ),
                (
                    BaseLayerCircuitType::StorageFilter,
                    storage_filter_input_commitments[0],
                ),
                (
                    BaseLayerCircuitType::StorageApplicator,
                    storage_applicator_input_commitments[0],
                ),
                (
                    BaseLayerCircuitType::L1MessagesHasher,
                    l1_messages_hasher_input_com,
                ),
            ]
            .into_iter(),
        );

    let output_commitments_as_map =
        HashMap::<BaseLayerCircuitType, [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH]>::from_iter(
            [
                (BaseLayerCircuitType::VM, vm_observable_output_commitment),
                (
                    BaseLayerCircuitType::DecommitmentsFilter,
                    decommittments_sorter_observable_output_commitment,
                ),
                (
                    BaseLayerCircuitType::Decommiter,
                    code_decommitter_observable_output_commitment,
                ),
                (
                    BaseLayerCircuitType::LogDemultiplexer,
                    log_demuxer_observable_output_commitment,
                ),
                (
                    BaseLayerCircuitType::KeccakPrecompile,
                    keccak_circuit_observable_output_commitment,
                ),
                (
                    BaseLayerCircuitType::Sha256Precompile,
                    sha256_circuit_observable_output_commitment,
                ),
                (
                    BaseLayerCircuitType::EcrecoverPrecompile,
                    ecrecover_circuit_observable_output_commitment,
                ),
                (
                    BaseLayerCircuitType::RamValidation,
                    [zero_num; CLOSED_FORM_COMMITTMENT_LENGTH], // formally set here
                ),
                (
                    BaseLayerCircuitType::EventsRevertsFilter,
                    events_filter_output_com,
                ),
                (
                    BaseLayerCircuitType::L1MessagesRevertsFilter,
                    l1_messages_filter_output_com,
                ),
                (
                    BaseLayerCircuitType::StorageFilter,
                    storage_filter_output_commitments[0],
                ),
                (
                    BaseLayerCircuitType::StorageApplicator,
                    storage_applicator_output_commitments[0],
                ),
                (
                    BaseLayerCircuitType::L1MessagesHasher,
                    l1_messages_hasher_output_com,
                ),
            ]
            .into_iter(),
        );

    // self-check
    for pair in SEQUENCE_OF_CIRCUIT_TYPES.windows(2) {
        assert_eq!((pair[0] as u8) + 1, pair[1] as u8);
    }

    // we can potentially skip some circuits
    let mut skip_flags = [None; NUM_CIRCUIT_TYPES_TO_SCHEDULE];
    // we can skip everything except VM
    skip_flags[(BaseLayerCircuitType::DecommitmentsFilter as u8 as usize) - 1] = Some(
        decommittments_sorter_circuit_input
            .initial_queue_state
            .tail
            .length
            .is_zero(cs),
    );
    skip_flags[(BaseLayerCircuitType::Decommiter as u8 as usize) - 1] = Some(
        code_decommitter_circuit_input
            .sorted_requests_queue_initial_state
            .tail
            .length
            .is_zero(cs),
    );
    skip_flags[(BaseLayerCircuitType::LogDemultiplexer as u8 as usize) - 1] = Some(
        log_demux_circuit_input
            .initial_log_queue_state
            .tail
            .length
            .is_zero(cs),
    );
    skip_flags[(BaseLayerCircuitType::KeccakPrecompile as u8 as usize) - 1] = Some(
        log_demuxer_observable_output
            .keccak256_access_queue_state
            .tail
            .length
            .is_zero(cs),
    );
    skip_flags[(BaseLayerCircuitType::Sha256Precompile as u8 as usize) - 1] = Some(
        log_demuxer_observable_output
            .sha256_access_queue_state
            .tail
            .length
            .is_zero(cs),
    );
    skip_flags[(BaseLayerCircuitType::EcrecoverPrecompile as u8 as usize) - 1] = Some(
        log_demuxer_observable_output
            .ecrecover_access_queue_state
            .tail
            .length
            .is_zero(cs),
    );
    skip_flags[(BaseLayerCircuitType::RamValidation as u8 as usize) - 1] = Some(
        ram_validation_circuit_input
            .unsorted_queue_initial_state
            .tail
            .length
            .is_zero(cs),
    );
    skip_flags[(BaseLayerCircuitType::StorageFilter as u8 as usize) - 1] =
        Some(storage_queues_state[0].tail.length.is_zero(cs));
    skip_flags[(BaseLayerCircuitType::StorageApplicator as u8 as usize) - 1] =
        Some(filtered_storage_queues_state[0].tail.length.is_zero(cs));
    skip_flags[(BaseLayerCircuitType::EventsRevertsFilter as u8 as usize) - 1] = Some(
        log_demuxer_observable_output
            .events_access_queue_state
            .tail
            .length
            .is_zero(cs),
    );
    skip_flags[(BaseLayerCircuitType::L1MessagesRevertsFilter as u8 as usize) - 1] = Some(
        log_demuxer_observable_output
            .l1messages_access_queue_state
            .tail
            .length
            .is_zero(cs),
    );

    // for (idx, el) in skip_flags.iter().enumerate() {
    //     if let Some(el) = el {
    //         let circuit_type = BaseLayerCircuitType::from_numeric_value((idx+1) as u8);
    //         println!("Skip for {:?} = {:?}", circuit_type, el.witness_hook(cs)());
    //     }
    // }

    // In practice we do NOT skip it
    // skip_flags[(BaseLayerCircuitType::L1MessagesHasher as u8 as usize) - 1] = Some(
    //     l1messages_sorter_observable_output.final_queue_state.tail.length.is_zero(cs)
    // );

    // now we just walk one by one

    let mut execution_stage_bitmask = [boolean_false; NUM_CIRCUIT_TYPES_TO_SCHEDULE];
    execution_stage_bitmask[0] = boolean_true; // VM

    assert_eq!(
        SEQUENCE_OF_CIRCUIT_TYPES.len(),
        execution_stage_bitmask.len()
    );

    let mut execution_flag = boolean_true;
    let mut previous_completion_flag = boolean_true;

    let empty_recursive_queue_state_tail = QueueTailState::empty(cs);
    let mut recursive_queue_state_tails =
        [empty_recursive_queue_state_tail; NUM_CIRCUIT_TYPES_TO_SCHEDULE];

    for _idx in 0..config.capacity {
        let mut next_mask = [boolean_false; NUM_CIRCUIT_TYPES_TO_SCHEDULE];

        let closed_form_input_witness = witness
            .per_circuit_closed_form_inputs
            .pop_front()
            .unwrap_or(ClosedFormInputCompactForm::placeholder_witness());
        let closed_form_input = ClosedFormInputCompactForm::allocate(cs, closed_form_input_witness);

        // we believe that prover gives us valid compact forms,
        // so we check equality
        let start_of_next_when_previous_is_finished =
            Boolean::equals(cs, &closed_form_input.start_flag, &previous_completion_flag);
        start_of_next_when_previous_is_finished.conditionally_enforce_true(cs, execution_flag);

        let mut computed_applicability_flags = [boolean_false; NUM_CIRCUIT_TYPES_TO_SCHEDULE];
        let mut circuit_type_to_use = Num::zero(cs);

        for (idx, ((circuit_type, stage_flag), skip_flag)) in SEQUENCE_OF_CIRCUIT_TYPES
            .iter()
            .zip(execution_stage_bitmask.iter())
            .zip(skip_flags.iter())
            .enumerate()
        {
            let sample_circuit_commitment = input_commitments_as_map
                .get(circuit_type)
                .cloned()
                .expect(&format!(
                    "circuit input commitment for type {:?}",
                    circuit_type
                ));
            // .unwrap_or([zero_num; CLOSED_FORM_COMMITTMENT_LENGTH]);

            let validate = if let Some(skip_flag) = skip_flag {
                let not_skip = skip_flag.negated(cs); // this is memoized
                Boolean::multi_and(cs, &[*stage_flag, execution_flag, not_skip])
            } else {
                Boolean::multi_and(cs, &[*stage_flag, execution_flag])
            };

            let validate_input = validate; // input commitment is ALWAYS the same for all the circuits of some type

            conditionally_enforce_circuit_commitment(
                cs,
                validate_input,
                &closed_form_input.observable_input_committment,
                &sample_circuit_commitment,
            );

            let validate_output = if let Some(skip_flag) = skip_flag {
                let not_skip = skip_flag.negated(cs); // this is memoized
                Boolean::multi_and(
                    cs,
                    &[closed_form_input.completion_flag, not_skip, *stage_flag],
                )
            } else {
                Boolean::multi_and(cs, &[closed_form_input.completion_flag, *stage_flag])
            };

            let sample_circuit_commitment = output_commitments_as_map
                .get(circuit_type)
                .cloned()
                .expect(&format!(
                    "circuit output commitment for type {:?}",
                    circuit_type
                ));
            // .unwrap_or([zero_num; CLOSED_FORM_COMMITTMENT_LENGTH]);

            conditionally_enforce_circuit_commitment(
                cs,
                validate_output,
                &closed_form_input.observable_output_committment,
                &sample_circuit_commitment,
            );

            let should_start_next = if let Some(skip_flag) = skip_flag {
                Boolean::multi_or(cs, &[closed_form_input.completion_flag, *skip_flag])
            } else {
                closed_form_input.completion_flag
            };

            let stage_just_finished =
                Boolean::multi_and(cs, &[should_start_next, execution_flag, *stage_flag]);
            next_mask[idx] = stage_just_finished;

            let circuit_type = UInt8::allocated_constant(cs, *circuit_type as u8).into_num();

            circuit_type_to_use =
                Num::conditionally_select(cs, validate, &circuit_type, &circuit_type_to_use);

            computed_applicability_flags[idx] = validate;
        }

        // now we can use a proper circuit type and manyally add it into single queue
        let mut tail_to_use = QueueTailState::empty(cs);
        for (_idx, (flag, state)) in computed_applicability_flags
            .iter()
            .zip(recursive_queue_state_tails.iter())
            .enumerate()
        {
            tail_to_use = conditionally_select_queue_tail(cs, *flag, &state, &tail_to_use);
        }

        let push_to_any = Boolean::multi_or(cs, &computed_applicability_flags);
        let closed_form_input_comm =
            commit_variable_length_encodable_item(cs, &closed_form_input, round_function);
        let query = RecursionQuery {
            circuit_type: circuit_type_to_use,
            input_commitment: closed_form_input_comm,
        };
        // push
        let mut tmp_queue = RecursionQueue::<F, R>::empty(cs);
        tmp_queue.tail = tail_to_use.tail;
        tmp_queue.length = tail_to_use.length;

        let _ = tmp_queue.push(cs, query, push_to_any);
        let tail_to_use_for_update = tmp_queue.into_state().tail;

        for (_idx, (flag, state)) in computed_applicability_flags
            .iter()
            .zip(recursive_queue_state_tails.iter_mut())
            .enumerate()
        {
            // if flag.witness_hook(cs)().unwrap_or(false) {
            //     let circuit_type = BaseLayerCircuitType::from_numeric_value((_idx+1) as u8);
            //     println!(
            //         "Pushing for circuit type {:?}, old state = {:?}, new state = {:?}",
            //         circuit_type,
            //         state.witness_hook(cs)(),
            //         tail_to_use_for_update.witness_hook(cs)(),
            //     );
            // }
            *state = conditionally_select_queue_tail(cs, *flag, &tail_to_use_for_update, &*state);
        }

        previous_completion_flag = Boolean::multi_or(cs, &next_mask);
        // for the next stage we do shifted AND
        let mut tmp = [boolean_false; NUM_CIRCUIT_TYPES_TO_SCHEDULE];
        // note skip(1)
        for (idx, start_next) in next_mask.iter().enumerate() {
            let finished_this_stage = *start_next;
            let not_finished = finished_this_stage.negated(cs);
            let proceed_current =
                Boolean::multi_and(cs, &[execution_stage_bitmask[idx], not_finished]);
            // update
            let start_as_next = tmp[idx];
            let do_this_stage = Boolean::multi_or(cs, &[start_as_next, proceed_current]);
            execution_stage_bitmask[idx] = do_this_stage;
            if idx + 1 < NUM_CIRCUIT_TYPES_TO_SCHEDULE {
                tmp[idx + 1] = finished_this_stage;
            }
        }

        // and check if we are done
        let just_finished = *next_mask.last().unwrap();
        let should_continue = just_finished.negated(cs);

        execution_flag = Boolean::multi_and(cs, &[execution_flag, should_continue]);
    }

    // so we are done!
    Boolean::enforce_equal(cs, &execution_flag, &boolean_false);

    // actually perform verification
    let leaf_layer_parameters = witness
        .leaf_layer_parameters
        .clone()
        .map(|el| RecursionLeafParameters::allocate(cs, el));

    let leaf_layer_parameters_commitment: [_; LEAF_LAYER_PARAMETERS_COMMITMENT_LENGTH] =
        commit_variable_length_encodable_item(cs, &leaf_layer_parameters, round_function);

    let node_layer_vk =
        AllocatedVerificationKey::<F, H>::allocate(cs, witness.node_layer_vk_witness.clone());
    let node_layer_vk_commitment: [_; VK_COMMITMENT_LENGTH] =
        commit_variable_length_encodable_item(cs, &node_layer_vk, round_function);

    if crate::config::CIRCUIT_VERSOBE {
        dbg!(leaf_layer_parameters_commitment.witness_hook(cs)());
        dbg!(node_layer_vk_commitment.witness_hook(cs)());
    }

    let mut proof_witnesses = witness.proof_witnesses;

    // create verifier
    let r = cs as *mut CS;

    assert_eq!(
        config.vk_fixed_parameters.parameters,
        verifier_builder.geometry()
    );

    let verifier = verifier_builder.create_recursive_verifier(cs);

    drop(cs);

    let cs = unsafe { &mut *r };

    for (_idx, (circuit_type, state)) in SEQUENCE_OF_CIRCUIT_TYPES
        .iter()
        .zip(recursive_queue_state_tails.into_iter())
        .enumerate()
    {
        println!("Verifying circuit type {:?}", circuit_type);

        let should_skip = state.length.is_zero(cs);
        let should_verify = should_skip.negated(cs);

        let circuit_type = UInt8::allocated_constant(cs, *circuit_type as u8).into_num();

        let mut queue_state = QueueState::empty(cs);
        queue_state.tail = state;

        let input: RecursionNodeInput<F> = RecursionNodeInput {
            branch_circuit_type: circuit_type,
            leaf_layer_parameters: leaf_layer_parameters,
            node_layer_vk_commitment: node_layer_vk_commitment,
            queue_state: queue_state,
        };

        let expected_input_commitment: [_; INPUT_OUTPUT_COMMITMENT_LENGTH] =
            commit_variable_length_encodable_item(cs, &input, round_function);

        let proof_witness = proof_witnesses.pop_front();

        let proof = AllocatedProof::allocate_from_witness(
            cs,
            proof_witness,
            &verifier,
            &config.vk_fixed_parameters,
            &config.proof_config,
        );

        let (is_valid, inputs) = verifier.verify::<H, TR, CTR, POW>(
            cs,
            transcript_params.clone(),
            &proof,
            &config.vk_fixed_parameters,
            &config.proof_config,
            &node_layer_vk,
        );

        is_valid.conditionally_enforce_true(cs, should_verify);
        assert_eq!(inputs.len(), expected_input_commitment.len());

        for (a, b) in inputs.iter().zip(expected_input_commitment.iter()) {
            Num::conditionally_enforce_equal(cs, should_verify, a, b);
        }
    }

    // now we can collapse queues
    let bootloader_heap_snapshot: [_; QUEUE_FINAL_STATE_COMMITMENT_LENGTH] =
        finalize_queue_state(cs, &bootloader_heap_memory_state, round_function);

    let events_snapshot: [_; QUEUE_FINAL_STATE_COMMITMENT_LENGTH] = finalize_queue_state(
        cs,
        &events_sorter_observable_output.final_queue_state.tail,
        round_function,
    );

    // Form a public block header
    let mut this_block_data = prev_block_data.clone();

    for ((dst, counter), root) in this_block_data
        .per_shard_states
        .iter_mut()
        .zip(final_enumeration_counters.iter())
        .zip(final_state_roots.iter())
    {
        dst.enumeration_counter = *counter;
        dst.state_root = *root;
    }

    let zero_u8 = UInt8::zero(cs);

    let mut bootloader_heap_initial_content = [zero_u8; 32];
    for (dst, src) in bootloader_heap_initial_content
        .array_chunks_mut::<8>()
        .zip(bootloader_heap_snapshot.iter())
    {
        let le_bytes = src.constraint_bit_length_as_bytes(cs, 64);
        dst.copy_from_slice(&le_bytes[..]);
        dst.reverse();
    }

    let mut events_queue_state = [zero_u8; 32];
    for (dst, src) in events_queue_state
        .array_chunks_mut::<8>()
        .zip(events_snapshot.iter())
    {
        let le_bytes = src.constraint_bit_length_as_bytes(cs, 64);
        dst.copy_from_slice(&le_bytes[..]);
        dst.reverse();
    }

    let aux_data = BlockAuxilaryOutput {
        rollup_state_diff_for_compression: storage_application_observable_output
            .state_diffs_keccak256_hash,
        bootloader_heap_initial_content,
        events_queue_state,
        l1_messages_linear_hash: l1messages_linear_hasher_observable_output.keccak256_hash,
    };

    let block_content_header = BlockContentHeader {
        block_data: this_block_data,
        block_meta: block_meta_parameters,
        auxilary_output: aux_data,
    };

    let (this_block_content_hash, _) = block_content_header.clone().into_formal_block_hash(cs);

    // we are done with this block, process the previous one
    let previous_block_passthrough_data = prev_block_data.into_flattened_bytes(cs);
    let previous_block_passthrough_hash =
        keccak256::keccak256(cs, &previous_block_passthrough_data);

    let previous_block_meta_hash = <[UInt8<F>; 32]>::allocate(cs, witness.previous_block_meta_hash);
    let previous_block_aux_hash = <[UInt8<F>; 32]>::allocate(cs, witness.previous_block_aux_hash);

    let previous_block_content_hash = BlockContentHeader::formal_block_hash_from_partial_hashes(
        cs,
        previous_block_passthrough_hash,
        previous_block_meta_hash,
        previous_block_aux_hash,
    );

    // form full block hash

    let mut flattened_public_input = vec![];
    flattened_public_input.extend(previous_block_content_hash);
    flattened_public_input.extend(this_block_content_hash);
    // recursion parameters

    let mut recursion_node_verification_key_hash = [zero_u8; 32];
    for (dst, src) in recursion_node_verification_key_hash
        .array_chunks_mut::<8>()
        .zip(node_layer_vk_commitment.iter())
    {
        let le_bytes = src.constraint_bit_length_as_bytes(cs, 64);
        dst.copy_from_slice(&le_bytes[..]);
        dst.reverse();
    }

    let mut leaf_layer_parameters_hash = [zero_u8; 32];
    for (dst, src) in leaf_layer_parameters_hash
        .array_chunks_mut::<8>()
        .zip(leaf_layer_parameters_commitment.iter())
    {
        let le_bytes = src.constraint_bit_length_as_bytes(cs, 64);
        dst.copy_from_slice(&le_bytes[..]);
        dst.reverse();
    }

    flattened_public_input.extend(recursion_node_verification_key_hash);
    flattened_public_input.extend(leaf_layer_parameters_hash);

    let input_keccak_hash = keccak256::keccak256(cs, &flattened_public_input);
    let take_by = F::CAPACITY_BITS / 8;

    for chunk in input_keccak_hash
        .chunks_exact(take_by)
        .take(NUM_SCHEDULER_PUBLIC_INPUTS)
    {
        let mut lc = Vec::with_capacity(chunk.len());
        // treat as BE
        for (idx, el) in chunk.iter().rev().enumerate() {
            lc.push((el.get_variable(), F::SHIFTS[idx * 8]));
        }
        let as_num = Num::linear_combination(cs, &lc);
        use boojum::cs::gates::PublicInputGate;
        let gate = PublicInputGate::new(as_num.get_variable());
        gate.add_to_cs(cs);
    }
}
