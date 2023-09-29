use super::*;
use boojum::cs::implementations::proof::Proof;
use boojum::cs::implementations::verifier::VerificationKey;

use boojum::field::SmallField;

use boojum::gadgets::{queue::*, traits::allocatable::*};

use crate::base_structures::precompile_input_outputs::PrecompileFunctionOutputDataWitness;

use crate::base_structures::vm_state::*;
use crate::code_unpacker_sha256::input::CodeDecommitterOutputDataWitness;

use crate::fsm_input_output::circuit_inputs::main_vm::VmOutputDataWitness;
use crate::linear_hasher::input::LinearHasherOutputDataWitness;
use crate::log_sorter::input::EventsDeduplicatorOutputDataWitness;

use crate::fsm_input_output::ClosedFormInputCompactFormWitness;
use crate::storage_application::input::StorageApplicationOutputDataWitness;
use crate::storage_validity_by_grand_product::input::StorageDeduplicatorOutputDataWitness;
use boojum::gadgets::num::Num;
use boojum::gadgets::recursion::recursive_tree_hasher::RecursiveTreeHasher;
use std::collections::VecDeque;

use crate::recursion::leaf_layer::input::*;
use crate::recursion::*;
use boojum::field::FieldExtension;

// This structure only keeps witness, but there is a lot of in unfortunately
#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug)]
#[serde(
    bound = "<H::CircuitOutput as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned,
    [RecursionLeafParametersWitness<F>; NUM_BASE_LAYER_CIRCUITS]: serde::Serialize + serde::de::DeserializeOwned"
)]
pub struct SchedulerCircuitInstanceWitness<
    F: SmallField,
    H: RecursiveTreeHasher<F, Num<F>>,
    EXT: FieldExtension<2, BaseField = F>,
> {
    pub prev_block_data: BlockPassthroughDataWitness<F>,
    pub block_meta_parameters: BlockMetaParametersWitness<F>,

    // passthrough outputs for all the circuits that produce such
    pub vm_end_of_execution_observable_output: VmOutputDataWitness<F>,
    pub decommits_sorter_observable_output: CodeDecommittmentsDeduplicatorOutputDataWitness<F>,
    pub code_decommitter_observable_output: CodeDecommitterOutputDataWitness<F>,
    pub log_demuxer_observable_output: LogDemuxerOutputDataWitness<F>,
    pub keccak256_observable_output: PrecompileFunctionOutputDataWitness<F>,
    pub sha256_observable_output: PrecompileFunctionOutputDataWitness<F>,
    pub ecrecover_observable_output: PrecompileFunctionOutputDataWitness<F>,
    // RAM permutation doesn't produce anything
    pub storage_sorter_observable_output: StorageDeduplicatorOutputDataWitness<F>,
    pub storage_application_observable_output: StorageApplicationOutputDataWitness<F>,
    pub events_sorter_observable_output: EventsDeduplicatorOutputDataWitness<F>,
    pub l1messages_sorter_observable_output: EventsDeduplicatorOutputDataWitness<F>,
    pub l1messages_linear_hasher_observable_output: LinearHasherOutputDataWitness<F>,

    // very few things that we need to properly produce this block
    pub storage_log_tail: [F; QUEUE_STATE_WIDTH],
    pub per_circuit_closed_form_inputs: VecDeque<ClosedFormInputCompactFormWitness<F>>,

    pub bootloader_heap_memory_state: QueueTailStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub ram_sorted_queue_state: QueueTailStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub decommits_sorter_intermediate_queue_state:
        QueueTailStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,

    // all multi-circuits responsible for sorting
    pub rollup_storage_sorter_intermediate_queue_state: QueueTailStateWitness<F, QUEUE_STATE_WIDTH>,
    pub events_sorter_intermediate_queue_state: QueueTailStateWitness<F, QUEUE_STATE_WIDTH>,
    pub l1messages_sorter_intermediate_queue_state: QueueTailStateWitness<F, QUEUE_STATE_WIDTH>,

    // extra information about the previous block
    pub previous_block_meta_hash: [u8; 32],
    pub previous_block_aux_hash: [u8; 32],

    // proofs for every individual circuit type's aggregation subtree
    #[derivative(Debug = "ignore")]
    pub proof_witnesses: VecDeque<Proof<F, H::NonCircuitSimulator, EXT>>,
    #[derivative(Debug = "ignore")]
    pub node_layer_vk_witness: VerificationKey<F, H::NonCircuitSimulator>,
    #[derivative(Debug = "ignore")]
    pub leaf_layer_parameters: [RecursionLeafParametersWitness<F>; NUM_BASE_LAYER_CIRCUITS],
}

impl<F: SmallField, H: RecursiveTreeHasher<F, Num<F>>, EXT: FieldExtension<2, BaseField = F>>
    SchedulerCircuitInstanceWitness<F, H, EXT>
{
    pub fn placeholder() -> Self {
        Self {
            prev_block_data: BlockPassthroughData::placeholder_witness(),
            block_meta_parameters: BlockMetaParameters::placeholder_witness(),

            vm_end_of_execution_observable_output: VmOutputData::placeholder_witness(),
            decommits_sorter_observable_output:
                CodeDecommittmentsDeduplicatorOutputData::placeholder_witness(),
            code_decommitter_observable_output: CodeDecommitterOutputData::placeholder_witness(),
            log_demuxer_observable_output: LogDemuxerOutputData::placeholder_witness(),
            keccak256_observable_output: PrecompileFunctionOutputData::placeholder_witness(),
            sha256_observable_output: PrecompileFunctionOutputData::placeholder_witness(),
            ecrecover_observable_output: PrecompileFunctionOutputData::placeholder_witness(),
            storage_sorter_observable_output: StorageDeduplicatorOutputData::placeholder_witness(),
            storage_application_observable_output:
                StorageApplicationOutputData::placeholder_witness(),
            events_sorter_observable_output: EventsDeduplicatorOutputData::placeholder_witness(),
            l1messages_sorter_observable_output: EventsDeduplicatorOutputData::placeholder_witness(
            ),
            l1messages_linear_hasher_observable_output: LinearHasherOutputData::placeholder_witness(
            ),

            storage_log_tail: [F::ZERO; QUEUE_STATE_WIDTH],
            per_circuit_closed_form_inputs: VecDeque::new(),

            bootloader_heap_memory_state: QueueTailState::placeholder_witness(),
            ram_sorted_queue_state: QueueTailState::placeholder_witness(),
            decommits_sorter_intermediate_queue_state: QueueTailState::placeholder_witness(),

            rollup_storage_sorter_intermediate_queue_state: QueueTailState::placeholder_witness(),
            events_sorter_intermediate_queue_state: QueueTailState::placeholder_witness(),
            l1messages_sorter_intermediate_queue_state: QueueTailState::placeholder_witness(),

            previous_block_meta_hash: [0u8; 32],
            previous_block_aux_hash: [0u8; 32],

            proof_witnesses: VecDeque::new(),
            node_layer_vk_witness: VerificationKey::default(),
            leaf_layer_parameters: std::array::from_fn(|_| {
                RecursionLeafParameters::placeholder_witness()
            }),
        }
    }
}
