use crate::base_structures::{
    log_query::{LogQuery, LOG_QUERY_PACKED_WIDTH},
    vm_state::*,
};
use boojum::cs::{traits::cs::ConstraintSystem, Variable};
use boojum::field::SmallField;
use boojum::gadgets::keccak256;
use boojum::gadgets::traits::auxiliary::PrettyComparison;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use boojum::gadgets::{
    boolean::Boolean,
    queue::*,
    traits::{
        allocatable::*, encodable::CircuitVarLengthEncodable, selectable::Selectable,
        witnessable::WitnessHookable,
    },
};
use boojum::serde_utils::BigArraySerde;
use cs_derive::*;
use derivative::*;
use std::collections::VecDeque;

pub const STORAGE_DEPTH: usize = 256;

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct StorageApplicationFSMInputOutput<F: SmallField> {
    pub current_root_hash: [UInt8<F>; 32],
    pub next_enumeration_counter: [UInt32<F>; 2],
    pub current_storage_application_log_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub current_diffs_keccak_accumulator_state:
        [[[UInt8<F>; keccak256::BYTES_PER_WORD]; keccak256::LANE_WIDTH]; keccak256::LANE_WIDTH],
}

impl<F: SmallField> CSPlaceholder<F> for StorageApplicationFSMInputOutput<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            current_root_hash: [UInt8::<F>::placeholder(cs); 32],
            next_enumeration_counter: [UInt32::<F>::placeholder(cs); 2],
            current_storage_application_log_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(
                cs,
            ),
            current_diffs_keccak_accumulator_state: [[[UInt8::<F>::placeholder(cs);
                keccak256::BYTES_PER_WORD];
                keccak256::LANE_WIDTH];
                keccak256::LANE_WIDTH],
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct StorageApplicationInputData<F: SmallField> {
    pub shard: UInt8<F>,
    pub initial_root_hash: [UInt8<F>; 32],
    pub initial_next_enumeration_counter: [UInt32<F>; 2],
    pub storage_application_log_state: QueueState<F, QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for StorageApplicationInputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            shard: UInt8::<F>::placeholder(cs),
            initial_root_hash: [UInt8::<F>::placeholder(cs); 32],
            initial_next_enumeration_counter: [UInt32::<F>::placeholder(cs); 2],
            storage_application_log_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct StorageApplicationOutputData<F: SmallField> {
    pub new_root_hash: [UInt8<F>; 32],
    pub new_next_enumeration_counter: [UInt32<F>; 2],
    pub state_diffs_keccak256_hash: [UInt8<F>; 32],
}

impl<F: SmallField> CSPlaceholder<F> for StorageApplicationOutputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            new_root_hash: [UInt8::<F>::placeholder(cs); 32],
            new_next_enumeration_counter: [UInt32::<F>::placeholder(cs); 2],
            state_diffs_keccak256_hash: [UInt8::<F>::placeholder(cs); 32],
        }
    }
}

pub type StorageApplicationInputOutput<F> = crate::fsm_input_output::ClosedFormInput<
    F,
    StorageApplicationFSMInputOutput<F>,
    StorageApplicationInputData<F>,
    StorageApplicationOutputData<F>,
>;

pub type StorageApplicationInputOutputWitness<F> = crate::fsm_input_output::ClosedFormInputWitness<
    F,
    StorageApplicationFSMInputOutput<F>,
    StorageApplicationInputData<F>,
    StorageApplicationOutputData<F>,
>;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug, Default)]
#[serde(bound = "")]
pub struct StorageApplicationCircuitInstanceWitness<F: SmallField> {
    pub closed_form_input: StorageApplicationInputOutputWitness<F>,
    // #[serde(bound(
    //     serialize = "CircuitQueueRawWitness<F, LogQuery<F>, 4, LOG_QUERY_PACKED_WIDTH>: serde::Serialize"
    // ))]
    // #[serde(bound(
    //     deserialize = "CircuitQueueRawWitness<F, LogQuery<F>, 4, LOG_QUERY_PACKED_WIDTH>: serde::de::DeserializeOwned"
    // ))]
    pub storage_queue_witness: CircuitQueueRawWitness<F, LogQuery<F>, 4, LOG_QUERY_PACKED_WIDTH>,
    pub merkle_paths: VecDeque<Vec<[u8; 32]>>,
    pub leaf_indexes_for_reads: VecDeque<u64>,
}
