use crate::base_structures::{
    log_query::{LogQuery, LOG_QUERY_PACKED_WIDTH},
    vm_state::*,
};
use crate::DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS;
use boojum::cs::{traits::cs::ConstraintSystem, Variable};
use boojum::field::SmallField;
use boojum::gadgets::traits::auxiliary::PrettyComparison;
use boojum::{
    gadgets::{
        boolean::Boolean,
        num::*,
        queue::*,
        traits::{
            allocatable::*, encodable::CircuitVarLengthEncodable, selectable::Selectable,
            witnessable::WitnessHookable,
        },
        u160::*,
        u256::*,
        u32::*,
        u8::*,
    },
    serde_utils::BigArraySerde,
};
use cs_derive::*;
use derivative::*;

pub const PACKED_KEY_LENGTH: usize = 5 + 8;

use super::TimestampedStorageLogRecord;

// FSM

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct StorageDeduplicatorFSMInputOutput<F: SmallField> {
    pub lhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub rhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub current_unsorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub current_intermediate_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub current_final_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub cycle_idx: UInt32<F>,
    pub previous_packed_key: [UInt32<F>; PACKED_KEY_LENGTH],
    pub previous_key: UInt256<F>,
    pub previous_address: UInt160<F>,
    pub previous_timestamp: UInt32<F>,
    pub this_cell_has_explicit_read_and_rollback_depth_zero: Boolean<F>,
    pub this_cell_base_value: UInt256<F>,
    pub this_cell_current_value: UInt256<F>,
    pub this_cell_current_depth: UInt32<F>,
}

impl<F: SmallField> CSPlaceholder<F> for StorageDeduplicatorFSMInputOutput<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_num = Num::<F>::zero(cs);
        let zero_u32 = UInt32::zero(cs);
        let zero_address = UInt160::zero(cs);
        let zero_u256 = UInt256::zero(cs);
        let boolean_false = Boolean::allocated_constant(cs, false);

        Self {
            lhs_accumulator: [zero_num; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
            rhs_accumulator: [zero_num; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
            current_unsorted_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
            current_intermediate_sorted_queue_state:
                QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
            current_final_sorted_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
            cycle_idx: zero_u32,
            previous_packed_key: [zero_u32; PACKED_KEY_LENGTH],
            previous_key: zero_u256,
            previous_address: zero_address,
            previous_timestamp: zero_u32,
            this_cell_has_explicit_read_and_rollback_depth_zero: boolean_false,
            this_cell_base_value: zero_u256,
            this_cell_current_value: zero_u256,
            this_cell_current_depth: zero_u32,
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Debug)]
pub struct StorageDeduplicatorInputData<F: SmallField> {
    pub shard_id_to_process: UInt8<F>,
    pub unsorted_log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub intermediate_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for StorageDeduplicatorInputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            shard_id_to_process: UInt8::placeholder(cs),
            unsorted_log_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
            intermediate_sorted_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct StorageDeduplicatorOutputData<F: SmallField> {
    pub final_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for StorageDeduplicatorOutputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            final_sorted_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
        }
    }
}

pub type StorageDeduplicatorInputOutput<F> = crate::fsm_input_output::ClosedFormInput<
    F,
    StorageDeduplicatorFSMInputOutput<F>,
    StorageDeduplicatorInputData<F>,
    StorageDeduplicatorOutputData<F>,
>;
pub type StorageDeduplicatorInputOutputWitness<F> = crate::fsm_input_output::ClosedFormInputWitness<
    F,
    StorageDeduplicatorFSMInputOutput<F>,
    StorageDeduplicatorInputData<F>,
    StorageDeduplicatorOutputData<F>,
>;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug, Default)]
#[serde(bound = "")]
pub struct StorageDeduplicatorInstanceWitness<F: SmallField> {
    pub closed_form_input: StorageDeduplicatorInputOutputWitness<F>,
    pub unsorted_queue_witness: CircuitQueueRawWitness<F, LogQuery<F>, 4, LOG_QUERY_PACKED_WIDTH>,
    pub intermediate_sorted_queue_witness:
        CircuitQueueRawWitness<F, TimestampedStorageLogRecord<F>, 4, LOG_QUERY_PACKED_WIDTH>,
}
