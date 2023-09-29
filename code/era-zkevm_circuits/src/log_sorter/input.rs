use crate::base_structures::{
    log_query::{LogQuery, LOG_QUERY_PACKED_WIDTH},
    vm_state::*,
};
use boojum::cs::{traits::cs::ConstraintSystem, Variable};
use boojum::field::SmallField;
use boojum::gadgets::queue::QueueState;
use boojum::gadgets::traits::auxiliary::PrettyComparison;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::{
    boolean::Boolean,
    num::Num,
    queue::*,
    traits::{
        allocatable::*, encodable::CircuitVarLengthEncodable, selectable::Selectable,
        witnessable::WitnessHookable,
    },
};
use boojum::serde_utils::BigArraySerde;
use cs_derive::*;
use derivative::*;

use crate::DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS;

#[derive(Derivative, CSAllocatable, CSVarLengthEncodable, CSSelectable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct EventsDeduplicatorFSMInputOutput<F: SmallField> {
    pub lhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub rhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub initial_unsorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub intermediate_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub final_result_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub previous_key: UInt32<F>,
    pub previous_item: LogQuery<F>,
}

impl<F: SmallField> CSPlaceholder<F> for EventsDeduplicatorFSMInputOutput<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_num = Num::zero(cs);
        let zero_u32 = UInt32::zero(cs);
        Self {
            lhs_accumulator: [zero_num; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
            rhs_accumulator: [zero_num; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
            initial_unsorted_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
            intermediate_sorted_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
            final_result_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
            previous_key: zero_u32,
            previous_item: LogQuery::<F>::placeholder(cs),
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct EventsDeduplicatorInputData<F: SmallField> {
    pub initial_log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub intermediate_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for EventsDeduplicatorInputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            initial_log_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
            intermediate_sorted_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct EventsDeduplicatorOutputData<F: SmallField> {
    pub final_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for EventsDeduplicatorOutputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            final_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
        }
    }
}

pub type EventsDeduplicatorInputOutput<F> = crate::fsm_input_output::ClosedFormInput<
    F,
    EventsDeduplicatorFSMInputOutput<F>,
    EventsDeduplicatorInputData<F>,
    EventsDeduplicatorOutputData<F>,
>;
pub type EventsDeduplicatorInputOutputWitness<F> = crate::fsm_input_output::ClosedFormInputWitness<
    F,
    EventsDeduplicatorFSMInputOutput<F>,
    EventsDeduplicatorInputData<F>,
    EventsDeduplicatorOutputData<F>,
>;
#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug, Default)]
#[serde(bound = "")]
pub struct EventsDeduplicatorInstanceWitness<F: SmallField> {
    pub closed_form_input: EventsDeduplicatorInputOutputWitness<F>,
    pub initial_queue_witness: CircuitQueueRawWitness<F, LogQuery<F>, 4, LOG_QUERY_PACKED_WIDTH>,
    pub intermediate_sorted_queue_witness:
        CircuitQueueRawWitness<F, LogQuery<F>, 4, LOG_QUERY_PACKED_WIDTH>,
}
