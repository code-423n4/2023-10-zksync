use crate::base_structures::decommit_query::DECOMMIT_QUERY_PACKED_WIDTH;
use crate::sort_decommittment_requests::full_state_queue::FullStateCircuitQueueRawWitness;
use crate::sort_decommittment_requests::*;
use boojum::cs::{traits::cs::ConstraintSystem, Variable};
use boojum::field::SmallField;
use boojum::gadgets::num::Num;
use boojum::gadgets::traits::auxiliary::PrettyComparison;
use boojum::gadgets::u32::UInt32;
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

pub const PACKED_KEY_LENGTH: usize = 8 + 1;

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct CodeDecommittmentsDeduplicatorFSMInputOutput<F: SmallField> {
    pub initial_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub sorted_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub final_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,

    pub lhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub rhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],

    pub previous_packed_key: [UInt32<F>; PACKED_KEY_LENGTH],
    pub first_encountered_timestamp: UInt32<F>,
    pub previous_record: DecommitQuery<F>,
}

impl<F: SmallField> CSPlaceholder<F> for CodeDecommittmentsDeduplicatorFSMInputOutput<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_num = Num::zero(cs);
        let zero_u32 = UInt32::zero(cs);

        Self {
            initial_queue_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(cs),
            sorted_queue_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(cs),
            final_queue_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(cs),

            lhs_accumulator: [zero_num; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
            rhs_accumulator: [zero_num; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],

            previous_packed_key: [zero_u32; PACKED_KEY_LENGTH],
            first_encountered_timestamp: zero_u32,
            previous_record: DecommitQuery::<F>::placeholder(cs),
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct CodeDecommittmentsDeduplicatorInputData<F: SmallField> {
    pub initial_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub sorted_queue_initial_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for CodeDecommittmentsDeduplicatorInputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            initial_queue_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(cs),
            sorted_queue_initial_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(
                cs,
            ),
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct CodeDecommittmentsDeduplicatorOutputData<F: SmallField> {
    pub final_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for CodeDecommittmentsDeduplicatorOutputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            final_queue_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(cs),
        }
    }
}

pub type CodeDecommittmentsDeduplicatorInputOutput<F> = crate::fsm_input_output::ClosedFormInput<
    F,
    CodeDecommittmentsDeduplicatorFSMInputOutput<F>,
    CodeDecommittmentsDeduplicatorInputData<F>,
    CodeDecommittmentsDeduplicatorOutputData<F>,
>;
pub type CodeDecommittmentsDeduplicatorInputOutputWitness<F> =
    crate::fsm_input_output::ClosedFormInputWitness<
        F,
        CodeDecommittmentsDeduplicatorFSMInputOutput<F>,
        CodeDecommittmentsDeduplicatorInputData<F>,
        CodeDecommittmentsDeduplicatorOutputData<F>,
    >;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug, Default)]
#[serde(bound = "")]
pub struct CodeDecommittmentsDeduplicatorInstanceWitness<F: SmallField> {
    pub closed_form_input: CodeDecommittmentsDeduplicatorInputOutputWitness<F>,
    pub initial_queue_witness: FullStateCircuitQueueRawWitness<
        F,
        DecommitQuery<F>,
        FULL_SPONGE_QUEUE_STATE_WIDTH,
        DECOMMIT_QUERY_PACKED_WIDTH,
    >,
    pub sorted_queue_witness: FullStateCircuitQueueRawWitness<
        F,
        DecommitQuery<F>,
        FULL_SPONGE_QUEUE_STATE_WIDTH,
        DECOMMIT_QUERY_PACKED_WIDTH,
    >,
}
