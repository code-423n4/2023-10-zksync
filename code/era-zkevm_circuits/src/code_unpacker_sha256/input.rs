use crate::base_structures::vm_state::*;
use crate::ethereum_types::U256;
use boojum::cs::{traits::cs::ConstraintSystem, Variable};
use boojum::field::SmallField;
use boojum::gadgets::traits::auxiliary::PrettyComparison;
use boojum::gadgets::{
    boolean::Boolean,
    queue::*,
    traits::{
        allocatable::*, encodable::CircuitVarLengthEncodable, selectable::Selectable,
        witnessable::WitnessHookable,
    },
    u16::UInt16,
    u256::UInt256,
    u32::UInt32,
};
use boojum::serde_utils::BigArraySerde;
use cs_derive::*;
use derivative::*;

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct CodeDecommittmentFSM<F: SmallField> {
    pub sha256_inner_state: [UInt32<F>; 8], // 8 uint32 words of internal sha256 state
    pub hash_to_compare_against: UInt256<F>,
    pub current_index: UInt32<F>,
    pub current_page: UInt32<F>,
    pub timestamp: UInt32<F>,
    pub num_rounds_left: UInt16<F>,
    pub length_in_bits: UInt32<F>,
    pub state_get_from_queue: Boolean<F>,
    pub state_decommit: Boolean<F>,
    pub finished: Boolean<F>,
}

impl<F: SmallField> CSPlaceholder<F> for CodeDecommittmentFSM<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let bool_false = Boolean::allocated_constant(cs, false);
        let zero_uint16 = UInt16::zero(cs);
        let zero_uint32 = UInt32::zero(cs);
        let zero_uint256 = UInt256::zero(cs);

        Self {
            sha256_inner_state: [zero_uint32; 8],
            hash_to_compare_against: zero_uint256,
            current_index: zero_uint32,
            current_page: zero_uint32,
            timestamp: zero_uint32,
            num_rounds_left: zero_uint16,
            length_in_bits: zero_uint32,
            state_get_from_queue: bool_false,
            state_decommit: bool_false,
            finished: bool_false,
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct CodeDecommitterFSMInputOutput<F: SmallField> {
    pub internal_fsm: CodeDecommittmentFSM<F>,
    pub decommittment_requests_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub memory_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for CodeDecommitterFSMInputOutput<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            internal_fsm: CodeDecommittmentFSM::<F>::placeholder(cs),
            decommittment_requests_queue_state:
                QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(cs),
            memory_queue_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(cs),
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct CodeDecommitterInputData<F: SmallField> {
    pub memory_queue_initial_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub sorted_requests_queue_initial_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for CodeDecommitterInputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            memory_queue_initial_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(
                cs,
            ),
            sorted_requests_queue_initial_state:
                QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(cs),
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct CodeDecommitterOutputData<F: SmallField> {
    pub memory_queue_final_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for CodeDecommitterOutputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            memory_queue_final_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(
                cs,
            ),
        }
    }
}

pub type CodeDecommitterCycleInputOutput<F> = crate::fsm_input_output::ClosedFormInput<
    F,
    CodeDecommitterFSMInputOutput<F>,
    CodeDecommitterInputData<F>,
    CodeDecommitterOutputData<F>,
>;
pub type CodeDecommitterCycleInputOutputWitness<F> =
    crate::fsm_input_output::ClosedFormInputWitness<
        F,
        CodeDecommitterFSMInputOutput<F>,
        CodeDecommitterInputData<F>,
        CodeDecommitterOutputData<F>,
    >;

use crate::code_unpacker_sha256::full_state_queue::FullStateCircuitQueueRawWitness;
use crate::code_unpacker_sha256::{DecommitQuery, DECOMMIT_QUERY_PACKED_WIDTH};

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug, Default)]
#[serde(bound = "")]
pub struct CodeDecommitterCircuitInstanceWitness<F: SmallField> {
    pub closed_form_input: CodeDecommitterCycleInputOutputWitness<F>,

    pub sorted_requests_queue_witness:
        FullStateCircuitQueueRawWitness<F, DecommitQuery<F>, 12, DECOMMIT_QUERY_PACKED_WIDTH>,
    pub code_words: Vec<Vec<U256>>,
}
