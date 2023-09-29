use std::collections::VecDeque;

use super::*;

use crate::base_structures::precompile_input_outputs::*;
use crate::base_structures::vm_state::*;
use boojum::cs::Variable;
use boojum::gadgets::queue::*;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::allocatable::CSPlaceholder;
use boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;

use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::keccak256::{BYTES_PER_WORD, LANE_WIDTH};
use boojum::gadgets::traits::auxiliary::PrettyComparison;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::serde_utils::BigArraySerde;

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct Keccak256RoundFunctionFSM<F: SmallField> {
    pub read_precompile_call: Boolean<F>,
    pub read_unaligned_words_for_round: Boolean<F>,
    pub completed: Boolean<F>,
    pub keccak_internal_state: [[[UInt8<F>; BYTES_PER_WORD]; LANE_WIDTH]; LANE_WIDTH],
    pub timestamp_to_use_for_read: UInt32<F>,
    pub timestamp_to_use_for_write: UInt32<F>,
    pub precompile_call_params: Keccak256PrecompileCallParams<F>,
    pub u8_words_buffer: [UInt8<F>; BYTES_BUFFER_SIZE],
    pub u64_words_buffer_markers: [Boolean<F>; BUFFER_SIZE_IN_U64_WORDS],
}

impl<F: SmallField> CSPlaceholder<F> for Keccak256RoundFunctionFSM<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let boolean_false = Boolean::allocated_constant(cs, false);
        let zero_u8 = UInt8::zero(cs);
        let zero_u32 = UInt32::zero(cs);
        Self {
            read_precompile_call: boolean_false,
            read_unaligned_words_for_round: boolean_false,
            completed: boolean_false,
            keccak_internal_state: [[[zero_u8; BYTES_PER_WORD]; LANE_WIDTH]; LANE_WIDTH],
            timestamp_to_use_for_read: zero_u32,
            timestamp_to_use_for_write: zero_u32,
            precompile_call_params: Keccak256PrecompileCallParams::<F>::placeholder(cs),
            u8_words_buffer: [zero_u8; BYTES_BUFFER_SIZE],
            u64_words_buffer_markers: [boolean_false; BUFFER_SIZE_IN_U64_WORDS],
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct Keccak256RoundFunctionFSMInputOutput<F: SmallField> {
    pub internal_fsm: Keccak256RoundFunctionFSM<F>,
    pub log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub memory_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for Keccak256RoundFunctionFSMInputOutput<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            internal_fsm: Keccak256RoundFunctionFSM::placeholder(cs),
            log_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
            memory_queue_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(cs),
        }
    }
}

pub type Keccak256RoundFunctionCircuitInputOutput<F> = ClosedFormInput<
    F,
    Keccak256RoundFunctionFSMInputOutput<F>,
    PrecompileFunctionInputData<F>,
    PrecompileFunctionOutputData<F>,
>;
pub type Keccak256RoundFunctionCircuitInputOutputWitness<F> = ClosedFormInputWitness<
    F,
    Keccak256RoundFunctionFSMInputOutput<F>,
    PrecompileFunctionInputData<F>,
    PrecompileFunctionOutputData<F>,
>;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug, Default)]
#[serde(bound = "")]
pub struct Keccak256RoundFunctionCircuitInstanceWitness<F: SmallField> {
    pub closed_form_input: Keccak256RoundFunctionCircuitInputOutputWitness<F>,
    pub requests_queue_witness: CircuitQueueRawWitness<F, LogQuery<F>, 4, LOG_QUERY_PACKED_WIDTH>,
    pub memory_reads_witness: VecDeque<U256>,
}
