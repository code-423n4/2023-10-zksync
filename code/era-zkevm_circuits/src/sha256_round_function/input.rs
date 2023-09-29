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
use boojum::gadgets::traits::auxiliary::PrettyComparison;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::serde_utils::BigArraySerde;

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct Sha256RoundFunctionFSM<F: SmallField> {
    pub read_precompile_call: Boolean<F>,
    pub read_words_for_round: Boolean<F>,
    pub completed: Boolean<F>,
    pub sha256_inner_state: [UInt32<F>; 8],
    pub timestamp_to_use_for_read: UInt32<F>,
    pub timestamp_to_use_for_write: UInt32<F>,
    pub precompile_call_params: Sha256PrecompileCallParams<F>,
}

impl<F: SmallField> CSPlaceholder<F> for Sha256RoundFunctionFSM<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let boolean_false = Boolean::allocated_constant(cs, false);
        let zero_u32 = UInt32::zero(cs);
        Self {
            read_precompile_call: boolean_false,
            read_words_for_round: boolean_false,
            completed: boolean_false,
            sha256_inner_state: boojum::gadgets::sha256::ivs_as_uint32(cs),
            timestamp_to_use_for_read: zero_u32,
            timestamp_to_use_for_write: zero_u32,
            precompile_call_params: Sha256PrecompileCallParams::<F>::placeholder(cs),
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct Sha256RoundFunctionFSMInputOutput<F: SmallField> {
    pub internal_fsm: Sha256RoundFunctionFSM<F>,
    pub log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub memory_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for Sha256RoundFunctionFSMInputOutput<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            internal_fsm: Sha256RoundFunctionFSM::placeholder(cs),
            log_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
            memory_queue_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(cs),
        }
    }
}

pub type Sha256RoundFunctionCircuitInputOutput<F> = ClosedFormInput<
    F,
    Sha256RoundFunctionFSMInputOutput<F>,
    PrecompileFunctionInputData<F>,
    PrecompileFunctionOutputData<F>,
>;
pub type Sha256RoundFunctionCircuitInputOutputWitness<F> = ClosedFormInputWitness<
    F,
    Sha256RoundFunctionFSMInputOutput<F>,
    PrecompileFunctionInputData<F>,
    PrecompileFunctionOutputData<F>,
>;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug, Default)]
#[serde(bound = "")]
pub struct Sha256RoundFunctionCircuitInstanceWitness<F: SmallField> {
    pub closed_form_input: Sha256RoundFunctionCircuitInputOutputWitness<F>,
    pub requests_queue_witness: CircuitQueueRawWitness<F, LogQuery<F>, 4, LOG_QUERY_PACKED_WIDTH>,
    pub memory_reads_witness: VecDeque<U256>,
}
