use super::*;

use crate::base_structures::vm_state::*;
use boojum::gadgets::queue::*;
use boojum::serde_utils::BigArraySerde;

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Debug)]
pub struct VmInputData<F: SmallField> {
    pub rollback_queue_tail_for_block: [Num<F>; QUEUE_STATE_WIDTH],
    pub memory_queue_initial_state: QueueTailState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub decommitment_queue_initial_state: QueueTailState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub per_block_context: GlobalContext<F>,
}

impl<F: SmallField> CSPlaceholder<F> for VmInputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_num = Num::zero(cs);
        let empty_tail = QueueTailState::placeholder(cs);
        let placeholder_ctx = GlobalContext::<F>::placeholder(cs);
        Self {
            rollback_queue_tail_for_block: [zero_num; QUEUE_STATE_WIDTH],
            memory_queue_initial_state: empty_tail,
            decommitment_queue_initial_state: empty_tail,
            per_block_context: placeholder_ctx,
        }
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Debug)]
#[DerivePrettyComparison("true")]
pub struct VmOutputData<F: SmallField> {
    pub log_queue_final_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub memory_queue_final_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub decommitment_queue_final_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

impl<F: SmallField> CSPlaceholder<F> for VmOutputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let empty_small = QueueState::placeholder(cs);
        let empty_large = QueueState::placeholder(cs);
        Self {
            log_queue_final_state: empty_small,
            memory_queue_final_state: empty_large,
            decommitment_queue_final_state: empty_large,
        }
    }
}

use crate::base_structures::vm_state::VmLocalState;

pub type VmCircuitInputOutput<F> =
    crate::fsm_input_output::ClosedFormInput<F, VmLocalState<F>, VmInputData<F>, VmOutputData<F>>;
pub type VmCircuitInputOutputWitness<F> = crate::fsm_input_output::ClosedFormInputWitness<
    F,
    VmLocalState<F>,
    VmInputData<F>,
    VmOutputData<F>,
>;

use crate::main_vm::witness_oracle::WitnessOracle;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug(bound = ""), Default)]
#[serde(bound = "")]
pub struct VmCircuitWitness<F: SmallField, W: WitnessOracle<F>> {
    pub closed_form_input: VmCircuitInputOutputWitness<F>,
    #[derivative(Debug = "ignore")]
    pub witness_oracle: W,
}
