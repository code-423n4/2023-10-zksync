use crate::base_structures::{
    memory_query::{MemoryQuery, MEMORY_QUERY_PACKED_WIDTH},
    vm_state::*,
};
use crate::boojum::gadgets::traits::auxiliary::PrettyComparison;
use crate::DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS;
use boojum::cs::{traits::cs::ConstraintSystem, Variable};
use boojum::field::SmallField;
use boojum::gadgets::{
    boolean::Boolean,
    num::Num,
    queue::full_state_queue::*,
    queue::*,
    traits::{
        allocatable::*, encodable::CircuitVarLengthEncodable, selectable::Selectable,
        witnessable::WitnessHookable,
    },
    u256::UInt256,
    u32::UInt32,
};
use boojum::serde_utils::BigArraySerde;
use cs_derive::*;
use derivative::*;

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Debug)]
pub struct RamPermutationInputData<F: SmallField> {
    pub unsorted_queue_initial_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub sorted_queue_initial_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub non_deterministic_bootloader_memory_snapshot_length: UInt32<F>,
}

impl<F: SmallField> CSPlaceholder<F> for RamPermutationInputData<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_u32 = UInt32::zero(cs);
        let empty_state = QueueState::placeholder(cs);

        Self {
            unsorted_queue_initial_state: empty_state,
            sorted_queue_initial_state: empty_state,
            non_deterministic_bootloader_memory_snapshot_length: zero_u32,
        }
    }
}

pub const RAM_SORTING_KEY_LENGTH: usize = 3;
pub const RAM_FULL_KEY_LENGTH: usize = 2;

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[DerivePrettyComparison("true")]
pub struct RamPermutationFSMInputOutput<F: SmallField> {
    pub lhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub rhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub current_unsorted_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub current_sorted_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub previous_sorting_key: [UInt32<F>; RAM_SORTING_KEY_LENGTH],
    pub previous_full_key: [UInt32<F>; RAM_FULL_KEY_LENGTH],
    pub previous_value: UInt256<F>,
    pub previous_is_ptr: Boolean<F>,
    pub num_nondeterministic_writes: UInt32<F>,
}

impl<F: SmallField> CSPlaceholder<F> for RamPermutationFSMInputOutput<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_num = Num::zero(cs);
        let zero_u32 = UInt32::zero(cs);
        let zero_u256 = UInt256::zero(cs);
        let boolean_false = Boolean::allocated_constant(cs, false);
        let empty_state = QueueState::placeholder(cs);

        Self {
            lhs_accumulator: [zero_num; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
            rhs_accumulator: [zero_num; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
            current_unsorted_queue_state: empty_state,
            current_sorted_queue_state: empty_state,
            previous_sorting_key: [zero_u32; RAM_SORTING_KEY_LENGTH],
            previous_full_key: [zero_u32; RAM_FULL_KEY_LENGTH],
            previous_value: zero_u256,
            previous_is_ptr: boolean_false,
            num_nondeterministic_writes: zero_u32,
        }
    }
}

pub type RamPermutationCycleInputOutput<F> = crate::fsm_input_output::ClosedFormInput<
    F,
    RamPermutationFSMInputOutput<F>,
    RamPermutationInputData<F>,
    (),
>;
pub type RamPermutationCycleInputOutputWitness<F> = crate::fsm_input_output::ClosedFormInputWitness<
    F,
    RamPermutationFSMInputOutput<F>,
    RamPermutationInputData<F>,
    (),
>;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug, Default)]
#[serde(bound = "")]
pub struct RamPermutationCircuitInstanceWitness<F: SmallField> {
    pub closed_form_input: RamPermutationCycleInputOutputWitness<F>,

    pub unsorted_queue_witness: FullStateCircuitQueueRawWitness<
        F,
        MemoryQuery<F>,
        FULL_SPONGE_QUEUE_STATE_WIDTH,
        MEMORY_QUERY_PACKED_WIDTH,
    >,
    pub sorted_queue_witness: FullStateCircuitQueueRawWitness<
        F,
        MemoryQuery<F>,
        FULL_SPONGE_QUEUE_STATE_WIDTH,
        MEMORY_QUERY_PACKED_WIDTH,
    >,
}

pub type MemoryQueriesQueue<F, R> =
    FullStateCircuitQueue<F, MemoryQuery<F>, 8, 12, 4, MEMORY_QUERY_PACKED_WIDTH, R>;
