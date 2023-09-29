use super::*;

use boojum::cs::gates::PublicInputGate;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::cs::{Place, Variable};
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::num::Num;
use boojum::gadgets::queue::{QueueState, QueueTailState};
use boojum::gadgets::traits::castable::WitnessCastable;

use crate::base_structures::vm_state::VmLocalState;
use boojum::config::*;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use boojum::{field::SmallField, gadgets::u16::UInt16};

pub mod cycle;
pub mod decoded_opcode;
pub mod loading;
pub mod opcode_bitmask;
pub mod opcodes;
pub mod pre_state;
pub mod register_input_view;
pub mod state_diffs;
pub mod utils;
pub mod witness_oracle;

use crate::base_structures::decommit_query::DecommitQuery;
use crate::base_structures::log_query::LogQuery;
use crate::base_structures::memory_query::MemoryQuery;
use crate::base_structures::vm_state::saved_context::ExecutionContextRecord;
use crate::base_structures::vm_state::{FULL_SPONGE_QUEUE_STATE_WIDTH, QUEUE_STATE_WIDTH};
use crate::fsm_input_output::circuit_inputs::main_vm::VmCircuitWitness;
use crate::fsm_input_output::circuit_inputs::main_vm::*;
use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use crate::fsm_input_output::commit_variable_length_encodable_item;
use crate::fsm_input_output::ClosedFormInputCompactForm;
use crate::main_vm::cycle::vm_cycle;
use crate::main_vm::loading::initial_bootloader_state;
use crate::main_vm::witness_oracle::{SynchronizedWitnessOracle, WitnessOracle};
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::gadgets::traits::allocatable::{CSAllocatableExt, CSPlaceholder};
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::traits::witnessable::WitnessHookable;

pub fn main_vm_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    W: WitnessOracle<F>,
>(
    cs: &mut CS,
    witness: VmCircuitWitness<F, W>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    let VmCircuitWitness {
        closed_form_input,
        witness_oracle,
    } = witness;

    let mut structured_input =
        VmCircuitInputOutput::alloc_ignoring_outputs(cs, closed_form_input.clone());

    let start_flag = structured_input.start_flag;
    let observable_input = structured_input.observable_input.clone();
    let hidden_fsm_input = structured_input.hidden_fsm_input.clone();

    let VmInputData {
        rollback_queue_tail_for_block,
        memory_queue_initial_state,
        decommitment_queue_initial_state,
        per_block_context,
    } = observable_input;

    // we also need to create the state that reflects the "initial" state for boot process

    let bootloader_state = initial_bootloader_state(
        cs,
        memory_queue_initial_state.length,
        memory_queue_initial_state.tail,
        decommitment_queue_initial_state.length,
        decommitment_queue_initial_state.tail,
        rollback_queue_tail_for_block,
        round_function,
    );

    // or may be it's from FSM, so select
    let mut state =
        VmLocalState::conditionally_select(cs, start_flag, &bootloader_state, &hidden_fsm_input);

    let synchronized_oracle = SynchronizedWitnessOracle::new(witness_oracle);

    // we run `limit` of "normal" cycles
    for _cycle_idx in 0..limit {
        state = vm_cycle(
            cs,
            state,
            &synchronized_oracle,
            &per_block_context,
            round_function,
        );
    }

    // here we have too large state to run self-tests, so we will compare it only against the full committments

    // check for "done" flag
    let done = state.callstack.is_empty(cs);

    // we can not fail exiting, so check for our convention that pc == 0 on success, and != 0 in failure
    let bootloader_exited_successfully =
        state.callstack.current_context.saved_context.pc.is_zero(cs);

    // bootloader must exist succesfully
    bootloader_exited_successfully.conditionally_enforce_true(cs, done);

    structured_input.completion_flag = done;

    let final_state = state;

    let mut observable_output = VmOutputData::placeholder(cs);

    let full_empty_state_large = QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::empty(cs);

    // select tails

    // memory

    let memory_queue_current_tail = QueueTailState {
        tail: final_state.memory_queue_state,
        length: final_state.memory_queue_length,
    };
    let memory_queue_final_tail = QueueTailState::conditionally_select(
        cs,
        structured_input.completion_flag,
        &memory_queue_current_tail,
        &full_empty_state_large.tail,
    );

    // code decommit
    let decommitment_queue_current_tail = QueueTailState {
        tail: final_state.code_decommittment_queue_state,
        length: final_state.code_decommittment_queue_length,
    };
    let decommitment_queue_final_tail = QueueTailState::conditionally_select(
        cs,
        structured_input.completion_flag,
        &decommitment_queue_current_tail,
        &full_empty_state_large.tail,
    );

    // log. We IGNORE rollbacks that never happened obviously
    let final_log_state_tail = final_state.callstack.current_context.log_queue_forward_tail;
    let final_log_state_length = final_state
        .callstack
        .current_context
        .log_queue_forward_part_length;

    // but we CAN still check that it's potentially mergeable, basically to check that witness generation is good
    for (a, b) in final_log_state_tail.iter().zip(
        final_state
            .callstack
            .current_context
            .saved_context
            .reverted_queue_head
            .iter(),
    ) {
        Num::conditionally_enforce_equal(cs, structured_input.completion_flag, a, b);
    }

    let full_empty_state_small = QueueState::<F, QUEUE_STATE_WIDTH>::empty(cs);

    let log_queue_current_tail = QueueTailState {
        tail: final_log_state_tail,
        length: final_log_state_length,
    };
    let log_queue_final_tail = QueueTailState::conditionally_select(
        cs,
        structured_input.completion_flag,
        &log_queue_current_tail,
        &full_empty_state_small.tail,
    );

    // set everything

    observable_output.log_queue_final_state.tail = log_queue_final_tail;
    observable_output.memory_queue_final_state.tail = memory_queue_final_tail;
    observable_output.decommitment_queue_final_state.tail = decommitment_queue_final_tail;

    structured_input.observable_output = observable_output;
    structured_input.hidden_fsm_output = final_state;

    // if we generate witness then we can self-check
    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        let value_fn = move |_ins: [F; 1]| {
            let mut guard = synchronized_oracle.inner.write().expect("not poisoned");
            let consumed_witness = std::mem::replace(&mut *guard, W::default());
            drop(guard);

            consumed_witness.at_completion();

            []
        };

        cs.set_values_with_dependencies(
            &[structured_input.completion_flag.get_variable().into()],
            &[],
            value_fn,
        );
    }

    structured_input.hook_compare_witness(&*cs, &closed_form_input);

    let compact_form =
        ClosedFormInputCompactForm::from_full_form(cs, &structured_input, round_function);

    let input_commitment: [_; INPUT_OUTPUT_COMMITMENT_LENGTH] =
        commit_variable_length_encodable_item(cs, &compact_form, round_function);
    for el in input_commitment.iter() {
        let gate = PublicInputGate::new(el.get_variable());
        gate.add_to_cs(cs);
    }

    input_commitment
}
