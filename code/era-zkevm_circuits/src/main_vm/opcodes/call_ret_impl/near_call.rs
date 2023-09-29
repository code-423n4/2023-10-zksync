use super::*;

use crate::base_structures::vm_state::saved_context::ExecutionContextRecord;
use crate::base_structures::vm_state::saved_context::ExecutionContextRecordWitness;
use crate::main_vm::witness_oracle::SynchronizedWitnessOracle;
use crate::main_vm::witness_oracle::WitnessOracle;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::allocatable::CSAllocatableExt;
use boojum::gadgets::traits::castable::WitnessCastable;

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub(crate) struct NearCallData<F: SmallField> {
    pub(crate) apply_near_call: Boolean<F>,
    pub(crate) old_context: ExecutionContextRecord<F>,
    pub(crate) new_context: ExecutionContextRecord<F>,
    // we do not need to change queues on call
}

struct NearCallABI<F: SmallField> {
    ergs_passed: UInt32<F>,
}

use crate::main_vm::register_input_view::RegisterInputView;

impl<F: SmallField> NearCallABI<F> {
    fn from_register_view(input: &RegisterInputView<F>) -> Self {
        Self {
            ergs_passed: input.u32x8_view[0],
        }
    }
}

pub(crate) fn callstack_candidate_for_near_call<
    F: SmallField,
    CS: ConstraintSystem<F>,
    W: WitnessOracle<F>,
>(
    cs: &mut CS,
    draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    opcode_carry_parts: &AfterDecodingCarryParts<F>,
    witness_oracle: &SynchronizedWitnessOracle<F, W>,
) -> NearCallData<F>
where
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    // new callstack should be just the same a the old one, but we also need to update the pricing for pubdata in the rare case
    const NEAR_CALL_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::NearCall(zkevm_opcode_defs::NearCallOpcode);

    let execute = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(NEAR_CALL_OPCODE);

    if crate::config::CIRCUIT_VERSOBE {
        if (execute.witness_hook(&*cs))().unwrap_or(false) {
            println!("Applying NEAR CALL");
        }
    }

    let mut current_callstack_entry = draft_vm_state.callstack.current_context.saved_context;

    // perform all known modifications, like PC/SP saving
    current_callstack_entry.pc = opcode_carry_parts.next_pc;

    // for NEAR CALL the next callstack entry is largely the same
    let mut new_callstack_entry = current_callstack_entry.clone();
    // on call-like path we continue the forward queue, but have to allocate the rollback queue state from witness
    let call_timestamp = draft_vm_state.timestamp;

    let oracle = witness_oracle.clone();
    let dependencies = [
        execute.get_variable().into(),
        call_timestamp.get_variable().into(),
    ];
    let potential_rollback_queue_segment_tail =
        Num::allocate_multiple_from_closure_and_dependencies(
            cs,
            move |inputs: &[F]| {
                let execute = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
                let timestamp = <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[1]);

                let mut guard = oracle.inner.write().expect("not poisoned");
                let witness = guard.get_rollback_queue_tail_witness_for_call(timestamp, execute);
                drop(guard);

                witness
            },
            &dependencies,
        );

    let zero_u32 = UInt32::zero(cs);

    new_callstack_entry.reverted_queue_tail = potential_rollback_queue_segment_tail;
    new_callstack_entry.reverted_queue_head = potential_rollback_queue_segment_tail;
    new_callstack_entry.reverted_queue_segment_len = zero_u32;

    let dst_pc = common_opcode_state.decoded_opcode.imm0;
    let eh_pc = common_opcode_state.decoded_opcode.imm1;

    let near_call_abi = NearCallABI::from_register_view(&common_opcode_state.src0_view);
    let pass_all_ergs = near_call_abi.ergs_passed.is_zero(cs);

    let preliminary_ergs_left = opcode_carry_parts.preliminary_ergs_left;

    // we did spend some ergs on decoding, so we use one from prestate
    let ergs_to_pass = UInt32::conditionally_select(
        cs,
        pass_all_ergs,
        &preliminary_ergs_left,
        &near_call_abi.ergs_passed,
    );

    let (remaining_for_this_context, uf) = preliminary_ergs_left.overflowing_sub(cs, ergs_to_pass);

    let remaining_ergs_if_pass = remaining_for_this_context;
    let passed_ergs_if_pass = ergs_to_pass;

    // if underflow than we pass everything!
    let remaining_ergs_if_pass =
        UInt32::conditionally_select(cs, uf, &zero_u32, &remaining_ergs_if_pass);

    let passed_ergs_if_pass =
        UInt32::conditionally_select(cs, uf, &preliminary_ergs_left, &passed_ergs_if_pass);

    current_callstack_entry.ergs_remaining = remaining_ergs_if_pass;

    let oracle = witness_oracle.clone();
    let mut dependencies = Vec::with_capacity(
        <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 2,
    );
    dependencies.push(execute.get_variable().into());
    dependencies.push(
        draft_vm_state
            .callstack
            .context_stack_depth
            .get_variable()
            .into(),
    );
    dependencies.extend(Place::from_variables(
        current_callstack_entry.flatten_as_variables(),
    ));

    let _: [Num<F>; 0] = Num::allocate_multiple_from_closure_and_dependencies(
        cs,
        move |inputs: &[F]| {
            let execute = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
            let current_depth = <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[1]);

            let mut context =
                [F::ZERO; <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN];
            context.copy_from_slice(&inputs[2..]);
            let context: ExecutionContextRecordWitness<F> =
                CSAllocatableExt::witness_from_set_of_values(context);

            let mut guard = oracle.inner.write().expect("not poisoned");
            guard.push_callstack_witness(&context, current_depth, execute);
            drop(guard);

            []
        },
        &dependencies,
    );

    // ---------------------
    // actually "apply" far call

    let boolean_true = Boolean::allocated_constant(cs, true);

    new_callstack_entry.ergs_remaining = passed_ergs_if_pass;
    new_callstack_entry.pc = dst_pc;
    new_callstack_entry.exception_handler_loc = eh_pc;
    new_callstack_entry.is_local_call = boolean_true;

    let full_data = NearCallData {
        apply_near_call: execute,
        old_context: current_callstack_entry,
        new_context: new_callstack_entry,
    };

    full_data
}
