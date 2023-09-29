use super::*;
use boojum::serde_utils::BigArraySerde;

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[CSSelectableBound(
    "where [(); <ExecutionContextRecord::<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:"
)]
pub struct Callstack<F: SmallField> {
    pub current_context: FullExecutionContext<F>,
    pub context_stack_depth: UInt32<F>,
    pub stack_sponge_state: [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
}

impl<F: SmallField> Callstack<F> {
    pub fn empty<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_u32 = UInt32::zero(cs);
        let zero_num = Num::zero(cs);
        Self {
            current_context: FullExecutionContext::uninitialized(cs),
            context_stack_depth: zero_u32,
            stack_sponge_state: [zero_num; FULL_SPONGE_QUEUE_STATE_WIDTH],
        }
    }

    pub fn is_empty<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Boolean<F> {
        self.context_stack_depth.is_zero(cs)
    }

    pub fn is_full<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Boolean<F> {
        let max_depth =
            UInt32::allocated_constant(cs, zkevm_opcode_defs::system_params::VM_MAX_STACK_DEPTH);
        UInt32::equals(cs, &self.context_stack_depth, &max_depth)
    }
}

use boojum::gadgets::traits::allocatable::CSAllocatableExt;

use crate::base_structures::vm_state::saved_context::ExecutionContextRecord;

// execution context that keeps all explicit data about the current execution frame,
// and avoid recomputing of quantities that also do not change between calls
#[derive(Derivative, CSAllocatable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct FullExecutionContext<F: SmallField> {
    pub saved_context: ExecutionContextRecord<F>,
    pub log_queue_forward_tail: [Num<F>; 4],
    pub log_queue_forward_part_length: UInt32<F>,
}

impl<F: SmallField> Selectable<F> for FullExecutionContext<F>
where
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    fn conditionally_select<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        flag: Boolean<F>,
        a: &Self,
        b: &Self,
    ) -> Self {
        let saved_context = ExecutionContextRecord::conditionally_select(
            cs,
            flag,
            &a.saved_context,
            &b.saved_context,
        );
        let log_queue_forward_tail = Num::parallel_select(
            cs,
            flag,
            &a.log_queue_forward_tail,
            &b.log_queue_forward_tail,
        );
        let log_queue_forward_part_length = UInt32::conditionally_select(
            cs,
            flag,
            &a.log_queue_forward_part_length,
            &b.log_queue_forward_part_length,
        );

        Self {
            saved_context,
            log_queue_forward_tail,
            log_queue_forward_part_length,
        }
    }
}

impl<F: SmallField> FullExecutionContext<F> {
    pub fn uninitialized<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_u32 = UInt32::zero(cs);
        let zero_num = Num::zero(cs);
        Self {
            saved_context: ExecutionContextRecord::uninitialized(cs),
            log_queue_forward_tail: [zero_num; 4],
            log_queue_forward_part_length: zero_u32,
        }
    }
}
