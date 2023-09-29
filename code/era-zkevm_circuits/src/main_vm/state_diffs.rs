use arrayvec::ArrayVec;

use super::*;
use crate::base_structures::vm_state::*;
use crate::base_structures::{
    register::VMRegister,
    vm_state::{callstack::Callstack, ArithmeticFlagsPort},
};
use boojum::field::SmallField;
use boojum::gadgets::num::Num;
use boojum::gadgets::{boolean::Boolean, u16::UInt16, u32::UInt32};

use crate::main_vm::opcodes::{AddSubRelation, MulDivRelation};

pub(crate) const MAX_SPONGES_PER_CYCLE: usize = 8;
pub(crate) const MAX_ADD_SUB_RELATIONS_PER_CYCLE: usize = 1;
pub(crate) const MAX_MUL_DIV_RELATIONS_PER_CYCLE: usize = 3;

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct StateDiffsAccumulator<F: SmallField> {
    // dst0 candidates
    pub dst_0_values: Vec<(bool, Boolean<F>, VMRegister<F>)>,
    // dst1 candidates
    pub dst_1_values: Vec<(Boolean<F>, VMRegister<F>)>,
    // flags candidates
    pub flags: Vec<(Boolean<F>, ArithmeticFlagsPort<F>)>,
    // specific register updates
    pub specific_registers_updates: [Vec<(Boolean<F>, VMRegister<F>)>; REGISTERS_COUNT],
    // zero out specific registers
    pub specific_registers_zeroing: [Vec<Boolean<F>>; REGISTERS_COUNT],
    // remove ptr markers on specific registers
    pub remove_ptr_on_specific_registers: [Vec<Boolean<F>>; REGISTERS_COUNT],
    // pending exceptions, to be resolved next cycle. Should be masked by opcode applicability already
    pub pending_exceptions: Vec<Boolean<F>>,
    // ergs left, PC
    // new ergs left if it's not one available after decoding
    pub new_ergs_left_candidates: Vec<(Boolean<F>, UInt32<F>)>,
    // new PC in case if it's not just PC+1
    pub new_pc_candidates: Vec<(Boolean<F>, UInt16<F>)>,
    // other meta parameters of VM
    pub new_tx_number: Option<(Boolean<F>, UInt32<F>)>,
    pub new_ergs_per_pubdata: Option<(Boolean<F>, UInt32<F>)>,
    // memory bouds
    pub new_heap_bounds: Vec<(Boolean<F>, UInt32<F>)>,
    pub new_aux_heap_bounds: Vec<(Boolean<F>, UInt32<F>)>,
    // u128 special register, one from context, another from call/ret
    pub context_u128_candidates: Vec<(Boolean<F>, [UInt32<F>; 4])>,
    // internal machinery
    pub callstacks: Vec<(Boolean<F>, Callstack<F>)>,
    // memory page counter
    pub memory_page_counters: Option<UInt32<F>>,
    // decommittment queue
    pub decommitment_queue_candidates: Option<(
        Boolean<F>,
        UInt32<F>,
        [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    )>,
    // memory queue
    pub memory_queue_candidates: Vec<(
        Boolean<F>,
        UInt32<F>,
        [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    )>,
    // forward piece of log queue
    pub log_queue_forward_candidates: Vec<(Boolean<F>, UInt32<F>, [Num<F>; QUEUE_STATE_WIDTH])>,
    // rollback piece of log queue
    pub log_queue_rollback_candidates: Vec<(Boolean<F>, UInt32<F>, [Num<F>; QUEUE_STATE_WIDTH])>,
    // sponges to run. Should not include common sponges for src/dst operands
    pub sponge_candidates_to_run: Vec<(
        bool,
        bool,
        Boolean<F>,
        ArrayVec<
            (
                Boolean<F>,
                [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
                [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
            ),
            MAX_SPONGES_PER_CYCLE,
        >,
    )>,
    // add/sub relations to enforce
    pub add_sub_relations: Vec<(
        Boolean<F>,
        ArrayVec<AddSubRelation<F>, MAX_ADD_SUB_RELATIONS_PER_CYCLE>,
    )>,
    // mul/div relations to enforce
    pub mul_div_relations: Vec<(
        Boolean<F>,
        ArrayVec<MulDivRelation<F>, MAX_MUL_DIV_RELATIONS_PER_CYCLE>,
    )>,
}
