use super::register::VMRegister;
use super::*;
use crate::base_structures::vm_state::saved_context::ExecutionContextRecord;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::cs::Variable;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::num::Num;
use boojum::gadgets::traits::allocatable::*;
use boojum::gadgets::traits::auxiliary::PrettyComparison;
use boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;
use boojum::gadgets::traits::selectable::*;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::u16::UInt16;
use boojum::gadgets::u160::UInt160;
use boojum::gadgets::u256::UInt256;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use boojum::serde_utils::BigArraySerde;
use cs_derive::*;

pub mod callstack;
pub mod saved_context;

use crate::base_structures::vm_state::callstack::Callstack;

pub const FULL_SPONGE_QUEUE_STATE_WIDTH: usize = 12;
pub const QUEUE_STATE_WIDTH: usize = 4;

pub(crate) const REGISTERS_COUNT: usize = 15;

#[derive(Derivative, CSAllocatable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct ArithmeticFlagsPort<F: SmallField> {
    pub overflow_or_less_than: Boolean<F>,
    pub equal: Boolean<F>,
    pub greater_than: Boolean<F>,
}

impl<F: SmallField> Selectable<F> for ArithmeticFlagsPort<F> {
    fn conditionally_select<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        flag: Boolean<F>,
        a: &Self,
        b: &Self,
    ) -> Self {
        // use parallel select

        let boolean_false = Boolean::allocated_constant(cs, false);

        let a = [
            a.overflow_or_less_than,
            a.equal,
            a.greater_than,
            boolean_false,
        ];
        let b = [
            b.overflow_or_less_than,
            b.equal,
            b.greater_than,
            boolean_false,
        ];

        let [overflow_or_less_than, equal, greater_than, _] =
            Boolean::parallel_select(cs, flag, &a, &b);

        Self {
            overflow_or_less_than,
            equal,
            greater_than,
        }
    }
}

impl<F: SmallField> ArithmeticFlagsPort<F> {
    pub fn reseted_flags<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let boolean_false = Boolean::allocated_constant(cs, false);
        Self {
            overflow_or_less_than: boolean_false,
            equal: boolean_false,
            greater_than: boolean_false,
        }
    }
}

#[derive(Derivative, CSSelectable, CSAllocatable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
#[CSSelectableBound(
    "where [(); <ExecutionContextRecord::<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:"
)]
#[DerivePrettyComparison("true")]
pub struct VmLocalState<F: SmallField> {
    pub previous_code_word: UInt256<F>,
    pub registers: [VMRegister<F>; REGISTERS_COUNT],
    pub flags: ArithmeticFlagsPort<F>,
    pub timestamp: UInt32<F>,
    pub memory_page_counter: UInt32<F>,
    pub tx_number_in_block: UInt32<F>,
    pub previous_code_page: UInt32<F>,
    pub previous_super_pc: UInt16<F>,
    pub pending_exception: Boolean<F>,
    pub ergs_per_pubdata_byte: UInt32<F>,
    pub callstack: Callstack<F>,
    pub memory_queue_state: [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    pub memory_queue_length: UInt32<F>,
    pub code_decommittment_queue_state: [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    pub code_decommittment_queue_length: UInt32<F>,
    pub context_composite_u128: [UInt32<F>; 4],
}

impl<F: SmallField> VmLocalState<F> {
    pub fn uninitialized<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_u32 = UInt32::zero(cs);
        let zero_u16 = UInt16::zero(cs);
        let zero_num = Num::zero(cs);
        let boolean_false = Boolean::allocated_constant(cs, false);
        let zero_u256 = UInt256::zero(cs);
        let callstack = Callstack::empty(cs);
        let empty_reg = VMRegister {
            is_pointer: boolean_false,
            value: zero_u256,
        };

        Self {
            previous_code_word: zero_u256,
            registers: [empty_reg; REGISTERS_COUNT],
            flags: ArithmeticFlagsPort {
                overflow_or_less_than: boolean_false,
                equal: boolean_false,
                greater_than: boolean_false,
            },
            timestamp: zero_u32,
            memory_page_counter: zero_u32,
            tx_number_in_block: zero_u32,
            previous_code_page: zero_u32,
            previous_super_pc: zero_u16,
            pending_exception: boolean_false,
            ergs_per_pubdata_byte: zero_u32,
            callstack,
            memory_queue_state: [zero_num; FULL_SPONGE_QUEUE_STATE_WIDTH],
            memory_queue_length: zero_u32,
            code_decommittment_queue_state: [zero_num; FULL_SPONGE_QUEUE_STATE_WIDTH],
            code_decommittment_queue_length: zero_u32,
            context_composite_u128: [zero_u32; 4],
        }
    }
}

impl<F: SmallField> CSPlaceholder<F> for VmLocalState<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self::uninitialized(cs)
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct GlobalContext<F: SmallField> {
    pub zkporter_is_available: Boolean<F>,
    pub default_aa_code_hash: UInt256<F>,
}

impl<F: SmallField> CSPlaceholder<F> for GlobalContext<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let boolean_false = Boolean::allocated_constant(cs, false);
        let zero_u256 = UInt256::zero(cs);
        Self {
            zkporter_is_available: boolean_false,
            default_aa_code_hash: zero_u256,
        }
    }
}
