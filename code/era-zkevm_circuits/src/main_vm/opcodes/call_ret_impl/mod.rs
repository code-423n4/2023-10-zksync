use crate::main_vm::register_input_view::RegisterInputView;

use super::*;
use cs_derive::*;

pub mod far_call;
pub mod near_call;
pub mod ret;

pub use self::far_call::*;
pub use self::near_call::*;
pub use self::ret::*;

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug)]

pub(crate) struct ForwardingModeABI<F: SmallField> {
    pub(crate) forwarding_mode_byte: UInt8<F>,
}

impl<F: SmallField> ForwardingModeABI<F> {
    pub fn from_register_view<CS: ConstraintSystem<F>>(
        _cs: &mut CS,
        input: &RegisterInputView<F>,
    ) -> Self {
        // higher parts of highest 64 bits
        let forwarding_mode_byte = input.u8x32_view
            [zkevm_opcode_defs::definitions::abi::far_call::FAR_CALL_FORWARDING_MODE_BYTE_IDX];

        let new = Self {
            forwarding_mode_byte,
        };

        new
    }
}

pub(crate) fn compute_shared_abi_parts<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    src0_view: &RegisterInputView<F>,
) -> (
    CommonCallRetABI<F>,
    FarCallPartialABI<F>,
    CallRetForwardingMode<F>,
) {
    let far_call_abi = FarCallPartialABI::from_register_view(cs, src0_view);
    let forwarding_mode_abi = ForwardingModeABI::from_register_view(cs, &src0_view);
    // we can share some checks

    let use_aux_heap_marker =
        UInt8::allocated_constant(cs, FarCallForwardPageType::UseAuxHeap as u8);
    let forward_fat_pointer_marker =
        UInt8::allocated_constant(cs, FarCallForwardPageType::ForwardFatPointer as u8);

    let call_ret_use_aux_heap = UInt8::equals(
        cs,
        &forwarding_mode_abi.forwarding_mode_byte,
        &use_aux_heap_marker,
    );
    let call_ret_forward_fat_pointer = UInt8::equals(
        cs,
        &forwarding_mode_abi.forwarding_mode_byte,
        &forward_fat_pointer_marker,
    );
    let call_ret_use_heap =
        Boolean::multi_or(cs, &[call_ret_use_aux_heap, call_ret_forward_fat_pointer]).negated(cs);

    let do_not_forward_ptr = call_ret_forward_fat_pointer.negated(cs);

    let (fat_ptr, upper_bound, ptr_validation_data) =
        FatPtrInABI::parse_and_validate(cs, src0_view, do_not_forward_ptr);

    let common_parts = CommonCallRetABI {
        fat_ptr,
        upper_bound,
        ptr_validation_data,
    };

    let forwarding_mode = CallRetForwardingMode {
        use_heap: call_ret_use_heap,
        use_aux_heap: call_ret_use_aux_heap,
        forward_fat_pointer: call_ret_forward_fat_pointer,
    };

    (common_parts, far_call_abi, forwarding_mode)
}
