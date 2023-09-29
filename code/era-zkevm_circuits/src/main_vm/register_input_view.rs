use super::*;
use crate::base_structures::register::VMRegister;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::u32::UInt32;
use boojum::serde_utils::BigArraySerde;
use boojum::{field::SmallField, gadgets::u8::UInt8};
use cs_derive::*;
use std::mem::MaybeUninit;

// we can decompose register into bytes before passing it into individual opcodes
// because eventually those bytes will go into XOR/AND/OR table as inputs and will be range checked
// anyway

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Clone, Debug)]
pub struct RegisterInputView<F: SmallField> {
    // used for bitwise operations and as a shift
    pub u8x32_view: [UInt8<F>; 32],
    // copied from initial decomposition
    pub u32x8_view: [UInt32<F>; 8],
    pub is_ptr: Boolean<F>,
}

impl<F: SmallField> RegisterInputView<F> {
    pub fn from_input_value<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        register: &VMRegister<F>,
    ) -> Self {
        let mut u8x32_view: [MaybeUninit<UInt8<F>>; 32] = [MaybeUninit::uninit(); 32];

        for (src, dst) in register
            .value
            .inner
            .iter()
            .zip(u8x32_view.array_chunks_mut::<4>())
        {
            let decomposition = unsafe { src.decompose_into_bytes_unchecked(cs) };
            dst[0].write(decomposition[0]);
            dst[1].write(decomposition[1]);
            dst[2].write(decomposition[2]);
            dst[3].write(decomposition[3]);
        }

        let u8x32_view = unsafe { u8x32_view.map(|el| el.assume_init()) };

        Self {
            u8x32_view,
            u32x8_view: register.value.inner,
            is_ptr: register.is_pointer,
        }
    }
}
