use boojum::field::SmallField;
use boojum::{cs::traits::cs::ConstraintSystem, gadgets::u8::UInt8};

use super::*;

pub mod decommit_query;
pub mod log_query;
pub mod memory_query;
pub mod recursion_query;
pub mod register;
pub mod vm_state;

pub mod precompile_input_outputs;
pub mod state_diff_record;

pub trait ByteSerializable<F: SmallField, const N: usize> {
    fn into_bytes<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> [UInt8<F>; N];
}
