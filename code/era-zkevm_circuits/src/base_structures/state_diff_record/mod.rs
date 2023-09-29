use super::*;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;

use boojum::cs::traits::cs::ConstraintSystem;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::u8::UInt8;
use boojum::serde_utils::BigArraySerde;
use cs_derive::*;

use boojum::gadgets::keccak256::KECCAK_RATE_BYTES;

pub const STATE_DIFF_RECORD_BYTE_ENCODING_LEN: usize = 20 + 32 + 32 + 8 + 32 + 32;
pub const NUM_KECCAK256_ROUNDS_PER_RECORD_ACCUMULATION: usize = 2;
const _: () = if STATE_DIFF_RECORD_BYTE_ENCODING_LEN
    <= KECCAK_RATE_BYTES * NUM_KECCAK256_ROUNDS_PER_RECORD_ACCUMULATION
{
    ()
} else {
    panic!()
};

#[derive(Derivative, CSAllocatable, CSSelectable, WitnessHookable)]
#[derivative(Clone, Copy, Debug, Hash)]
pub struct StateDiffRecord<F: SmallField> {
    pub address: [UInt8<F>; 20],
    pub key: [UInt8<F>; 32],
    pub derived_key: [UInt8<F>; 32],
    pub enumeration_index: [UInt8<F>; 8],
    pub initial_value: [UInt8<F>; 32],
    pub final_value: [UInt8<F>; 32],
}

impl<F: SmallField> StateDiffRecord<F> {
    // the only thing we need is byte encoding
    pub fn encode<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> [UInt8<F>; STATE_DIFF_RECORD_BYTE_ENCODING_LEN] {
        let zero_u8 = UInt8::zero(cs);
        let mut encoding = [zero_u8; STATE_DIFF_RECORD_BYTE_ENCODING_LEN];
        let mut offset = 0;
        let mut end = 0;

        end += self.address.len();
        encoding[offset..end].copy_from_slice(&self.address);
        offset = end;

        end += self.key.len();
        encoding[offset..end].copy_from_slice(&self.key);
        offset = end;

        end += self.derived_key.len();
        encoding[offset..end].copy_from_slice(&self.derived_key);
        offset = end;

        end += self.enumeration_index.len();
        encoding[offset..end].copy_from_slice(&self.enumeration_index);
        offset = end;

        end += self.initial_value.len();
        encoding[offset..end].copy_from_slice(&self.initial_value);
        offset = end;

        end += self.final_value.len();
        encoding[offset..end].copy_from_slice(&self.final_value);
        offset = end;

        debug_assert_eq!(offset, encoding.len());

        encoding
    }
}
