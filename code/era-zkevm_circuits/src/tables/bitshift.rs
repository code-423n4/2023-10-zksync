use super::*;
use crate::ethereum_types::U256;
use boojum::cs::implementations::lookup_table::LookupTable;
use boojum::field::SmallField;

pub const VM_SHIFT_TO_NUM_CONVERTER_TABLE_NAME: &'static str = "Shift to num converter table";

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitshiftTable;

pub fn create_shift_to_num_converter_table<F: SmallField>() -> LookupTable<F, 3> {
    // there are 256 possible shifts and 8 32-bit limbs in any 256-bit register
    // we give the value of two limbs per row, so the total number of rows in the table is:
    // 256 * 8/2 = 256 * 4 = 1024
    let num_rows = 1024;
    let mut all_keys = Vec::with_capacity(num_rows);

    for shift in 0..256 {
        let mut modulus = U256::from(1u64) << shift;
        let mut idx = 0;
        while idx < 4 {
            let x = F::from_u64((shift + (idx << 8)) as u64).unwrap();
            let y = F::from_u64(modulus.low_u32() as u64).unwrap();
            modulus >>= 32;
            let z = F::from_u64(modulus.low_u32() as u64).unwrap();
            modulus >>= 32;
            idx += 1;

            let row = [x, y, z];
            all_keys.push(row);
        }
    }

    LookupTable::new_from_content(
        all_keys,
        VM_SHIFT_TO_NUM_CONVERTER_TABLE_NAME.to_string(),
        1,
    )
}
