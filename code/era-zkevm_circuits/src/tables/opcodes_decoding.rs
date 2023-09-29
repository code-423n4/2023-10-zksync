use super::*;
use boojum::cs::implementations::lookup_table::LookupTable;
use boojum::field::SmallField;

use zkevm_opcode_defs::OPCODES_TABLE_WIDTH;

pub const VM_OPCODE_DECODING_AND_PRICING_TABLE_NAME: &'static str =
    "Opcode decoding and pricing table";

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VMOpcodeDecodingTable;

pub fn create_opcodes_decoding_and_pricing_table<F: SmallField>() -> LookupTable<F, 3> {
    let mut all_keys = Vec::with_capacity(1 << OPCODES_TABLE_WIDTH);
    let num_rows = zkevm_opcode_defs::OPCODES_TABLE.len();
    assert_eq!(num_rows, 1 << OPCODES_TABLE_WIDTH);

    for x in 0..num_rows {
        let opcode_as_integer = x as u64;
        let opcode_props_encoding = zkevm_opcode_defs::OPCODES_PROPS_INTEGER_BITMASKS[x];
        let price = zkevm_opcode_defs::OPCODES_PRICES[x];

        let row = [
            F::from_u64(opcode_as_integer).unwrap(),
            F::from_u64(price as u64).unwrap(),
            F::from_u64(opcode_props_encoding).unwrap(),
        ];

        all_keys.push(row);
    }

    LookupTable::new_from_content(
        all_keys,
        VM_OPCODE_DECODING_AND_PRICING_TABLE_NAME.to_string(),
        1,
    )
}
