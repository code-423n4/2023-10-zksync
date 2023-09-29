use super::*;
use boojum::cs::implementations::lookup_table::LookupTable;
use boojum::field::SmallField;

pub const FLAGS_PACKED_ENCODING_BIT_WIDTH: usize = 3;

pub(crate) fn integer_into_flags(encoding: u8) -> (bool, bool, bool) {
    (
        (encoding & 0x1) != 0,
        ((encoding & 0x2) != 0),
        ((encoding & 0x4) != 0),
    )
}

pub const VM_CONDITIONAL_RESOLUTION_TABLE_NAME: &'static str = "Conditional resolution table";

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VMConditionalResolutionTable;

pub fn create_conditionals_resolution_table<F: SmallField>() -> LookupTable<F, 3> {
    let num_rows = 8 * 8;

    let mut all_keys = Vec::with_capacity(num_rows);

    let all_conditions = zkevm_opcode_defs::ALL_CONDITIONS;
    use zkevm_opcode_defs::Condition;
    for condition in all_conditions.iter() {
        let x = condition.variant_index(); // integer encoding
        for i in 0..(1 << FLAGS_PACKED_ENCODING_BIT_WIDTH) {
            let (of, eq, gt) = integer_into_flags(i as u8);
            let resolution = match condition {
                Condition::Always => true,
                Condition::Lt => of,
                Condition::Eq => eq,
                Condition::Gt => gt,
                Condition::Ge => gt || eq,
                Condition::Le => of || eq,
                Condition::Ne => !eq,
                Condition::GtOrLt => gt || of,
            };

            let row = [
                F::from_u64(x as u64).unwrap(),
                F::from_u64(i as u64).unwrap(),
                F::from_u64(resolution as u64).unwrap(),
            ];

            all_keys.push(row);
        }
    }

    LookupTable::new_from_content(
        all_keys,
        VM_CONDITIONAL_RESOLUTION_TABLE_NAME.to_string(),
        2,
    )
}
